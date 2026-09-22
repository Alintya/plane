# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import os
import time
from datetime import datetime, timedelta
from urllib.parse import urlencode, urlparse

import pytz
import requests

# Module imports
from plane.authentication.adapter.oauth import OauthAdapter
from plane.license.utils.instance_value import get_configuration_value
from plane.authentication.adapter.error import (
    AUTHENTICATION_ERROR_CODES,
    AuthenticationException,
)

# Discovery documents change rarely and are fetched on both the initiate and the
# callback leg of every login, so cache them briefly per issuer.
DISCOVERY_CACHE_TTL = 300
_discovery_cache = {}


def get_discovery_document(issuer_url):
    """Resolve an issuer's OpenID Connect discovery document.

    The issuer URL is configured by the instance admin (trusted input), so this
    is a plain fetch — unlike avatar URLs, which are attacker-influenceable and
    go through the SSRF-safe pinned client.
    """
    cached = _discovery_cache.get(issuer_url)
    if cached and (time.monotonic() - cached[0]) < DISCOVERY_CACHE_TTL:
        return cached[1]

    try:
        response = requests.get(
            f"{issuer_url}/.well-known/openid-configuration",
            headers={"Accept": "application/json"},
            timeout=10,
        )
        response.raise_for_status()
        document = response.json()
    except (requests.RequestException, ValueError):
        raise AuthenticationException(
            error_code=AUTHENTICATION_ERROR_CODES["OIDC_OAUTH_PROVIDER_ERROR"],
            error_message="OIDC_OAUTH_PROVIDER_ERROR",
        )

    if not isinstance(document, dict) or not all(
        document.get(endpoint) for endpoint in ("authorization_endpoint", "token_endpoint", "userinfo_endpoint")
    ):
        raise AuthenticationException(
            error_code=AUTHENTICATION_ERROR_CODES["OIDC_OAUTH_PROVIDER_ERROR"],
            error_message="OIDC_OAUTH_PROVIDER_ERROR",
        )

    _discovery_cache[issuer_url] = (time.monotonic(), document)
    return document


class OIDCOAuthProvider(OauthAdapter):
    provider = "oidc"
    scope = "openid email profile"

    def __init__(self, request, code=None, state=None, callback=None):
        (OIDC_ISSUER_URL, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET) = get_configuration_value(
            [
                {
                    "key": "OIDC_ISSUER_URL",
                    "default": os.environ.get("OIDC_ISSUER_URL"),
                },
                {
                    "key": "OIDC_CLIENT_ID",
                    "default": os.environ.get("OIDC_CLIENT_ID"),
                },
                {
                    "key": "OIDC_CLIENT_SECRET",
                    "default": os.environ.get("OIDC_CLIENT_SECRET"),
                },
            ]
        )

        if not (OIDC_ISSUER_URL and OIDC_CLIENT_ID and OIDC_CLIENT_SECRET):
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["OIDC_NOT_CONFIGURED"],
                error_message="OIDC_NOT_CONFIGURED",
            )

        # Enforce scheme and normalize trailing slash(es)
        parsed = urlparse(OIDC_ISSUER_URL)
        if parsed.scheme not in ("https", "http") or not parsed.netloc:
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["OIDC_NOT_CONFIGURED"],
                error_message="OIDC_NOT_CONFIGURED",  # avoid leaking details to query params
            )
        OIDC_ISSUER_URL = OIDC_ISSUER_URL.rstrip("/")

        discovery_document = get_discovery_document(OIDC_ISSUER_URL)
        self.token_url = discovery_document["token_endpoint"]
        self.userinfo_url = discovery_document["userinfo_endpoint"]

        client_id = OIDC_CLIENT_ID
        client_secret = OIDC_CLIENT_SECRET

        redirect_uri = f"{'https' if request.is_secure() else 'http'}://{request.get_host()}/auth/oidc/callback/"
        url_params = {
            "client_id": client_id,
            "scope": self.scope,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "state": state,
        }
        auth_url = f"{discovery_document['authorization_endpoint']}?{urlencode(url_params)}"

        super().__init__(
            request,
            self.provider,
            client_id,
            self.scope,
            redirect_uri,
            auth_url,
            self.token_url,
            self.userinfo_url,
            client_secret,
            code,
            callback=callback,
        )

    def set_token_data(self):
        data = {
            "grant_type": "authorization_code",
            "code": self.code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        token_response = self.get_user_token(data=data, headers={"Accept": "application/json"})
        super().set_token_data(
            {
                "access_token": token_response.get("access_token"),
                "refresh_token": token_response.get("refresh_token", None),
                # OIDC token responses carry a relative `expires_in` and no issue
                # timestamp, so the expiry is computed from now.
                "access_token_expired_at": (
                    datetime.now(tz=pytz.utc) + timedelta(seconds=token_response.get("expires_in"))
                    if token_response.get("expires_in")
                    else None
                ),
                "refresh_token_expired_at": (
                    datetime.now(tz=pytz.utc) + timedelta(seconds=token_response.get("refresh_expires_in"))
                    if token_response.get("refresh_expires_in")
                    else None
                ),
                "id_token": token_response.get("id_token", ""),
            }
        )

    def set_user_data(self):
        user_info_response = self.get_user_response()

        # `email_verified` is optional in the spec and plenty of enterprise IdPs omit
        # it, so an absent claim is accepted. An explicit false is rejected: trusting
        # it would let anyone register an unverified address on the IdP and take over
        # a matching Plane account (GHSA-7j95-vh8g-f365).
        if user_info_response.get("email_verified") is False:
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["OAUTH_PROVIDER_UNVERIFIED_EMAIL"],
                error_message="OAUTH_PROVIDER_UNVERIFIED_EMAIL",
            )

        email = user_info_response.get("email")
        provider_id = user_info_response.get("sub")
        if not email or not provider_id:
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["OIDC_OAUTH_PROVIDER_ERROR"],
                error_message="OIDC_OAUTH_PROVIDER_ERROR",
            )

        super().set_user_data(
            {
                "email": email,
                "user": {
                    "provider_id": str(provider_id),
                    "email": email,
                    "avatar": user_info_response.get("picture") or "",
                    "first_name": user_info_response.get("given_name") or user_info_response.get("name") or "",
                    "last_name": user_info_response.get("family_name") or "",
                    "display_name": user_info_response.get("preferred_username"),
                    "is_password_autoset": True,
                },
            }
        )
