# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""Unit tests for the generic OIDC OAuth provider."""

from unittest.mock import MagicMock, patch

import pytest
import requests

from plane.authentication.adapter.error import AuthenticationException
from plane.authentication.provider.oauth import oidc as oidc_module
from plane.authentication.provider.oauth.oidc import OIDCOAuthProvider

ISSUER = "https://idp.example.com/application/o/plane"

DISCOVERY_DOCUMENT = {
    "issuer": ISSUER,
    "authorization_endpoint": f"{ISSUER}/authorize",
    "token_endpoint": f"{ISSUER}/token",
    "userinfo_endpoint": f"{ISSUER}/userinfo",
}

CONFIGURED = [ISSUER, "plane-client", "plane-secret"]


def fake_request():
    """Minimal stand-in for the Django request the provider reads host info from."""
    request = MagicMock()
    request.is_secure.return_value = True
    request.get_host.return_value = "plane.example.com"
    request.session = {}
    return request


def discovery_response(payload, status_ok=True):
    response = MagicMock()
    response.json.return_value = payload
    if not status_ok:
        response.raise_for_status.side_effect = requests.HTTPError("boom")
    return response


def build_provider(config=None, document=None, **kwargs):
    with (
        patch(
            "plane.authentication.provider.oauth.oidc.get_configuration_value",
            return_value=config if config is not None else CONFIGURED,
        ),
        patch(
            "plane.authentication.provider.oauth.oidc.requests.get",
            return_value=discovery_response(DISCOVERY_DOCUMENT if document is None else document),
        ),
    ):
        return OIDCOAuthProvider(request=fake_request(), **kwargs)


@pytest.fixture(autouse=True)
def clear_discovery_cache():
    oidc_module._discovery_cache.clear()
    yield
    oidc_module._discovery_cache.clear()


@pytest.mark.unit
class TestOIDCDiscovery:
    """Endpoints are resolved from the issuer's discovery document."""

    def test_endpoints_resolved_from_discovery_document(self):
        provider = build_provider(state="state-token")

        assert provider.token_url == f"{ISSUER}/token"
        assert provider.userinfo_url == f"{ISSUER}/userinfo"
        assert provider.get_auth_url().startswith(f"{ISSUER}/authorize?")
        assert "scope=openid+email+profile" in provider.get_auth_url()
        assert "state=state-token" in provider.get_auth_url()
        assert "redirect_uri=https%3A%2F%2Fplane.example.com%2Fauth%2Foidc%2Fcallback%2F" in provider.get_auth_url()

    def test_discovery_url_is_derived_from_the_issuer(self):
        with (
            patch(
                "plane.authentication.provider.oauth.oidc.get_configuration_value",
                return_value=[f"{ISSUER}/", "plane-client", "plane-secret"],
            ),
            patch(
                "plane.authentication.provider.oauth.oidc.requests.get",
                return_value=discovery_response(DISCOVERY_DOCUMENT),
            ) as mocked_get,
        ):
            OIDCOAuthProvider(request=fake_request())

        assert mocked_get.call_args.args[0] == f"{ISSUER}/.well-known/openid-configuration"

    def test_document_is_cached_per_issuer(self):
        with (
            patch(
                "plane.authentication.provider.oauth.oidc.get_configuration_value",
                return_value=CONFIGURED,
            ),
            patch(
                "plane.authentication.provider.oauth.oidc.requests.get",
                return_value=discovery_response(DISCOVERY_DOCUMENT),
            ) as mocked_get,
        ):
            OIDCOAuthProvider(request=fake_request())
            OIDCOAuthProvider(request=fake_request())

        assert mocked_get.call_count == 1

    def test_missing_endpoint_raises_provider_error(self):
        incomplete = {key: value for key, value in DISCOVERY_DOCUMENT.items() if key != "token_endpoint"}

        with pytest.raises(AuthenticationException) as exc:
            build_provider(document=incomplete)

        assert exc.value.error_code == 5114

    def test_unreachable_issuer_raises_provider_error(self):
        with (
            patch(
                "plane.authentication.provider.oauth.oidc.get_configuration_value",
                return_value=CONFIGURED,
            ),
            patch(
                "plane.authentication.provider.oauth.oidc.requests.get",
                side_effect=requests.ConnectionError("unreachable"),
            ),
        ):
            with pytest.raises(AuthenticationException) as exc:
                OIDCOAuthProvider(request=fake_request())

        assert exc.value.error_code == 5114


@pytest.mark.unit
class TestOIDCConfiguration:
    """Incomplete instance configuration is reported as "not configured"."""

    @pytest.mark.parametrize(
        "config",
        [
            [None, "plane-client", "plane-secret"],
            [ISSUER, None, "plane-secret"],
            [ISSUER, "plane-client", None],
        ],
    )
    def test_missing_configuration_raises_not_configured(self, config):
        with pytest.raises(AuthenticationException) as exc:
            build_provider(config=config)

        assert exc.value.error_code == 5113

    def test_issuer_without_scheme_raises_not_configured(self):
        with pytest.raises(AuthenticationException) as exc:
            build_provider(config=["idp.example.com", "plane-client", "plane-secret"])

        assert exc.value.error_code == 5113


@pytest.mark.unit
class TestOIDCUserData:
    """Standard claims are mapped onto Plane's user payload."""

    def set_user_data(self, claims):
        provider = build_provider()
        with patch.object(OIDCOAuthProvider, "get_user_response", return_value=claims):
            provider.set_user_data()
        return provider.user_data

    def test_standard_claims_are_mapped(self):
        user_data = self.set_user_data(
            {
                "sub": "af1a1e00-1111-4a4a-9999-abcdefabcdef",
                "email": "ada@example.com",
                "email_verified": True,
                "given_name": "Ada",
                "family_name": "Lovelace",
                "picture": "https://idp.example.com/avatar.png",
                "preferred_username": "ada",
            }
        )

        assert user_data == {
            "email": "ada@example.com",
            "user": {
                "provider_id": "af1a1e00-1111-4a4a-9999-abcdefabcdef",
                "email": "ada@example.com",
                "avatar": "https://idp.example.com/avatar.png",
                "first_name": "Ada",
                "last_name": "Lovelace",
                "display_name": "ada",
                "is_password_autoset": True,
            },
        }

    def test_name_claim_is_used_when_given_name_is_absent(self):
        user_data = self.set_user_data(
            {"sub": "1", "email": "grace@example.com", "name": "Grace Hopper"},
        )

        assert user_data["user"]["first_name"] == "Grace Hopper"
        assert user_data["user"]["last_name"] == ""
        assert user_data["user"]["avatar"] == ""
        assert user_data["user"]["display_name"] is None

    def test_absent_email_verified_claim_is_accepted(self):
        user_data = self.set_user_data({"sub": "1", "email": "grace@example.com"})

        assert user_data["email"] == "grace@example.com"

    def test_explicitly_unverified_email_is_rejected(self):
        with pytest.raises(AuthenticationException) as exc:
            self.set_user_data(
                {"sub": "1", "email": "attacker@example.com", "email_verified": False},
            )

        assert exc.value.error_code == 5124

    @pytest.mark.parametrize(
        "claims",
        [
            {"sub": "1"},
            {"email": "grace@example.com"},
        ],
    )
    def test_missing_identity_claims_raise_provider_error(self, claims):
        with pytest.raises(AuthenticationException) as exc:
            self.set_user_data(claims)

        assert exc.value.error_code == 5114


@pytest.mark.unit
class TestOIDCTokenData:
    """The token exchange uses the authorization-code grant."""

    def test_token_exchange_payload_and_expiry(self):
        provider = build_provider(code="auth-code")

        with patch.object(
            OIDCOAuthProvider,
            "get_user_token",
            return_value={"access_token": "at", "refresh_token": "rt", "expires_in": 300},
        ) as mocked_token:
            provider.set_token_data()

        payload = mocked_token.call_args.kwargs["data"]
        assert payload["grant_type"] == "authorization_code"
        assert payload["code"] == "auth-code"
        assert payload["client_id"] == "plane-client"
        assert payload["client_secret"] == "plane-secret"
        assert payload["redirect_uri"] == "https://plane.example.com/auth/oidc/callback/"

        assert provider.token_data["access_token"] == "at"
        assert provider.token_data["access_token_expired_at"] is not None

    def test_expiry_is_none_when_provider_omits_expires_in(self):
        provider = build_provider(code="auth-code")

        with patch.object(OIDCOAuthProvider, "get_user_token", return_value={"access_token": "at"}):
            provider.set_token_data()

        assert provider.token_data["access_token_expired_at"] is None
