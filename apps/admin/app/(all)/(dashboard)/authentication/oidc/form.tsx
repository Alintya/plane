/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { useState } from "react";
import { isEmpty } from "lodash-es";
import Link from "next/link";
import { useForm } from "react-hook-form";
// plane internal packages
import { API_BASE_URL } from "@plane/constants";
import { Button } from "@makeplane/propel/components/button";
import { TOAST_TYPE, setToast } from "@/providers/toast";
import type { IFormattedInstanceConfiguration, TInstanceOIDCAuthenticationConfigurationKeys } from "@plane/types";
// components
import { CodeBlock } from "@/components/common/code-block";
import { ConfirmDiscardModal } from "@/components/common/confirm-discard-modal";
import type { TControllerInputFormField } from "@/components/common/controller-input";
import { ControllerInput } from "@/components/common/controller-input";
import type { TControllerSwitchFormField } from "@/components/common/controller-switch";
import { ControllerSwitch } from "@/components/common/controller-switch";
import type { TCopyField } from "@/components/common/copy-field";
import { CopyField } from "@/components/common/copy-field";
// hooks
import { useInstance } from "@/hooks/store";

type Props = {
  config: IFormattedInstanceConfiguration;
};

type OIDCConfigFormValues = Record<TInstanceOIDCAuthenticationConfigurationKeys, string>;

const OIDC_FORM_SWITCH_FIELD: TControllerSwitchFormField<OIDCConfigFormValues> = {
  name: "ENABLE_OIDC_SYNC",
  label: "OIDC",
};

export function InstanceOIDCConfigForm(props: Props) {
  const { config } = props;
  // states
  const [isDiscardChangesModalOpen, setIsDiscardChangesModalOpen] = useState(false);
  // store hooks
  const { updateInstanceConfigurations } = useInstance();
  // form data
  const {
    handleSubmit,
    control,
    reset,
    formState: { errors, isDirty, isSubmitting },
  } = useForm<OIDCConfigFormValues>({
    defaultValues: {
      OIDC_ISSUER_URL: config["OIDC_ISSUER_URL"],
      OIDC_CLIENT_ID: config["OIDC_CLIENT_ID"],
      OIDC_CLIENT_SECRET: config["OIDC_CLIENT_SECRET"],
      OIDC_PROVIDER_NAME: config["OIDC_PROVIDER_NAME"] || "OIDC",
      ENABLE_OIDC_SYNC: config["ENABLE_OIDC_SYNC"] || "0",
    },
  });

  const originURL = !isEmpty(API_BASE_URL) ? API_BASE_URL : typeof window !== "undefined" ? window.location.origin : "";

  const OIDC_FORM_FIELDS: TControllerInputFormField<OIDCConfigFormValues>[] = [
    {
      key: "OIDC_ISSUER_URL",
      type: "text",
      label: "Issuer URL",
      description: (
        <>
          The base URL of your identity provider. Plane reads the authorization, token, and userinfo endpoints from{" "}
          <CodeBlock darkerShade>{"<issuer>/.well-known/openid-configuration"}</CodeBlock>, so make sure that document
          is reachable from this server.
        </>
      ),
      placeholder: "https://authentik.example.com/application/o/plane/",
      error: Boolean(errors.OIDC_ISSUER_URL),
      required: true,
    },
    {
      key: "OIDC_CLIENT_ID",
      type: "text",
      label: "Client ID",
      description: <>The client ID of the OAuth2 / OpenID Connect application you created on your provider.</>,
      placeholder: "plane",
      error: Boolean(errors.OIDC_CLIENT_ID),
      required: true,
    },
    {
      key: "OIDC_CLIENT_SECRET",
      type: "password",
      label: "Client secret",
      description: <>The client secret issued alongside the client ID. Confidential clients only.</>,
      placeholder: "9b0050f94ec1b744e32ce79ea4ffacd40d4119cb",
      error: Boolean(errors.OIDC_CLIENT_SECRET),
      required: true,
    },
    {
      key: "OIDC_PROVIDER_NAME",
      type: "text",
      label: "Provider name",
      description: <>Shown on the login button, as in &quot;Continue with Authentik&quot;. Defaults to OIDC.</>,
      placeholder: "Authentik",
      error: Boolean(errors.OIDC_PROVIDER_NAME),
      required: false,
    },
  ];

  const OIDC_SERVICE_FIELD: TCopyField[] = [
    {
      key: "Callback_URI",
      label: "Callback URI",
      url: `${originURL}/auth/oidc/callback/`,
      description: (
        <>
          We will auto-generate this. Add it to the <CodeBlock darkerShade>Redirect URIs</CodeBlock> of your OIDC
          application. If you also use Plane&apos;s public spaces, add{" "}
          <CodeBlock darkerShade>{`${originURL}/auth/spaces/oidc/callback/`}</CodeBlock> as a second redirect URI.
        </>
      ),
    },
  ];

  const onSubmit = async (formData: OIDCConfigFormValues) => {
    const payload: Partial<OIDCConfigFormValues> = { ...formData };

    try {
      const response = await updateInstanceConfigurations(payload);
      setToast({
        type: TOAST_TYPE.SUCCESS,
        title: "Done!",
        message: "Your OIDC authentication is configured. You should test it now.",
      });
      reset({
        OIDC_ISSUER_URL: response.find((item) => item.key === "OIDC_ISSUER_URL")?.value,
        OIDC_CLIENT_ID: response.find((item) => item.key === "OIDC_CLIENT_ID")?.value,
        OIDC_CLIENT_SECRET: response.find((item) => item.key === "OIDC_CLIENT_SECRET")?.value,
        OIDC_PROVIDER_NAME: response.find((item) => item.key === "OIDC_PROVIDER_NAME")?.value,
        ENABLE_OIDC_SYNC: response.find((item) => item.key === "ENABLE_OIDC_SYNC")?.value,
      });
    } catch (err) {
      console.error(err);
    }
  };

  const handleGoBack = (e: React.MouseEvent<HTMLAnchorElement, MouseEvent>) => {
    if (isDirty) {
      e.preventDefault();
      setIsDiscardChangesModalOpen(true);
    }
  };

  return (
    <>
      <ConfirmDiscardModal
        isOpen={isDiscardChangesModalOpen}
        onDiscardHref="/authentication"
        handleClose={() => setIsDiscardChangesModalOpen(false)}
      />
      <div className="flex flex-col gap-8">
        <div className="grid w-full grid-cols-2 gap-x-12 gap-y-8">
          <div className="col-span-2 flex flex-col gap-y-4 pt-1 md:col-span-1">
            <div className="pt-2.5 text-18 font-medium">Provider-provided details for Plane</div>
            {OIDC_FORM_FIELDS.map((field) => (
              <ControllerInput
                key={field.key}
                control={control}
                type={field.type}
                name={field.key}
                label={field.label}
                description={field.description}
                placeholder={field.placeholder}
                error={field.error}
                required={field.required}
              />
            ))}
            <ControllerSwitch control={control} field={OIDC_FORM_SWITCH_FIELD} />
            <div className="flex flex-col gap-1 pt-4">
              <div className="flex items-center gap-4">
                <Button
                  variant="primary"
                  size="md"
                  stretch="auto"
                  onClick={(e) => void handleSubmit(onSubmit)(e)}
                  loading={isSubmitting}
                  disabled={!isDirty}
                  label={isSubmitting ? "Saving" : "Save changes"}
                />
                <Button
                  variant="secondary"
                  size="md"
                  stretch="auto"
                  nativeButton={false}
                  render={<Link href="/authentication" onClick={handleGoBack} />}
                  label="Go back"
                />
              </div>
            </div>
          </div>
          <div className="col-span-2 md:col-span-1">
            <div className="flex flex-col gap-y-4 rounded-lg bg-layer-1 px-6 pt-1.5 pb-4">
              <div className="pt-2 text-18 font-medium">Plane-provided details for your provider</div>
              {OIDC_SERVICE_FIELD.map((field) => (
                <CopyField key={field.key} label={field.label} url={field.url} description={field.description} />
              ))}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
