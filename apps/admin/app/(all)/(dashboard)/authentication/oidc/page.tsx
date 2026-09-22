/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { useState } from "react";
import { KeyRound } from "lucide-react";
import { observer } from "mobx-react";
import useSWR from "swr";
// plane internal packages
import { Switch } from "@makeplane/propel/components/switch";
// components
import { AuthenticationMethodCard } from "@/components/authentication/authentication-method-card";
import { PageWrapper } from "@/components/common/page-wrapper";
import { Skeleton } from "@/components/common/skeleton";
import { setPromiseToast } from "@/providers/toast";
// hooks
import { useInstance } from "@/hooks/store";
// types
import type { Route } from "./+types/page";
// local
import { InstanceOIDCConfigForm } from "./form";

const InstanceOIDCAuthenticationPage = observer(function InstanceOIDCAuthenticationPage() {
  // store
  const { fetchInstanceConfigurations, formattedConfig, updateInstanceConfigurations } = useInstance();
  // state
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  // config
  const enableOIDCConfig = formattedConfig?.IS_OIDC_ENABLED ?? "";
  useSWR("INSTANCE_CONFIGURATIONS", () => fetchInstanceConfigurations());

  const updateConfig = async (key: "IS_OIDC_ENABLED", value: string) => {
    setIsSubmitting(true);

    const payload = {
      [key]: value,
    };

    const updateConfigPromise = updateInstanceConfigurations(payload);

    setPromiseToast(updateConfigPromise, {
      loading: "Saving Configuration",
      success: {
        title: "Configuration saved",
        message: () => `OIDC authentication is now ${value === "1" ? "active" : "disabled"}.`,
      },
      error: {
        title: "Error",
        message: () => "Failed to save configuration",
      },
    });

    await updateConfigPromise
      .then(() => {
        setIsSubmitting(false);
      })
      .catch((err) => {
        console.error(err);
        setIsSubmitting(false);
      });
  };

  const isOIDCEnabled = enableOIDCConfig === "1";

  return (
    <PageWrapper
      customHeader={
        <AuthenticationMethodCard
          name="OIDC"
          description="Allow members to login or sign up to plane with your OpenID Connect identity provider."
          icon={<KeyRound className="h-6 w-6 p-0.5 text-tertiary" />}
          config={
            <Switch
              checked={isOIDCEnabled}
              onCheckedChange={() => {
                updateConfig("IS_OIDC_ENABLED", isOIDCEnabled ? "0" : "1");
              }}
              size="sm"
              disabled={isSubmitting || !formattedConfig}
            />
          }
          disabled={isSubmitting || !formattedConfig}
          withBorder={false}
        />
      }
    >
      {formattedConfig ? (
        <InstanceOIDCConfigForm config={formattedConfig} />
      ) : (
        <Skeleton className="space-y-8">
          <Skeleton.Item height="50px" width="25%" />
          <Skeleton.Item height="50px" />
          <Skeleton.Item height="50px" />
          <Skeleton.Item height="50px" />
          <Skeleton.Item height="50px" width="50%" />
        </Skeleton>
      )}
    </PageWrapper>
  );
});
export const meta: Route.MetaFunction = () => [{ title: "OIDC Authentication - God Mode" }];

export default InstanceOIDCAuthenticationPage;
