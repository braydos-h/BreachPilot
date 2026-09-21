// /system route: the Sandbox/Firewall posture card (effective mode, Docker
// health, firewall enforcement, containment facts) above the settings screen.

import { SettingsPage } from "@/features/settings/SettingsPage";
import { SandboxFirewallCard } from "./SandboxFirewallCard";

export function SystemPage() {
  return (
    <>
      <div className="w-full px-4 pt-4 md:px-6 md:pt-6">
        <SandboxFirewallCard />
      </div>
      <SettingsPage />
    </>
  );
}
