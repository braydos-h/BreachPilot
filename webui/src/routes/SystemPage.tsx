// Thin route wrapper for /system — the real screen lives in
// features/settings/SettingsPage. Kept so the lazy route + nav link stay put.

import { SettingsPage } from "@/features/settings/SettingsPage";

export function SystemPage() {
  return <SettingsPage />;
}
