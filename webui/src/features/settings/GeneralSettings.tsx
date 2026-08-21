// General: common application configuration with friendly labels. The
// ConfigEditor renders every general-category field from the backend schema.

import { ConfigEditor } from "./ConfigEditor";

export function GeneralSettings() {
  return <ConfigEditor category="general" />;
}
