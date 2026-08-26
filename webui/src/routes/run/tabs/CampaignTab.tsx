import { CampaignView } from "@/components/OrchestrationViews";

interface CampaignTabProps {
  loading: boolean;
  error: unknown;
  state: unknown;
}

export function CampaignTab({ loading, error, state }: CampaignTabProps) {
  return <CampaignView loading={loading} error={error} state={state} />;
}
