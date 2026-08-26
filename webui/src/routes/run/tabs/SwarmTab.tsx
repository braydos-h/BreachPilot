import { SwarmView } from "@/components/OrchestrationViews";

interface WitnessFlagView {
  signal: string;
  severity: string;
  message: string;
  timestamp?: string;
}

interface SwarmTabProps {
  loading: boolean;
  error: unknown;
  state: unknown;
  witnessFlags?: WitnessFlagView[];
  witnessLoading?: boolean;
  negotiationRounds?: number;
}

export function SwarmTab({ loading, error, state, witnessFlags, witnessLoading, negotiationRounds }: SwarmTabProps) {
  return (
    <SwarmView
      loading={loading}
      error={error}
      state={state}
      witnessFlags={witnessFlags}
      witnessLoading={witnessLoading}
      negotiationRounds={negotiationRounds}
    />
  );
}
