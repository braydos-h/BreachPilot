import { SessionSummaryCard } from "@/components/SessionSummaryCard";
import type { RunResult } from "@/api/types";

interface SummaryTabProps {
  result: RunResult;
  title?: string;
}

export function SummaryTab({ result, title }: SummaryTabProps) {
  return <SessionSummaryCard result={result} title={title} />;
}
