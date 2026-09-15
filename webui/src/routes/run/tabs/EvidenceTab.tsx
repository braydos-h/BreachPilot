import { useMemo } from "react";
import { Check, FileCheck, X } from "lucide-react";
import { Link, useSearchParams } from "react-router-dom";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SkeletonRows } from "@/components/Loading";
import { EmptyState } from "@/components/EmptyState";
import { ApiError } from "@/api/client";
import { useDecideFinding, useProposed } from "@/api/hooks";
import type { ProposedFinding } from "@/api/types";
import { useState } from "react";

interface EvidenceTabProps {
  runId: string;
}

function sevVariant(sev: string): "danger" | "warn" | "info" | "muted" {
  switch (sev.toLowerCase()) {
    case "critical":
    case "high":
      return "danger";
    case "medium":
      return "warn";
    case "low":
      return "info";
    default:
      return "muted";
  }
}

function ProofCapsule({ finding }: { finding: ProposedFinding }) {
  const proof = finding.proof;
  return (
    <div className="space-y-2 rounded-md border bg-muted/20 p-2 text-[13px]">
      <div>
        <div className="mb-1 font-medium text-muted-foreground">Probe command</div>
        <code className="block break-all rounded bg-background p-1.5">{proof.probe_exec || "—"}</code>
      </div>
      <div className="flex flex-wrap gap-1.5">
        <Badge variant="info">Verification: {proof.verify_status || "HOLDING"}</Badge>
        {proof.retest_status && <Badge variant="secondary">Retest: {proof.retest_status}</Badge>}
        {proof.proof_runs > 0 && <Badge variant="muted">Proof passed {proof.proof_runs}/{proof.proof_runs}</Badge>}
        {proof.proof_sha256 && (
          <Badge variant="muted" title={proof.proof_sha256}>
            sha {proof.proof_sha256.slice(0, 12)}…
          </Badge>
        )}
      </div>
      {(proof.verify_detail || proof.retest_detail) && (
        <div className="text-muted-foreground">
          {[proof.verify_detail, proof.retest_detail].filter(Boolean).join(" · ")}
        </div>
      )}
      {proof.output_excerpt && (
        <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-all rounded bg-background p-1.5 text-xs">
          {proof.output_excerpt}
        </pre>
      )}
    </div>
  );
}

function ProposalRow({
  finding,
  runId,
}: {
  finding: ProposedFinding;
  runId: string;
}) {
  const [expanded, setExpanded] = useState(false);
  const [note, setNote] = useState("");
  const decide = useDecideFinding(runId);

  const submit = (decision: "APPROVED" | "REJECTED") => {
    decide.mutate(
      { findingId: finding.finding_id, decision, note },
      { onSuccess: () => setExpanded(false) },
    );
  };

  const status = (finding.hitl_status || "PROPOSED").toUpperCase();
  return (
    <div className="rounded-md border p-2">
      <button
        type="button"
        onClick={() => setExpanded((v) => !v)}
        className="flex w-full flex-wrap items-center gap-2 text-left"
        aria-expanded={expanded}
      >
        <Badge variant={status === "APPROVED" ? "success" : status === "REJECTED" ? "muted" : "warn"}>{status}</Badge>
        <Badge variant={sevVariant(finding.severity)}>{finding.severity || "Medium"}</Badge>
        <span className="min-w-0 flex-1 truncate text-sm font-medium">{finding.title}</span>
        <span className="text-[13px] text-muted-foreground">Target {finding.affected_asset}</span>
      </button>
      {expanded && (
        <div className="mt-2 space-y-2">
          {finding.summary && <p className="text-[13px] text-muted-foreground">{finding.summary}</p>}
          <div className="text-[13px]">
            <span className="font-medium">Affected endpoint → impact → evidence → proof → retest → attack-path context. </span>
            <Link to={`/runs/${runId}/graph`} className="text-primary hover:underline">Open attack path</Link>
          </div>
          <ProofCapsule finding={finding} />
          <Input
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="Reviewer note (optional)"
            className="h-8 text-[13px]"
            aria-label="Reviewer note"
          />
          {decide.error && (
            <div className="text-[13px] text-destructive">
              {decide.error instanceof ApiError ? decide.error.message : "Decision failed."}
            </div>
          )}
          <div className="flex gap-2">
            <Button size="sm" onClick={() => submit("APPROVED")} disabled={decide.isPending}>
              <Check className="mr-1 h-3 w-3" />
              {decide.isPending ? "Saving…" : "Approve"}
            </Button>
            <Button size="sm" variant="outline" onClick={() => submit("REJECTED")} disabled={decide.isPending}>
              <X className="mr-1 h-3 w-3" />
              Reject
            </Button>
            <Button size="sm" variant="ghost" asChild>
              <Link to={`/runs/${runId}/artifacts`}>View report</Link>
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

type LifecycleFilter = "all" | "awaiting" | "verified" | "inconclusive" | "rejected" | "fixed";

export function EvidenceTab({ runId }: EvidenceTabProps) {
  const [params, setParams] = useSearchParams();
  const filter = params.get("q") ?? "";
  const lifecycle = (params.get("lifecycle") as LifecycleFilter | null) ?? "all";
  const setFilter = (v: string) => {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      if (!v) next.delete("q");
      else next.set("q", v);
      return next;
    }, { replace: true });
  };
  const setLifecycle = (v: LifecycleFilter) => {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      if (v === "all") next.delete("lifecycle");
      else next.set("lifecycle", v);
      return next;
    }, { replace: true });
  };
  const proposed = useProposed(runId, true);

  const rows = useMemo(() => {
    const q = filter.trim().toLowerCase();
    let all = proposed.data?.proposed ?? [];
    if (lifecycle === "awaiting") all = all.filter((f) => (f.hitl_status || "PROPOSED").toUpperCase() === "PROPOSED");
    else if (lifecycle === "verified") all = all.filter((f) => (f.hitl_status || "").toUpperCase() === "APPROVED");
    else if (lifecycle === "rejected") all = all.filter((f) => (f.hitl_status || "").toUpperCase() === "REJECTED");
    if (!q) return all;
    return all.filter(
      (f) =>
        f.title.toLowerCase().includes(q) || f.affected_asset.toLowerCase().includes(q),
    );
  }, [proposed.data, filter, lifecycle]);

  if (proposed.isLoading) return <SkeletonRows count={3} />;
  if (proposed.error) {
    return <div className="text-sm text-destructive">Failed to load evidence. <Button size="sm" variant="outline" onClick={() => proposed.refetch()}>Retry</Button></div>;
  }
  const total = proposed.data?.proposed.length ?? 0;

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="info">
          <FileCheck className="mr-1 h-3 w-3" />
          {total} findings
        </Badge>
        <span className="text-[13px] text-muted-foreground">Pending → Approved → Verified / Holding / Inconclusive → Retested / Fixed / Rejected.</span>
        <div className="ml-auto w-full sm:w-56">
          <Input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter by title or asset…"
            className="h-8 text-[13px]"
            aria-label="Filter findings"
          />
        </div>
      </div>
      <div className="flex flex-wrap gap-1.5" role="tablist" aria-label="Finding lifecycle filter">
        {(["all", "awaiting", "verified", "inconclusive", "rejected", "fixed"] as LifecycleFilter[]).map((l) => (
          <button
            key={l}
            type="button"
            role="tab"
            aria-selected={lifecycle === l}
            onClick={() => setLifecycle(l)}
            className={`rounded-full border px-2.5 py-1 text-[13px] ${lifecycle === l ? "border-primary/50 bg-primary/10 text-primary" : "text-muted-foreground hover:bg-accent"}`}
          >
            {l === "all" ? "All" : l === "awaiting" ? "Awaiting review" : `${l[0]?.toUpperCase()}${l.slice(1)}`}
          </button>
        ))}
      </div>
      {rows.length === 0 ? (
        total === 0 ? (
          <EmptyState
            title="No findings yet"
            reason="The run is still active or no candidate findings passed verification. Approved findings appear here with proof capsules."
            actionLabel="View run activity"
            actionTo={`/runs/${runId}?tab=overview`}
          />
        ) : (
          <p className="text-sm text-muted-foreground">No findings match this filter.</p>
        )
      ) : (
        rows.map((f) => <ProposalRow key={f.finding_id} finding={f} runId={runId} />)
      )}
    </div>
  );
}
