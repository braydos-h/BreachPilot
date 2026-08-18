import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { riskColor } from "@/lib/risk";
import type { ReconAssessment } from "@/api/types";

interface ReconAssessmentCardProps {
  assessment: ReconAssessment;
  className?: string;
}

function osVerdictColor(verdict: string): string {
  const v = verdict.toUpperCase();
  if (v === "UNKNOWN") return "text-muted-foreground";
  if (v.includes("WINDOWS")) return "text-sky-400";
  return "text-emerald-400";
}

export function ReconAssessmentCard({ assessment, className }: ReconAssessmentCardProps) {
  const ports = assessment.open_ports ?? [];
  const services = assessment.services ?? [];
  const cves = assessment.cve_findings ?? [];
  const score = assessment.overall_risk_score ?? 0;
  const hints = assessment.os_hints ?? [];

  return (
    <Card className={cn("border-border/60", className)}>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <span>Reconnaissance Assessment</span>
          <Badge variant="outline" className="tabular-nums">
            surface {score}/100
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 text-sm">
        <div className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 font-mono text-xs">
          <span className="text-muted-foreground">Target:</span>
          <span>{assessment.target_ip}</span>

          <span className="text-muted-foreground">OS Verdict:</span>
          <span className={osVerdictColor(assessment.os_verdict)}>
            {assessment.os_verdict || "UNKNOWN"}
            {hints.length > 0 && (
              <span className="text-muted-foreground">  -&gt; {hints.join(", ")}</span>
            )}
          </span>

          <span className="text-muted-foreground">Open Ports:</span>
          <span>
            {ports.length} {ports.length > 0 ? `(${ports.join(", ")})` : "(none)"}
          </span>

          <span className="text-muted-foreground">Services:</span>
          <span>{services.length}</span>
        </div>

        {services.length > 0 && (
          <ul className="space-y-1 pl-4 text-xs">
            {services.map((svc, i) => (
              <li key={i} className="flex flex-wrap items-center gap-2">
                <Badge variant="outline" className="font-mono">
                  {String(svc.name ?? "unknown")}
                </Badge>
                {svc.port != null && (
                  <span className="text-muted-foreground">port {String(svc.port)}/tcp</span>
                )}
                {svc.risk != null && (() => {
                  const r = Number(svc.risk);
                  return (
                    <span className={Number.isFinite(r) ? riskColor(r) : ""}>[risk:{String(svc.risk)}]</span>
                  );
                })()}
                {svc.banner && (
                  <span className="text-muted-foreground">banner: {String(svc.banner)}</span>
                )}
              </li>
            ))}
          </ul>
        )}

        {cves.length > 0 && (
          <div className="space-y-1 text-xs">
            <span className="text-muted-foreground">CVEs Found:</span>
            <ul className="space-y-0.5 pl-4">
              {cves.map((cve, i) => (
                <li key={i} className="text-muted-foreground">
                  - {String(cve.service ?? "unknown")}{" "}
                  {cve.product ? `${cve.product} ${cve.version ?? ""}` : ""}: {String(cve.count ?? 0)} CVE(s)
                </li>
              ))}
            </ul>
          </div>
        )}

        <div className="flex items-center gap-2 pt-1 text-xs">
          <span className="text-muted-foreground">Attack Surface:</span>
          <span className={cn("font-mono font-semibold", riskColor(score))}>{score}/100</span>
        </div>
      </CardContent>
    </Card>
  );
}