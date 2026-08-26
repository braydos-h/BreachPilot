import { useEffect, useState } from "react";
import { ReconAssessmentCard } from "@/components/ReconAssessmentCard";
import { Spinner } from "@/components/Loading";
import { ApiError } from "@/api/client";
import { useFetchArtifactBlob } from "@/api/hooks";
import type { ReconAssessment } from "@/api/types";

interface ReconTabProps {
  fetchArtifact: ReturnType<typeof useFetchArtifactBlob>;
  ready: boolean;
}

export function ReconTab({ fetchArtifact, ready }: ReconTabProps) {
  const [assessment, setAssessment] = useState<ReconAssessment | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>("");
  const mutate = fetchArtifact.mutate;

  useEffect(() => {
    if (!ready) {
      setLoading(false);
      setAssessment(null);
      setError("");
      return;
    }
    setLoading(true);
    setError("");
    mutate("recon_assessment.json", {
      onSuccess: async (blob) => {
        try {
          const text = await blob.text();
          const data = JSON.parse(text) as ReconAssessment;
          setAssessment(data);
        } catch {
          setError("recon_assessment.json is not valid JSON.");
        }
        setLoading(false);
      },
      onError: (err) => {
        setError(
          err instanceof ApiError && err.isNotFound
            ? "No recon was run for this session."
            : "Failed to load recon assessment.",
        );
        setAssessment(null);
        setLoading(false);
      },
    });
  }, [mutate, ready]);

  if (loading) return <Spinner label="Loading recon..." />;
  if (assessment) return <ReconAssessmentCard assessment={assessment} />;
  return (
    <div className="space-y-2 rounded-md border border-dashed p-4 text-sm text-muted-foreground">
      {error || "Recon in progress — assessment will appear here once recon completes."}
    </div>
  );
}
