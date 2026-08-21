import { useNavigate } from "react-router-dom";
import { RunWizard } from "@/components/run-create/RunWizard";

export function NewRunPage() {
  const navigate = useNavigate();
  return (
    <RunWizard onCreated={(runId) => navigate(`/runs/${runId}`)} />
  );
}
