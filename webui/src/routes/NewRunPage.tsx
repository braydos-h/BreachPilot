import { useNavigate } from "react-router-dom";
import { Wizard } from "@/components/Wizard";

export function NewRunPage() {
  const navigate = useNavigate();
  return (
    <Wizard onCreated={(runId) => navigate(`/runs/${runId}`)} />
  );
}