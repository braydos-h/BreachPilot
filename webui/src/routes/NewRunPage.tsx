import { useNavigate } from "react-router-dom";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { RunForm } from "@/components/RunForm";

export function NewRunPage() {
  const navigate = useNavigate();
  return (
    <div className="mx-auto max-w-3xl space-y-4 p-4 md:p-6">
      <div>
        <h1 className="text-lg font-semibold">New run</h1>
        <p className="text-sm text-muted-foreground">Configure an assessment and submit it to the local API.</p>
      </div>
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Run configuration</CardTitle>
          <CardDescription>Fields map to POST /api/v1/runs.</CardDescription>
        </CardHeader>
        <CardContent>
          <RunForm onCreated={(runId, state) => navigate(`/runs/${runId}`, { state: { justCreated: state } })} />
        </CardContent>
      </Card>
    </div>
  );
}