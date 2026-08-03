import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "@/components/Layout";
import { OnboardingGate } from "@/components/OnboardingGate";
import { TokenGate } from "@/components/TokenGate";
import { HomePage } from "@/routes/HomePage";
import { RunListPage } from "@/routes/RunListPage";
import { NewRunPage } from "@/routes/NewRunPage";
import { RunPage } from "@/routes/RunPage";
import { ArtifactsPage } from "@/routes/ArtifactsPage";
import { LootPage } from "@/routes/LootPage";
import { SkillsPage } from "@/routes/SkillsPage";
import { SystemPage } from "@/routes/SystemPage";
import { Toaster } from "@/components/Toaster";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: (failureCount, error) => {
        if (error && typeof error === "object" && "status" in error) {
          const status = (error as { status: number }).status;
          if (status >= 400 && status < 500 && status !== 408 && status !== 429) return false;
        }
        return failureCount < 2;
      },
      refetchOnWindowFocus: false,
    },
  },
});

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <TokenGate>
          <OnboardingGate>
            <Routes>
              <Route element={<Layout />}>
                <Route path="/" element={<HomePage />} />
                <Route path="/sessions" element={<RunListPage />} />
                <Route path="/runs/new" element={<NewRunPage />} />
                <Route path="/runs/:runId" element={<RunPage />} />
                <Route path="/runs/:runId/artifacts" element={<ArtifactsPage />} />
                <Route path="/runs/:runId/loot" element={<LootPage />} />
                <Route path="/skills" element={<SkillsPage />} />
                <Route path="/system" element={<SystemPage />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Route>
            </Routes>
          </OnboardingGate>
        </TokenGate>
      </BrowserRouter>
      <Toaster />
    </QueryClientProvider>
  );
}
