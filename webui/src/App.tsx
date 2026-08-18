import { lazy, Suspense } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "@/components/Layout";
import { OnboardingGate } from "@/components/OnboardingGate";
import { TokenGate } from "@/components/TokenGate";
import { WelcomeGate } from "@/components/WelcomeScreen";
import { HomePage } from "@/routes/HomePage";
import { Spinner } from "@/components/Loading";
import { Toaster } from "@/components/Toaster";

const RunListPage = lazy(() => import("@/routes/RunListPage").then((m) => ({ default: m.RunListPage })));
const NewRunPage = lazy(() => import("@/routes/NewRunPage").then((m) => ({ default: m.NewRunPage })));
const RunPage = lazy(() => import("@/routes/RunPage").then((m) => ({ default: m.RunPage })));
const ArtifactsPage = lazy(() => import("@/routes/ArtifactsPage").then((m) => ({ default: m.ArtifactsPage })));
const LootPage = lazy(() => import("@/routes/LootPage").then((m) => ({ default: m.LootPage })));
const GraphPage = lazy(() => import("@/routes/GraphPage").then((m) => ({ default: m.GraphPage })));
const MemoryPage = lazy(() => import("@/routes/MemoryPage").then((m) => ({ default: m.MemoryPage })));
const SkillsPage = lazy(() => import("@/routes/SkillsPage").then((m) => ({ default: m.SkillsPage })));
const SystemPage = lazy(() => import("@/routes/SystemPage").then((m) => ({ default: m.SystemPage })));
const AttackModulesPage = lazy(() => import("@/routes/AttackModulesPage").then((m) => ({ default: m.AttackModulesPage })));
const GoalsPage = lazy(() => import("@/routes/GoalsPage").then((m) => ({ default: m.GoalsPage })));
const HelpPage = lazy(() => import("@/routes/HelpPage").then((m) => ({ default: m.HelpPage })));

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
            <WelcomeGate>
              <Suspense
                fallback={
                  <div className="flex min-h-[50vh] items-center justify-center">
                    <Spinner label="Loading..." />
                  </div>
                }
              >
                <Routes>
                  <Route element={<Layout />}>
                    <Route path="/" element={<HomePage />} />
                    <Route path="/sessions" element={<RunListPage />} />
                    <Route path="/runs/new" element={<NewRunPage />} />
                    <Route path="/runs/:runId" element={<RunPage />} />
                    <Route path="/runs/:runId/artifacts" element={<ArtifactsPage />} />
                    <Route path="/runs/:runId/loot" element={<LootPage />} />
                    <Route path="/runs/:runId/graph" element={<GraphPage />} />
                    <Route path="/skills" element={<SkillsPage />} />
                    <Route path="/modules" element={<AttackModulesPage />} />
                    <Route path="/goals" element={<GoalsPage />} />
                    <Route path="/help" element={<HelpPage />} />
                    <Route path="/memory" element={<MemoryPage />} />
                    <Route path="/system" element={<SystemPage />} />
                    <Route path="*" element={<Navigate to="/" replace />} />
                  </Route>
                </Routes>
              </Suspense>
            </WelcomeGate>
          </OnboardingGate>
        </TokenGate>
      </BrowserRouter>
      <Toaster />
    </QueryClientProvider>
  );
}
