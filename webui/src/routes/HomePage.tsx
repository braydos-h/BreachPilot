import { useHomePage } from "@/features/home/useHomePage";
import { FullAccessNotice, NOTICE_KEY, NOTICE_DISMISSED_KEY } from "@/features/home/FullAccessNotice";
import { SandboxBanner } from "@/features/home/SandboxBanner";
import { SandboxFixDialog } from "@/features/home/SandboxFixDialog";
import { HomeHero, HomeActiveBanner } from "@/features/home/HomeHero";
import { HomeActions, HomeLaunchpad } from "@/features/home/HomeLaunchpad";
import { HomeRecentRuns } from "@/features/home/HomeRecentRuns";

// Re-exported: SandboxFirewallCard imports the dialog from this route module,
// and HomePage tests import the banner plus notice keys.
export { FullAccessNotice, NOTICE_KEY, NOTICE_DISMISSED_KEY, SandboxBanner, SandboxFixDialog };

export function HomePage() {
  const page = useHomePage();

  return (
    <div className="relative mx-auto max-w-5xl space-y-8 p-4 md:p-8">
      <FullAccessNotice />
      <HomeHero page={page} />
      <SandboxBanner />
      <HomeActiveBanner page={page} />
      <HomeLaunchpad page={page} />
      <HomeActions />

      <HomeRecentRuns page={page} />

      <p className="flex items-center justify-center gap-1.5 text-center text-[13px] tracking-wide text-muted-foreground">
        <span className="inline-block h-1.5 w-1.5 rounded-full bg-muted-foreground/40" />
        Authorized use only — operate exclusively against assets you own or are explicitly authorized to test.
      </p>
    </div>
  );
}
