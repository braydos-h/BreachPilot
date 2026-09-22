import { TooltipProvider } from "@/components/ui/tooltip";
import { useSkillsPage } from "@/features/skills/useSkillsPage";
import { SkillsHeader } from "@/features/skills/SkillsHeader";
import { SkillsConfigBar } from "@/features/skills/SkillsConfigBar";
import { SkillsCatalog } from "@/features/skills/SkillsCatalog";
import { SkillDetailPanel } from "@/features/skills/SkillDetailPanel";
import { AddSkillDialog } from "@/features/skills/AddSkillDialog";
import { DeleteSkillDialog } from "@/features/skills/DeleteSkillDialog";

export function SkillsPage() {
  const page = useSkillsPage();
  return (
    <TooltipProvider delayDuration={200}>
      <div className="mx-auto flex max-w-[1600px] flex-col gap-4 p-4 md:p-6">
        <SkillsHeader page={page} />
        <SkillsConfigBar page={page} />
        <div className="grid min-h-0 flex-1 gap-4 lg:grid-cols-[360px_minmax(0,1fr)] lg:items-start">
          <SkillsCatalog page={page} />
          <SkillDetailPanel page={page} />
        </div>
        <AddSkillDialog page={page} />
        <DeleteSkillDialog page={page} />
      </div>
    </TooltipProvider>
  );
}
