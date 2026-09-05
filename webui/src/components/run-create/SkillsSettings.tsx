import { Label } from "@/components/ui/label";
import { SegmentedControl, SkillMultiSelect } from "@/components/ui/segmented";
import type { SkillsMode } from "@/api/types";

const SKILLS_OPTIONS: Array<{ value: SkillsMode; label: string; body: string }> = [
  { value: "off", label: "Off", body: "Do not load advisory skills. Pure agent reasoning." },
  { value: "on", label: "Enabled", body: "Load relevant skills into the agent context." },
  { value: "hints", label: "Hints", body: "Use skills as lightweight guidance." },
  { value: "lookup", label: "Lookup", body: "Retrieve skills as needed during execution." },
];

interface SkillsSettingsProps {
  skillsMode: SkillsMode;
  setSkillsMode: (v: SkillsMode) => void;
  skillsList: string[];
  skillsInclude: string[];
  skillsExclude: string[];
  setSkillsInclude: (v: string[]) => void;
  setSkillsExclude: (v: string[]) => void;
}

/** Skills mode with the same API values (off/on/hints/lookup) and clearer
 *  descriptions; include/exclude filters appear once a non-off mode is picked. */
export function SkillsSettings({
  skillsMode,
  setSkillsMode,
  skillsList,
  skillsInclude,
  skillsExclude,
  setSkillsInclude,
  setSkillsExclude,
}: SkillsSettingsProps) {
  const current = SKILLS_OPTIONS.find((o) => o.value === skillsMode) ?? SKILLS_OPTIONS[0];
  const open = skillsMode !== "off";

  return (
    <div className="space-y-2">
      <Label className="text-sm font-semibold">Skills</Label>
      <SegmentedControl
        value={skillsMode}
        onChange={(v) => setSkillsMode(v as SkillsMode)}
        options={SKILLS_OPTIONS.map((o) => ({ value: o.value, label: o.label }))}
      />
      <p className="text-xs text-muted-foreground">{current?.body ?? ""}</p>
      {open && (
        <div className="grid gap-3 sm:grid-cols-2">
          <SkillMultiSelect
            label="Include"
            skills={skillsList}
            selected={skillsInclude}
            onChange={setSkillsInclude}
          />
          <SkillMultiSelect
            label="Exclude"
            skills={skillsList}
            selected={skillsExclude}
            onChange={setSkillsExclude}
          />
        </div>
      )}
    </div>
  );
}
