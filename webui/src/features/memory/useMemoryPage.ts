import { useMemo, useState } from "react";
import { useMemory } from "@/api/hooks";
import {
  deriveMemoryOverview,
  filterAndSortAttackMemory,
  filterAndSortConfidence,
  filterAndSortLessons,
  type AttackResultFilter,
  type AttackSort,
  type ConfidenceSort,
  type LessonOutcomeFilter,
  type LessonSort,
} from "./memoryFilters";

/** Memory page state: the store query, per-tab filters, and derived lists. */
export function useMemoryPage() {
  const memory = useMemory();
  const rawConfidence = memory.data?.confidence ?? [];
  const rawLessons = memory.data?.lessons ?? [];
  const rawAttack = memory.data?.attack_memory ?? [];

  const isInitialLoading = memory.isLoading && !memory.data;
  const isRefreshing = memory.isFetching && Boolean(memory.data);
  const hasCached = Boolean(memory.data);
  const hasError = Boolean(memory.error);
  const isEmptyStore =
    !isInitialLoading && !hasError && rawConfidence.length === 0 && rawLessons.length === 0 && rawAttack.length === 0;

  const overview = useMemo(
    () => deriveMemoryOverview(rawConfidence, rawLessons, rawAttack),
    [rawConfidence, rawLessons, rawAttack],
  );

  const [confQuery, setConfQuery] = useState("");
  const [confSort, setConfSort] = useState<ConfidenceSort>("confidence_desc");
  const [confMinObs, setConfMinObs] = useState<string>("0");

  const [lessonQuery, setLessonQuery] = useState("");
  const [lessonOutcome, setLessonOutcome] = useState<LessonOutcomeFilter>("all");
  const [lessonSort, setLessonSort] = useState<LessonSort>("newest");

  const [attackQuery, setAttackQuery] = useState("");
  const [attackTarget, setAttackTarget] = useState("");
  const [attackCategory, setAttackCategory] = useState("");
  const [attackResult, setAttackResult] = useState<AttackResultFilter>("all");
  const [attackSort, setAttackSort] = useState<AttackSort>("recent");

  const [activeTab, setActiveTab] = useState("confidence");

  const targetOptions = useMemo(
    () => [...new Set(rawAttack.map((m) => m.target_ip).filter(Boolean))].sort(),
    [rawAttack],
  );
  const categoryOptions = useMemo(
    () => [...new Set(rawAttack.map((m) => m.category).filter(Boolean))].sort(),
    [rawAttack],
  );

  const confidenceFiltered = useMemo(
    () => filterAndSortConfidence(rawConfidence, confQuery, confSort, Number(confMinObs) || 0),
    [rawConfidence, confQuery, confSort, confMinObs],
  );

  const lessonsFiltered = useMemo(
    () => filterAndSortLessons(rawLessons, lessonQuery, lessonOutcome, lessonSort),
    [rawLessons, lessonQuery, lessonOutcome, lessonSort],
  );

  const attackFiltered = useMemo(
    () => filterAndSortAttackMemory(rawAttack, attackQuery, attackTarget, attackCategory, attackResult, attackSort),
    [rawAttack, attackQuery, attackTarget, attackCategory, attackResult, attackSort],
  );

  const confHasActiveFilters = confQuery.trim().length > 0 || confMinObs !== "0";
  const lessonHasActiveFilters = lessonQuery.trim().length > 0 || lessonOutcome !== "all";
  const attackHasActiveFilters =
    attackQuery.trim().length > 0 || attackTarget !== "" || attackCategory !== "" || attackResult !== "all";

  const clearConfidenceFilters = () => {
    setConfQuery("");
    setConfMinObs("0");
    setConfSort("confidence_desc");
  };
  const clearLessonFilters = () => {
    setLessonQuery("");
    setLessonOutcome("all");
    setLessonSort("newest");
  };
  const clearAttackFilters = () => {
    setAttackQuery("");
    setAttackTarget("");
    setAttackCategory("");
    setAttackResult("all");
    setAttackSort("recent");
  };

  return {
    memory,
    rawConfidence,
    rawLessons,
    rawAttack,
    isInitialLoading,
    isRefreshing,
    hasCached,
    hasError,
    isEmptyStore,
    overview,
    confQuery,
    setConfQuery,
    confSort,
    setConfSort,
    confMinObs,
    setConfMinObs,
    lessonQuery,
    setLessonQuery,
    lessonOutcome,
    setLessonOutcome,
    lessonSort,
    setLessonSort,
    attackQuery,
    setAttackQuery,
    attackTarget,
    setAttackTarget,
    attackCategory,
    setAttackCategory,
    attackResult,
    setAttackResult,
    attackSort,
    setAttackSort,
    activeTab,
    setActiveTab,
    targetOptions,
    categoryOptions,
    confidenceFiltered,
    lessonsFiltered,
    attackFiltered,
    confHasActiveFilters,
    lessonHasActiveFilters,
    attackHasActiveFilters,
    clearConfidenceFilters,
    clearLessonFilters,
    clearAttackFilters,
  };
}

export type MemoryPageState = ReturnType<typeof useMemoryPage>;
