---
title: UI Primitives
sources:
  - webui/src/components/ui/button.tsx
  - webui/src/components/ui/badge.tsx
  - webui/src/components/ui/card.tsx
  - webui/src/components/ui/dialog.tsx
  - webui/src/components/ui/input.tsx
  - webui/src/components/ui/label.tsx
  - webui/src/components/ui/tabs.tsx
  - webui/src/components/ui/select.tsx
  - webui/src/components/ui/checkbox.tsx
  - webui/src/components/ui/switch.tsx
  - webui/src/components/ui/popover.tsx
  - webui/src/components/ui/tooltip.tsx
  - webui/src/components/ui/toast.tsx
  - webui/src/components/ui/scroll-area.tsx
  - webui/src/components/ui/separator.tsx
  - webui/src/components/ui/skeleton.tsx
  - webui/src/components/ui/textarea.tsx
  - webui/components.json
tests: []
subsystem: webui
---

# UI Primitives (`components/ui/*`)

Vendored shadcn/ui pattern (Radix + `class-variance-authority` + `cn()` from `lib/utils.ts:4` = `twMerge(clsx)`). Not a barrel npm component library — edit in place or regenerate from shadcn. All primitives verified under `webui/src/components/ui/*.tsx` (17 files enumerated `glob:*`).

## Inventory

| File | Underlying | Exports | Key props / notes |
|------|------------|---------|-------------------|
| `button.tsx:6` | `Radix Slot` + `cva` | `Button`, `buttonVariants` | `variant default|destructive|outline|secondary|ghost|link`, `size default|sm|lg|icon`, `asChild`, `gap-2`, `active:scale-[0.98]`, disabled opacity 50. Icons `size-4` via `[_svg]` tailwind |
| `badge.tsx:5` | `cva` div | `Badge`, `badgeVariants` | `variant default|secondary|destructive|outline|success|warn|danger|info|muted|violet` — success emerald, warn yellow, danger red, info primary |
| `card.tsx:4` | div | `Card`, `CardHeader`, `CardTitle`, `CardDescription`, `CardContent`, `CardFooter` | `Card hover:shadow-md hover:-translate-y-0.5` (`card.tsx:8`), default padding `p-4`, header `space-y-1.5` |
| `dialog.tsx` | `Radix Dialog` | `Dialog`, `DialogTrigger`, `DialogContent`, `DialogHeader`, `DialogTitle`, `DialogDescription`, `DialogFooter` | used for Help/Permission/Skill add/delete, Home notice. `DialogContent sm:max-w-*` |
| `input.tsx` | native input | `Input` | `h-9 border-input bg-background` |
| `label.tsx` | `Radix Label` | `Label` | `text-sm font-medium` |
| `textarea.tsx` | native textarea | `Textarea` | `min-h-[80px]` for ManualToolPanel JSON |
| `tabs.tsx` | `Radix Tabs` | `Tabs`, `TabsList`, `TabsTrigger`, `TabsContent` | RunPage `TabsTrigger h-6 px-2 text-xs`, Artifacts/Run tabs |
| `select.tsx` | `Radix Select` | `Select`, `SelectTrigger`, `SelectValue`, `SelectContent`, `SelectItem` | RunList sort, Skills page sort |
| `checkbox.tsx` | `Radix Checkbox` | `Checkbox` | ToggleRow, GraphFilters, RunWizard skip-confirm |
| `switch.tsx` | `Radix Switch` | `Switch` | Skills Configuration master + feature switches |
| `popover.tsx` | `Radix Popover` | `Popover`, `PopoverTrigger`, `PopoverContent` | SkillRowActions, skill tag filter |
| `tooltip.tsx` | `Radix Tooltip` | `TooltipProvider`, `Tooltip`, `TooltipTrigger`, `TooltipContent` | Stats page metric help, icon hints (delayDuration 120) |
| `toast.tsx` | `Radix Toast` | `Toast`, `ToastProvider`, `ToastViewport` + `hooks/use-toast.ts` store | `Toaster` (`components/Toaster.tsx`) viewport for `useToast` |
| `scroll-area.tsx` | `Radix ScrollArea` | `ScrollArea`, `ScrollBar` | RunPage tab list (`type scroll`), Artifacts tabs |
| `separator.tsx` | `Radix Separator` | `Separator` | vertical/horizontal dividers |
| `skeleton.tsx` | div | `Skeleton` | `skeleton` shimmer bg `index.css:150` + `h-4 w-*` placeholders (`components/Loading.tsx` re-exports shaped rows) |

Also present via `glob:` `components.json` (shadcn config), `tailwind.config.ts` Radix-animate wiring.

## Custom wrappers (non-`ui`)

These are app components, not primitives, but are shared "mini-primitives":

| Component | File | Purpose |
|-----------|------|---------|
| `StatusBadge` | `components/StatusBadge.tsx` | `RunState` → colored `Badge` (draft/awaiting/queued/running/... variants) |
| `CopyButton` | `components/CopyButton.tsx` | clipboard copy `value` + icon/label, `size sm|icon` |
| `Loading` | `components/Loading.tsx` | `Spinner`, `SkeletonRows(count)`, `SkeletonCards(count)`, `Skeleton`, `ErrorState(message,onRetry)`, `EmptyState(message)` |
| `Toaster` | `components/Toaster.tsx` | `Radix Toast` viewport + `useToast` consumer |
| `ErrorBoundary` | `components/ErrorBoundary.tsx` | class component wrapping `App` (`main.tsx:10`) |

## Patterns

- `buttonVariants` / `badgeVariants` are `cva` so `cn(buttonVariants({variant,size,className}))` merges correctly with overrides (`Badge` in risk filters passes `activeCls`).
- `Card` hover translate is subtle (`-translate-y-0.5`) but visible on `GoalCard`, `Skill` rows, `ModuleRow`. Disable via extra `className` when `blocked` (`GoalsPage`).
- Dialogs: every destructive action confirms via `Dialog` (RunList delete, Skills delete, Cancel run). Props mirror Radix — `open/onOpenChange`, `DialogHeader/Title/Description/Footer`.
- Inputs: filter fields use `h-8 text-xs` (RunList, Artifacts), skills search `h-9 pl-8`, dialog inputs `h-9 font-mono`.
- `TabsList` in RunPage is `h-7 bg-transparent p-0.5` with `TabsTrigger h-6 text-xs`, plus a separator `|`.
- Accessibility: all icons have `aria-hidden`, interactive elements expose `aria-label`, `aria-pressed`, tables have `sr-only caption`.

## Styling hooks

Colors via CSS vars (`card.tsx:8` `border bg-card text-card-foreground` etc.) from `index.css`. Utilities `cn` resolves conflicts (e.g. `border-primary` vs `border-border` precedence). See `docs/webui/build.md` for Tailwind config.
