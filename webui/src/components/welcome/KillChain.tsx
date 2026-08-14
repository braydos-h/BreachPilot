// Animated kill-chain diagram: Plan → Recon → Exploit → Report.
// Plain paths + polygons (no SVG <marker>) to avoid id collisions under StrictMode.

const NODES = [
  { x: 80, label: "Plan" },
  { x: 240, label: "Recon" },
  { x: 400, label: "Exploit" },
  { x: 560, label: "Report" },
];
const R = 28;
const Y = 60;

export function KillChain({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 640 120"
      className={className ?? "w-full h-auto"}
      role="img"
      aria-label="Kill chain: Plan, Recon, Exploit, Report"
    >
      {NODES.slice(0, -1).map((n, i) => {
        const x1 = n.x + R;
        const x2 = NODES[i + 1].x - R;
        return (
          <g key={n.label}>
            <path
              d={`M ${x1} ${Y} L ${x2} ${Y}`}
              stroke="hsl(var(--border))"
              strokeWidth="1.5"
              strokeDasharray="6 6"
              fill="none"
              className="animate-dash-flow"
            />
            <polygon
              points={`${x2},${Y} ${x2 - 8},${Y - 6} ${x2 - 8},${Y + 6}`}
              fill="hsl(var(--muted-foreground))"
            />
          </g>
        );
      })}
      {NODES.map((n, i) => (
        <g
          key={n.label}
          className="animate-fade-in-up"
          style={{ animationDelay: `${i * 150}ms` }}
        >
          <circle cx={n.x} cy={Y} r={R} fill="hsl(var(--card))" stroke="hsl(var(--border))" />
          <circle cx={n.x} cy={Y} r={4} fill="hsl(var(--primary))" className="animate-node-pulse" />
          <text
            x={n.x}
            y={100}
            textAnchor="middle"
            className="fill-muted-foreground text-[10px] uppercase tracking-wide"
          >
            {n.label}
          </text>
        </g>
      ))}
    </svg>
  );
}
