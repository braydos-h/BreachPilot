export function ratingColor(rating: number): string {
  if (rating >= 80) return "text-emerald-400";
  if (rating >= 55) return "text-yellow-400";
  return "text-red-400";
}

export function ratingBar(rating: number): string {
  if (rating >= 80) return "bg-emerald-500";
  if (rating >= 55) return "bg-yellow-500";
  return "bg-red-500";
}

export function riskColor(score: number): string {
  if (score >= 80) return "text-emerald-400";
  if (score >= 55) return "text-yellow-400";
  return "text-red-400";
}
