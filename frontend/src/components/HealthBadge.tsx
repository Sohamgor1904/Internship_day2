import { Badge } from "@/components/ui/badge";

interface HealthBadgeProps {
  name: string;
  status: "healthy" | "unhealthy" | "OK" | "FAIL" | string;
}

export function HealthBadge({ name, status }: HealthBadgeProps) {
  const isHealthy = status.toLowerCase() === "healthy" || status.toUpperCase() === "OK";
  return (
    <div className="flex items-center gap-2">
      <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">{name}:</span>
      <Badge variant="outline" className={isHealthy ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20" : "bg-rose-500/10 text-rose-400 border-rose-500/30 hover:bg-rose-500/20"}>
        <span className={`w-1.5 h-1.5 rounded-full mr-1.5 ${isHealthy ? "bg-emerald-400 animate-pulse" : "bg-rose-400"}`} />
        {isHealthy ? "ONLINE" : "FAIL"}
      </Badge>
    </div>
  );
}
