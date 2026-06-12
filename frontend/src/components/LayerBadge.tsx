import { Badge } from "@/components/ui/badge";

interface LayerBadgeProps {
  layer: number | string;
}

export function LayerBadge({ layer }: LayerBadgeProps) {
  const layerNum = typeof layer === "string" ? parseInt(layer.replace(/\D/g, ""), 10) : layer;

  let styles = "bg-yellow-500/10 text-yellow-400 border-yellow-500/30";
  let label = "Layer 1 (Triage)";

  if (layerNum === 2) {
    styles = "bg-orange-500/10 text-orange-400 border-orange-500/30";
    label = "Layer 2 (RF Classifier)";
  } else if (layerNum === 3) {
    styles = "bg-red-500/10 text-red-400 border-red-500/30";
    label = "Layer 3 (Sequential LSTM)";
  }

  return (
    <Badge variant="outline" className={`${styles} font-medium`}>
      {label}
    </Badge>
  );
}
