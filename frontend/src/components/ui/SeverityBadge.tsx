import { Badge } from "./Badge";

export function SeverityBadge({ severity }: { severity: string }) {
  const s = (severity || "").toLowerCase();
  let variant: "critical" | "high" | "medium" | "low" | "normal" | "default" = "default";
  
  if (s.includes("critical")) variant = "critical";
  else if (s.includes("high")) variant = "high";
  else if (s.includes("medium")) variant = "medium";
  else if (s.includes("low")) variant = "low";
  else if (s.includes("info") || s.includes("normal")) variant = "normal";

  return <Badge variant={variant}>{severity || "Unknown"}</Badge>;
}
