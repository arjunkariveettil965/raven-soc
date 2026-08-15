import "./styles.css";

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: "critical" | "high" | "medium" | "low" | "normal" | "default";
}

export function Badge({ variant = "default", className = "", children, ...props }: BadgeProps) {
  return (
    <span className={`ui-badge ${variant !== "default" ? variant : ""} ${className}`.trim()} {...props}>
      {children}
    </span>
  );
}
