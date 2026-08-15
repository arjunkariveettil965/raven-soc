import "./styles.css";

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "danger";
}

export function Button({ variant = "secondary", className = "", children, ...props }: ButtonProps) {
  const baseClass = "ui-button";
  const variantClass = variant === "primary" ? "primary" : variant === "danger" ? "danger" : "";
  return (
    <button className={`${baseClass} ${variantClass} ${className}`.trim()} {...props}>
      {children}
    </button>
  );
}
