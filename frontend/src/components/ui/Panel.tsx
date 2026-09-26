import "./styles.css";

export function Panel({ children, className = "", style, ...props }: { children: React.ReactNode; className?: string; style?: React.CSSProperties; } & React.HTMLAttributes<HTMLDivElement>) {
  return <div className={`ui-panel ${className}`.trim()} style={style} {...props}>{children}</div>;
}

export function PanelHeader({ title, children, className = "", style, ...props }: { title?: string; children?: React.ReactNode; className?: string; style?: React.CSSProperties; } & React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={`ui-panel-header ${className}`.trim()} style={style} {...props}>
      {title && <h3 className="ui-panel-title">{title}</h3>}
      {children}
    </div>
  );
}

export function PanelContent({ children, className = "", style, ...props }: { children: React.ReactNode; className?: string; style?: React.CSSProperties; } & React.HTMLAttributes<HTMLDivElement>) {
  return <div className={`ui-panel-content ${className}`.trim()} style={style} {...props}>{children}</div>;
}
