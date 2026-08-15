import "./styles.css";

export function Table({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={`ui-table-container ${className}`.trim()}>
      <table className="ui-table">{children}</table>
    </div>
  );
}

export function Th({ children, ...props }: React.ThHTMLAttributes<HTMLTableCellElement>) {
  return <th {...props}>{children}</th>;
}

export function Td({ children, ...props }: React.TdHTMLAttributes<HTMLTableCellElement>) {
  return <td {...props}>{children}</td>;
}
