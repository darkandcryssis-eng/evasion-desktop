import type { ReactNode } from "react";

type PageHeaderProps = {
  title: string;
  description: string;
  badge?: string;
  action?: ReactNode;
};

export function PageHeader({ title, description, badge, action }: PageHeaderProps) {
  return (
    <header className="page-header">
      <div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>

      <div className="page-header__actions">
        {badge && <span className="source-badge">{badge}</span>}
        {action}
      </div>
    </header>
  );
}
