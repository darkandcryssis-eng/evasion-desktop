import { type ReactNode, useId, useState } from "react";
import { AnimatedCollapse } from "./AnimatedCollapse";

type DisclosureProps = {
  summary: ReactNode;
  children: ReactNode;
  className?: string;
};

export function Disclosure({ summary, children, className = "" }: DisclosureProps) {
  const [open, setOpen] = useState(false);
  const id = useId();

  return (
    <section className={`disclosure${open ? " disclosure--open" : ""} ${className}`.trim()}>
      <button className="disclosure__trigger" type="button" aria-expanded={open} aria-controls={id} onClick={() => setOpen((value) => !value)}>
        {summary}
      </button>
      <AnimatedCollapse open={open} id={id}>{children}</AnimatedCollapse>
    </section>
  );
}
