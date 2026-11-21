import { type ReactNode, useLayoutEffect, useRef } from "react";

type SlidingNavigationProps = {
  activeTab: string;
  className?: string;
  children: ReactNode;
};

export function SlidingNavigation({ activeTab, className = "", children }: SlidingNavigationProps) {
  const groupRef = useRef<HTMLDivElement>(null);
  const indicatorRef = useRef<HTMLSpanElement>(null);

  useLayoutEffect(() => {
    const group = groupRef.current;
    const indicator = indicatorRef.current;
    if (!group || !indicator) return;

    const measure = () => {
      const active = group.querySelector<HTMLElement>('[aria-current="page"]');
      indicator.dataset.visible = String(Boolean(active));
      if (!active) return;

      const parent = group.getBoundingClientRect();
      const button = active.getBoundingClientRect();
      indicator.style.setProperty("--nav-x", `${button.left - parent.left - group.clientLeft}px`);
      indicator.style.setProperty("--nav-y", `${button.top - parent.top - group.clientTop}px`);
      indicator.style.setProperty("--nav-width", `${button.width}px`);
      indicator.style.setProperty("--nav-height", `${button.height}px`);
    };

    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(group);
    group.querySelectorAll("button").forEach((button) => observer.observe(button));
    const frame = requestAnimationFrame(() => { group.dataset.ready = "true"; });

    return () => {
      cancelAnimationFrame(frame);
      observer.disconnect();
    };
  }, [activeTab]);

  return (
    <div className={`side-navigation__group ${className}`.trim()} ref={groupRef}>
      <span className="side-navigation__indicator" ref={indicatorRef} aria-hidden="true" />
      {children}
    </div>
  );
}
