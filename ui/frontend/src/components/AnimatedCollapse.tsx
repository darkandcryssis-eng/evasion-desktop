import { type ReactNode, useEffect, useLayoutEffect, useRef } from "react";

type AnimatedCollapseProps = {
  open: boolean;
  children: ReactNode;
  className?: string;
  id?: string;
};

export function AnimatedCollapse({ open, children, className = "", id }: AnimatedCollapseProps) {
  const rootRef = useRef<HTMLDivElement>(null);
  const animationRef = useRef<Animation | null>(null);

  useLayoutEffect(() => {
    const root = rootRef.current;
    if (!root) return;

    // Read the current frame before cancelling, so rapid reversals stay smooth.
    const startHeight = root.getBoundingClientRect().height;
    const startOpacity = getComputedStyle(root).opacity;
    animationRef.current?.cancel();
    animationRef.current = null;
    root.hidden = false;
    root.inert = !open;
    root.style.height = "auto";
    const endHeight = open ? root.getBoundingClientRect().height : 0;
    root.style.height = `${startHeight}px`;
    root.style.opacity = startOpacity;
    root.style.overflow = "hidden";

    const finish = () => {
      root.style.height = open ? "auto" : "0px";
      root.style.opacity = open ? "1" : "0";
      root.style.overflow = open ? "visible" : "hidden";
      root.hidden = !open;
    };

    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const duration = reduced ? 0 : Number.parseFloat(getComputedStyle(root).getPropertyValue("--reveal-duration")) || 0;
    if (!duration || Math.abs(endHeight - startHeight) < 0.5) {
      finish();
      return;
    }

    const animation = root.animate(
      [{ height: `${startHeight}px`, opacity: startOpacity }, { height: `${endHeight}px`, opacity: open ? 1 : 0 }],
      { duration, easing: "cubic-bezier(.22, 1, .36, 1)", fill: "both" },
    );
    animationRef.current = animation;
    animation.onfinish = () => {
      if (animationRef.current !== animation) return;
      animationRef.current = null;
      finish();
      animation.cancel();
    };
  }, [open]);

  useEffect(() => {
    const preference = window.matchMedia("(prefers-reduced-motion: reduce)");
    const onChange = () => { if (preference.matches) animationRef.current?.finish(); };
    preference.addEventListener("change", onChange);
    return () => {
      preference.removeEventListener("change", onChange);
      animationRef.current?.cancel();
    };
  }, []);

  return <div className={`animated-collapse ${className}`.trim()} ref={rootRef} id={id} aria-hidden={!open}>{children}</div>;
}
