import { Check, ChevronDown } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { AnimatedCollapse } from "./AnimatedCollapse";

export type SelectOption = { id: string; label: string; desc?: string };

type SelectProps = {
  value: string;
  options: SelectOption[];
  onChange: (id: string) => void;
  disabled?: boolean;
};

// Список с пояснениями и закрытием по Escape или клику вне меню.
export function Select({ value, options, onChange, disabled }: SelectProps) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const current = options.find((o) => o.id === value);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
        triggerRef.current?.focus();
      }
    };
    window.addEventListener("mousedown", onDown);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("mousedown", onDown);
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const pick = (id: string) => {
    onChange(id);
    setOpen(false);
    triggerRef.current?.focus();
  };

  return (
    <div className={`select${open ? " select--open" : ""}`} ref={rootRef}>
      <button
        type="button"
        className="select__trigger"
        ref={triggerRef}
        disabled={disabled}
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
      >
        <span>{current?.label ?? "—"}</span>
        <ChevronDown className="select__chevron" size={14} />
      </button>

      <AnimatedCollapse open={open} className="select__popover">
        <ul className="select__menu" role="listbox">
          {options.map((o) => (
            <li key={o.id}>
              <button
                type="button"
                role="option"
                aria-selected={o.id === value}
                className={`select__option${o.id === value ? " select__option--active" : ""}`}
                onClick={() => pick(o.id)}
              >
                <span className="select__option-copy">
                  <span className="select__option-label">{o.label}</span>
                  {o.desc && <span className="select__option-desc">{o.desc}</span>}
                </span>
                {o.id === value && <Check className="select__option-check" size={13} />}
              </button>
            </li>
          ))}
        </ul>
      </AnimatedCollapse>
    </div>
  );
}
