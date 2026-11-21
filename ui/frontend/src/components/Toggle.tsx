type ToggleProps = {
  checked: boolean;
  label: string;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
};

export function Toggle({ checked, label, onChange, disabled }: ToggleProps) {
  return (
    <button
      className={`toggle${checked ? " toggle--checked" : ""}`}
      type="button"
      disabled={disabled}
      role="switch"
      aria-checked={checked}
      aria-label={label}
      onClick={() => onChange(!checked)}
    >
      <span />
    </button>
  );
}
