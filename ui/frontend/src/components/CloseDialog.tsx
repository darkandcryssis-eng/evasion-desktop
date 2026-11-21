import { ChevronDown, Power, X } from "lucide-react";
import { useEffect, useRef } from "react";

type CloseDialogProps = {
  open: boolean;
  onCancel: () => void;
  onTray: () => void;
  onQuit: () => void;
};

export function CloseDialog({ open, onCancel, onTray, onQuit }: CloseDialogProps) {
  const dialog = useRef<HTMLElement>(null);
  const cancel = useRef(onCancel);
  cancel.current = onCancel;
  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement as HTMLElement | null;
    const buttons = dialog.current?.querySelectorAll<HTMLButtonElement>("button");
    buttons?.[0]?.focus();
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") cancel.current();
      if (event.key === "Tab" && buttons?.length) {
        const first = buttons[0];
        const last = buttons[buttons.length - 1];
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => { window.removeEventListener("keydown", handleKeyDown); previous?.focus(); };
  }, [open]);

  if (!open) return null;

  return (
    <div className="close-dialog__backdrop" role="presentation" onMouseDown={onCancel}>
      <section
        ref={dialog}
        className="close-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="close-dialog-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <button className="close-dialog__dismiss" type="button" aria-label="Отмена" onClick={onCancel}>
          <X size={14} />
        </button>

        <div className="close-dialog__mark"><Power size={18} strokeWidth={1.6} /></div>
        <h2 id="close-dialog-title">Что сделать с приложением?</h2>
        <p>Свернуть в трей и оставить движок работать — или полностью закрыть.</p>

        <div className="close-dialog__actions">
          <button className="close-choice" type="button" onClick={onTray}>
            <ChevronDown size={16} />
            <span><strong>Свернуть в трей</strong><small>Окно скроется, значок останется у часов</small></span>
          </button>
          <button className="close-choice close-choice--quit" type="button" onClick={onQuit}>
            <Power size={16} />
            <span><strong>Закрыть приложение</strong><small>Остановить движок и выйти</small></span>
          </button>
        </div>
      </section>
    </div>
  );
}
