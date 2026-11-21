import { Send, X } from "lucide-react";
import { useEffect, useRef } from "react";

export function TelegramPrompt({ open, onAnswer, onCancel }: { open: boolean; onAnswer: (enabled: boolean) => void; onCancel: () => void }) {
  const root = useRef<HTMLElement>(null);
  const cancel = useRef(onCancel);
  cancel.current = onCancel;
  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement as HTMLElement | null;
    const buttons = root.current?.querySelectorAll<HTMLButtonElement>("button");
    buttons?.[1]?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") cancel.current();
      if (event.key !== "Tab" || !buttons?.length) return;
      if (event.shiftKey && document.activeElement === buttons[0]) { event.preventDefault(); buttons[buttons.length - 1].focus(); }
      else if (!event.shiftKey && document.activeElement === buttons[buttons.length - 1]) { event.preventDefault(); buttons[0].focus(); }
    };
    window.addEventListener("keydown", onKey);
    return () => { window.removeEventListener("keydown", onKey); previous?.focus(); };
  }, [open]);
  if (!open) return null;
  return (
    <div className="close-dialog__backdrop" onMouseDown={onCancel}>
      <section ref={root} className="close-dialog" role="dialog" aria-modal="true" aria-labelledby="telegram-prompt-title" onMouseDown={(e) => e.stopPropagation()}>
        <button className="close-dialog__dismiss" type="button" aria-label="Отмена" onClick={onCancel}><X size={14} /></button>
        <div className="close-dialog__mark"><Send size={20} /></div>
        <h2 id="telegram-prompt-title">Включить телеграмм прокси?</h2>
        <p>Запустить вместе с обходом. При первом включении подтвердите подключение в Telegram. При блокировке прямого канала доступны резервные узлы сообщества.</p>
        <div className="telegram-prompt-actions">
          <button className="secondary-button telegram-primary" type="button" onClick={() => onAnswer(true)}>Да</button>
          <button className="secondary-button" type="button" onClick={() => onAnswer(false)}>Нет</button>
        </div>
      </section>
    </div>
  );
}
