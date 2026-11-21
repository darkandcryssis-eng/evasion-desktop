import type { ReactNode } from "react";

type InfoLabelProps = {
  children: ReactNode;
  tip: string;
};

// InfoLabel — заголовок функции, который сам является областью наведения:
// навёл на текст (он с пунктирным подчёркиванием) — снизу раскрывается
// пояснение. Поповер открывается вниз-вправо от заголовка, поэтому не уходит
// под навигацию слева и не обрезается.
export function InfoLabel({ children, tip }: InfoLabelProps) {
  return (
    <span className="info-label" tabIndex={0} role="note">
      <span className="info-label__text">{children}</span>
      <span className="info-label__tip" role="tooltip">{tip}</span>
    </span>
  );
}
