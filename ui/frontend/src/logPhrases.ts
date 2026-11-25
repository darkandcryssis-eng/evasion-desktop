// The session window shows the journal in plain words: known events get a short phrase, everything technical is left out.
export type Line = { msg: string; attrs: string };

const PHRASES: [RegExp, (attr: (key: string) => string, found: RegExpMatchArray) => string][] = [
  [/^журнал событий поднят/, () => "Журнал запущен"],
  [/^перехват: разбор ClientHello/, () => "Соединения идут через обход"],
  [/^стратегия по группе \(ротация\)/, (a) => `Меняем обход${service(a("группа"))}`],
  [/^стратегия по группе/, (a) => `Обход${service(a("группа"))} подобран`],
  [/^стратегия цели сменилась/, () => "Способ обхода обновлён"],
  [/^стратегия закреплена/, () => "Способ обхода закреплён"],
  [/^ступень стратегии изменилась/, () => "Сила обхода изменена"],
  [/^обвал портфеля снят/, () => "Рабочий способ обхода найден"],
  [/^полный обвал портфеля/, () => "Ищем новый способ обхода"],
  [/^переклейка RTC-портов включена/, () => "Голос Discord под защитой"],
  [/^десинк голоса применён \(звонок Telegram/, () => "Звонок Telegram идёт через обход"],
  [/^десинк голоса применён/, () => "Голос Discord идёт через обход"],
  [/^голос: сервер дёргается/, () => "Голосовой сервер сменён"],
  [/^QUIC заблокирован/, () => "Быстрый протокол отключён"],
  [/^QUIC переписан/, () => "Быстрый протокол под защитой"],
  [/^YouTube: прямой обход восстановлен/, () => "YouTube снова идёт напрямую"],
  [/^YouTube: прямой обход нестабилен/, () => "YouTube идёт запасным путём"],
  [/^автоматический VLESS-резерв YouTube готов/, () => "Запасной маршрут YouTube готов"],
  [/^резервный маршрут (\S+) готов/, (_, found) => `Запасной маршрут ${found[1]} готов`],
  [/^резервный маршрут (\S+) (недоступен|остановился)/, (_, found) => `Запасной путь ${found[1]} недоступен`],
  [/^tunnel: рукопожатие прошло/, () => "Запасной маршрут подключён"],
  [/^transport_fallback: применён блок/, () => "Запасные адреса подключены"],
  [/^свой список IP подключён/, () => "Свой список адресов подключён"],
  [/^blocklist: обновлён/, () => "Список сайтов обновлён"],
  [/^игровой фильтр включён/, () => "Игровой режим включён"],
  [/^конфигурация перечитана/, () => "Настройки применены"],
  [/^соединение принято/, () => "Новое соединение"],
  [/^начало соединения обработано/, () => "Соединение прошло через обход"],
  [/^соединение с сервером не установлено/, () => "Сервер молчит, пробуем снова"],
  [/^базовый RTT измерен/, () => "Скорость сети измерена"],
  // Logged for every outcome, and a baseline probe reads the other way round: say only that a check ran.
  [/^проба выполнена/, () => "Проверяем связь"],
  [/^круг проб не удался/, () => "Повторяем проверку связи"],
  [/^связность восстановлена/, () => "Связь восстановлена"],
  [/^ТРЕВОГА: связность потеряна/, () => "Связь пропала, ждём сеть"],
  [/^точка наблюдения сменилась/, () => "Сеть сменилась, настраиваемся"],
  [/^(тёплый старт: наблюдения загружены|оценки прогреты из журнала)/, () => "Вспомнили настройки этой сети"],
  [/^Запуск: Discord перезапущен/, () => "Discord перезапущен"],
];

// Engine group names (discord_cdn, googlevideo) are internal: name the service, or nothing.
const SERVICES: [RegExp, string][] = [[/^discord/, "Discord"], [/^(youtube|googlevideo)/, "YouTube"], [/^telegram/, "Telegram"]];
function service(group: string): string {
  const name = SERVICES.find(([pattern]) => pattern.test(group))?.[1];
  return name ? ` для ${name}` : "";
}

export function plain(line: Line): string {
  const attr = (key: string) => line.attrs.match(new RegExp(`(?:^|\\s)${key}=(\\S+)`))?.[1] ?? "";
  for (const [pattern, say] of PHRASES) {
    const found = line.msg.match(pattern);
    if (found) return say(attr, found);
  }
  // The shell and the Telegram proxy already write whole sentences for people.
  return /^[А-ЯЁ][а-яё]+ [^:]{2,24}$/.test(line.msg) ? line.msg : "";
}

// The newest distinct phrases, oldest first.
export function phrases(lines: Line[], limit: number): string[] {
  const found: string[] = [];
  for (let i = lines.length - 1; i >= 0 && found.length < limit; i--) {
    const text = plain(lines[i]);
    if (text && !found.includes(text)) found.push(text);
  }
  return found.reverse();
}
