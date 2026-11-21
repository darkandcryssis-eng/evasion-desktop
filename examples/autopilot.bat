@echo off
rem ============================================================
rem  Автопилот: движок САМ ищет на выделенных пробах TCP-стратегию,
rem  обходящую DPI (в т.ч. RST-инъекцию), повышает рабочую по порогу и
rem  переключает на неё реальный трафик — не трогая пользовательские
rem  соединения во время поиска (5.2). Стартовый портфель уже содержит
rem  анти-RST фейки (fake-ttl, fake-badsum, fake-split-sni, ...).
rem
rem  Нужен curl в PATH (есть в Windows 10/11). Запускать из cmd ОТ
rem  АДМИНИСТРАТОРА (WinDivert).
rem
rem  Использование:
rem    examples\autopilot.bat           только стартовый портфель (быстрее)
rem    examples\autopilot.bat search    + генетический поиск новых стратегий
rem
rem  Что искать в логе ЭТОГО окна (значит, движок нашёл рабочую стратегию):
rem    "кандидат на доле трафика"       кандидат пошёл в пробу
rem    "ступень стратегии изменилась"   кандидат повышен
rem    "стратегия цели сменилась"       к цели применена рабочая стратегия
rem    "обвал портфеля снят"            рабочая найдена — YouTube должен ожить
rem  В другом окне в любой момент:  evasion.exe status
rem ============================================================
setlocal
pushd "%~dp0.."
set "GOTOOLCHAIN=go1.27.2"

echo === Сборка evasion.exe ===
go build -o evasion.exe .\cmd\evasion
if errorlevel 1 (
  echo.
  echo СБОРКА НЕ УДАЛАСЬ — исправьте ошибки выше.
  popd
  endlocal
  exit /b 1
)

set "EXTRA="
if /i "%~1"=="search" set "EXTRA=--search"

echo.
echo === Автопилот: intercept --auto %EXTRA%   ^(Ctrl+C — стоп^) ===
echo === YouTube держите открытым; при "стратегия цели сменилась" обновите ===
echo.
evasion.exe run --mode intercept --config examples\config.json --auto %EXTRA%

popd
endlocal
