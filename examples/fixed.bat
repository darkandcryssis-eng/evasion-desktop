@echo off
rem ============================================================
rem  Применить ОДИН проверенный приём как фиксированную стратегию — сразу на
rem  весь трафик к радиусу, без ожидания сходимости автопилота. По живому
rem  прогону лучший против этого DPI — fake-disorder-sni (~54% успеха против
rem  RST; базовая линия без обхода — 0%). Запускать из cmd ОТ АДМИНИСТРАТОРА.
rem
rem  Использование:
rem    examples\fixed.bat                      fake-disorder-sni, QUIC блокируется
rem    examples\fixed.bat fake-badsum          другой приём (~54%)
rem    examples\fixed.bat fake-disorder-sni off  не блокировать QUIC (пусть
rem                                            видео googlevideo идёт по QUIC)
rem
rem  Приём шаткий (~половина соединений) — страница может требовать обновления.
rem  Это предел текущего набора примитивов против этого DPI; надёжнее ищет
rem  автопилот с генератором (examples\autopilot.bat search).
rem ============================================================
setlocal
pushd "%~dp0.."
set "NAME=%~1"
if "%NAME%"=="" set "NAME=fake-disorder-sni"
rem Второй аргумент — режим QUIC: block (умолч.), desync, off. off полезен,
rem когда главная страница лечится по TCP, а медиа (googlevideo) хочет QUIC.
set "QUIC=%~2"
set "QUICARG="
if not "%QUIC%"=="" set "QUICARG=--quic %QUIC%"
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

if not exist "examples\strategies\%NAME%.json" (
  echo.
  echo Нет такого приёма: examples\strategies\%NAME%.json
  echo Доступные:
  dir /b examples\strategies\*.json
  popd
  endlocal
  exit /b 1
)

echo.
echo === Фиксированная стратегия %NAME% (intercept, QUIC блокируется^). Ctrl+C — стоп. ===
echo === Откройте/обновите YouTube. Не помогло — попробуйте другой приём. ===
echo.
evasion.exe run --mode intercept --config examples\strategies\%NAME%.json %QUICARG%

popd
endlocal
