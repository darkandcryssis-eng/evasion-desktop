@echo off
rem ============================================================
rem  Живой тест QUIC одним запуском. Собирает и запускает движок.
rem  Запускать из cmd ОТ АДМИНИСТРАТОРА (нужен WinDivert).
rem
rem  Использование:
rem    examples\quic-test.bat            режим desync (по умолчанию)
rem    examples\quic-test.bat block      блокировка QUIC (откат на TCP)
rem    examples\quic-test.bat off        QUIC не трогать
rem
rem  Остановка — Ctrl+C. После остановки в этом же окне будет видна
rem  итоговая строка «QUIC-...остановлен ... датаграмм_udp443=.. с_именем=..
rem  переписано=..» — по ней понятно, шёл ли QUIC и сработал ли десинк.
rem ============================================================
setlocal
rem Переходим в корень репозитория (на уровень выше examples\).
pushd "%~dp0.."

set "MODE=%~1"
if "%MODE%"=="" set "MODE=desync"
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

if exist state\quic.json del state\quic.json

echo.
echo === Запуск: intercept, QUIC=%MODE%  ^(Ctrl+C — остановка^) ===
echo.
evasion.exe run --mode intercept --config examples\config.json --quic %MODE%

popd
endlocal
