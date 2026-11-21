@echo off
chcp 65001 >nul
rem Прогон всех кандидатов стратегий по очереди: поднять движок, проверить
rem curl, остановить, напечатать результат. Запускать ИЗ ОКНА cmd ОТ ИМЕНИ
rem АДМИНИСТРАТОРА (движку нужен драйвер WinDivert).
rem
rem evasion.exe должен лежать в корне репозитория (собери: go build -o
rem evasion.exe .\cmd\evasion). Код youtube 200/301 = обход работает, 000 =
rem соединение сброшено (не взяло). example обязан быть 200 (нет вреда).
setlocal enabledelayedexpansion
cd /d "%~dp0..\.."

if not exist evasion.exe (
  echo Не найден evasion.exe в %cd%. Собери: go build -o evasion.exe .\cmd\evasion
  exit /b 1
)

echo Останавливаю сторонние обходы и старые экземпляры...
taskkill /im evasion.exe /f >nul 2>&1

set CONFIGS=fake-badsum fake-disorder-sni fake-split-sni disorder-sni fake-ttl

echo.
echo === базовая линия (движок выключен) ===
call :probe base

for %%C in (%CONFIGS%) do (
  echo.
  echo === %%C ===
  start "evasion" /min evasion.exe run --mode intercept --config "examples\strategies\%%C.json"
  rem даём подняться драйверу и слушателю
  timeout /t 3 >nul
  tasklist /fi "imagename eq evasion.exe" | find /i "evasion.exe" >nul || echo   [!] движок не запустился: проверь WinDivert.dll/.sys рядом с evasion.exe и права администратора
  call :probe %%C
  taskkill /im evasion.exe /f >nul 2>&1
  timeout /t 2 >nul
)

echo.
echo Готово. 200/301 у youtube = обход сработал; 000 = сброс. example должен быть 200.
exit /b 0

:probe
set YT=000
set EX=000
for /f "delims=" %%L in ('curl -s -o nul -w "%%{http_code}" --max-time 8 https://youtube.com') do set YT=%%L
for /f "delims=" %%L in ('curl -s -o nul -w "%%{http_code}" --max-time 8 https://example.com') do set EX=%%L
echo %~1: youtube=!YT!  example=!EX!
exit /b 0
