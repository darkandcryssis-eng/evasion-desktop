@echo off
chcp 65001 >nul
title movok launcher

REM ============================================================================
REM  movok: запуск Discord через встроенный DPI-движок (обход TSPU).
REM
REM  Делает в один клик:
REM    1. собирает свежий evasion.exe из исходников (если найден go);
REM    2. поднимает движок перехвата в отдельном окне (нужны права админа);
REM    3. закрывает запущенный Discord;
REM    4. запускает Discord с выключенным DoH (чтобы он уважал hosts).
REM ============================================================================

REM --- Права администратора: WinDivert без них не поднимется ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [movok] Нужны права администратора, перезапускаю с повышением...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

REM --- Корень репозитория (каталог выше scripts\) ---
cd /d "%~dp0.."

REM --- Закрыть ранее запущенные движки ПЕРЕД сборкой ---
REM  Параллельные evasion.exe конфликтуют за WinDivert handle на одних пакетах
REM  — поток портится и голос рвётся. Плюс запущенный .exe блокирует перезапись
REM  бинарника на этапе сборки. Поэтому глушим в начале.
echo [movok] Закрываю ранее запущенные движки...
taskkill /F /IM evasion.exe /T >nul 2>&1
timeout /t 1 /nobreak >nul

if not exist "examples\config.json" (
    echo [movok] ОШИБКА: examples\config.json не найден в %cd%
    pause
    exit /b 1
)

REM --- Сборка evasion.exe ---
REM  Всегда собираем свежий бинарник, если найден go: после git pull легко
REM  остаться на устаревшей версии. Версия тулчейна задаётся в go.mod
REM  (toolchain go1.27.2) — переменная ниже только подсказывает, какую именно
REM  тащить, если локального нет.
set "GOTOOLCHAIN=go1.27.2"
where go >nul 2>&1
if %errorlevel% equ 0 goto :do_build
echo [movok] go не найден в PATH — беру существующий evasion.exe.
goto :check_exe

:do_build
echo [movok] Собираю evasion.exe из исходников...
go build -o evasion.exe .\cmd\evasion
if %errorlevel% equ 0 (
    echo [movok] Сборка готова.
) else (
    echo [movok] ВНИМАНИЕ: сборка не удалась — беру существующий evasion.exe.
)

:check_exe
if not exist "evasion.exe" (
    echo [movok] ОШИБКА: evasion.exe не найден и собрать не удалось.
    echo [movok] Установи Go ^(https://go.dev/dl/^) и запусти снова.
    pause
    exit /b 1
)

REM --- Снять блок RTC-портов, если остался от прежних запусков ---
netsh advfirewall firewall delete rule name="movok-discord-bad-rtc" >nul 2>&1

REM --- Движок в отдельном окне ---
REM  --voice ttl — десинк голосового UDP Discord (IP discovery, 6 decoy
REM                 с TTL=6 перед настоящим пакетом).
REM  --quic off  — не трогать QUIC: приложение само договорится.
echo [movok] Поднимаю движок обхода DPI...
start "movok-engine" cmd /k "evasion.exe run --mode intercept --config examples\config.json --quic off --voice ttl"

REM --- Дать движку встать на перехват до старта Discord ---
timeout /t 4 /nobreak >nul

REM --- Перезапустить Discord ---
echo [movok] Перезапускаю Discord...
taskkill /F /IM Discord.exe /T >nul 2>&1
timeout /t 1 /nobreak >nul

REM --- Запустить последнюю установленную версию с выключенным DoH ---
set "DISCORD_DIR=%LocalAppData%\Discord"
for /f "delims=" %%d in ('dir /b /ad /o-n "%DISCORD_DIR%\app-*" 2^>nul') do (
    start "" "%DISCORD_DIR%\%%d\Discord.exe" --disable-features=DnsOverHttps
    echo [movok] Discord запущен: %%d
    goto :launched
)
echo [movok] ВНИМАНИЕ: Discord.exe не найден в "%DISCORD_DIR%\app-*"
echo [movok] Проверь путь установки Discord.
:launched

echo.
echo [movok] Готово. Движок работает в окне "movok-engine" — не закрывай его,
echo [movok] пока пользуешься Discord. Чтобы остановить обход: Ctrl+C в том
echo [movok] окне и, при желании, выполни:  evasion.exe hosts clean
echo.
timeout /t 6 /nobreak >nul
