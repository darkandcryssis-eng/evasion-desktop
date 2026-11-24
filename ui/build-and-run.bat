@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
title Evasion UI — сборка единого .exe

REM ============================================================================
REM  Собирает единый Evasion.exe: оболочка (Wails) + встроенный движок
REM  evasion.exe + WinDivert + эталонный конфиг. Готовый файл запускается одним
REM  кликом (с запросом прав администратора) и сам распаковывает движок.
REM
REM  Требуется: Go 1.27 (toolchain из go.mod подтянется), Node.js, интернет для
REM  wails CLI и, при первом запуске, для WinDivert.
REM ============================================================================

cd /d "%~dp0"
set "UI_DIR=%CD%"
set "ROOT=%UI_DIR%\.."
set "PAYLOAD=%UI_DIR%\payload"
set "WINDIVERT_VER=2.2.2"
set "WINDIVERT_DLL_SHA=c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2"
set "WINDIVERT_SYS_SHA=8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2"

REM --- Версия тулчейна Go: подсказка, какую тащить, если локальной нет ---
set "GOTOOLCHAIN=go1.27.2"

where go >nul 2>&1 || (echo [ошибка] Go не найден в PATH. Установите https://go.dev/dl/ & pause & exit /b 1)
where node >nul 2>&1 || (echo [ошибка] Node.js не найден в PATH. Установите https://nodejs.org/ & pause & exit /b 1)

if not exist "%PAYLOAD%" mkdir "%PAYLOAD%"

REM --- 1. Собрать движок из исходников в payload\evasion.exe ---
echo [1/5] Собираю evasion.exe из исходников...
pushd "%ROOT%"
go build -o "%PAYLOAD%\evasion.exe" .\cmd\evasion
if errorlevel 1 (echo [ошибка] сборка движка не удалась & popd & pause & exit /b 1)
popd

REM --- 2. Эталонный конфиг ---
echo [2/5] Копирую config.json...
copy /y "%ROOT%\examples\config.json" "%PAYLOAD%\config.json" >nul
if errorlevel 1 (echo [ошибка] не найден examples\config.json & pause & exit /b 1)

REM --- 3. WinDivert: из корня репозитория, иначе официальный релиз ---
echo [3/5] Готовлю WinDivert...
call :ensure_windivert
if errorlevel 1 (pause & exit /b 1)

REM --- 4. wails CLI ---
echo [4/5] Проверяю wails CLI...
set "WAILS=%USERPROFILE%\go\bin\wails.exe"
if not exist "%WAILS%" (
    echo     ставлю wails@v2.17.0...
    go install github.com/wailsapp/wails/v2/cmd/wails@v2.17.0
    if errorlevel 1 (echo [ошибка] не удалось установить wails & pause & exit /b 1)
)

REM --- 5. Сборка единого exe ---
REM  Удаляем старый сгенерированный icon.ico: Wails пересоздаёт его из
REM  build\appicon.png только если файла нет. Иначе остаётся иконка от первой
REM  сборки, и новая не применяется.
if exist "build\windows\icon.ico" del /q "build\windows\icon.ico"
echo [5/5] Собираю Evasion.exe (wails build)...
"%WAILS%" build
if errorlevel 1 (echo [ошибка] wails build не удался & pause & exit /b 1)

echo.
echo === Готово: %UI_DIR%\build\bin\Evasion.exe ===
echo Запускаю (попросит права администратора)...
start "" "%UI_DIR%\build\bin\Evasion.exe"
endlocal
exit /b 0

REM ---------------------------------------------------------------------------
:ensure_windivert
REM Уже в payload? — ничего не делаем.
if exist "%PAYLOAD%\WinDivert.dll" if exist "%PAYLOAD%\WinDivert64.sys" (
    echo     WinDivert уже в payload, пропуск.
    exit /b 0
)
REM Лежит рядом с репозиторием? — берём оттуда (своя сборка пользователя).
if exist "%ROOT%\WinDivert.dll" if exist "%ROOT%\WinDivert64.sys" (
    echo     беру WinDivert из корня репозитория.
    copy /y "%ROOT%\WinDivert.dll"   "%PAYLOAD%\WinDivert.dll"   >nul
    copy /y "%ROOT%\WinDivert64.sys" "%PAYLOAD%\WinDivert64.sys" >nul
    exit /b 0
)
REM Иначе — официальный релиз с проверкой SHA-256.
set "WD_ZIP=%TEMP%\WinDivert-%WINDIVERT_VER%-A.zip"
set "WD_URL=https://github.com/basil00/WinDivert/releases/download/v%WINDIVERT_VER%/WinDivert-%WINDIVERT_VER%-A.zip"
set "WD_DIR=%TEMP%\WinDivert-%WINDIVERT_VER%-A"
echo     скачиваю WinDivert %WINDIVERT_VER%...
powershell -NoProfile -Command "try { Invoke-WebRequest -Uri '%WD_URL%' -OutFile '%WD_ZIP%' } catch { exit 1 }"
if errorlevel 1 (echo [ошибка] не удалось скачать WinDivert & exit /b 1)
powershell -NoProfile -Command "Expand-Archive -Force '%WD_ZIP%' '%WD_DIR%'"
if errorlevel 1 (echo [ошибка] не удалось распаковать WinDivert & exit /b 1)
REM В архиве файлы лежат во вложенной папке WinDivert-<версия>-A.
if not exist "%WD_DIR%\x64\WinDivert.dll" set "WD_DIR=%WD_DIR%\WinDivert-%WINDIVERT_VER%-A"
call :check_sha
if not exist "%~1" (echo [ошибка] не найден файл %~1 & exit /b 1)
set "GOT="
for /f "usebackq delims=" %%H in (`powershell -NoProfile -Command "(Get-FileHash -Algorithm SHA256 -LiteralPath '%~1').Hash"`) do set "GOT=%%H"
if not defined GOT (echo [ошибка] не удалось посчитать SHA-256 для %~1 & exit /b 1)
if /i "!GOT!"=="%~2" exit /b 0
echo [ошибка] SHA-256 не совпал для %~1
echo     ожидался %~2
echo     получен  !GOT!
exit /b 1
