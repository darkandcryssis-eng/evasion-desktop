@echo off
chcp 65001 >nul
title evasion: прогон тестов
REM ============================================================================
REM  Удобный прогон всех проверок движка в один клик.
REM    1. сборка (go build);
REM    2. статический анализ (go vet);
REM    3. подробный прогон тестов примитивов Волны 1 (md5sig, ipv6_ext);
REM    4. полный набор go test по всем пакетам.
REM  Любой провал останавливает прогон с ненулевым кодом возврата.
REM
REM  Детектор гонок (-race) требует C-компилятора (gcc/clang). Если его нет,
REM  скрипт честно прогонит тесты без -race — корректность проверится, гонки нет.
REM ============================================================================

REM --- Корень репозитория (каталог выше scripts\) ---
cd /d "%~dp0.."

REM Тулчейн берётся из go.mod (toolchain), auto — скачать при отсутствии.
set "GOTOOLCHAIN=auto"

where go >nul 2>&1
if %errorlevel% neq 0 (
    echo [test] ОШИБКА: go не найден в PATH. Установи Go ^(https://go.dev/dl/^).
    exit /b 1
)

REM --- Есть ли C-компилятор для -race? ---
set "RACE=-race"
for /f "delims=" %%c in ('go env CC 2^>nul') do set "CCNAME=%%c"
where %CCNAME% >nul 2>&1
if %errorlevel% neq 0 (
    set "RACE="
    echo [test] C-компилятор ^(%CCNAME%^) не найден — тесты без -race ^(гонки не проверяются^).
)

echo [test] 1/4 сборка: go build ./...
go build ./... || goto :fail

echo [test] 2/4 анализ: go vet ./...
go vet ./... || goto :fail

echo [test] 3/4 примитивы и cover-пресеты, подробно:
go test %RACE% -count=1 -v ^
  -run "MD5|InsertTCPOption|IPv6Ext|IPv6HopByHop|BuildPlanMD5|BuildPlanIPv6|ExecuteMD5|ExecuteIPv6|AssembledTCPOverlap|Cover681|CoverPreset|TCPOverlap|GeneratesTCPOverlap" ^
  ./internal/packet/ ./internal/strategy/ ./internal/desync/ ./internal/packetexec/ ./internal/intercept/ ./internal/tlsfake/ ./internal/generator/ || goto :fail

echo [test] 4/4 полный набор: go test %RACE% -count=1 ./...
go test %RACE% -count=1 ./... || goto :fail

echo.
echo [test] ВСЁ ЗЕЛЁНОЕ.
goto :end

:fail
echo.
echo [test] ПРОВАЛ — смотри вывод выше.
exit /b 1

:end
