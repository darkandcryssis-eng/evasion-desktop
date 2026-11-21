<#
.SYNOPSIS
    Полный прогон проверок evasion на Windows: статический анализ, тесты,
    живая матрица прогонов через прокси, перебор смещений разреза и дамп пакетов.

.DESCRIPTION
    Скрипт существует, чтобы прогон был воспроизводимым и не зависел от того,
    какие команды человек вспомнил набрать. Всё, что он собирает, кладётся в
    папку отчёта reports\<дата-время>\ — её можно отдать целиком.

    Главный вопрос, на который отвечает дамп: уходит ClientHello одним сегментом
    или двумя. Без этого ответа нельзя отличить «стратегия применилась, но DPI не
    обманулся» от «стратегия физически не применилась, ОС склеила записи». Это
    разные диагнозы, и оценивать стратегии до их различения бессмысленно.

    Перебор смещений — временная мера. Абсолютное смещение зависит от соединения
    (длина session_id, набор шифров, порядок расширений), поэтому осмысленные
    значения приходится искать перебором. После появления символьных точек
    разреза (inside_sni) перебор станет не нужен.

.PARAMETER Target
    Цель, которая предположительно блокируется. По ней измеряется обход.

.PARAMETER Control
    Контрольная цель, которая обязана работать всегда. Нужна, чтобы отличить
    блокировку цели от общей поломки сети или самого прокси (4.5, collateral).

.PARAMETER Offsets
    Смещения разреза для перебора. Пустой список отключает перебор.

.PARAMETER Port
    Порт прослушивания прокси.

.PARAMETER TimeoutSec
    Предел ожидания одного запроса curl. Заблокированное соединение висит до
    предела, поэтому значение прямо влияет на длительность прогона.

.PARAMETER CutPoints
    Структурные точки разреза для перебора. В отличие от числовых смещений, они
    не зависят от конкретного соединения: положение имени сервера в ClientHello
    меняется от клиента к клиенту, поэтому одно и то же число попадает то внутрь
    имени, то в список шифров. Пустой список отключает перебор.

.PARAMETER Services
    Какие сервисы проверять на работоспособность. Доступны youtube и discord.

.PARAMETER ServiceTimeoutSec
    Предел ожидания для проверки сервисов. Отдельный от TimeoutSec и меньше его:
    точек проверки много, и каждая недоступная стоит полный предел ожидания.

.PARAMETER Iface
    Номер интерфейса для tshark (см. tshark -D). Если не задан, дамп снимается
    через pktmon, встроенный в Windows (нужны права администратора).

.PARAMETER SkipStatic
    Пропустить сборку, тесты и статический анализ.

.PARAMETER SkipCapture
    Пропустить снятие дампа.

.PARAMETER SkipServices
    Пропустить проверку работоспособности сервисов.

.PARAMETER SkipOffsets
    Пропустить перебор числовых смещений разреза.

    Отдельный переключатель, а не пустой список в -Offsets: при запуске через
    `powershell -File` аргументы приходят строками, и значение @() попадает в
    скрипт как текст, который к массиву чисел не приводится.

.PARAMETER SkipCuts
    Пропустить перебор структурных точек разреза.

.PARAMETER Delays
    Паузы между частями разреза (миллисекунды) для перебора. Пауза направлена
    против DPI, который собирает поток в ограниченном по времени окне: если окно
    истечёт до прихода второй части, целое имя сервера он собрать не успеет.

.PARAMETER SkipDelays
    Пропустить перебор паузы.

.PARAMETER AllowConflicts
    Продолжить прогон, даже если найден другой инструмент обхода (zapret,
    GoodbyeDPI и подобные). По умолчанию прогон прерывается: такие инструменты
    применяют свой десинк поверх нашего, и измеряется сумма двух воздействий.

.PARAMETER SkipStaticcheck
    Пропустить только staticcheck (он медленный при первом запуске: качает
    зависимости).

.EXAMPLE
    .\tests\windows-full-check\check.ps1
    Обычный прогон: всё, кроме дампа, если нет прав администратора.

.EXAMPLE
    .\tests\windows-full-check\check.ps1 -SkipStatic -Offsets 125,130,135
    Быстрый повторный прогон только живой части с тремя смещениями.
#>

[CmdletBinding()]
param(
    [string]   $Target          = 'https://www.youtube.com/',
    [string]   $Control         = 'https://example.com/',
    [int[]]    $Offsets         = @(5, 43, 76, 110, 120, 125, 130, 135, 140, 150),
    [int]      $Port            = 1080,
    [int]      $TimeoutSec      = 10,
    [string[]] $CutPoints       = @('record_header', 'handshake_header', 'extensions', 'before_sni', 'inside_sni', 'after_sni'),
    [int[]]    $Delays          = @(50, 200, 600, 1500),
    [string[]] $Services        = @('youtube', 'discord'),
    [int]      $ServiceTimeoutSec = 6,
    [string]   $Iface           = '',
    [switch]   $SkipStatic,
    [switch]   $SkipCapture,
    [switch]   $SkipServices,
    [switch]   $SkipOffsets,
    [switch]   $SkipCuts,
    [switch]   $SkipDelays,
    [switch]   $SkipStaticcheck,
    [switch]   $AllowConflicts
)

# Режим обработки ошибок намеренно НЕ 'Stop'.
#
# Windows PowerShell 5.1 превращает любой вывод внешней программы в поток ошибок
# в объект ошибки (NativeCommandError). При 'Stop' скрипт обрывался бы на
# команде, которая всего лишь напечатала диагностику, — а именно это и
# проверяется в фазе 2, где движок обязан отказать с сообщением. Поэтому об
# успехе внешних команд судим по коду возврата (см. Invoke-Native), а свои
# аварийные ситуации обозначаем throw.
$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest

# Вывод внешних программ читаем как UTF-8.
#
# Движок печатает сообщения в UTF-8, а консоль Windows по умолчанию отдаёт их
# PowerShell в кодировке OEM (cp866 на русской системе) — русский текст
# превращался в мусор. Прежнее значение запоминаем и возвращаем в конце, чтобы
# не менять настройку сеанса, из которого скрипт запустили.
$prevConsoleEncoding = [Console]::OutputEncoding
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}

# ---------------------------------------------------------------------------
# Подготовка окружения отчёта
# ---------------------------------------------------------------------------

# Корень репозитория вычисляем от расположения скрипта, а не от текущего
# каталога: иначе прогон зависел бы от того, откуда его запустили.
#
# Ищем go.mod вверх по дереву, а не отсчитываем уровни каталогов. Отсчёт здесь
# уже сломался: скрипт жил в tests\, брал два уровня вверх, затем переехал в
# tests\windows-full-check\ вместе с библиотекой прогонов — и те же два уровня
# стали указывать на tests\. Скрипт падал с «go.mod не найден», причём только у
# владельца: pwsh в песочнице разработки нет, и запустить его там нельзя.
# Поиск вверх делает расположение скрипта неважным и повторить эту ошибку не
# даёт. Тем же способом находят корень Go-прогоны (tests\harness).
$repoRoot = Split-Path -Parent $PSCommandPath
while ($true) {
    if (Test-Path (Join-Path $repoRoot 'go.mod')) { break }
    $parent = Split-Path -Parent $repoRoot
    if ([string]::IsNullOrEmpty($parent) -or $parent -eq $repoRoot) {
        throw "go.mod не найден выше $PSCommandPath. Скрипт должен лежать внутри репозитория."
    }
    $repoRoot = $parent
}
Set-Location $repoRoot

$stamp     = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$reportDir = Join-Path $repoRoot "reports\$stamp"
$binDir    = Join-Path $repoRoot 'bin'
New-Item -ItemType Directory -Force -Path $reportDir | Out-Null
New-Item -ItemType Directory -Force -Path $binDir    | Out-Null

$exe = Join-Path $binDir 'evasion.exe'

# Сводка собирается в список объектов и печатается таблицей в конце: читать
# итог посреди вывода тестов невозможно.
$summary = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param([string]$Phase, [string]$Name, [string]$Result, [string]$Detail = '')
    $summary.Add([pscustomobject]@{
        Phase  = $Phase
        Name   = $Name
        Result = $Result
        Detail = $Detail
    })
}

function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('=' * 72) -ForegroundColor DarkGray
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ('=' * 72) -ForegroundColor DarkGray
}

function Save-Output {
    param([string]$FileName, [string]$Content)
    $Content | Out-File -FilePath (Join-Path $reportDir $FileName) -Encoding utf8
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).
    IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ---------------------------------------------------------------------------
# Запуск внешних программ
# ---------------------------------------------------------------------------

# Invoke-Native запускает внешнюю программу и возвращает её вывод вместе с кодом
# возврата.
#
# Существует ради одной особенности Windows PowerShell 5.1: вывод внешней
# программы в поток ошибок становится объектом ошибки, и при строгом режиме
# обработки это обрывает скрипт. Здесь потоки сливаются, объекты ошибок
# приводятся к тексту, а признаком неудачи служит только код возврата — то есть
# ровно то, на что программа и опирается.
function Invoke-Native {
    param([string]$File, [string[]]$Arguments = @())

    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $global:LASTEXITCODE = 0
        $raw  = & $File @Arguments 2>&1
        $code = $LASTEXITCODE
        # Элементы могут быть как строками, так и объектами ошибок: приводим всё
        # к тексту единообразно.
        # Строки из потока ошибок приходят объектами ErrorRecord. Их ToString()
        # в части случаев отдаёт имя класса исключения вместо текста — поэтому
        # сообщение берём из самого исключения.
        $text = (@($raw) | ForEach-Object {
            if ($null -eq $_) { return }
            if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { [string]$_ }
        }) -join [Environment]::NewLine
        return [pscustomobject]@{ Text = $text.Trim(); Code = $code }
    } catch {
        # Отсутствие программы движок не находит сам: это ошибка уровня
        # оболочки. Возвращаем её как обычную неудачу с внятным текстом, иначе
        # наружу вылезла бы трассировка.
        return [pscustomobject]@{ Text = "не удалось запустить ${File}: $($_.Exception.Message)"; Code = 127 }
    } finally {
        $ErrorActionPreference = $prev
    }
}

# Find-CCompiler возвращает путь к компилятору C или пустую строку.
#
# Нужен только детектору гонок: продукт собирается без CGO (3.1). Ищем в трёх
# местах, чтобы не требовать правки PATH — она на Windows из cmd делается
# небезопасно (setx с %PATH% сливает машинный путь в пользовательский и может
# его обрезать), а ради одной проверки рисковать путём незачем.
function Find-CCompiler {
    if ($env:CC -and (Test-Path $env:CC)) { return $env:CC }
    $inPath = Get-Command gcc -ErrorAction SilentlyContinue
    if ($inPath) { return $inPath.Source }
    # Стандартные места установки MSYS2. Порядок: ucrt64 современнее mingw64.
    foreach ($p in @(
        'C:\msys64\ucrt64\bin\gcc.exe',
        'C:\msys64\mingw64\bin\gcc.exe',
        'C:\msys2\ucrt64\bin\gcc.exe')) {
        if (Test-Path $p) { return $p }
    }
    return ''
}

# Test-Tool сообщает, доступна ли программа в PATH.
function Test-Tool {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

# ---------------------------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------------------------

# New-EvasionConfig пишет конфиг без метки BOM.
#
# Set-Content в Windows PowerShell 5.1 добавляет метку BOM в начало файла, а
# строгий разбор JSON в Go на ней падает. WriteAllText этого не делает.
function New-EvasionConfig {
    param(
        [string]    $Path,
        [object]    $Offset,   # $null и пустой $At — конфиг без стратегии
        [hashtable] $Groups,
        [string]    $At = '',  # структурная точка разреза вместо числа
        [int]       $DelayMs = 0
    )

    $groupsJson = ($Groups.GetEnumerator() | ForEach-Object {
        $domains = ($_.Value | ForEach-Object { '"' + $_ + '"' }) -join ', '
        '    "' + $_.Key + '": [' + $domains + ']'
    }) -join ",`n"

    # Место разреза задаётся ровно одним способом: числом или видом точки.
    # Движок отвергает описание, где заданы оба или ни один.
    $placeJson = ''
    if ($At) { $placeJson = '"at": "' + $At + '"' }
    elseif ($null -ne $Offset) { $placeJson = '"offset": ' + $Offset }

    $delayJson = ''
    if ($DelayMs -gt 0) { $delayJson = ', "delay_ms": ' + $DelayMs }

    $strategyJson = 'null'
    if ($placeJson) {
        $strategyJson = @"
{
    "rules": [{
      "direction": "outbound",
      "trigger": {"match": "client_hello"},
      "action": {
        "kind": "fragment",
        "params": {"proto": "tcp", $placeJson$delayJson},
        "left": {"kind": "send"},
        "right": {"kind": "send"}
      }
    }]
  }
"@
    }

    $json = @"
{
  "listen": "127.0.0.1:$Port",
  "groups": {
$groupsJson
  },
  "strategy": $strategyJson
}
"@
    [IO.File]::WriteAllText($Path, $json)
}

# Wait-Port ждёт, пока прокси начнёт принимать соединения. Без ожидания первый
# curl мог бы прийти раньше привязки сокета и дать ложный провал.
#
# Готовность определяется по таблице слушающих сокетов, а не пробным
# подключением: подключение с немедленным разрывом движок честно записывал в
# журнал как неудавшееся рукопожатие SOCKS, и этот шум путался с настоящими
# наблюдениями. Если командлет недоступен, остаётся пробное подключение.
function Wait-Port {
    param([int]$P, [int]$WaitSec = 10)

    $canQuery = [bool](Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $WaitSec) {
        if ($canQuery) {
            $listening = Get-NetTCPConnection -LocalPort $P -State Listen -ErrorAction SilentlyContinue
            if ($listening) { return $true }
        } else {
            try {
                $c = New-Object Net.Sockets.TcpClient
                $c.Connect('127.0.0.1', $P)
                $c.Close()
                return $true
            } catch {}
        }
        Start-Sleep -Milliseconds 200
    }
    return $false
}

# Get-AppliedStrategy достаёт из журнала, какая стратегия применилась к
# соединению с заданным хостом.
#
# Отбор именно по хосту принципиален. Раньше бралось последнее упоминание в
# журнале, а последним шло соединение с контрольной целью — она вне радиуса и
# даёт «none». Столбец показывал контроль вместо цели, то есть проверка,
# созданная против ложного вывода «стратегия не работает», сама такой вывод и
# порождала.
# Get-LogIssues возвращает предупреждения и ошибки из журнала прокси.
#
# Нужно потому, что без них прогон врал: если исполнение стратегии прерывалось
# ошибкой, движок писал об этом WARN, а скрипт показывал только код ответа и
# применённую стратегию. Выходило «стратегия применена, цель недоступна», тогда
# как в журнале стояла причина.
function Get-LogIssues {
    param([string]$LogPath)
    if (-not (Test-Path $LogPath)) { return @() }
    return @(Select-String -Path $LogPath -Pattern '"level":"(WARN|ERROR)"' |
             ForEach-Object { $_.Line })
}

# Show-LogIssues печатает найденные предупреждения и заносит их число в сводку.
function Show-LogIssues {
    param([string]$LogPath, [string]$Phase, [string]$Name)
    # Обёртка @() обязательна: PowerShell разворачивает пустой массив,
    # возвращаемый функцией, в $null, а при строгом режиме обращение к $null.Count
    # прерывает выполнение. Для одного элемента она же даёт массив из одного.
    $issues = @(Get-LogIssues -LogPath $LogPath)
    if ($issues.Count -eq 0) { return }
    Write-Host ("    предупреждений в журнале: {0}" -f $issues.Count) -ForegroundColor Yellow
    foreach ($i in ($issues | Select-Object -First 5)) {
        Write-Host "      $i" -ForegroundColor DarkYellow
    }
    # Скобки обязательны: без них $Name перед двоеточием читается как указание
    # области видимости переменной (как в $env:PATH), и разбор падает.
    Add-Result $Phase "${Name}: предупреждения" $issues.Count 'подробности в журнале фазы'
}

# Measure-PktmonSegments разбирает текстовый дамп pktmon и возвращает по каждому
# исходящему соединению последовательность длин пакетов с данными.
#
# Отвечает на главный вопрос прогона: уходит ClientHello одним сегментом или
# несколькими. Если первый пакет с данными равен заданному смещению разреза,
# нарезка дошла до сети. Если он равен всему ClientHello — записи склеены, и
# стратегия физически не применилась.
#
# Разметка дампа: строка-заголовок с направлением и номером, следом строка с
# разбором пакета вида
#   SRC.PORT > DST.PORT: Flags [P.], seq N:M, ack K, win W, options [...], length L
# Направление определяем по порту назначения, а не по слову в заголовке: слово
# переведено на язык системы, а номер порта нет.
#
# Один и тот же пакет записывается несколько раз — на разных уровнях стека
# (компонентах). Поэтому записи устраняются по содержимому. Цена: повторная
# передача того же сегмента неотличима от записи с другого уровня и будет
# слита с ней. Для вопроса о длине первого пакета это несущественно.
function Measure-PktmonSegments {
    param([string]$TextPath, [int]$Port = 443)

    $rx = '(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+):\s+Flags \[([^\]]*)\]' +
          '(?:,\s+seq (\d+)(?::(\d+))?)?.*?length (\d+)\s*$'

    $seen    = @{}
    $streams = [ordered]@{}

    foreach ($line in [IO.File]::ReadLines($TextPath)) {
        if ($line -notmatch $rx) { continue }
        $srcIP = $Matches[1]; $srcPort = $Matches[2]
        $dstIP = $Matches[3]; $dstPort = $Matches[4]
        $flags = $Matches[5]; $seq = $Matches[6]; $len = [int]$Matches[8]

        # Только исходящие к наблюдаемому порту и только несущие данные:
        # подтверждения и установка соединения к вопросу не относятся.
        if ($dstPort -ne "$Port" -or $len -le 0) { continue }

        $key = "$srcIP|$srcPort|$dstIP|$seq|$len|$flags"
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true

        $sk = "$dstIP (локальный порт $srcPort)"
        if (-not $streams.Contains($sk)) {
            $streams[$sk] = [System.Collections.Generic.List[int]]::new()
        }
        $streams[$sk].Add($len)
    }
    return $streams
}

function Get-AppliedStrategy {
    param([string]$LogPath, [string]$HostName)

    if (-not (Test-Path $LogPath)) { return 'нет журнала' }
    # В строке журнала target идёт раньше strategy, поэтому одного выражения
    # достаточно. Имя хоста экранируем: в нём есть точки.
    $pattern = '"target":"' + [regex]::Escape($HostName) + ':\d+".*?"strategy":"([^"]*)"'
    $m = Select-String -Path $LogPath -Pattern $pattern | Select-Object -Last 1
    if ($m) { return $m.Matches[0].Groups[1].Value }
    return 'соединение не найдено'
}

# Start-Evasion запускает прокси в фоне. Поток вывода и поток ошибок идут в
# разные файлы: на stdout движок кладёт машинную сводку, на stderr — журнал, и
# смешивать их нельзя (это контракт CLI).
function Start-Evasion {
    param([string]$ConfigPath, [string[]]$ExtraArgs = @(), [string]$Tag)

    $outFile = Join-Path $reportDir "$Tag.stdout.json"
    $errFile = Join-Path $reportDir "$Tag.log"

    $argList = @('run', '--config', $ConfigPath, '--json') + $ExtraArgs
    $proc = Start-Process -FilePath $exe -ArgumentList $argList `
        -RedirectStandardOutput $outFile -RedirectStandardError $errFile `
        -PassThru -WindowStyle Hidden

    if (-not (Wait-Port -P $Port)) {
        try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {}
        throw "прокси не начал слушать порт $Port. Подробности: $errFile"
    }
    return $proc
}

function Stop-Evasion {
    param($Proc)
    if ($null -eq $Proc) { return }
    try { Stop-Process -Id $Proc.Id -Force -ErrorAction SilentlyContinue } catch {}
    # Небольшая пауза, чтобы порт освободился до следующего запуска.
    Start-Sleep -Milliseconds 400
}

# Invoke-Probe делает один запрос curl и возвращает код ответа и время.
#
# Код 000 означает, что ответа не было вовсе (обрыв или таймаут) — именно так
# выглядит блокировка после ClientHello.
function Invoke-Probe {
    param([string]$Url, [switch]$ThroughProxy, [int]$MaxTime = 0)

    if ($MaxTime -le 0) { $MaxTime = $TimeoutSec }
    $fmt = 'code=%{http_code} time=%{time_total}'
    $a = @('-s', '-o', 'NUL', '-w', $fmt, '--max-time', "$MaxTime")
    if ($ThroughProxy) {
        # socks5-hostname, а не socks5: имя обязано разрешаться на стороне
        # прокси, иначе движок не увидит доменное имя цели.
        $a += @('--socks5-hostname', "127.0.0.1:$Port")
    }
    $a += $Url

    $r = Invoke-Native -File 'curl.exe' -Arguments $a

    $code = 'n/a'; $time = 'n/a'
    if ($r.Text -match 'code=(\S+)\s+time=(\S+)') {
        $code = $Matches[1]; $time = $Matches[2]
    }
    return [pscustomobject]@{ Code = $code; Time = $time; Raw = $r.Text }
}

# ---------------------------------------------------------------------------
# Каталог сервисов
# ---------------------------------------------------------------------------

# $serviceCatalog описывает, из чего состоит каждый сервис.
#
# Проверка по одному адресу недостаточна: YouTube и Discord опираются на
# несколько независимых систем, и блокировка бывает выборочной — главная
# страница открывается, а видеопоток или шлюз реального времени нет. Для
# движка это и есть смысл понятия «группа доменов»: группа работает ровно
# настолько, насколько доступны её части.
#
# Признаком доступности считается ЛЮБОЙ код ответа HTTP, включая 403, 404 и 405:
# он доказывает, что рукопожатие TLS прошло и сервер ответил. Недоступность —
# только код 000, то есть ответа не было вовсе. Поэтому адреса выбраны за
# устойчивость отклика, а не за осмысленность содержимого.
#
# Domains задают радиус поражения в конфиге. Группы выводятся из этого же
# каталога, чтобы радиус не разошёлся с тем, что проверяется.
$serviceCatalog = [ordered]@{
    youtube = @{
        # googleapis.com шире, чем нужно: под него попадают все службы Google,
        # а не только YouTube. Для проверочного конфига это допустимо, в рабочем
        # стоит сузить до youtubei.googleapis.com.
        Domains   = @('youtube.com', 'youtu.be', 'ytimg.com', 'googlevideo.com', 'googleapis.com')
        Endpoints = @(
            @{ Url = 'https://www.youtube.com/';           Note = 'главная страница' },
            @{ Url = 'https://m.youtube.com/';             Note = 'мобильный фронтенд' },
            @{ Url = 'https://youtubei.googleapis.com/';   Note = 'внутренний API воспроизведения' },
            @{ Url = 'https://redirector.googlevideo.com/'; Note = 'выдача адресов видеопотока' },
            @{ Url = 'https://www.googlevideo.com/';       Note = 'видеопоток (CDN)' },
            @{ Url = 'https://i.ytimg.com/';               Note = 'превью' }
        )
    }
    discord = @{
        Domains   = @('discord.com', 'discord.gg', 'discordapp.com', 'discordapp.net')
        Endpoints = @(
            @{ Url = 'https://discord.com/';                   Note = 'главная страница' },
            @{ Url = 'https://discord.com/api/v10/gateway';    Note = 'API' },
            @{ Url = 'https://gateway.discord.gg/';            Note = 'шлюз реального времени' },
            @{ Url = 'https://cdn.discordapp.com/';            Note = 'файлы и картинки' },
            @{ Url = 'https://media.discordapp.net/';          Note = 'медиа' },
            @{ Url = 'https://discord.gg/';                    Note = 'приглашения' }
        )
    }
}

# Группы для конфига берём из каталога целиком, независимо от -Services:
# сужение списка проверяемых сервисов не должно менять радиус, иначе проверки
# разных прогонов станут несравнимыми.
$groups = @{}
foreach ($name in $serviceCatalog.Keys) {
    $groups[$name] = $serviceCatalog[$name].Domains
}

$proc           = $null
$captureStarted = $false   # дамп реально запущен — только тогда его надо останавливать
$capturer       = 'none'
$aborted        = $false

# Имя хоста цели нужно, чтобы искать в журнале именно её соединение, а не
# контрольное.
$targetHost = ([Uri]$Target).Host

try {
    # -----------------------------------------------------------------------
    # Фаза 0. Наличие инструментов и конфликты перехвата
    # -----------------------------------------------------------------------
    foreach ($tool in @('go', 'curl.exe')) {
        if (-not (Test-Tool $tool)) { throw "$tool не найден в PATH" }
    }

    # Другой инструмент обхода, работающий одновременно с нами, делает прогон
    # бессмысленным: он перехватывает те же пакеты и применяет свой десинк
    # поверх нашего. Измеряется тогда сумма двух воздействий, а не наша
    # стратегия. Задание требует сообщать о таких конфликтах (5.9), поэтому
    # прогон останавливается, а не продолжается с оговоркой.
    $conflictNames = @('winws', 'goodbyedpi', 'zapret', 'ciadpi', 'byedpi', 'spoofdpi', 'greendpi')
    $running = @(Get-Process -Name $conflictNames -ErrorAction SilentlyContinue)
    $conflictServices = @(Get-Service -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -eq 'Running' -and $_.Name -match 'winws|zapret|goodbyedpi' })

    # Драйвер WinDivert отдельно и только предупреждением: после остановки
    # инструмента служба драйвера часто остаётся запущенной, но сама по себе
    # трафик не отводит — для этого нужен процесс с открытым дескриптором.
    # Прерывать прогон из-за неё означало бы требовать перезагрузки впустую.
    $divert = @(Get-Service -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -eq 'Running' -and $_.Name -match 'windivert' })
    if ($divert.Count -gt 0 -and $running.Count -eq 0 -and $conflictServices.Count -eq 0) {
        Write-Host ''
        Write-Host ("Замечание: загружен драйвер {0}, но процессов перехвата не видно." -f ($divert.Name -join ', ')) -ForegroundColor DarkYellow
        Write-Host 'Сам по себе он трафик не отводит. Если измерения будут странными, перезагрузитесь.' -ForegroundColor DarkYellow
        Add-Result 'conflict' 'драйвер WinDivert' 'загружен' 'процессов перехвата не обнаружено'
    }

    if ($running.Count -gt 0 -or $conflictServices.Count -gt 0) {
        Write-Section 'Обнаружен конфликт перехвата'
        foreach ($p in $running) {
            Write-Host ("  процесс: {0} (PID {1})" -f $p.ProcessName, $p.Id) -ForegroundColor Red
            Add-Result 'conflict' "процесс $($p.ProcessName)" 'ЗАПУЩЕН' "PID $($p.Id)"
        }
        foreach ($s in $conflictServices) {
            Write-Host ("  служба: {0} ({1})" -f $s.Name, $s.DisplayName) -ForegroundColor Red
            Add-Result 'conflict' "служба $($s.Name)" 'ЗАПУЩЕНА' $s.DisplayName
        }
        Write-Host ''
        Write-Host '  Эти инструменты обрабатывают те же пакеты и применяют свой десинк поверх нашего.' -ForegroundColor Yellow
        Write-Host '  Прогон измерял бы сумму двух воздействий, а не нашу стратегию.' -ForegroundColor Yellow
        Write-Host '  Выключите их и повторите. Запуск вопреки этому: -AllowConflicts' -ForegroundColor Yellow
        if (-not $AllowConflicts) {
            throw 'обнаружен другой инструмент перехвата; выключите его или укажите -AllowConflicts'
        }
        Write-Host '  -AllowConflicts: продолжаю, но измерения недостоверны.' -ForegroundColor Red
        Add-Result 'conflict' 'достоверность прогона' 'ПОД СОМНЕНИЕМ' 'запущен другой инструмент перехвата'
    } else {
        Add-Result 'conflict' 'другие инструменты перехвата' 'не обнаружены'
    }

    # -----------------------------------------------------------------------
    # Фаза 1. Сборка, тесты, статический анализ
    # -----------------------------------------------------------------------
    if (-not $SkipStatic) {
        Write-Section 'Фаза 1: сборка, тесты, статический анализ'

        $steps = @(
            @{ Name = 'go build'; File = 'go'; Args = @('build', './...') },
            @{ Name = 'go vet';   File = 'go'; Args = @('vet',   './...') },
            @{ Name = 'go test';  File = 'go'; Args = @('test',  './...') }
        )
        if (-not $SkipStaticcheck) {
            $steps += @{ Name = 'staticcheck'; File = 'go'
                         Args = @('run', 'honnef.co/go/tools/cmd/staticcheck@latest', './...') }
        }

        foreach ($s in $steps) {
            Write-Host "-> $($s.Name)" -ForegroundColor Yellow
            $r = Invoke-Native -File $s.File -Arguments $s.Args
            Save-Output ("static_" + ($s.Name -replace '\W', '_') + '.txt') $r.Text
            if ($r.Text) { Write-Host $r.Text }
            $verdict = if ($r.Code -eq 0) { 'OK' } else { 'FAIL' }
            Write-Host ("   {0} (код возврата {1})" -f $verdict, $r.Code) `
                -ForegroundColor $(if ($r.Code -eq 0) { 'Green' } else { 'Red' })
            Add-Result 'static' $s.Name $verdict "код возврата $($r.Code)"
        }

        # Продукт обязан собираться БЕЗ CGO (3.1): от этого зависит простота
        # поставки — один исполняемый файл без внешних зависимостей времени
        # выполнения. Пока компилятора C на машине не было, требование
        # соблюдалось само собой. С появлением mingw-w64 для детектора гонок
        # нарушить его стало легко и незаметно: достаточно импорта пакета,
        # который тянет cgo, и сборка продолжит работать на этой машине, но
        # перестанет собираться там, где компилятора нет.
        Write-Host '-> сборка без CGO' -ForegroundColor Yellow
        $prevCgo = $env:CGO_ENABLED
        $env:CGO_ENABLED = '0'
        $r = Invoke-Native -File 'go' -Arguments @('build', './...')
        if ($null -eq $prevCgo) { Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue }
        else { $env:CGO_ENABLED = $prevCgo }
        if ($r.Text) { Write-Host $r.Text }
        $verdict = if ($r.Code -eq 0) { 'OK' } else { 'FAIL' }
        Write-Host ("   {0} (код возврата {1})" -f $verdict, $r.Code) `
            -ForegroundColor $(if ($r.Code -eq 0) { 'Green' } else { 'Red' })
        Add-Result 'static' 'сборка без CGO' $verdict 'требование 3.1: поставка без внешних зависимостей'

        # go test -race требует cgo и mingw-w64; отмечаем явно, а не делаем вид,
        # что проверка прошла.
        $cc = Find-CCompiler
        if ($cc) {
            Write-Host "-> go test -race (компилятор: $cc)" -ForegroundColor Yellow
            # CGO_ENABLED и CC ставим только на эту проверку и возвращаем
            # прежние значения: продукт обязан собираться без CGO, и менять
            # окружение вызывающего сеанса нельзя.
            $prevCgo  = $env:CGO_ENABLED
            $prevCC   = $env:CC
            $prevPath = $env:PATH
            $env:CGO_ENABLED = '1'
            $env:CC = $cc
            # Каталог компилятора добавляется в PATH, и это обязательно.
            #
            # gcc.exe — лишь оболочка: настоящую работу делает cc1.exe, который
            # лежит в lib\gcc\..., а его библиотеки (libisl, libmpc, libmpfr,
            # libgmp, libwinpthread) остались в bin. Для дочернего процесса
            # каталог запустившей программы не подставляется, поэтому без bin в
            # PATH cc1.exe не стартует и умирает БЕЗ сообщения — gcc возвращает
            # код 1 с пустым выводом, и причину приходится искать вручную.
            $ccDir = Split-Path -Parent $cc
            if ($ccDir) { $env:PATH = $ccDir + ';' + $env:PATH }
            $r = Invoke-Native -File 'go' -Arguments @('test', '-race', './...')
            if ($null -eq $prevCgo) { Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue } else { $env:CGO_ENABLED = $prevCgo }
            if ($null -eq $prevCC)  { Remove-Item Env:CC -ErrorAction SilentlyContinue }          else { $env:CC = $prevCC }
            $env:PATH = $prevPath

            Save-Output 'static_go_test_race.txt' $r.Text
            if ($r.Text) { Write-Host $r.Text }

            # Неисправный компилятор отличаем от провала тестов.
            #
            # Иначе прогон выглядел бы так, будто код сломан, тогда как сломано
            # окружение: детектор гонок на Windows требует cgo, а свежие версии
            # gcc местами не собирают runtime/cgo. Называть это провалом тестов
            # значило бы вводить в заблуждение и портить код возврата скрипта.
            $toolchainBroken = ($r.Text -match 'runtime/cgo|cgo\.exe|build failed|exec: .*gcc')
            $verdict = if ($r.Code -eq 0) { 'OK' } elseif ($toolchainBroken) { 'ТУЛЧЕЙН' } else { 'FAIL' }
            $color = switch ($verdict) { 'OK' { 'Green' } 'ТУЛЧЕЙН' { 'Yellow' } default { 'Red' } }
            Write-Host ("   {0} (код возврата {1})" -f $verdict, $r.Code) -ForegroundColor $color
            if ($toolchainBroken) {
                Write-Host '   Сборка с cgo не удалась. Это окружение, а не код: детектор гонок пропущен.' -ForegroundColor Yellow
            }
            Add-Result 'static' 'go test -race' $verdict "компилятор: $cc"
        } else {
            Add-Result 'static' 'go test -race' 'SKIP' 'компилятор C не найден: нужен mingw-w64'
        }
    }

    Write-Host '-> сборка бинарника' -ForegroundColor Yellow
    $r = Invoke-Native -File 'go' -Arguments @('build', '-o', $exe, './cmd/evasion')
    if ($r.Text) { Write-Host $r.Text }
    if ($r.Code -ne 0) { throw "не удалось собрать bin\evasion.exe (код возврата $($r.Code))" }

    # -----------------------------------------------------------------------
    # Фаза 2. Проверки флагов — прокси не поднимается
    # -----------------------------------------------------------------------
    Write-Section 'Фаза 2: обработка неверных флагов'

    $cfgMain = Join-Path $binDir 'np.json'
    New-EvasionConfig -Path $cfgMain -Offset 5 -Groups $groups
    Copy-Item $cfgMain (Join-Path $reportDir 'config_used.json') -Force

    $flagCases = @(
        @{ Name = 'режим intercept отвергнут';      Args = @('run', '--mode', 'intercept') },
        @{ Name = 'неизвестная группа отвергнута';  Args = @('run', '--config', $cfgMain, '--groups', 'nosuchgroup') },
        @{ Name = 'неизвестная команда отвергнута'; Args = @('bogus') }
    )
    $flagLog = ''
    foreach ($c in $flagCases) {
        $r = Invoke-Native -File $exe -Arguments $c.Args
        # Ожидание: ненулевой код возврата. Нулевой означал бы, что движок
        # проглотил неверный ввод.
        $verdict = if ($r.Code -ne 0) { 'OK' } else { 'FAIL' }
        $flagLog += "### $($c.Name) (код возврата $($r.Code))$([Environment]::NewLine)$($r.Text)$([Environment]::NewLine)$([Environment]::NewLine)"
        Write-Host ("{0,-32} {1}  код={2}  {3}" -f $c.Name, $verdict, $r.Code, $r.Text) `
            -ForegroundColor $(if ($verdict -eq 'OK') { 'Green' } else { 'Red' })
        Add-Result 'flags' $c.Name $verdict
    }
    Save-Output 'flags.txt' $flagLog

    # -----------------------------------------------------------------------
    # Фаза 3. Базовая линия без прокси
    # -----------------------------------------------------------------------
    Write-Section 'Фаза 3: базовая линия (без evasion)'

    $baseTarget  = Invoke-Probe -Url $Target
    $baseControl = Invoke-Probe -Url $Control
    Write-Host ("цель     {0,-38} code={1} time={2}" -f $Target,  $baseTarget.Code,  $baseTarget.Time)
    Write-Host ("контроль {0,-38} code={1} time={2}" -f $Control, $baseControl.Code, $baseControl.Time)
    Add-Result 'baseline' 'цель без прокси'     $baseTarget.Code  "time=$($baseTarget.Time)"
    Add-Result 'baseline' 'контроль без прокси' $baseControl.Code "time=$($baseControl.Time)"

    # Если контрольная цель не работает и без прокси, дальше мерить нечего:
    # сеть сломана, и любые выводы о стратегиях будут мусором.
    if ($baseControl.Code -eq '000') {
        Write-Host 'Контрольная цель недоступна и без прокси: сеть неисправна, прогон прерван.' -ForegroundColor Red
        Add-Result 'baseline' 'пригодность прогона' 'ABORT' 'контроль недоступен без прокси'
        $aborted = $true
    }

    if (-not $aborted) {
        # -------------------------------------------------------------------
        # Фаза 4. Стратегия на контрольной цели — проверка собственного кода
        # -------------------------------------------------------------------
        #
        # Самая важная проверка во всём прогоне, и она должна идти первой.
        # Контрольная цель цензурой не затронута, поэтому применение к ней
        # стратегии отвечает на вопрос, который иначе остаётся неразрешимым:
        #
        #   контроль сломался  -> виноват наш код (или сегментация вредна сама
        #                         по себе), и все дальнейшие измерения — шум;
        #   контроль уцелел    -> нарезка исправна, и поломка цензурируемых
        #                         целей вызвана сетью, а не реализацией.
        #
        # Без этой развилки «цель недоступна при стратегии» нельзя истолковать.
        Write-Section 'Фаза 4: стратегия на контрольной цели (проверка собственного кода)'

        $controlHost = ([Uri]$Control).Host
        $cfgControl  = Join-Path $binDir 'np_control.json'
        New-EvasionConfig -Path $cfgControl -Offset 5 -Groups @{ control = @($controlHost) }

        $proc = Start-Evasion -ConfigPath $cfgControl -Tag 'control_strategy'
        $ctlProxied = Invoke-Probe -Url $Control -ThroughProxy
        Stop-Evasion $proc; $proc = $null

        $ctlLog     = Join-Path $reportDir 'control_strategy.log'
        $ctlApplied = Get-AppliedStrategy -LogPath $ctlLog -HostName $controlHost

        Write-Host ("  {0}: без прокси={1}, со стратегией={2}, применено: {3}" -f `
            $controlHost, $baseControl.Code, $ctlProxied.Code, $ctlApplied)
        Show-LogIssues -LogPath $ctlLog -Phase 'selfcheck' -Name $controlHost

        if ($ctlApplied -notmatch '^[0-9a-f]{32}$') {
            # Стратегия к контролю не применилась — проверка ничего не доказала.
            Write-Host '  Стратегия к контрольной цели не применилась: проверка недействительна.' -ForegroundColor Yellow
            Add-Result 'selfcheck' 'стратегия на контроле' 'НЕДЕЙСТВИТЕЛЬНА' "применено=$ctlApplied"
        } elseif ($ctlProxied.Code -eq '000' -and $baseControl.Code -ne '000') {
            Write-Host '  ВЫВОД: стратегия ломает цель, которая не цензурируется.' -ForegroundColor Red
            Write-Host '  Значит дело в реализации или в самой сегментации, а не в блокировке.' -ForegroundColor Red
            Write-Host '  Измерения по цензурируемым целям ниже истолковывать нельзя.' -ForegroundColor Red
            Add-Result 'selfcheck' 'стратегия на контроле' 'ЛОМАЕТ' `
                "без прокси=$($baseControl.Code), со стратегией=000 — виноват не DPI"
        } else {
            Write-Host '  ВЫВОД: нарезка не вредит нецензурируемой цели.' -ForegroundColor Green
            Add-Result 'selfcheck' 'стратегия на контроле' 'не вредит' `
                "без прокси=$($baseControl.Code), со стратегией=$($ctlProxied.Code)"
        }

        # -------------------------------------------------------------------
        # Фаза 5. Работоспособность сервисов
        # -------------------------------------------------------------------
        # Пустые элементы отбрасываем, а не просто считаем: @($null) даёт
        # массив из одного элемента, и подсчёт признал бы такой список непустым.
        $serviceList = @($Services | Where-Object { $_ })
        if (-not $SkipServices -and $serviceList.Count -gt 0) {
            Write-Section 'Фаза 5: работоспособность сервисов'
            Write-Host 'Доступностью считается любой код ответа HTTP; 000 означает отсутствие ответа.' -ForegroundColor DarkGray
            Write-Host 'Голос Discord и QUIC идут по UDP и через TCP-прокси не проходят — здесь не проверяются.' -ForegroundColor DarkGray

            # Проверяем только известные сервисы: опечатка в -Services не должна
            # молча сократить проверку.
            $checkList = @()
            foreach ($svc in $serviceList) {
                if (-not $serviceCatalog.Contains($svc)) {
                    throw "сервис '$svc' неизвестен. Доступны: $($serviceCatalog.Keys -join ', ')"
                }
                $checkList += $svc
            }

            # Проход 1: без прокси. Нужен как база сравнения — без него нельзя
            # отличить блокировку от того, что сервис лежит сам по себе.
            Write-Host ''
            Write-Host 'Проход 1 из 2: без прокси' -ForegroundColor Yellow
            $svcBaseline = @{}
            foreach ($svc in $checkList) {
                foreach ($ep in $serviceCatalog[$svc].Endpoints) {
                    $r = Invoke-Probe -Url $ep.Url -MaxTime $ServiceTimeoutSec
                    $svcBaseline[$ep.Url] = $r
                    Write-Host ("  {0,-9} {1,-44} code={2,-5} time={3}" -f $svc, $ep.Url, $r.Code, $r.Time) `
                        -ForegroundColor $(if ($r.Code -eq '000') { 'DarkGray' } else { 'Gray' })
                }
            }

            # Проход 2: через прокси со стратегией. Прокси поднимается один раз
            # на все адреса: перезапуск на каждый адрес лишь растянул бы прогон.
            Write-Host ''
            Write-Host 'Проход 2 из 2: через прокси со стратегией' -ForegroundColor Yellow
            $proc = Start-Evasion -ConfigPath $cfgMain -Tag 'services'
            $svcProxied = @{}
            foreach ($svc in $checkList) {
                foreach ($ep in $serviceCatalog[$svc].Endpoints) {
                    $svcProxied[$ep.Url] = Invoke-Probe -Url $ep.Url -ThroughProxy -MaxTime $ServiceTimeoutSec
                }
            }
            Stop-Evasion $proc; $proc = $null

            # Сводим вместе и показываем, что именно применялось к каждому
            # адресу: без этого «не работает» нельзя отличить от «стратегия не
            # применялась».
            $svcLog = Join-Path $reportDir 'services.log'
            Write-Host ''
            foreach ($svc in $checkList) {
                Write-Host "  $svc" -ForegroundColor Cyan
                $okBase = 0; $okProxy = 0; $total = 0
                foreach ($ep in $serviceCatalog[$svc].Endpoints) {
                    $total++
                    $b = $svcBaseline[$ep.Url]
                    $p = $svcProxied[$ep.Url]
                    if ($b.Code -ne '000') { $okBase++ }
                    if ($p.Code -ne '000') { $okProxy++ }

                    $epHost  = ([Uri]$ep.Url).Host
                    $applied = Get-AppliedStrategy -LogPath $svcLog -HostName $epHost

                    # Сравнение базы и прокси: именно оно отвечает, помогла
                    # стратегия, навредила или не изменила ничего.
                    $delta = switch ("$($b.Code -ne '000')/$($p.Code -ne '000')") {
                        'True/True'   { 'без изменений' }
                        'False/True'  { 'ПОМОГЛА' }
                        'True/False'  { 'НАВРЕДИЛА' }
                        'False/False' { 'блок в обоих случаях' }
                        default       { '?' }
                    }
                    $color = switch ($delta) {
                        'ПОМОГЛА'   { 'Green' }
                        'НАВРЕДИЛА' { 'Red' }
                        default     { 'Gray' }
                    }
                    Write-Host ("    {0,-44} база={1,-5} прокси={2,-5} {3,-22} применено: {4}" -f `
                        $epHost, $b.Code, $p.Code, $delta, $applied) -ForegroundColor $color

                    Add-Result "service:$svc" $epHost "база=$($b.Code) прокси=$($p.Code)" `
                        "$($ep.Note); $delta; применено=$applied"
                }
                $rollup = "без прокси $okBase/$total, через прокси $okProxy/$total"
                Write-Host ("    итог: {0}" -f $rollup) -ForegroundColor `
                    $(if ($okProxy -ge $okBase -and $okProxy -gt 0) { 'Green' } elseif ($okProxy -lt $okBase) { 'Red' } else { 'Yellow' })
                Add-Result "service:$svc" 'ИТОГ' "$okProxy/$total" $rollup
            }
        }

        # -------------------------------------------------------------------
        # Фаза 5. Матрица режимов
        # -------------------------------------------------------------------
        Write-Section 'Фаза 6: режимы прокси'

        # Прозрачный режим: стратегии нет вообще. Проверяет сам прокси отдельно
        # от обхода — если здесь сломается контроль, виноват прокси, а не
        # стратегия.
        $cfgNoStrategy = Join-Path $binDir 'np_nostrategy.json'
        New-EvasionConfig -Path $cfgNoStrategy -Offset $null -Groups $groups

        $modes = @(
            @{ Tag = 'passthrough'; Cfg = $cfgNoStrategy; Args = @();            Note = 'без стратегии' },
            @{ Tag = 'strategy';    Cfg = $cfgMain;       Args = @();            Note = 'стратегия offset=5' },
            @{ Tag = 'observe';     Cfg = $cfgMain;       Args = @('--observe'); Note = 'режим наблюдения' }
        )

        # Группу для проверки «цель вне радиуса» подбираем так, чтобы цель в неё
        # не входила. Жёстко заданная группа сломала бы проверку при смене цели:
        # с -Target https://discord.com/ цель оказалась бы внутри радиуса, и
        # ожидание «стратегия не применяется» стало бы неверным.
        $outGroup = $null
        foreach ($name in $serviceCatalog.Keys) {
            $contains = $false
            foreach ($d in $serviceCatalog[$name].Domains) {
                if ($targetHost -eq $d -or $targetHost.EndsWith(".$d")) { $contains = $true; break }
            }
            if (-not $contains) { $outGroup = $name; break }
        }
        if ($outGroup) {
            $modes += @{ Tag = 'groups'; Cfg = $cfgMain; Args = @('--groups', $outGroup)
                         Note = "радиус: $outGroup" }
        } else {
            Add-Result 'modes' 'цель вне радиуса' 'SKIP' 'цель входит во все группы каталога'
        }

        foreach ($m in $modes) {
            $proc = Start-Evasion -ConfigPath $m.Cfg -ExtraArgs $m.Args -Tag $m.Tag
            $t = Invoke-Probe -Url $Target  -ThroughProxy
            $c = Invoke-Probe -Url $Control -ThroughProxy
            Stop-Evasion $proc; $proc = $null

            # Из журнала вытаскиваем, какая стратегия фактически применилась к
            # ЦЕЛИ. Это защита от вывода «не работает» по стратегии, которая не
            # применялась.
            $applied = Get-AppliedStrategy -LogPath (Join-Path $reportDir "$($m.Tag).log") -HostName $targetHost

            Write-Host ("{0,-12} {1,-20} цель: code={2} time={3} | контроль: code={4} | применено: {5}" -f `
                $m.Tag, $m.Note, $t.Code, $t.Time, $c.Code, $applied)
            Add-Result 'modes' "$($m.Tag): цель"     $t.Code "time=$($t.Time); применено=$applied"
            Add-Result 'modes' "$($m.Tag): контроль" $c.Code ''
        }

        # -------------------------------------------------------------------
        # Фаза 7. Перебор смещений разреза
        # -------------------------------------------------------------------
        $best = $null
        $offsetList = @($Offsets | Where-Object { $null -ne $_ })
        if (-not $SkipOffsets -and $offsetList.Count -gt 0) {
            Write-Section 'Фаза 7: перебор смещений разреза'
            Write-Host 'Смещение абсолютное и зависит от соединения, поэтому это перебор, а не подбор.' -ForegroundColor DarkGray

            foreach ($off in $offsetList) {
                $cfgOff = Join-Path $binDir "np_off$off.json"
                New-EvasionConfig -Path $cfgOff -Offset $off -Groups $groups

                $proc = Start-Evasion -ConfigPath $cfgOff -Tag "offset_$off"
                $t = Invoke-Probe -Url $Target -ThroughProxy
                Stop-Evasion $proc; $proc = $null

                # Применённую стратегию печатаем на каждом смещении: без этого
                # нельзя отличить «разрез не помог» от «разрез не применился».
                $appliedOff = Get-AppliedStrategy -LogPath (Join-Path $reportDir "offset_$off.log") -HostName $targetHost
                $verdict = if ($t.Code -eq '000') { 'блок' } else { "ОТВЕТ $($t.Code)" }
                Write-Host ("offset={0,-5} code={1,-5} time={2,-9} {3,-12} применено: {4}" -f `
                    $off, $t.Code, $t.Time, $verdict, $appliedOff) `
                    -ForegroundColor $(if ($t.Code -eq '000') { 'DarkGray' } else { 'Green' })
                Add-Result 'offsets' "offset=$off" $t.Code "time=$($t.Time); применено=$appliedOff"

                if ($t.Code -ne '000' -and $null -eq $best) { $best = $off }
            }

            if ($null -ne $best) {
                Write-Host "Первое смещение с ответом: $best" -ForegroundColor Green
            } else {
                Write-Host 'Ни одно смещение не дало ответа.' -ForegroundColor Yellow
            }
        }

        # -------------------------------------------------------------------
        # Фаза 7б. Перебор структурных точек разреза
        # -------------------------------------------------------------------
        #
        # Главная проверка после числового перебора. Числовое смещение означает
        # для каждого соединения разное место, поэтому перебор чисел не
        # доказывал, что разрез вообще попадал внутрь имени сервера. Вид точки
        # устойчив, и «внутри имени» значит одно и то же всегда.
        $bestCut = $null
        $cutList = @($CutPoints | Where-Object { $_ })
        if (-not $SkipCuts -and $cutList.Count -gt 0) {
            Write-Section 'Фаза 7б: перебор структурных точек разреза'
            Write-Host 'Вид точки не зависит от соединения, поэтому это подбор, а не перебор наугад.' -ForegroundColor DarkGray

            foreach ($cp in $cutList) {
                $cfgCut = Join-Path $binDir ("np_cut_" + $cp + ".json")
                New-EvasionConfig -Path $cfgCut -At $cp -Groups $groups

                $proc = Start-Evasion -ConfigPath $cfgCut -Tag "cut_$cp"
                $t = Invoke-Probe -Url $Target -ThroughProxy
                Stop-Evasion $proc; $proc = $null

                $logCut = Join-Path $reportDir "cut_$cp.log"
                $appliedCut = Get-AppliedStrategy -LogPath $logCut -HostName $targetHost
                $verdict = if ($t.Code -eq '000') { 'блок' } else { "ОТВЕТ $($t.Code)" }
                Write-Host ("at={0,-18} code={1,-5} time={2,-9} {3,-12} применено: {4}" -f `
                    $cp, $t.Code, $t.Time, $verdict, $appliedCut) `
                    -ForegroundColor $(if ($t.Code -eq '000') { 'DarkGray' } else { 'Green' })
                # Предупреждения важны особенно здесь: недоступная точка разреза
                # даёт прозрачный пропуск, и без них «блок» нельзя отличить от
                # «стратегия не применилась».
                Show-LogIssues -LogPath $logCut -Phase 'cuts' -Name $cp
                Add-Result 'cuts' "at=$cp" $t.Code "time=$($t.Time); применено=$appliedCut"

                if ($t.Code -ne '000' -and $null -eq $bestCut) { $bestCut = $cp }
            }

            if ($null -ne $bestCut) {
                Write-Host "Первая точка разреза с ответом: $bestCut" -ForegroundColor Green
            } else {
                Write-Host 'Ни одна структурная точка не дала ответа.' -ForegroundColor Yellow
            }
        }

        # -------------------------------------------------------------------
        # Фаза 7в. Перебор паузы между частями
        # -------------------------------------------------------------------
        #
        # Последняя механика, выразимая в пользовательском пространстве. Разрез
        # сам по себе проверен и не помог: DPI пересобирает поток. Пауза
        # проверяет, ограничено ли окно пересборки по времени.
        #
        # Разрез берётся внутри имени сервера: если окно истечёт, собрать имя
        # целиком не удастся именно при таком разрезе.
        $bestDelay = $null
        $delayList = @($Delays | Where-Object { $_ -gt 0 })
        if (-not $SkipDelays -and $delayList.Count -gt 0) {
            Write-Section 'Фаза 7в: перебор паузы между частями'
            Write-Host 'Разрез внутри имени сервера, меняется только пауза.' -ForegroundColor DarkGray

            foreach ($ms in $delayList) {
                $cfgDelay = Join-Path $binDir ("np_delay_" + $ms + ".json")
                New-EvasionConfig -Path $cfgDelay -At 'inside_sni' -DelayMs $ms -Groups $groups

                $proc = Start-Evasion -ConfigPath $cfgDelay -Tag "delay_$ms"
                # Предел ожидания увеличиваем на величину паузы: иначе долгая
                # пауза сама привела бы к отказу по таймауту, и результат
                # означал бы не блокировку, а нашу собственную задержку.
                $t = Invoke-Probe -Url $Target -ThroughProxy -MaxTime ($TimeoutSec + [int][math]::Ceiling($ms / 1000.0) + 1)
                Stop-Evasion $proc; $proc = $null

                $logDelay = Join-Path $reportDir "delay_$ms.log"
                $appliedDelay = Get-AppliedStrategy -LogPath $logDelay -HostName $targetHost
                $verdict = if ($t.Code -eq '000') { 'блок' } else { "ОТВЕТ $($t.Code)" }
                Write-Host ("пауза={0,-6} code={1,-5} time={2,-9} {3,-12} применено: {4}" -f `
                    "${ms}мс", $t.Code, $t.Time, $verdict, $appliedDelay) `
                    -ForegroundColor $(if ($t.Code -eq '000') { 'DarkGray' } else { 'Green' })
                Show-LogIssues -LogPath $logDelay -Phase 'delays' -Name "${ms}мс"
                Add-Result 'delays' "пауза=${ms}мс" $t.Code "time=$($t.Time); применено=$appliedDelay"

                if ($t.Code -ne '000' -and $null -eq $bestDelay) { $bestDelay = $ms }
            }

            if ($null -ne $bestDelay) {
                Write-Host "Первая пауза с ответом: $bestDelay мс" -ForegroundColor Green
            } else {
                Write-Host 'Ни одна пауза не дала ответа.' -ForegroundColor Yellow
            }
        }

        # -------------------------------------------------------------------
        # Фаза 8. Дамп пакетов
        # -------------------------------------------------------------------
        if (-not $SkipCapture) {
            Write-Section 'Фаза 8: дамп пакетов'

            $hasTshark  = Test-Tool 'tshark'
            $hasPktmon  = Test-Tool 'pktmon'
            $pcap       = Join-Path $reportDir 'clienthello.pcapng'
            $etl        = Join-Path $reportDir 'clienthello.etl'
            # Что снимать дампом: удачную находку, иначе разрез внутри имени
            # сервера — именно он проверяется в первую очередь.
            $captureAt  = ''
            $captureOff = $null
            if ($null -ne $best)         { $captureOff = $best }
            elseif ($null -ne $bestCut)  { $captureAt  = $bestCut }
            else                         { $captureAt  = 'inside_sni' }

            if ($hasTshark -and $Iface) { $capturer = 'tshark' }
            elseif ($hasPktmon -and $isAdmin) { $capturer = 'pktmon' }

            if ($capturer -eq 'none') {
                $why = if (-not $isAdmin) { 'нет прав администратора' } else { 'нет tshark (-Iface) и pktmon' }
                Write-Host "Дамп пропущен: $why" -ForegroundColor Yellow
                Add-Result 'capture' 'дамп' 'SKIP' $why
            } else {
                $capPlace = if ($captureAt) { "точка $captureAt" } else { "смещение $captureOff" }
                Write-Host "Снимаю дамп через $capturer, $capPlace" -ForegroundColor Yellow
                $cfgCap = Join-Path $binDir 'np_capture.json'
                New-EvasionConfig -Path $cfgCap -Offset $captureOff -At $captureAt -Groups $groups

                $capProc = $null
                if ($capturer -eq 'tshark') {
                    $capProc = Start-Process -FilePath 'tshark' `
                        -ArgumentList @('-i', $Iface, '-f', 'tcp port 443', '-w', $pcap) `
                        -PassThru -WindowStyle Hidden
                    Start-Sleep -Seconds 2
                } else {
                    # pktmon встроен в Windows, драйвер ставить не нужно. Фильтр
                    # сужаем до 443, иначе в дамп попадёт весь трафик машины.
                    Invoke-Native -File 'pktmon' -Arguments @('filter', 'remove') | Out-Null
                    Invoke-Native -File 'pktmon' -Arguments @('filter', 'add', 'evasion443', '-p', '443', '-t', 'TCP') | Out-Null
                    Invoke-Native -File 'pktmon' -Arguments @('start', '--capture', '--pkt-size', '0', '-f', $etl) | Out-Null
                }
                $captureStarted = $true

                $proc = Start-Evasion -ConfigPath $cfgCap -Tag 'capture'
                $capProbe = Invoke-Probe -Url $Target -ThroughProxy
                Stop-Evasion $proc; $proc = $null

                Start-Sleep -Seconds 1
                if ($capturer -eq 'tshark') {
                    try { Stop-Process -Id $capProc.Id -Force -ErrorAction SilentlyContinue } catch {}
                } else {
                    Invoke-Native -File 'pktmon' -Arguments @('stop') | Out-Null
                    Invoke-Native -File 'pktmon' -Arguments @('filter', 'remove') | Out-Null
                    # Имя подкоманды преобразования различается между сборками
                    # Windows, поэтому пробуем оба варианта.
                    Invoke-Native -File 'pktmon' -Arguments @('pcapng', $etl, '-o', $pcap) | Out-Null
                    if (-not (Test-Path $pcap)) {
                        Invoke-Native -File 'pktmon' -Arguments @('etl2pcap', $etl, '-o', $pcap) | Out-Null
                    }
                }
                $captureStarted = $false

                Add-Result 'capture' 'дамп снят' $capturer "$capPlace; code=$($capProbe.Code)"

                # Разбор дампа: сколько пакетов с данными ушло в начале
                # соединения. Пересборку потока отключаем — иначе tshark склеит
                # сегменты и покажет один ClientHello там, где их было два.
                if ((Test-Path $pcap) -and $hasTshark) {
                    Write-Host 'Исходящие пакеты с данными на порт 443 (без пересборки потока):'
                    $segs = Invoke-Native -File 'tshark' -Arguments @(
                        '-r', $pcap, '-o', 'tcp.desegment_tcp_streams:FALSE',
                        '-Y', 'tcp.dstport==443 && tcp.len>0',
                        '-T', 'fields', '-e', 'frame.number', '-e', 'ip.dst', '-e', 'tcp.seq', '-e', 'tcp.len')
                    Write-Host $segs.Text
                    Save-Output 'capture_segments.txt' $segs.Text

                    $hello = Invoke-Native -File 'tshark' -Arguments @(
                        '-r', $pcap, '-o', 'tcp.desegment_tcp_streams:FALSE',
                        '-Y', 'tls.handshake.type==1',
                        '-T', 'fields', '-e', 'frame.number', '-e', 'tcp.len',
                        '-e', 'tls.handshake.extensions_server_name')
                    Save-Output 'capture_clienthello.txt' $hello.Text

                    # Ключевой вывод: два пакета с данными в начале потока
                    # означают, что сегментация реально произошла. Один —
                    # что ОС склеила записи и стратегия не применилась физически.
                    $dataPkts = @($segs.Text -split "`r?`n" | Where-Object { $_ -match '\S' }).Count
                    $segVerdict = switch ($dataPkts) {
                        0       { 'пакетов с данными нет: дамп снят не с того интерфейса' }
                        1       { 'ОДИН сегмент: записи склеены, сегментация не применилась' }
                        default { "сегментов с данными: $dataPkts, разрез, судя по дампу, произошёл" }
                    }
                    Write-Host "Вывод: $segVerdict" -ForegroundColor Magenta
                    Add-Result 'capture' 'сегментация ClientHello' $segVerdict
                } elseif ($capturer -eq 'pktmon' -and (Test-Path $etl)) {
                    # Разбор без Wireshark: pktmon переводит свой дамп в текст,
                    # а Measure-PktmonSegments извлекает из него длины
                    # исходящих пакетов с данными. Этого достаточно для ответа
                    # о числе сегментов, поэтому сторонние программы не нужны.
                    $txt   = Join-Path $reportDir 'capture_pktmon.txt'
                    $stats = Join-Path $reportDir 'capture_pktmon_stats.txt'

                    # Имя подкоманды и флага вывода различаются между сборками
                    # Windows (etl2txt против format, --out против -o), поэтому
                    # перебираем варианты, пока не появится файл.
                    $variants = @(
                        @('etl2txt', $etl, '--out', $txt),
                        @('etl2txt', $etl, '-o',    $txt),
                        @('format',  $etl, '--out', $txt),
                        @('format',  $etl, '-o',    $txt)
                    )
                    foreach ($v in $variants) {
                        $res = Invoke-Native -File 'pktmon' -Arguments $v
                        if (Test-Path $txt) { break }
                        Save-Output 'capture_pktmon_error.txt' $res.Text
                    }
                    # Сводка по дампу: короткая и полезна сама по себе.
                    Invoke-Native -File 'pktmon' -Arguments @('etl2txt', $etl, '--stats-only', '--out', $stats) | Out-Null

                    if (Test-Path $txt) {
                        # Адреса цели нужны, чтобы отделить её соединения от
                        # остального трафика машины на порт 443: фильтр дампа
                        # по порту пропускает всё подряд.
                        $targetIPs = @()
                        try {
                            $targetIPs = @([Net.Dns]::GetHostAddresses($targetHost) |
                                Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                                ForEach-Object { $_.IPAddressToString })
                        } catch {}

                        $streams = Measure-PktmonSegments -TextPath $txt
                        Write-Host ("Исходящих соединений с данными на порт 443: {0}" -f $streams.Keys.Count)

                        $targetStreams = @()
                        foreach ($k in $streams.Keys) {
                            $isTarget = $false
                            foreach ($ip in $targetIPs) { if ($k.StartsWith($ip)) { $isTarget = $true; break } }
                            $lens = $streams[$k] -join ', '
                            if ($isTarget) {
                                Write-Host ("  ЦЕЛЬ {0}: длины пакетов {1}" -f $k, $lens) -ForegroundColor Cyan
                                $targetStreams += ,@($streams[$k])
                            } else {
                                Write-Host ("       {0}: длины пакетов {1}" -f $k, $lens) -ForegroundColor DarkGray
                            }
                        }

                        # Главный вывод прогона. Первый пакет с данными, равный
                        # заданному смещению, доказывает, что разрез дошёл до
                        # сети. Пакет размером во весь ClientHello доказывает
                        # обратное: записи склеены операционной системой.
                        # При числовом смещении ожидаемая длина первого пакета
                        # известна и проверяется точно. При структурной точке она
                        # зависит от соединения, поэтому судим по числу пакетов с
                        # данными: два и более означают, что разрез состоялся.
                        $segVerdict = 'соединений с целью в дампе нет'
                        if ($targetStreams.Count -gt 0) {
                            $first = @($targetStreams[0])
                            $tail  = if ($first.Count -ge 2) { $first[1..($first.Count - 1)] -join ', ' } else { '' }
                            if ($first.Count -eq 1) {
                                $segVerdict = "СКЛЕЙКА: один пакет $($first[0]) байт, разрез не состоялся ($capPlace)"
                            } elseif ($captureAt) {
                                $segVerdict = "РАЗРЕЗ ДОШЁЛ ДО СЕТИ: пакеты $($first -join ', ') при точке $captureAt"
                            } elseif ($first[0] -eq $captureOff) {
                                $segVerdict = "РАЗРЕЗ ДОШЁЛ ДО СЕТИ: первый пакет $($first[0]) байт = смещение $captureOff, далее $tail"
                            } else {
                                $segVerdict = "неоднозначно: длины $($first -join ', ') при смещении $captureOff"
                            }
                        }
                        Write-Host ''
                        Write-Host "ВЫВОД О СЕГМЕНТАЦИИ: $segVerdict" -ForegroundColor Magenta
                        Add-Result 'capture' 'сегментация ClientHello' $segVerdict

                        $report = foreach ($k in $streams.Keys) { "$k : $($streams[$k] -join ', ')" }
                        Save-Output 'capture_segments.txt' (($report -join [Environment]::NewLine))
                        Write-Host 'Полный текст: capture_pktmon.txt, разбор: capture_segments.txt' -ForegroundColor DarkGray
                    } else {
                        Add-Result 'capture' 'разбор дампа' 'SKIP' 'pktmon не дал текстового дампа'
                    }
                } elseif (Test-Path $pcap) {
                    Write-Host "Дамп сохранён: $pcap (tshark не найден, разбор не сделан)" -ForegroundColor Yellow
                    Add-Result 'capture' 'разбор дампа' 'SKIP' 'нет tshark'
                } else {
                    Write-Host 'Файл дампа не создан.' -ForegroundColor Red
                    Add-Result 'capture' 'разбор дампа' 'FAIL' 'файл дампа отсутствует'
                }
            }
        }
    }
}
catch {
    Write-Host ''
    Write-Host "ПРОГОН ПРЕРВАН: $($_.Exception.Message)" -ForegroundColor Red
    Add-Result 'script' 'прогон' 'FAIL' $_.Exception.Message
}
finally {
    # Прокси и фильтры pktmon не должны оставаться после сбоя скрипта:
    # остаточные правила — это ровно то, чего задание требует избегать (3.3).
    Stop-Evasion $proc
    if ($captureStarted -and $capturer -eq 'pktmon') {
        Invoke-Native -File 'pktmon' -Arguments @('stop')             | Out-Null
        Invoke-Native -File 'pktmon' -Arguments @('filter', 'remove') | Out-Null
    }
}

# ---------------------------------------------------------------------------
# Сводка
# ---------------------------------------------------------------------------
Write-Section 'Сводка'
$table = $summary | Format-Table -AutoSize | Out-String -Width 200
Write-Host $table

$table | Out-File (Join-Path $reportDir 'summary.txt') -Encoding utf8
$summary | ConvertTo-Json -Depth 4 | Out-File (Join-Path $reportDir 'summary.json') -Encoding utf8

Write-Host "Отчёт целиком: $reportDir" -ForegroundColor Green
Write-Host 'Прислать можно всю папку либо summary.txt вместе с разбором дампа.' -ForegroundColor DarkGray

# Возвращаем кодировку консоли: скрипт не должен менять настройки сеанса, из
# которого его запустили.
try { [Console]::OutputEncoding = $prevConsoleEncoding } catch {}

# Ненулевой код возврата при провале — чтобы прогон можно было встроить в CI и
# не разбирать вывод глазами. Заблокированная цель провалом не считается: это
# измерение, а не поломка.
if (@($summary | Where-Object { $_.Result -eq 'FAIL' }).Count -gt 0) { exit 1 }
exit 0
