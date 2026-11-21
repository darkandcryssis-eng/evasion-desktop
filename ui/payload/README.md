# payload/

Файлы, которые встраиваются в `Evasion.exe` через `go:embed`. Наполняет
каталог скрипт `ui\build-and-run.bat`; в git лежит только этот README.

| Файл | Откуда |
|---|---|
| `evasion.exe` | `go build ./cmd/evasion` из корня репозитория |
| `config.json` | копия `examples/config.json` |
| `WinDivert.dll`, `WinDivert64.sys` | из корня репозитория, если лежат там; иначе официальный релиз WinDivert 2.2.2 (проверка SHA-256) |
| `WinDivert-LICENSE.txt` | `LICENSE` из того же релиза WinDivert (LGPLv3) |

При запуске оболочка распаковывает их в `runtime\` рядом с `Evasion.exe`.
`evasion.exe` и `config.json` обновляются при каждой новой версии оболочки.
WinDivert пишется только если файлов ещё нет, поэтому их можно заменить своей
сборкой.
