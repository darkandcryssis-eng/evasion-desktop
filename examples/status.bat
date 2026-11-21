@echo off
rem Состояние работающего движка. Запускать во ВТОРОМ окне, пока идёт
rem autopilot.bat (можно без прав администратора — читает файл состояния).
rem
rem   examples\status.bat            человекочитаемо
rem   examples\status.bat --json     машинно-читаемо
setlocal
pushd "%~dp0.."
evasion.exe status %*
popd
endlocal
