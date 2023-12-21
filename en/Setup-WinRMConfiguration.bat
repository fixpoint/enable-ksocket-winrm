@echo off
setlocal

pushd "%~dp0"

openfiles > nul
if errorlevel 1 echo Execute as administrator. & pause & exit 1

rem Check files exist
if not exist .\Setup-WinRMConfiguration.ps1 (
    echo `Setup-WinRMConfiguration.ps1` does not exist.
    echo Place `setup.bat` in the same folder as `Setup-WinRMConfiguration.ps1`.
    pause
    exit 1
)

SET /P ANSWER="This script sets up for WinRM connection. Are you sure (y/n)?"
if /i {%ANSWER%}=={y} (goto :yes)
if /i {%ANSWER%}=={Y} (goto :yes)
if /i {%ANSWER%}=={yes} (goto :yes)
echo 'n' selected. Aborting.
pause
exit 0

:yes

echo Enter account name.
echo Account name is of the form `copmuterName\accountName` or `domainName\accountName`.
set /p account=">"
echo. > .\Setup-WinRMConfiguration.ps1:Zone.Identifier
powershell -ExecutionPolicy RemoteSigned -File .\Setup-WinRMConfiguration.ps1 %account%

if not %errorlevel% equ 0 (
    echo Failed to configure for WinRM connection. Aborting.
    pause
    exit 1
)

echo Succeeded to set up for WinRM connection.
popd

pause

exit 0
