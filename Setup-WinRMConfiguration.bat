@echo off
setlocal

pushd "%~dp0"

openfiles > nul
if errorlevel 1 echo 管理者として実行してください！ & pause & exit 1

rem ファイルの存在確認
if not exist .\Setup-WinRMConfiguration.ps1 (
    echo 「Setup-WinRMConfiguration.ps1」がありません。
    echo 「setup.bat」を「Setup-WinRMConfiguration.ps1」と同じフォルダに配置してください。
    pause
    exit 1
)

SET /P ANSWER="WinRM接続のための設定を開始します。よろしいですか (y/n)？"
if /i {%ANSWER%}=={y} (goto :yes)
if /i {%ANSWER%}=={Y} (goto :yes)
if /i {%ANSWER%}=={yes} (goto :yes)
echo 「n」が選択されたのでセットアップを終了します。
pause
exit 0

:yes

echo アカウント名を入力してください。
echo アカウント名は「コンピュータ名\アカウント名」または「ドメイン名\アカウント名」で指定できます。
set /p account=">"
echo. > .\Setup-WinRMConfiguration.ps1:Zone.Identifier
powershell -ExecutionPolicy RemoteSigned -File .\Setup-WinRMConfiguration.ps1 %account%

if not %errorlevel% equ 0 (
    echo WinRM接続の設定に失敗しました。セットアップを終了します。
    pause
    exit 1
)

echo WinRM接続の設定が完了しました。セットアップを終了します。
popd

pause

exit 0