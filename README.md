# enable-ksocket-winrm

ksocket からの WinRM アクセスを有効にするためのスクリプトです。  
本リポジトリのスクリプトを Windows 上で実行することで、構成情報の取得ができるようになります。

## 使い方

Setup-WinRMConfiguration.ps1 をダウンロードし、WinRM によるアクセスを許可したい Windows 上に配置してください。  
スクリプトを `$env:USERPROFILE\Downloads` にダウンロードしたと仮定し、以下に示すコマンドを PowerShell で実行してください。

    (PowerShell 管理者権限)
    # Setup-WinRMConfiguration.ps1 を配置したフォルダに移動する
    > cd ~\Downloads

    # ダウンロードしたスクリプトのため、実行のブロックを解除する
    > Unblock-File .\Setup-WinRMConfiguration.ps1

    # WinRMを有効化するアカウントを引数とし、スクリプトを実行する
    # ローカルアカウント/ドメインアカウントに関わらず、コンピュータ名を忘れないようにしてください
    > .\Setup-WinRMConfiguration.ps1 $env:COMPUTERNAME\YourAccountName

前提として、ネットワークプロファイルは Private または DomainAutheticated である必要があります。  
ネットワークプロファイルが Public である場合、スクリプト実行以前に以下のコマンドを管理者権限の PowerShell で実行してください。

    Set-NetConnectionProfile -NetworkCategory Private

