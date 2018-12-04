# enable-ksocket-winrm

ksocket からの WinRM アクセスを有効にするためのスクリプトです。  
本リポジトリのスクリプトを Windows 上で実行することで、構成情報の取得ができるようになります。

## ファイルのダウンロード

[Releasesページ](https://github.com/fixpoint/enable-ksocket-winrm/releases) より最新のファイルをダウンロードし、ksocketからのWinRMアクセスを有効にしたいWindowsに配置してください。


## スクリプトの実行

`Setup-WinRMConfiguration.bat` を管理者権限で実行してください。

実行するとコンソールが開き、アカウント名の入力を求めます。  
コンピュータに登録されたアカウント名を入力してください。

```
WinRM接続のための設定を開始します。よろしいですか (y/n)？y
アカウント名を入力してください。
アカウント名は「コンピュータ名\アカウント名」または「ドメイン名\アカウント名」で指定できます。
>
```

アカウント名を入力すると、そのアカウントでのWinRMアクセスに必要な設定が自動で行われます。

```
WinRM サービスは、既にこのコンピューターで実行されています。
このコンピューター上でのリモート管理には、WinRM が既に設定されています。
Auth
    Basic = true
    Kerberos = true
    Negotiate = true
    Certificate = false
    CredSSP = false
    CbtHardeningLevel = Relaxed

Service
    RootSDDL = O:NSG:BAD:P(A;;GR;;;IU)(A;;GA;;;BA)(A;;GXGR;;;S-1-5-21-1561492669-3598970178-1692085620-1001)(A;;GXGR;;;S-1-5-21-1561492669-3598970178-1692085620-1002)S:P(AU;FA;GA;;;WD)(AU;SA;GXGW;;;WD)
    MaxConcurrentOperations = 4294967295
    MaxConcurrentOperationsPerUser = 1500
    EnumerationTimeoutms = 240000
    MaxConnections = 300
    MaxPacketRetrievalTimeSeconds = 120
    AllowUnencrypted = true
    Auth
        Basic = true
        Kerberos = true
        Negotiate = true
        Certificate = false
        CredSSP = false
        CbtHardeningLevel = Relaxed
    DefaultPorts
        HTTP = 5985
        HTTPS = 5986
    IPv4Filter = *
    IPv6Filter = *
    EnableCompatibilityHttpListener = false
    EnableCompatibilityHttpsListener = false
    CertificateThumbprint
    AllowRemoteAccess = true

WinRMサービスを有効化しました
WinRM RootSDDLセキュリティ設定を更新しました
WMIセキュリティ設定を更新しました
WinRM接続の設定が完了しました。セットアップを終了します。
続行するには何かキーを押してください . . .
```

上記のようなメッセージが出力された場合、設定は完了となります。  
ksocketにWinRMのアカウント設定を行い、スキャンをしてみましょう。


## トラブルシューティング

### ネットワーク接続の種類が Public になっている

Windowsには、接続するネットワークごとにネットワークの種類、「Public」「Private」「DomainAuthenticated」のいずれかを選択する機能があります。  
ネットワークが「Public」に設定されている場合、外部からのアクセスを行うことができず、設定スクリプトは以下のようにエラーを出力して終了します。

```
WinRM サービスは、既にこのコンピューターで実行されています。
WSManFault
    Message
        ProviderFault
            WSManFault
                Message = このコンピューターのネットワーク接続の種類の 1 つが Public に設定されているため、WinRM ファイアウォール例外は機能しません。 ネットワーク接続の種類を Domain または Private に変更して、やり直してください。

エラー番号:  -2144108183 0x80338169
このコンピューターのネットワーク接続の種類の 1 つが Public に設定されているため、WinRM ファイアウォール例外は機能しません。 ネットワーク接続の種類を Domain または Private に変更して、やり直してください。
main : ERROR: WinRMの有効化でエラー発生しました[ ScriptHalted ]
発生場所 C:\Users\kompira\Downloads\enable-ksocket-winrm-1.0.0\enable-ksocket-winrm-1.0.0\Setup-WinRMConfiguration.ps1:156
文字:1
+ main($account)
+ ~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorException
    + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorException,main

WinRM接続の設定に失敗しました。セットアップを終了します。
続行するには何かキーを押してください . . .
```

この場合、ネットワーク接続の種類を「Private」か「DomainAuthenticated」に変更する必要があります。  
PowerShellを管理者権限で起動し、以下のコマンドを実行することで、ネットワーク接続の種類を Private に変更することができます。

```
> Set-NetConnectionProfile -NetworkCategory Private
```
