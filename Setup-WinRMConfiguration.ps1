Param (
    [parameter(Mandatory = $true)][string] $account
)

$rootSddlPath = "WSMan:\localhost\Service\RootSDDL"          # RootSDDLパス
$namespaces   = @("root/cimv2", "root/standardcimv2" )       # WMIリソースを指定
$permissions  = @("Enable", "MethodExecute", "RemoteAccess") # 許可する権限を指定

function Get-AccessMaskFromPermission($permissions) {
    $WBEM_ENABLE = 1
    $WBEM_METHOD_EXECUTE = 2
    $WBEM_FULL_WRITE_REP = 4
    $WBEM_PARTIAL_WRITE_REP = 8
    $WBEM_WRITE_PROVIDER = 0x10
    $WBEM_REMOTE_ACCESS = 0x20
    $WBEM_RIGHT_SUBSCRIBE = 0x40
    $WBEM_RIGHT_PUBLISH = 0x80
    $READ_CONTROL = 0x20000
    $WRITE_DAC = 0x40000

    $WBEM_RIGHTS_FLAGS = $WBEM_ENABLE, $WBEM_METHOD_EXECUTE, $WBEM_FULL_WRITE_REP, $WBEM_PARTIAL_WRITE_REP, $WBEM_WRITE_PROVIDER, $WBEM_REMOTE_ACCESS, $READ_CONTROL, $WRITE_DAC
    $WBEM_RIGHTS_STRINGS = 'Enable', 'MethodExecute', 'FullWrite', 'PartialWrite', 'ProviderWrite', 'RemoteAccess', 'ReadSecurity', 'WriteSecurity'

    $permissionTable = @{}

    for ($i = 0; $i -lt $WBEM_RIGHTS_FLAGS.Length; $i++) {
        $permissionTable.Add($WBEM_RIGHTS_STRINGS[$i].ToLower(), $WBEM_RIGHTS_FLAGS[$i])
    }
    $accessMask = 0

    foreach ($permission in $permissions) {
        if (-not $permissionTable.ContainsKey($permission.ToLower())) {
            throw "Unknown permission: $permission`nValid permissions: $($permissionTable.Keys)"
        }
        $accessMask += $permissionTable[$permission.ToLower()]
    }
    return $accessMask
}

function Set-WmiNamespaceSecurity {
    Param (
        [parameter(Mandatory = $true)][string] $sid,
        [parameter(Mandatory = $true)][string] $namespace,
        [string[]] $permissions = $null
    )

    try {
        $output = Invoke-WmiMethod -Name GetSecurityDescriptor -Namespace $namespace -Path '__systemsecurity=@'
    } catch {
        return $false
    }
    if ($output.ReturnValue -ne 0) {
        throw "failed GetSecurityDescriptor"
    }

    $acl = $output.Descriptor

    $accessMask = Get-AccessMaskFromPermission($permissions)
    Write-Verbose "accessMask:$accessMask"

    $ace = (New-Object System.Management.ManagementClass('win32_Ace')).CreateInstance()
    $ace.AccessMask = $accessMask
    $ace.AceFlags = 0

    $trustee = (New-Object System.Management.ManagementClass('win32_Trustee')).CreateInstance()
    $trustee.SidString = $sid
    $ace.Trustee = $trustee

    $ace.AceType = 0

    $acl.DACL += $ace.psobject.immediateBaseObject

    $output = Invoke-WmiMethod -Name SetSecurityDescriptor -Namespace $namespace -Path '__systemsecurity=@' -ArgumentList $acl.psobject.immediateBaseObject
    if ($output.ReturnValue -ne 0) {
        throw "failed SetSecurityDescriptor"
    }

    return $true
}

function Invoke-QuickConfig {
    sc.exe start WinRM
    sc.exe config WinRM start= delayed-auto
    winrm create winrm/config/listener?Address=*+Transport=HTTP
    netsh firewall add portopening TCP 5985 "Windows Remote Management"
}

function main($account) {
    $ErrorActionPreference = "Stop"

    # Get user SID
    try {
        $sid = (New-Object System.Security.Principal.NTAccount($account)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        Write-Error "ERROR: 指定されたアカウント名が見つからないか、SIDに変換できませんでした"
    }

    # Set ExecutionPolicy
    try {
        Set-ExecutionPolicy RemoteSigned
    }
    catch {
        Write-Error "ERROR: ExecutionPolicyをRemoteSignedに変更できませんでした"
    }

    # Enable WinRM
    try {
        # winrm qc -quiet
        Invoke-QuickConfig
        if ($LASTEXITCODE -ne 0) { throw }

        winrm set winrm/config/service/auth '@{Basic="true"}'
        if ($LASTEXITCODE -ne 0) { throw }

        winrm set winrm/config/service '@{AllowUnencrypted="true"}'
        if ($LASTEXITCODE -ne 0) { throw }
    }
    catch {
        Write-Error "ERROR: WinRMの有効化でエラー発生しました[ $($_) ]"
    }
    Write-Output "WinRMサービスを有効化しました"

    # Set RootSDDL Security
    try {
        # Get existing SDDL
        $existingSDDL = (Get-Item -Path $rootSddlPath).Value
        $SecurityDescriptor = New-Object -TypeName Security.AccessControl.CommonSecurityDescriptor -ArgumentList $false, $false, $existingSDDL

        # Add the new SID
        $accessType = "Allow"
        $accessMask = -1610612736 # GXGR権限(読み取り,実行)
        $inheritanceFlags = "none"
        $propagationFlags = "none"
        $SecurityDescriptor.DiscretionaryAcl.AddAccess($accessType, $sid, $accessMask, $inheritanceFlags, $propagationFlags)

        # Combined SDDL
        $newSDDL = $SecurityDescriptor.GetSddlForm("All")

        Set-Item -Path $rootSddlPath -Value $newSDDL -Confirm:$false -Verbose:$false -Force
    }
    catch {
        Write-Error "ERROR: WinRM RootSDDLセキュリティ設定の更新処理中にエラーが発生しました[ $($_) ]"
    }
    Write-Output "WinRM RootSDDLセキュリティ設定を更新しました"

    # Set WMI Security
    try {
        foreach ($namespace in $namespaces) {
            $result = Set-WmiNamespaceSecurity -sid $sid -namespace $namespace -permissions $permissions
            if ($result) {
                Write-Verbose "$namespace security setting succeeded"
            } else {
                Write-Verbose "$namespace security setting skipped"
            }
        }
    }
    catch {
        Write-Error "ERROR: WMIセキュリティ設定の更新処理中にエラーが発生しました[ $($_) ]"
    }
    Write-Output "WMIセキュリティ設定を更新しました"
}

main($account)
