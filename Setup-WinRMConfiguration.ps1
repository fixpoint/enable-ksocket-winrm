Param (
    [parameter(Mandatory = $true)][string] $account
)

$rootSddlPath = "WSMan:\localhost\Service\RootSDDL"          # RootSDDLパス
$namespaces   = @("root/cimv2", "root/standardcimv2" )       # WMIリソースを指定
$permissions  = @("Enable", "MethodExecute", "RemoteAccess") # 許可する権限を指定

function Enable-Privilege {
# https://stackoverflow.com/questions/45013591/set-registry-key-owner-to-system-user
 param(
  ## The privilege to adjust. This set is taken from
  ## http://msdn.microsoft.com/en-us/library/bb530716(VS.85).aspx
  [ValidateSet(
   "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
   "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",
   "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
   "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
   "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege",
   "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",
   "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege",
   "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege",
   "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
   "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
   "SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
  $Privilege,
  ## The process on which to adjust the privilege. Defaults to the current process.
  $ProcessId = $pid,
  ## Switch to disable the privilege, rather than enable it.
  [Switch] $Disable
 )

 ## Taken from P/Invoke.NET with minor adjustments.
 $definition = @'
 using System;
 using System.Runtime.InteropServices;
  
 public class AdjPriv
 {
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
   ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
  
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
  [DllImport("advapi32.dll", SetLastError = true)]
  internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  internal struct TokPriv1Luid
  {
   public int Count;
   public long Luid;
   public int Attr;
  }
  
  internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
  internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
  internal const int TOKEN_QUERY = 0x00000008;
  internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
  public static bool EnablePrivilege(long processHandle, string privilege, bool disable)
  {
   bool retVal;
   TokPriv1Luid tp;
   IntPtr hproc = new IntPtr(processHandle);
   IntPtr htok = IntPtr.Zero;
   retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
   tp.Count = 1;
   tp.Luid = 0;
   if(disable)
   {
    tp.Attr = SE_PRIVILEGE_DISABLED;
   }
   else
   {
    tp.Attr = SE_PRIVILEGE_ENABLED;
   }
   retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
   retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
   return retVal;
  }
 }
'@

 $processHandle = (Get-Process -id $ProcessId).Handle
 $type = Add-Type $definition -PassThru
 $type[0]::EnablePrivilege($processHandle, $Privilege, $Disable)
}

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
    } catch [System.Management.ManagementException] {
        if ($PSItem.ToString().Contains("予期せぬエラーです") -or $PSItem.Exception.StackTrace.Contains("ThrowWithExtendedInfo(ManagementStatus errorCode)")) {
            throw "WMIセキュリティ識別子の読み取りで予期せぬエラーが発生しました。" +
                  "無効なユーザー(削除済みユーザー等)設定が存在している可能性があるため、削除してから再度スクリプトを実行してください。"
        } else {
            return $false
        }
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

function Set-ComponentService{
    Param (
        [parameter(Mandatory = $true)][string] $sid
    )
    # Add PSDrive
    $hkcr = Get-PSDrive -PSProvider Registry | Where-Object {$_.ROOT -eq "HKEY_CLASSES_ROOT"}
    if($hkcr -eq $null){
        New-PSDrive -PSProvider Registry -Name HKCR -Root HKEY_CLASSES_ROOT
        $hkcr = Get-PSDrive -PSProvider Registry | Where-Object {$_.ROOT -eq "HKEY_CLASSES_ROOT"}
    }

    $appId_path = $hkcr.Name + ":AppID\"

    $ti_obj = Get-ChildItem $appId_path | Get-ItemProperty | Where-Object {$_."(default)" -eq "Trusted Installer Service"}

    $ti_path = Join-Path $appId_path $ti_obj.PSChildName

    $reg_key_name = "AppID\"+ $ti_obj.PSChildName

    Enable-Privilege SeTakeOwnershipPrivilege 

    # Change Owner to the local Administrators group
    $regKey = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey($reg_key_name,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::TakeOwnership)
    $regACL = $regKey.GetAccessControl()
    $regACL.SetOwner([System.Security.Principal.NTAccount]"Administrators")
    $regKey.SetAccessControl($regACL)
    # Change Permissions for the local Administrators group
    $regKey = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey($reg_key_name,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::ChangePermissions)
    $regACL = $regKey.GetAccessControl()
    $regRule = New-Object System.Security.AccessControl.RegistryAccessRule ("Administrators","FullControl","ContainerInherit","None","Allow")
    $regACL.SetAccessRule($regRule)
    $regKey.SetAccessControl($regACL)

    $dcom_app = Get-WMIobject Win32_DCOMApplicationSetting -enableallprivileges |Where-Object {$_.AppID -eq $ti_obj.PSChildName} 

    $trustee = ([wmiclass] 'Win32_Trustee').CreateInstance()
    $trustee.SIDString = $sid
    $ace = ([wmiclass] 'Win32_ACE').CreateInstance()
    $ace.AceFlags = 0
    $ace.AceType = 0
    $ace.Trustee = $trustee
    $ace.AccessMask = 31 

    $sdRes = $dcom_app.GetLaunchSecurityDescriptor()
    $sd = $sdRes.Descriptor
    [System.Management.ManagementBaseObject[]] $newDACL = $sd.DACL + @($ace)
    $sd.DACL = $newDACL
    $dcom_app.SetLaunchSecurityDescriptor($sd)

    $sdRes = $dcom_app.GetAccessSecurityDescriptor()
    $sd = $sdRes.Descriptor
    [System.Management.ManagementBaseObject[]] $newDACL = $sd.DACL + @($ace)
    $sd.DACL = $newDACL
    $dcom_app.SetAccessSecurityDescriptor($sd)

    $ace.AccessMask = 268435456
    $sdRes = $dcom_app.GetConfigurationSecurityDescriptor()
    $sd = $sdRes.Descriptor
    [System.Management.ManagementBaseObject[]] $newDACL = $sd.DACL + @($ace)
    $sd.DACL = $newDACL
    $dcom_app.SetConfigurationSecurityDescriptor($sd)
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
        $result = Set-WmiNamespaceSecurity -sid $sid -namespace 'root' -permissions @("Enable", "RemoteAccess")
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

    try{
        Set-ComponentService $sid
    }catch {
         Write-Error "ERROR: DCOM構成「TrustedInstallerService」のアクセス権設定中にエラーが発生しました[ $($_) ]"
    }
}

main($account)
