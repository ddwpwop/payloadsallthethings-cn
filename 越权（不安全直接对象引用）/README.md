# 不安全直接对象引用

> 当应用程序根据用户提供的输入直接提供对对象的访问时，就会发生不安全的直接对象引用。由于这种漏洞，攻击者可以绕过授权，直接访问系统中的资源，例如数据库记录或文件。- OWASP


## 摘要

* [工具](#工具)
* [实验室](#实验室)
* [利用](#利用)
  * [数字值参数](#数字值参数)
  * [常见标识符参数](#常见标识符参数) 
  * [弱伪随机数生成器](#弱伪随机数生成器) 
  * [哈希参数](#哈希参数)
  * [通配符参数](#通配符参数)
  * [IDOR提示](#idor提示)
* [参考资料](#参考资料)


## 工具

- [PortSwigger/BApp Store > Authz](https://portswigger.net/bappstore/4316cc18ac5f434884b2089831c7d19e)
- [PortSwigger/BApp Store > AuthMatrix](https://portswigger.net/bappstore/30d8ee9f40c041b0bfec67441aad158e)
- [PortSwigger/BApp Store > Autorize](https://portswigger.net/bappstore/f9bbac8c4acf4aefa4d7dc92a991af2f)


## 实验室

* [PortSwigger - 不安全直接对象引用](https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references)


## 利用

IDOR代表不安全直接对象引用。这是一种安全漏洞，当应用程序根据用户提供的输入直接提供对对象的访问时就会出现。因此，攻击者可以绕过授权，直接访问系统中的资源，可能导致未经授权的 信息泄露、修改或删除。

**IDOR示例**

想象一个Web应用程序，允许用户通过点击链接 `https://example.com/profile?user_id=123` 查看他们的个人资料：

```php
<?php
    $user_id = $_GET['user_id'];
    $user_info = get_user_info($user_id);
    ...
```

这里，`user_id=123` 是对特定用户个人资料的直接引用。如果应用程序没有正确检查登录用户是否有权查看与 `user_id=123` 关联的个人资料，攻击者可以简单地更改 `user_id` 参数以查看其他用户的个人资料：

```ps1
https://example.com/profile?user_id=124
```

![https://lh5.googleusercontent.com/VmLyyGH7dGxUOl60h97Lr57F7dcnDD8DmUMCZTD28BKivVI51BLPIqL0RmcxMPsmgXgvAqY8WcQ-Jyv5FhRiCBueX9Wj0HSCBhE-_SvrDdA6_wvDmtMSizlRsHNvTJHuy36LG47lstLpTqLK](https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Insecure%20Direct%20Object%20References/Images/idor.png)


### 数字值参数

增减这些值以访问敏感信息。

* 十进制值：`287789`、`287790`、`287791`...
* 十六进制：`0x4642d`、`0x4642e`、`0x4642f`...
* Unix时间戳：`1695574808`、`1695575098`...

**示例** 

* [HackerOne - 通过IDOR查看用户订单信息 - meals](https://hackerone.com/reports/287789)
* [HackerOne - 通过IDOR删除消息 - naaash](https://hackerone.com/reports/697412)

### 常见标识符参数

有些标识符可以猜测，如姓名和电子邮件，它们可能会授予你访问客户数据的权限。

* 姓名：`john`、`doe`、`john.doe`...
* 电子邮件：`john.doe@mail.com`
* Base64编码值：`am9obi5kb2VAbWFpbC5jb20=`

**示例** 

* [HackerOne - 不安全直接对象引用（IDOR）- 删除活动 - datph4m](https://hackerone.com/reports/1969141)

### 弱伪随机数生成器

* UUID/GUID v1如果能知道它们的创建时间，则可以预测：`95f6e264-bb00-11ec-8833-00155d01ef00`
* MongoDB对象Id的生成方式是可预测的：`5ae9b90a2c144b9def01ec37`
  * 表示自Unix纪元以来的秒数的4字节值
  * 3字节机器标识符
  * 2字节进程id
  * 以随机值开始的3字节计数器

**示例** 

* [HackerOne - 通过IDOR允许读取另一个用户在社交媒体广告服务上的令牌 - a_d_a_m](https://hackerone.com/reports/1464168)
* [通过预测MongoDB对象ID进行IDOR](https://techkranti.com/idor-through-mongodb-object-ids-prediction/)

### 哈希参数

有时我们看到网站使用哈希值来生成随机用户id或令牌，如`sha1(username)`、`md5(email)`...

* MD5：`098f6bcd4621d373cade4e832627b4f6`
* SHA1：`a94a8fe5ccb19ba61c4c0873d391e987982fbbd3`
* SHA2：`9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08`

**示例** 

* [可预测的HMAC生成的IDOR - DiceCTF 2022 - CryptoCat](https://youtu.be/Og5_5tEg6M0)

### 通配符参数

发送通配符而不是ID，一些后端可能会响应所有用户的数据。

* `GET /api/users/* HTTP/1.1`
* `GET /api/users/% HTTP/1.1`
* `GET /api/users/_ HTTP/1.1`
* `GET /api/users/. HTTP/1.1`


**示例** 

* [TODO]()


### IDOR提示

* 更改HTTP请求：`POST → PUT`
* 更改内容类型：`XML → JSON`
* 将数值转换为数组：`{"id":19} → {"id":[19]}`
* 使用参数污染：`user_id=hacker_id&user_id=victim_id`


## 参考资料

* [OWASP - 测试不安全直接对象引用 (OTG-AUTHZ-004)](https://www.owasp.org/index.php/Testing_for_Insecure_Direct_Object_References_(OTG-AUTHZ-004))
* [OWASP - 不安全直接对象引用预防备忘单](https://www.owasp.org/index.php/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet)
* [BUGCROWD - 如何找到IDOR（不安全直接对象引用）漏洞以获得大额赏金 - Sam Houton](https://www.bugcrowd.com/blog/how-to-find-idor-insecure-direct-object-reference-vulnerabilities-for-large-bounty-rewards/)
* [操纵ETH余额](https://www.vicompany.nl/magazine/from-christmas-present-in-the-blockchain-to-massive-bug-bounty)
* [查看私人Airbnb消息](http://buer.haus/2017/03/31/airbnb-web-to-app-phone-notification-idor-to-view-everyones-airbnb-messages/) 
* [为了乐趣和利润而寻找不安全直接对象引用漏洞（第一部分）- Mohammed Abdul Raheem - 2018年2月2日](https://codeburst.io/hunting-insecure-direct-object-reference-vulnerabilities-for-fun-and-profit-part-1-f338c6a52782)
* [IDOR - 如何预测标识符？漏洞赏金案例研究 - Bug Bounty报告解释 - ](https://youtu.be/wx5TwS0Dres)
* [测试IDOR - PortSwigger](https://portswigger.net/burp/documentation/desktop/testing-workflow/access-controls/testing-for-idors)
* [不安全直接对象引用（IDOR）- PortSwigger](https://portswigger.net/web-security/access-control/idor)
* [IDOR的崛起 - HackerOne - 2021年4月2日](https://www.hackerone.com/company-news/rise-idor)