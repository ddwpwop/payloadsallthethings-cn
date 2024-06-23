# 大规模赋值

> 大规模赋值攻击是一种安全漏洞，当Web应用程序自动将用户提供的输入值分配给程序对象的属性或变量时会发生这种漏洞。如果用户能够修改他们不应该访问的属性，如用户的权限或管理员标志，这可能会成为一个问题。

## 摘要

* [利用](#exploit)
* [实验室](#labs)
* [参考资料](#references)

## 利用

大规模赋值漏洞在使用对象关系映射（ORM）技术或函数将用户输入映射到对象属性的Web应用程序中最为常见，这些属性可以一次性全部更新，而不是单独更新。许多流行的Web开发框架，如Ruby on Rails、Django和Laravel（PHP），都提供此功能。

例如，考虑一个使用ORM的Web应用程序，它有一个具有`username`、`email`、`password`和`isAdmin`属性的用户对象。在正常情况下，用户可能可以通过表单更新自己的用户名、电子邮件和密码，然后服务器将这些值分配给用户对象。

然而，攻击者可能会尝试在传入数据中添加一个`isAdmin`参数，如下所示：

```json
{
    "username": "attacker",
    "email": "attacker@email.com",
    "password": "unsafe_password",
    "isAdmin": true
}
```

如果Web应用程序没有检查允许以这种方式更新的参数，它可能会根据用户提供的输入设置`isAdmin`属性，从而赋予攻击者管理员权限。

## 实验室

* [PentesterAcademy - 大规模赋值 I](https://attackdefense.pentesteracademy.com/challengedetailsnoauth?cid=1964)
* [PentesterAcademy - 大规模赋值 II](https://attackdefense.pentesteracademy.com/challengedetailsnoauth?cid=1922)

## 参考资料

* [寻找大规模赋值 - Shivam Bathla - 2021年8月12日](https://blog.pentesteracademy.com/hunting-for-mass-assignment-56ed73095eda)
* [大规模赋值备忘单 - OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
* [什么是大规模赋值？攻击和安全提示 - Yoan MONTOYA - 2023年6月15日](https://www.vaadata.com/blog/what-is-mass-assignment-attacks-and-security-tips/)