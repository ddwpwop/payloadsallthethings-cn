# HTTP参数污染

> HTTP参数污染（HPP）是一种Web攻击规避技术，允许攻击者构造HTTP请求以操纵Web逻辑或检索隐藏信息。这种规避技术基于在多个同名参数的实例之间分割攻击向量（?param1=value&param1=value）。由于没有解析HTTP参数的正式方法，各个Web技术都有自己独特的解析和读取同名URL参数的方式。有些会取第一个出现的参数，有些会取最后一个出现的参数，还有些会将其读作数组。攻击者滥用这种行为来绕过基于模式的安全机制。

## 摘要

* [工具](#工具)
* [如何测试](#如何测试)
  * [参考表格](#参考表格)
* [参考资料](#参考资料)

## 工具

不需要工具。也许可以使用Burp或OWASP ZAP。

## 如何测试

HPP允许攻击者绕过基于模式/黑名单代理或Web应用程序防火墙检测机制。无论是否了解代理背后的Web技术，都可以通过简单的试错来实现。

```
示例场景。
WAF - 读取第一个参数
原始服务 - 读取第二个参数。在这种情况下，开发者信任WAF并且没有实施健全性检查。

攻击者 -- http://example.com?search=Beth&search=' OR 1=1;## --> WAF（读取第一个'search'参数，看起来无害。传递）--> 原始服务（如果在这里没有进行检查，则发生注入。）
```

### 参考表格

当 ?par1=a&par1=b

| 技术                                           | 解析结果                 | 结果 (par1=) |
| ---------------------------------------------- | ------------------------ | :----------: |
| ASP.NET/IIS                                    | 所有出现的情况           |     a,b      |
| ASP/IIS                                        | 所有出现的情况           |     a,b      |
| PHP/Apache                                     | 最后一次出现             |      b       |
| PHP/Zues                                       | 最后一次出现             |      b       |
| JSP,Servlet/Tomcat                             | 第一次出现               |      a       |
| Perl CGI/Apache                                | 第一次出现               |      a       |
| Python Flask                                   | 第一次出现               |      a       |
| Python Django                                  | 最后一次出现             |      b       |
| Nodejs                                         | 所有出现的情况           |     a,b      |
| Golang net/http - `r.URL.Query().Get("param")` | 第一次出现               |      a       |
| Golang net/http - `r.URL.Query()["param"]`     | 以数组形式所有出现的情况 |  ['a','b']   |
| IBM Lotus Domino                               | 第一次出现               |      a       |
| IBM HTTP Server                                | 第一次出现               |      a       |
| Perl CGI/Apache                                | 第一次出现               |      a       |
| mod_wsgi (Python)/Apache                       | 第一次出现               |      a       |
| Python/Zope                                    | 以数组形式所有出现的情况 |  ['a','b']   |
| Ruby on Rails                                  | 最后一次出现             |      b       |

## 参考资料

- [HTTP参数污染 - Imperva](https://www.imperva.com/learn/application-security/http-parameter-pollution/)
- [11分钟了解HTTP参数污染 | Web黑客 - PwnFunction](https://www.youtube.com/watch?v=QVZBl8yxVX0&ab_channel=PwnFunction)
- [如何检测HTTP参数污染攻击 - Acunetix](https://www.acunetix.com/blog/whitepaper-http-parameter-pollution/)
