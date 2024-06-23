# Linux - 逃避检测

## 摘要

- [文件名](#文件名)
- [命令历史](#命令历史)
- [隐藏文本](#隐藏文本)
- [时间戳篡改](#时间戳篡改)

## 文件名

可以在文件名中插入Unicode零宽空格，这使得名字在视觉上无法区分：

```bash
# 一个没有特殊字符的诱饵文件
touch 'index.php'

# 一个视觉上相同的冒名顶替文件
touch $'index\u200D.php'
```

## 命令历史

大多数shell会保存它们的命令历史，以便用户稍后可以再次调用。可以使用`history`命令或手动检查`$HISTFILE`指向的文件（例如`~/.bash_history`）的内容来查看命令历史。这可以通过多种方式防止。

```bash
# 完全禁止写入历史文件
unset HISTFILE

# 不保存本次会话的命令历史到内存
export HISTSIZE=0
```

与`HISTIGNORE`中的模式匹配的单个命令将被排除在命令历史记录之外，无论`HISTFILE`或`HISTSIZE`设置如何。默认情况下，`HISTIGNORE`将忽略所有以空白字符开头的命令：

```bash
# 注意行首的空格字符：
 my-sneaky-command
```

如果命令被意外添加到命令历史记录中，可以使用`history -d`删除单个命令条目：

```bash
# 删除最近记录的命令。
# 注意，我们实际上需要一次删除两个历史记录条目，
# 否则`history -d`命令本身也会被记录下来。
history -d -2 && history -d -1
```

整个命令历史也可以被清除，尽管这种方法不太隐蔽，很可能会被发现：

```bash
# 清除内存中的历史记录并将空历史记录写入磁盘。
history -c && history -w
```

## 隐藏文本

ANSI转义序列可以在某些情况下被滥用以隐藏文本。如果文件内容被打印到终端（例如`cat`、`head`、`tail`），则文本会被隐藏。如果使用编辑器（例如`vim`、`nano`、`emacs`）查看文件，则转义序列将可见。

```bash
echo "sneaky-payload-command" > script.sh
echo "# $(clear)" >> script.sh
echo "# 不要删除。由/etc/issue.conf通过configure生成。" >> script.sh

# 当打印时，终端将被清屏，只有最后一行可见：
cat script.sh
```

## 时间戳篡改

时间戳篡改指的是更改文件或目录的修改/访问时间戳，以隐藏其被修改的事实。完成这一点的最简单方法是使用`touch`命令：

```bash
# 使用YYYYMMDDhhmm格式更改访问（-a）和修改（-m）时间。
touch -a -m -t 202210312359 "example"

# 使用Unix纪元时间戳更改时间。
touch -a -m -d @1667275140 "example"

# 从一个文件复制时间戳到另一个文件。
touch -a -m -r "other_file" "example"

# 获取文件的修改时间戳，修改文件，然后恢复时间戳。
MODIFIED_TS=$(stat --format="%Y" "example")
echo "backdoor" >> "example"
touch -a -m -d @$MODIFIED_TS "example"
```

应该注意的是，`touch`只能修改访问和修改时间戳。它不能用来更新文件的“更改”或“创建”时间戳。如果文件系统支持，创建时间戳跟踪文件的创建时间。更改时间戳跟踪任何时候文件的元数据发生变化，包括访问和修改时间戳的更新。

如果攻击者具有root权限，他们可以通过修改系统时钟，创建或修改文件，然后恢复系统时钟来绕过这个限制：

```bash
ORIG_TIME=$(date)
date -s "2022-10-31 23:59:59"
touch -a -m "example"
date -s "${ORIG_TIME}"
```

不要忘记，创建文件也会更新父目录的修改时间戳！

## 参考资料

- [ATT&CK - 损害防御：损害命令历史记录日志记录](https://attack.mitre.org/techniques/T1562/003/)
- [ATT&CK - 指标移除：时间戳篡改](https://attack.mitre.org/techniques/T1070/006/)
- [ATT&CK - 主机上的指标移除：清除命令历史](https://attack.mitre.org/techniques/T1070/003/)
- [ATT&CK - 伪装：匹配合法名称或位置](https://attack.mitre.org/techniques/T1036/005/)
- [维基百科 - ANSI转义码](https://en.wikipedia.org/wiki/ANSI_escape_code)
- [InverseCos - 检测Linux反取证：时间戳篡改](https://www.inversecos.com/2022/08/detecting-linux-anti-forensics.html)
