# PsExec/Winexec/ScExec

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## 它们是如何工作的

该过程在以下步骤中概述，说明如何通过 SMB 操纵服务二进制文件以实现对目标机器的远程执行：

1. **通过 SMB 复制服务二进制文件到 ADMIN$ 共享**。
2. **在远程机器上创建服务**，指向该二进制文件。
3. 服务被**远程启动**。
4. 退出时，服务被**停止，二进制文件被删除**。

### **手动执行 PsExec 的过程**

假设有一个可执行有效载荷（使用 msfvenom 创建并使用 Veil 混淆以规避防病毒检测），名为 'met8888.exe'，代表一个 meterpreter reverse\_http 有效载荷，采取以下步骤：

* **复制二进制文件**：可执行文件从命令提示符复制到 ADMIN$ 共享，尽管它可以放置在文件系统的任何位置以保持隐蔽。
* **创建服务**：利用 Windows `sc` 命令，该命令允许远程查询、创建和删除 Windows 服务，创建一个名为 "meterpreter" 的服务，指向上传的二进制文件。
* **启动服务**：最后一步是启动服务，这可能会导致 "超时" 错误，因为该二进制文件不是一个真正的服务二进制文件，未能返回预期的响应代码。此错误无关紧要，因为主要目标是执行该二进制文件。

观察 Metasploit 监听器将显示会话已成功启动。

[了解更多关于 `sc` 命令的信息](https://technet.microsoft.com/en-us/library/bb490995.aspx)。

在此查找更详细的步骤：[https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**您还可以使用 Windows Sysinternals 二进制文件 PsExec.exe：**

![](<../../.gitbook/assets/image (928).png>)

您还可以使用 [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **在** **Twitter** 🐦 **上关注我们** [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
