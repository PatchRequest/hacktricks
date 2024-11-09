# SmbExec/ScExec

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

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**从黑客的角度审视您的网络应用、网络和云**

**查找并报告具有实际商业影响的关键可利用漏洞。** 使用我们 20 多个自定义工具来映射攻击面，发现让您提升权限的安全问题，并使用自动化漏洞收集重要证据，将您的辛勤工作转化为有说服力的报告。

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## 工作原理

**Smbexec** 是一个用于在 Windows 系统上远程执行命令的工具，类似于 **Psexec**，但它避免在目标系统上放置任何恶意文件。

### 关于 **SMBExec** 的关键点

- 它通过在目标机器上创建一个临时服务（例如，“BTOBTO”）来通过 cmd.exe (%COMSPEC%) 执行命令，而不放置任何二进制文件。
- 尽管采用隐蔽的方法，但它确实为每个执行的命令生成事件日志，提供了一种非交互式的“shell”。
- 使用 **Smbexec** 连接的命令如下：
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### 执行无二进制文件的命令

- **Smbexec** 通过服务 binPaths 直接执行命令，消除了在目标上需要物理二进制文件的需求。
- 这种方法对于在 Windows 目标上执行一次性命令非常有用。例如，将其与 Metasploit 的 `web_delivery` 模块配对，可以执行针对 PowerShell 的反向 Meterpreter 有效载荷。
- 通过在攻击者的机器上创建一个远程服务，并将 binPath 设置为通过 cmd.exe 运行提供的命令，可以成功执行有效载荷，实现回调和有效载荷执行与 Metasploit 监听器，即使发生服务响应错误。

### 命令示例

创建和启动服务可以通过以下命令完成：
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
FOr further details check [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## References
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**获取黑客对您的网络应用程序、网络和云的看法**

**查找并报告具有实际商业影响的关键可利用漏洞。** 使用我们20多个自定义工具来映射攻击面，查找让您提升权限的安全问题，并使用自动化漏洞收集重要证据，将您的辛勤工作转化为有说服力的报告。

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{% hint style="success" %}
学习和实践AWS黑客攻击：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks培训AWS红队专家（ARTE）**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践GCP黑客攻击：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks培训GCP红队专家（GRTE）**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持HackTricks</summary>

* 查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**在** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**上关注我们。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub库提交PR来分享黑客技巧。

</details>
{% endhint %}
