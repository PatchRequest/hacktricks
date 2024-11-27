# macOS 安全与权限提升

{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **通过提交 PR 到** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库分享黑客技巧。

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

加入 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 服务器，与经验丰富的黑客和漏洞赏金猎人交流！

**黑客见解**\
参与深入探讨黑客的刺激与挑战的内容

**实时黑客新闻**\
通过实时新闻和见解，保持对快速变化的黑客世界的了解

**最新公告**\
了解最新的漏洞赏金计划和重要平台更新

**今天就加入我们的** [**Discord**](https://discord.com/invite/N3FrSbmwdy)，与顶尖黑客开始合作吧！

## 基础 MacOS

如果你对 macOS 不熟悉，应该开始学习 macOS 的基础知识：

* 特殊的 macOS **文件与权限：**

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* 常见的 macOS **用户**

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* **内核**的 **架构**

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* 常见的 macOS n**etwork 服务与协议**

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **开源** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
* 要下载 `tar.gz`，将 URL 更改为 [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

在公司中，**macOS** 系统很可能会被 **MDM 管理**。因此，从攻击者的角度来看，了解 **其工作原理** 是很有趣的：

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - 检查、调试和模糊测试

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## MacOS 安全保护

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## 攻击面

### 文件权限

如果 **以 root 身份运行的进程写入** 一个可以被用户控制的文件，用户可能会利用这一点来 **提升权限**。\
这可能发生在以下情况下：

* 使用的文件已经由用户创建（由用户拥有）
* 使用的文件因组而可被用户写入
* 使用的文件位于用户拥有的目录中（用户可以创建该文件）
* 使用的文件位于 root 拥有的目录中，但用户因组而对其具有写入权限（用户可以创建该文件）

能够 **创建一个将被 root 使用的文件**，允许用户 **利用其内容**，甚至创建 **符号链接/硬链接** 指向另一个位置。

对于这种类型的漏洞，不要忘记 **检查易受攻击的 `.pkg` 安装程序**：

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}

### 文件扩展名与 URL 方案应用处理程序

通过文件扩展名注册的奇怪应用程序可能会被滥用，不同的应用程序可以注册以打开特定协议

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## macOS TCC / SIP 权限提升

在 macOS 中，**应用程序和二进制文件可以拥有** 访问文件夹或设置的权限，使其比其他应用程序更具特权。

因此，想要成功攻陷 macOS 机器的攻击者需要 **提升其 TCC 权限**（甚至 **绕过 SIP**，具体取决于其需求）。

这些权限通常以 **应用程序签名的权利** 形式授予，或者应用程序可能请求某些访问权限，经过 **用户批准后**，它们可以在 **TCC 数据库** 中找到。进程获得这些权限的另一种方式是成为具有这些 **权限** 的进程的 **子进程**，因为它们通常是 **继承的**。

请访问这些链接以找到不同的 [**在 TCC 中提升权限**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses)、[**绕过 TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) 和过去 [**如何绕过 SIP**](macos-security-protections/macos-sip.md#sip-bypasses)。

## macOS 传统权限提升

当然，从红队的角度来看，你也应该对提升到 root 感兴趣。查看以下帖子以获取一些提示：

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}

## macOS 合规性

* [https://github.com/usnistgov/macos\_security](https://github.com/usnistgov/macos_security)

## 参考资料

* [**OS X 事件响应：脚本和分析**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

加入 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 服务器，与经验丰富的黑客和漏洞赏金猎人交流！

**黑客见解**\
参与深入探讨黑客的刺激与挑战的内容

**实时黑客新闻**\
通过实时新闻和见解，保持对快速变化的黑客世界的了解

**最新公告**\
了解最新的漏洞赏金计划和重要平台更新

**今天就加入我们的** [**Discord**](https://discord.com/invite/N3FrSbmwdy)，与顶尖黑客开始合作吧！

{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **通过提交 PR 到** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库分享黑客技巧。

</details>
{% endhint %}
