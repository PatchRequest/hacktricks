# 其他网络技巧

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **在** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** 上关注我们。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**从黑客的角度看待您的网络应用、网络和云**

**发现并报告具有实际商业影响的关键可利用漏洞。** 使用我们 20 多个自定义工具来映射攻击面，找到让您提升权限的安全问题，并使用自动化利用收集重要证据，将您的辛勤工作转化为有说服力的报告。

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

### 主机头

几次后端信任 **Host header** 来执行某些操作。例如，它可能会使用其值作为 **发送密码重置的域**。因此，当您收到一封带有重置密码链接的电子邮件时，使用的域是您在 Host header 中输入的域。然后，您可以请求其他用户的密码重置，并将域更改为您控制的域，以窃取他们的密码重置代码。[WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)。

{% hint style="warning" %}
请注意，您甚至可能不需要等待用户点击重置密码链接来获取令牌，因为可能连 **垃圾邮件过滤器或其他中介设备/机器人都会点击它进行分析**。
{% endhint %}

### 会话布尔值

有时，当您正确完成某些验证时，后端会 **仅将值为 "True" 的布尔值添加到您的会话的安全属性中**。然后，另一个端点将知道您是否成功通过了该检查。\
但是，如果您 **通过检查** 并且您的会话在安全属性中获得了 "True" 值，您可以尝试 **访问其他资源**，这些资源 **依赖于相同的属性**，但您 **不应该有权限** 访问。[WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)。

### 注册功能

尝试以已存在用户的身份注册。也尝试使用等效字符（点、多个空格和 Unicode）。

### 接管电子邮件

注册一个电子邮件，在确认之前更改电子邮件，然后，如果新的确认电子邮件发送到第一个注册的电子邮件，您可以接管任何电子邮件。或者如果您可以启用第二个电子邮件确认第一个电子邮件，您也可以接管任何账户。

### 访问使用 Atlassian 的公司内部服务台

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### TRACE 方法

开发人员可能会忘记在生产环境中禁用各种调试选项。例如，HTTP `TRACE` 方法是为诊断目的而设计的。如果启用，Web 服务器将通过在响应中回显收到的确切请求来响应使用 `TRACE` 方法的请求。这种行为通常是无害的，但偶尔会导致信息泄露，例如可能由反向代理附加到请求的内部身份验证头的名称。![Image for post](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**从黑客的角度看待您的网络应用、网络和云**

**发现并报告具有实际商业影响的关键可利用漏洞。** 使用我们 20 多个自定义工具来映射攻击面，找到让您提升权限的安全问题，并使用自动化利用收集重要证据，将您的辛勤工作转化为有说服力的报告。

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **在** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** 上关注我们。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
