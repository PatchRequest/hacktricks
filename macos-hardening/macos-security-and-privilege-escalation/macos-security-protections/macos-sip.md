# macOS SIP

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## **基本信息**

**系统完整性保护 (SIP)** 在 macOS 中是一种机制，旨在防止即使是最特权的用户也无法对关键系统文件夹进行未经授权的更改。此功能在维护系统完整性方面发挥着至关重要的作用，通过限制在受保护区域内添加、修改或删除文件等操作。SIP 保护的主要文件夹包括：

* **/System**
* **/bin**
* **/sbin**
* **/usr**

管理 SIP 行为的规则定义在位于 **`/System/Library/Sandbox/rootless.conf`** 的配置文件中。在此文件中，以星号（\*）为前缀的路径被视为对其他严格 SIP 限制的例外。

考虑以下示例：
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
这个片段暗示，虽然 SIP 通常保护 **`/usr`** 目录，但有特定的子目录（`/usr/libexec/cups`、`/usr/local` 和 `/usr/share/man`）可以进行修改，如路径前的星号（\*）所示。

要验证某个目录或文件是否受到 SIP 保护，可以使用 **`ls -lOd`** 命令检查是否存在 **`restricted`** 或 **`sunlnk`** 标志。例如：
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
在这种情况下，**`sunlnk`** 标志表示 `/usr/libexec/cups` 目录本身 **无法被删除**，尽管可以创建、修改或删除其中的文件。

另一方面：
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
这里，**`restricted`** 标志表示 `/usr/libexec` 目录受到 SIP 保护。在 SIP 保护的目录中，文件不能被创建、修改或删除。

此外，如果一个文件包含属性 **`com.apple.rootless`** 扩展 **属性**，该文件也将 **受到 SIP 保护**。

{% hint style="success" %}
请注意，**Sandbox** 钩子 **`hook_vnode_check_setextattr`** 阻止任何尝试修改扩展属性 **`com.apple.rootless`** 的行为。
{% endhint %}

**SIP 还限制其他根操作**，例如：

* 加载不受信任的内核扩展
* 获取 Apple 签名进程的任务端口
* 修改 NVRAM 变量
* 允许内核调试

选项以位标志的形式保存在 nvram 变量中（在 Intel 上为 `csr-active-config`，在 ARM 上从启动的设备树中读取 `lp-sip0`）。您可以在 `csr.sh` 的 XNU 源代码中找到这些标志：

<figure><img src="../../../.gitbook/assets/image (1192).png" alt=""><figcaption></figcaption></figure>

### SIP 状态

您可以使用以下命令检查系统上是否启用了 SIP：
```bash
csrutil status
```
如果您需要禁用 SIP，您必须在恢复模式下重启计算机（在启动时按 Command+R），然后执行以下命令：
```bash
csrutil disable
```
如果您希望保持 SIP 启用但移除调试保护，可以使用：
```bash
csrutil enable --without debug
```
### 其他限制

* **禁止加载未签名的内核扩展**（kexts），确保只有经过验证的扩展与系统内核交互。
* **防止调试** macOS 系统进程，保护核心系统组件免受未经授权的访问和修改。
* **抑制工具** 如 dtrace 检查系统进程，进一步保护系统操作的完整性。

[**在此演讲中了解更多关于 SIP 的信息**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**

### **与 SIP 相关的权限**

* `com.apple.rootless.xpc.bootstrap`: 控制 launchd
* `com.apple.rootless.install[.heritable]`: 访问文件系统
* `com.apple.rootless.kext-management`: `kext_request`
* `com.apple.rootless.datavault.controller`: 管理 UF\_DATAVAULT
* `com.apple.rootless.xpc.bootstrap`: XPC 设置能力
* `com.apple.rootless.xpc.effective-root`: 通过 launchd XPC 获取 root 权限
* `com.apple.rootless.restricted-block-devices`: 访问原始块设备
* `com.apple.rootless.internal.installer-equivalent`: 不受限制的文件系统访问
* `com.apple.rootless.restricted-nvram-variables[.heritable]`: 完全访问 NVRAM
* `com.apple.rootless.storage.label`: 修改由 com.apple.rootless xattr 限制的文件，使用相应的标签
* `com.apple.rootless.volume.VM.label`: 在卷上维护 VM 交换

## SIP 绕过

绕过 SIP 使攻击者能够：

* **访问用户数据**：读取所有用户帐户的敏感用户数据，如邮件、消息和 Safari 历史记录。
* **TCC 绕过**：直接操纵 TCC（透明性、同意和控制）数据库，以授予对网络摄像头、麦克风和其他资源的未经授权访问。
* **建立持久性**：在 SIP 保护的位置放置恶意软件，使其即使在 root 权限下也难以删除。这还包括篡改恶意软件删除工具（MRT）的潜在能力。
* **加载内核扩展**：尽管有额外的保护，绕过 SIP 简化了加载未签名内核扩展的过程。

### 安装包

**使用 Apple 证书签名的安装包** 可以绕过其保护。这意味着即使是标准开发者签名的包，如果尝试修改 SIP 保护的目录，也会被阻止。

### 不存在的 SIP 文件

一个潜在的漏洞是，如果在 **`rootless.conf` 中指定了一个文件但当前不存在**，则可以创建它。恶意软件可以利用这一点在系统上 **建立持久性**。例如，如果恶意程序在 `rootless.conf` 中列出但不存在，它可以在 `/System/Library/LaunchDaemons` 中创建一个 .plist 文件。

### com.apple.rootless.install.heritable

{% hint style="danger" %}
权限 **`com.apple.rootless.install.heritable`** 允许绕过 SIP
{% endhint %}

#### [CVE-2019-8561](https://objective-see.org/blog/blog\_0x42.html) <a href="#cve" id="cve"></a>

发现可以在 **系统验证其代码** 签名后 **交换安装包**，然后系统将安装恶意包而不是原始包。由于这些操作是由 **`system_installd`** 执行的，因此可以绕过 SIP。

#### [CVE-2020–9854](https://objective-see.org/blog/blog\_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

如果从挂载的映像或外部驱动器安装包，**安装程序** 将 **执行** 来自 **该文件系统** 的二进制文件（而不是来自 SIP 保护的位置），使 **`system_installd`** 执行任意二进制文件。

#### CVE-2021-30892 - Shrootless

[**来自此博客文章的研究人员**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) 发现了 macOS 的系统完整性保护（SIP）机制中的一个漏洞，称为 'Shrootless' 漏洞。该漏洞围绕 **`system_installd`** 守护进程，该进程具有权限 **`com.apple.rootless.install.heritable`**，允许其任何子进程绕过 SIP 的文件系统限制。

**`system_installd`** 守护进程将安装由 **Apple** 签名的包。

研究人员发现，在安装 Apple 签名的包（.pkg 文件）期间，**`system_installd`** **运行** 包中包含的任何 **后安装** 脚本。这些脚本由默认 shell **`zsh`** 执行，如果存在，它会自动 **运行** 来自 **`/etc/zshenv`** 文件的命令，即使在非交互模式下。攻击者可以利用这种行为：通过创建恶意的 `/etc/zshenv` 文件并等待 **`system_installd` 调用 `zsh`**，他们可以在设备上执行任意操作。

此外，发现 **`/etc/zshenv` 可以作为一种通用攻击技术**，不仅仅用于 SIP 绕过。每个用户配置文件都有一个 `~/.zshenv` 文件，其行为与 `/etc/zshenv` 相同，但不需要 root 权限。该文件可以用作持久性机制，每次 `zsh` 启动时触发，或作为特权提升机制。如果管理员用户使用 `sudo -s` 或 `sudo <command>` 提升到 root，`~/.zshenv` 文件将被触发，有效地提升到 root。

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

在 [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) 中发现同样的 **`system_installd`** 进程仍然可以被滥用，因为它将 **后安装脚本放在一个随机命名的文件夹中，该文件夹在 `/tmp` 中受 SIP 保护**。问题是 **`/tmp` 本身不受 SIP 保护**，因此可以 **挂载** 一个 **虚拟映像**，然后 **安装程序** 会将 **后安装脚本** 放入其中，**卸载** 虚拟映像，**重新创建** 所有 **文件夹** 并 **添加** 带有 **有效载荷** 的 **后安装** 脚本以执行。

#### [fsck\_cs 工具](https://www.theregister.com/2016/03/30/apple\_os\_x\_rootless/)

发现了一个漏洞，其中 **`fsck_cs`** 被误导以破坏一个关键文件，因为它能够跟随 **符号链接**。具体来说，攻击者从 _`/dev/diskX`_ 创建了一个指向文件 `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist` 的链接。在 _`/dev/diskX`_ 上执行 **`fsck_cs`** 导致 `Info.plist` 的损坏。该文件的完整性对操作系统的 SIP（系统完整性保护）至关重要，SIP 控制内核扩展的加载。一旦损坏，SIP 管理内核排除的能力就会受到影响。

利用此漏洞的命令是：
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
该漏洞的利用具有严重的影响。`Info.plist` 文件，通常负责管理内核扩展的权限，变得无效。这包括无法将某些扩展列入黑名单，例如 `AppleHWAccess.kext`。因此，由于 SIP 的控制机制失效，该扩展可以被加载，从而授予对系统 RAM 的未经授权的读写访问。

#### [在 SIP 保护的文件夹上挂载](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

可以在 **SIP 保护的文件夹上挂载新的文件系统以绕过保护**。
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [升级绕过 (2016)](https://objective-see.org/blog/blog\_0x14.html)

系统设置为从 `Install macOS Sierra.app` 中的嵌入式安装程序磁盘映像启动以升级操作系统，利用 `bless` 工具。使用的命令如下：
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
该过程的安全性可能会受到威胁，如果攻击者在启动之前更改升级映像（`InstallESD.dmg`）。该策略涉及用恶意版本（`libBaseIA.dylib`）替换动态加载器（dyld）。此替换导致在启动程序时执行攻击者的代码。

攻击者的代码在升级过程中获得控制权，利用系统对安装程序的信任。攻击通过通过方法交换（method swizzling）更改`InstallESD.dmg`映像，特别针对`extractBootBits`方法。这允许在使用磁盘映像之前注入恶意代码。

此外，在`InstallESD.dmg`中，有一个`BaseSystem.dmg`，它作为升级代码的根文件系统。将动态库注入其中允许恶意代码在能够更改操作系统级文件的进程中运行，显著增加了系统被攻陷的潜力。

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

在[**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk)的演讲中，展示了**`systemmigrationd`**（可以绕过SIP）如何执行**bash**和**perl**脚本，这可以通过环境变量**`BASH_ENV`**和**`PERL5OPT`**进行滥用。

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

正如[**在这篇博客文章中详细说明的**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts)，来自`InstallAssistant.pkg`包的`postinstall`脚本允许执行：
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
and it was possible to crate a symlink in `${SHARED_SUPPORT_PATH}/SharedSupport.dmg` that would allow a user to **unrestrict any file, bypassing SIP protection**.

### **com.apple.rootless.install**

{% hint style="danger" %}
该权限 **`com.apple.rootless.install`** 允许绕过 SIP
{% endhint %}

权限 `com.apple.rootless.install` 被认为可以绕过 macOS 的系统完整性保护 (SIP)。这在与 [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/) 相关时特别提到。

在这个特定情况下，位于 `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` 的系统 XPC 服务拥有此权限。这使得相关进程能够绕过 SIP 限制。此外，该服务显著提供了一种方法，允许在不执行任何安全措施的情况下移动文件。

## 密封系统快照

密封系统快照是 Apple 在 **macOS Big Sur (macOS 11)** 中引入的一项功能，作为其 **系统完整性保护 (SIP)** 机制的一部分，以提供额外的安全性和系统稳定性。它们本质上是系统卷的只读版本。

以下是更详细的介绍：

1. **不可变系统**：密封系统快照使 macOS 系统卷“不可变”，这意味着它无法被修改。这防止了任何未经授权或意外的更改，从而可能危及安全性或系统稳定性。
2. **系统软件更新**：当您安装 macOS 更新或升级时，macOS 会创建一个新的系统快照。macOS 启动卷随后使用 **APFS (Apple 文件系统)** 切换到这个新快照。应用更新的整个过程变得更安全、更可靠，因为系统始终可以在更新过程中出现问题时恢复到先前的快照。
3. **数据分离**：结合在 macOS Catalina 中引入的数据和系统卷分离的概念，密封系统快照功能确保您的所有数据和设置存储在一个单独的“**数据**”卷上。这种分离使您的数据独立于系统，从而简化了系统更新的过程并增强了系统安全性。

请记住，这些快照由 macOS 自动管理，并且由于 APFS 的空间共享能力，不会占用您磁盘上的额外空间。还需要注意的是，这些快照与 **时间机器快照** 不同，后者是用户可访问的整个系统的备份。

### 检查快照

命令 **`diskutil apfs list`** 列出 **APFS 卷的详细信息**及其布局：

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-&#x3C; Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Physical Store Disk:   disk0s2
|   |   Size:                       494384795648 B (494.4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Volume Disk (Role):   disk3s1 (System)
</strong>|   |   Name:                      Macintosh HD (不区分大小写)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12.8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Yes (已解锁)
|   |   Encrypted:                 No
|   |   |
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Yes
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Disk (Role):   disk3s5 (Data)
|   Name:                      Macintosh HD - Data (不区分大小写)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412.1 GB)
</strong>    |   Sealed:                    No
|   FileVault:                 Yes (已解锁)
</code></pre>

在之前的输出中，可以看到 **用户可访问的位置** 被挂载在 `/System/Volumes/Data` 下。

此外，**macOS 系统卷快照** 被挂载在 `/` 并且是 **密封的**（由操作系统进行加密签名）。因此，如果绕过 SIP 并进行修改，**操作系统将无法启动**。

还可以通过运行来 **验证密封是否启用**：
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
此外，快照磁盘也被挂载为**只读**：
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **在** **Twitter** 🐦 **上关注我们** [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
