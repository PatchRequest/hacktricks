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

## **Basic Information**

**Ulinzi wa Uadilifu wa Mfumo (SIP)** katika macOS ni mekanizma iliyoundwa kuzuia hata watumiaji wenye mamlaka makubwa kufanya mabadiliko yasiyoidhinishwa kwenye folda muhimu za mfumo. Kipengele hiki kina jukumu muhimu katika kudumisha uadilifu wa mfumo kwa kuzuia vitendo kama kuongeza, kubadilisha, au kufuta faili katika maeneo yaliyo na ulinzi. Folda kuu zinazolindwa na SIP ni pamoja na:

* **/System**
* **/bin**
* **/sbin**
* **/usr**

Sheria zinazodhibiti tabia ya SIP zimefafanuliwa katika faili la usanidi lililoko kwenye **`/System/Library/Sandbox/rootless.conf`**. Ndani ya faili hii, njia ambazo zinaanzishwa na nyota (\*) zinaonyeshwa kama visingizio kwa vizuizi vya SIP ambavyo ni vikali.

Fikiria mfano ulio hapa chini:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Hii sehemu inaashiria kwamba ingawa SIP kwa ujumla inalinda **`/usr`** directory, kuna subdirectories maalum (`/usr/libexec/cups`, `/usr/local`, na `/usr/share/man`) ambapo mabadiliko yanaruhusiwa, kama inavyoonyeshwa na nyota (\*) inayotangulia njia zao.

Ili kuthibitisha ikiwa directory au faili inalindwa na SIP, unaweza kutumia amri **`ls -lOd`** kuangalia uwepo wa bendera **`restricted`** au **`sunlnk`**. Kwa mfano:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
Katika kesi hii, bendera **`sunlnk`** inaashiria kwamba saraka ya `/usr/libexec/cups` yenyewe **haiwezi kufutwa**, ingawa faili ndani yake zinaweza kuundwa, kubadilishwa, au kufutwa.

Kwa upande mwingine:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Hapa, bendera **`restricted`** inaonyesha kwamba saraka ya `/usr/libexec` inalindwa na SIP. Katika saraka iliyo na ulinzi wa SIP, faili haziwezi kuundwa, kubadilishwa, au kufutwa.

Zaidi ya hayo, ikiwa faili ina sifa **`com.apple.rootless`** sifa ya ziada, faili hiyo pia itakuwa **inalindwa na SIP**.

{% hint style="success" %}
Kumbuka kwamba **Sandbox** hook **`hook_vnode_check_setextattr`** inazuia jaribio lolote la kubadilisha sifa ya ziada **`com.apple.rootless`.**
{% endhint %}

**SIP pia inakadiria vitendo vingine vya root** kama:

* Kupakia nyongeza za kernel zisizoaminika
* Kupata task-ports kwa michakato iliyosainiwa na Apple
* Kubadilisha mabadiliko ya NVRAM
* Kuruhusu ufuatiliaji wa kernel

Chaguo zinawekwa katika mabadiliko ya nvram kama bitflag (`csr-active-config` kwenye Intel na `lp-sip0` inasomwa kutoka kwa Mti wa Kifaa kilichozinduliwa kwa ARM). Unaweza kupata bendera hizo katika msimbo wa chanzo wa XNU katika `csr.sh`:

<figure><img src="../../../.gitbook/assets/image (1192).png" alt=""><figcaption></figcaption></figure>

### Hali ya SIP

Unaweza kuangalia ikiwa SIP imewezeshwa kwenye mfumo wako kwa amri ifuatayo:
```bash
csrutil status
```
Ikiwa unahitaji kuzima SIP, lazima uanzishe tena kompyuta yako katika hali ya urejelezi (kwa kubonyeza Command+R wakati wa kuanzisha), kisha tekeleza amri ifuatayo:
```bash
csrutil disable
```
Ikiwa unataka kuweka SIP ikiwa imewezeshwa lakini kuondoa ulinzi wa ufuatiliaji, unaweza kufanya hivyo kwa:
```bash
csrutil enable --without debug
```
### Other Restrictions

* **Inakata kupakia nyongeza za kernel zisizo na saini** (kexts), kuhakikisha kwamba nyongeza zilizothibitishwa pekee ndizo zinazoingiliana na kernel ya mfumo.
* **Inazuia ufuatiliaji** wa michakato ya mfumo wa macOS, ikilinda sehemu za msingi za mfumo kutokana na ufikiaji na mabadiliko yasiyoidhinishwa.
* **Inakandamiza zana** kama dtrace kutoka kuangalia michakato ya mfumo, ikilinda zaidi uadilifu wa operesheni ya mfumo.

[**Jifunze zaidi kuhusu taarifa za SIP katika mazungumzo haya**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**

### **SIP related Entitlements**

* `com.apple.rootless.xpc.bootstrap`: Dhibiti launchd
* `com.apple.rootless.install[.heritable]`: Fikia mfumo wa faili
* `com.apple.rootless.kext-management`: `kext_request`
* `com.apple.rootless.datavault.controller`: Simamia UF\_DATAVAULT
* `com.apple.rootless.xpc.bootstrap`: Uwezo wa mipangilio ya XPC
* `com.apple.rootless.xpc.effective-root`: Mizizi kupitia launchd XPC
* `com.apple.rootless.restricted-block-devices`: Ufikiaji wa vifaa vya block vya raw
* `com.apple.rootless.internal.installer-equivalent`: Ufikiaji wa mfumo wa faili bila vizuizi
* `com.apple.rootless.restricted-nvram-variables[.heritable]`: Ufikiaji kamili wa NVRAM
* `com.apple.rootless.storage.label`: Badilisha faili zilizozuiliwa na com.apple.rootless xattr kwa lebo inayofanana
* `com.apple.rootless.volume.VM.label`: Hifadhi VM swap kwenye kiasi

## SIP Bypasses

Kupita SIP kunamwezesha mshambuliaji:

* **Fikia Data ya Mtumiaji**: Soma data nyeti za mtumiaji kama barua, ujumbe, na historia ya Safari kutoka akaunti zote za mtumiaji.
* **TCC Bypass**: Manipulate moja kwa moja hifadhidata ya TCC (Transparency, Consent, and Control) ili kutoa ufikiaji usioidhinishwa kwa kamera, kipaza sauti, na rasilimali nyingine.
* **Kuweka Uthibitisho**: Weka malware katika maeneo yaliyo na ulinzi wa SIP, na kuifanya kuwa sugu kwa kuondolewa, hata kwa ruhusa za mizizi. Hii pia inajumuisha uwezekano wa kuingilia kati Zana ya Kuondoa Malware (MRT).
* **Pakia Nyongeza za Kernel**: Ingawa kuna vizuizi vya ziada, kupita SIP kunarahisisha mchakato wa kupakia nyongeza za kernel zisizo na saini.

### Installer Packages

**Pakiti za installer zilizotiwa saini na cheti cha Apple** zinaweza kupita ulinzi wake. Hii inamaanisha kwamba hata pakiti zilizotiwa saini na waendelezaji wa kawaida zitazuiliwa ikiwa zitajaribu kubadilisha saraka zilizolindwa na SIP.

### Inexistent SIP file

Moja ya mianya inayoweza kutokea ni kwamba ikiwa faili imeainishwa katika **`rootless.conf` lakini haipo kwa sasa**, inaweza kuundwa. Malware inaweza kutumia hii ili **kuweka uthibitisho** kwenye mfumo. Kwa mfano, programu mbaya inaweza kuunda faili ya .plist katika `/System/Library/LaunchDaemons` ikiwa imeorodheshwa katika `rootless.conf` lakini haipo.

### com.apple.rootless.install.heritable

{% hint style="danger" %}
Ruhusa **`com.apple.rootless.install.heritable`** inaruhusu kupita SIP
{% endhint %}

#### [CVE-2019-8561](https://objective-see.org/blog/blog\_0x42.html) <a href="#cve" id="cve"></a>

Iligundulika kwamba ilikuwa inawezekana **kubadilisha pakiti ya installer baada ya mfumo kuthibitisha saini yake** na kisha, mfumo ungeweka pakiti mbaya badala ya asili. Kwa kuwa vitendo hivi vilifanywa na **`system_installd`**, ingekuwa inaruhusu kupita SIP.

#### [CVE-2020–9854](https://objective-see.org/blog/blog\_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Ikiwa pakiti ilipakiwa kutoka picha iliyowekwa au diski ya nje **installer** ingekuwa **inasimamia** binary kutoka **sistema hiyo** (badala ya eneo lililolindwa na SIP), ikifanya **`system_installd`** kuendesha binary isiyo na mpangilio.

#### CVE-2021-30892 - Shrootless

[**Watafiti kutoka kwenye chapisho hili la blog**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) waligundua udhaifu katika mfumo wa Ulinzi wa Uadilifu wa Mfumo (SIP) wa macOS, uliopewa jina la 'Shrootless'. Udhaifu huu unahusiana na **`system_installd`** daemon, ambayo ina ruhusa, **`com.apple.rootless.install.heritable`**, inayoruhusu mchakato wowote wa mtoto kupita vizuizi vya mfumo wa faili vya SIP.

**`system_installd`** daemon itasakinisha pakiti ambazo zimewekwa saini na **Apple**.

Watafiti waligundua kwamba wakati wa usakinishaji wa pakiti iliyotiwa saini na Apple (.pkg file), **`system_installd`** **inaendesha** yoyote **post-install** scripts zilizojumuishwa katika pakiti. Scripts hizi zinaendeshwa na shell ya kawaida, **`zsh`**, ambayo moja kwa moja **inaendesha** amri kutoka kwa **`/etc/zshenv`** faili, ikiwa ipo, hata katika hali isiyo ya mwingiliano. Tabia hii inaweza kutumiwa na washambuliaji: kwa kuunda faili mbaya ya `/etc/zshenv` na kusubiri **`system_installd` itumie `zsh`**, wangeweza kufanya operesheni zisizo na mpangilio kwenye kifaa.

Zaidi ya hayo, iligundulika kwamba **`/etc/zshenv` inaweza kutumika kama mbinu ya shambulio ya jumla**, sio tu kwa kupita SIP. Kila wasifu wa mtumiaji una faili `~/.zshenv`, ambayo inafanya kazi sawa na `/etc/zshenv` lakini haitahitaji ruhusa za mizizi. Faili hii inaweza kutumika kama mbinu ya uthibitisho, ikichochea kila wakati `zsh` inaanza, au kama mbinu ya kupandisha ruhusa. Ikiwa mtumiaji wa admin anapandisha hadi mizizi kwa kutumia `sudo -s` au `sudo <command>`, faili ya `~/.zshenv` itachochewa, ikipandisha hadi mizizi.

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

Katika [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) iligundulika kwamba mchakato sawa wa **`system_installd`** bado unaweza kutumiwa vibaya kwa sababu ilikuwa ikiweka **script ya baada ya usakinishaji ndani ya folda yenye jina la nasibu iliyolindwa na SIP ndani ya `/tmp`**. Jambo ni kwamba **`/tmp` yenyewe haijalindwa na SIP**, hivyo ilikuwa inawezekana **kuiweka** picha **ya virtual juu yake**, kisha **installer** ingekuwa ikiweka script ya **post-install**, **kuondoa** picha ya virtual, **kuunda upya** folda zote na **kuongeza** script ya **post installation** na **payload** ya kutekeleza.

#### [fsck\_cs utility](https://www.theregister.com/2016/03/30/apple\_os\_x\_rootless/)

Udhaifu ulitambuliwa ambapo **`fsck_cs`** ilipotoshwa kuharibu faili muhimu, kutokana na uwezo wake wa kufuata **viungo vya alama**. Kwa hasara, washambuliaji walitengeneza kiungo kutoka _`/dev/diskX`_ hadi faili `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. Kuendesha **`fsck_cs`** kwenye _`/dev/diskX`_ kulisababisha uharibifu wa `Info.plist`. Uadilifu wa faili hii ni muhimu kwa SIP (Ulinzi wa Uadilifu wa Mfumo) wa mfumo wa uendeshaji, ambayo inasimamia upakiaji wa nyongeza za kernel. Mara baada ya kuharibiwa, uwezo wa SIP wa kusimamia uondoaji wa kernel unaharibiwa.

Amri za kutumia udhaifu huu ni:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
The exploitation of this vulnerability has severe implications. The `Info.plist` file, normally responsible for managing permissions for kernel extensions, becomes ineffective. This includes the inability to blacklist certain extensions, such as `AppleHWAccess.kext`. Consequently, with the SIP's control mechanism out of order, this extension can be loaded, granting unauthorized read and write access to the system's RAM.

#### [Mount over SIP protected folders](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Ilikuwa inawezekana kupandisha mfumo mpya wa faili juu ya **SIP protected folders to bypass the protection**.
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog\_0x14.html)

Mfumo umewekwa kuanzisha kutoka kwa picha ya diski ya mfunguo iliyojumuishwa ndani ya `Install macOS Sierra.app` ili kuboresha OS, ikitumia zana ya `bless`. Amri inayotumika ni kama ifuatavyo:
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
The security of this process can be compromised if an attacker alters the upgrade image (`InstallESD.dmg`) before booting. The strategy involves substituting a dynamic loader (dyld) with a malicious version (`libBaseIA.dylib`). This replacement results in the execution of the attacker's code when the installer is initiated.

Usalama wa mchakato huu unaweza kuathiriwa ikiwa mshambuliaji atabadilisha picha ya sasisho (`InstallESD.dmg`) kabla ya kuanzisha. Mkakati huu unahusisha kubadilisha mzigo wa dinamik (dyld) na toleo la uhalifu (`libBaseIA.dylib`). Badiliko hili linapelekea utekelezaji wa msimbo wa mshambuliaji wakati mchakato wa kusakinisha unapoanzishwa.

The attacker's code gains control during the upgrade process, exploiting the system's trust in the installer. The attack proceeds by altering the `InstallESD.dmg` image via method swizzling, particularly targeting the `extractBootBits` method. This allows the injection of malicious code before the disk image is employed.

Msimbo wa mshambuliaji unapata udhibiti wakati wa mchakato wa sasisho, ukitumia imani ya mfumo kwa mchakato wa kusakinisha. Shambulio linaendelea kwa kubadilisha picha ya `InstallESD.dmg` kupitia mbinu ya swizzling, hasa ikilenga mbinu ya `extractBootBits`. Hii inaruhusu sindano ya msimbo wa uhalifu kabla ya picha ya diski kutumika.

Moreover, within the `InstallESD.dmg`, there's a `BaseSystem.dmg`, which serves as the upgrade code's root file system. Injecting a dynamic library into this allows the malicious code to operate within a process capable of altering OS-level files, significantly increasing the potential for system compromise.

Zaidi ya hayo, ndani ya `InstallESD.dmg`, kuna `BaseSystem.dmg`, ambayo inatumika kama mfumo wa faili wa mizizi wa msimbo wa sasisho. Kuingiza maktaba ya dinamik ndani yake inaruhusu msimbo wa uhalifu kufanya kazi ndani ya mchakato unaoweza kubadilisha faili za kiwango cha OS, ikiongeza kwa kiasi kikubwa uwezekano wa kuathiriwa kwa mfumo.

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

In this talk from [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk), it's shown how **`systemmigrationd`** (which can bypass SIP) executes a **bash** and a **perl** script, which can be abused via env variables **`BASH_ENV`** and **`PERL5OPT`**.

Katika mazungumzo haya kutoka [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk), inaonyeshwa jinsi **`systemmigrationd`** (ambayo inaweza kupita SIP) inavyotekeleza **bash** na **perl** script, ambazo zinaweza kutumika vibaya kupitia mabadiliko ya mazingira **`BASH_ENV`** na **`PERL5OPT`**.

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

As [**detailed in this blog post**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), a `postinstall` script from `InstallAssistant.pkg` packages allowed was executing:

Kama [**ilivyoelezwa katika chapisho hili la blog**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), script ya `postinstall` kutoka kwenye pakiti za `InstallAssistant.pkg` iliruhusiwa kutekelezwa:
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
and ilikuw possible kuunda symlink katika `${SHARED_SUPPORT_PATH}/SharedSupport.dmg` ambayo ingemruhusu mtumiaji **kuzuia kikomo chochote, kupita ulinzi wa SIP**.

### **com.apple.rootless.install**

{% hint style="danger" %}
Ruhusa **`com.apple.rootless.install`** inaruhusu kupita SIP
{% endhint %}

Ruhusa `com.apple.rootless.install` inajulikana kupita Ulinzi wa Uadilifu wa Mfumo (SIP) kwenye macOS. Hii ilitajwa kwa kiasi katika uhusiano na [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).

Katika kesi hii maalum, huduma ya mfumo wa XPC iliyoko katika `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` ina ruhusa hii. Hii inaruhusu mchakato unaohusiana kupita vikwazo vya SIP. Zaidi ya hayo, huduma hii inatoa njia ambayo inaruhusu kuhamasisha faili bila kutekeleza hatua zozote za usalama.

## Sealed System Snapshots

Sealed System Snapshots ni kipengele kilichozintroduced na Apple katika **macOS Big Sur (macOS 11)** kama sehemu ya **Ulinzi wa Uadilifu wa Mfumo (SIP)** ili kutoa safu ya ziada ya usalama na utulivu wa mfumo. Kimsingi ni toleo la mfumo wa volume lisiloweza kubadilishwa.

Hapa kuna muonekano wa kina:

1. **Mfumo Usio Badilika**: Sealed System Snapshots hufanya volume ya mfumo wa macOS "isiyoweza kubadilishwa", ikimaanisha kwamba haiwezi kubadilishwa. Hii inazuia mabadiliko yoyote yasiyoidhinishwa au ya bahati mbaya kwa mfumo ambayo yanaweza kuathiri usalama au utulivu wa mfumo.
2. **Maktaba ya Programu za Mfumo**: Unapoweka masasisho au maboresho ya macOS, macOS huunda snapshot mpya ya mfumo. Volume ya kuanzisha ya macOS kisha inatumia **APFS (Apple File System)** kubadilisha kwenda kwenye snapshot hii mpya. Mchakato mzima wa kutekeleza masasisho unakuwa salama zaidi na wa kuaminika kwani mfumo unaweza kila wakati kurudi kwenye snapshot ya awali ikiwa kitu kinakwenda vibaya wakati wa masasisho.
3. **Kutenganisha Data**: Kwa kushirikiana na dhana ya Kutenganisha Data na Mfumo iliyozintroduced katika macOS Catalina, kipengele cha Sealed System Snapshot kinahakikisha kwamba data na mipangilio yako yote huhifadhiwa kwenye volume tofauti ya "**Data**". Kutenganisha hii kunafanya data yako kuwa huru kutoka kwa mfumo, ambayo inarahisisha mchakato wa masasisho ya mfumo na kuimarisha usalama wa mfumo.

Kumbuka kwamba snapshots hizi zinadhibitiwa kiotomatiki na macOS na hazichukui nafasi ya ziada kwenye diski yako, shukrani kwa uwezo wa kushiriki nafasi wa APFS. Pia ni muhimu kutambua kwamba snapshots hizi ni tofauti na **Time Machine snapshots**, ambazo ni nakala za mfumo mzima zinazoweza kufikiwa na mtumiaji.

### Angalia Snapshots

Amri **`diskutil apfs list`** inaorodhesha **maelezo ya volumes za APFS** na mpangilio wao:

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
</strong>|   |   Name:                      Macintosh HD (Case-insensitive)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12.8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Yes (Unlocked)
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
|   Name:                      Macintosh HD - Data (Case-insensitive)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412.1 GB)
</strong>    |   Sealed:                    No
|   FileVault:                 Yes (Unlocked)
</code></pre>

Katika matokeo ya awali inawezekana kuona kwamba **sehemu zinazoweza kufikiwa na mtumiaji** zimewekwa chini ya `/System/Volumes/Data`.

Zaidi ya hayo, **snapshot ya volume ya mfumo wa macOS** imewekwa katika `/` na ni **sealed** (imeandikwa kwa cryptographically na OS). Hivyo, ikiwa SIP itapita na kuibadilisha, **OS haitaanza tena**.

Pia inawezekana **kuhakiki kwamba muhuri umewezeshwa** kwa kukimbia:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Zaidi ya hayo, diski ya snapshot pia imewekwa kama **read-only**:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
