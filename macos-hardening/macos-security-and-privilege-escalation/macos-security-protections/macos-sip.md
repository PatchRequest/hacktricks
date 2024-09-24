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

## **Basiese Inligting**

**Sisteem Integriteit Beskerming (SIP)** in macOS is 'n meganisme wat ontwerp is om selfs die mees bevoorregte gebruikers te verhoed om ongeoorloofde veranderinge aan sleutel sisteem vouers te maak. Hierdie funksie speel 'n belangrike rol in die handhawing van die integriteit van die stelsel deur aksies soos die toevoeging, wysiging of verwydering van lêers in beskermde areas te beperk. Die primêre vouers wat deur SIP beskerm word, sluit in:

* **/System**
* **/bin**
* **/sbin**
* **/usr**

Die reëls wat SIP se gedrag regeer, word gedefinieer in die konfigurasie lêer geleë by **`/System/Library/Sandbox/rootless.conf`**. Binne hierdie lêer word paaie wat met 'n asterisk (\*) voorafgegaan word, as uitsonderings op die andersins streng SIP beperkings aangedui.

Overweeg die voorbeeld hieronder:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Hierdie snit impliseer dat terwyl SIP oor die algemeen die **`/usr`** gids beveilig, daar spesifieke subgidses (`/usr/libexec/cups`, `/usr/local`, en `/usr/share/man`) is waar wysigings toegelaat word, soos aangedui deur die asterisk (\*) wat hul paaie voorafgaan.

Om te verifieer of 'n gids of lêer deur SIP beskerm word, kan jy die **`ls -lOd`** opdrag gebruik om die teenwoordigheid van die **`restricted`** of **`sunlnk`** vlag te kontroleer. Byvoorbeeld:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
In hierdie geval dui die **`sunlnk`** vlag aan dat die `/usr/libexec/cups` gids self **nie verwyder kan word** nie, hoewel lêers daarin geskep, gewysig of verwyder kan word.

Aan die ander kant:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Hierdie **`restricted`** vlag dui aan dat die `/usr/libexec` gids deur SIP beskerm word. In 'n SIP-beskermde gids kan lêers nie geskep, gewysig of verwyder word nie.

Boonop, as 'n lêer die attribuut **`com.apple.rootless`** uitgebreide **attribuut** bevat, sal daardie lêer ook **deur SIP beskerm word**.

{% hint style="success" %}
Let daarop dat die **Sandbox** haak **`hook_vnode_check_setextattr`** enige poging om die uitgebreide attribuut **`com.apple.rootless`** te wysig, voorkom.
{% endhint %}

**SIP beperk ook ander wortel aksies** soos:

* Laai onbetroubare kernuitbreidings
* Kry taak-poorte vir Apple-onderteken prosesse
* Wysig NVRAM veranderlikes
* Laat kernfoutopsporing toe

Opsies word in die nvram veranderlike as 'n bitflag gehou (`csr-active-config` op Intel en `lp-sip0` word van die gebootte toestelboom vir ARM gelees). Jy kan die vlae in die XNU bronskode in `csr.sh` vind:

<figure><img src="../../../.gitbook/assets/image (1192).png" alt=""><figcaption></figcaption></figure>

### SIP Status

Jy kan nagaan of SIP op jou stelsel geaktiveer is met die volgende opdrag:
```bash
csrutil status
```
As jy SIP moet deaktiveer, moet jy jou rekenaar in herstelmodus herbegin (deur Command+R tydens opstart te druk), en dan die volgende opdrag uitvoer:
```bash
csrutil disable
```
As jy SIP aangeskakel wil hou maar die foutopsporing beskerming wil verwyder, kan jy dit doen met:
```bash
csrutil enable --without debug
```
### Ander Beperkings

* **Verbied die laai van ongetekende kernuitbreidings** (kexts), wat verseker dat slegs geverifieerde uitbreidings met die stelselkern interaksie het.
* **Voorkom die debuggery** van macOS-stelselsprosesse, wat kernstelseldelers teen ongemagtigde toegang en wysigings beskerm.
* **Belemmer gereedskap** soos dtrace om stelselsprosesse te inspekteer, wat die integriteit van die stelsel se werking verder beskerm.

[**Leer meer oor SIP-inligting in hierdie praatjie**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**

### **SIP-verwante Regte**

* `com.apple.rootless.xpc.bootstrap`: Beheer launchd
* `com.apple.rootless.install[.heritable]`: Toegang tot lêerstelsel
* `com.apple.rootless.kext-management`: `kext_request`
* `com.apple.rootless.datavault.controller`: Bestuur UF\_DATAVAULT
* `com.apple.rootless.xpc.bootstrap`: XPC-opstelling vermoëns
* `com.apple.rootless.xpc.effective-root`: Root via launchd XPC
* `com.apple.rootless.restricted-block-devices`: Toegang tot rou bloktoestelle
* `com.apple.rootless.internal.installer-equivalent`: Onbeperkte lêerstelseloegang
* `com.apple.rootless.restricted-nvram-variables[.heritable]`: Volledige toegang tot NVRAM
* `com.apple.rootless.storage.label`: Wysig lêers wat deur com.apple.rootless xattr met die ooreenstemmende etiket beperk is
* `com.apple.rootless.volume.VM.label`: Onderhou VM-swap op volume

## SIP Omseilings

Om SIP te omseil stel 'n aanvaller in staat om:

* **Toegang tot Gebruikersdata**: Lees sensitiewe gebruikersdata soos pos, boodskappe en Safari-geskiedenis van alle gebruikersrekeninge.
* **TCC Omseiling**: Direk die TCC (Deursigtigheid, Toestemming en Beheer) databasis manipuleer om ongemagtigde toegang tot die webcam, mikrofoon en ander hulpbronne te verleen.
* **Vestiging van Volharding**: Plaas malware in SIP-beskermde plekke, wat dit bestand maak teen verwydering, selfs deur wortelregte. Dit sluit ook die potensiaal in om met die Malware Removal Tool (MRT) te sloop.
* **Laai Kernuitbreidings**: Alhoewel daar addisionele beskermings is, vereenvoudig die omseiling van SIP die proses om ongetekende kernuitbreidings te laai.

### Installer Pakkette

**Installer pakkette wat met Apple se sertifikaat geteken is** kan sy beskermings omseil. Dit beteken dat selfs pakkette wat deur standaard ontwikkelaars geteken is, geblokkeer sal word as hulle probeer om SIP-beskermde gidse te wysig.

### Nie-bestaande SIP-lêer

Een potensiële leemte is dat as 'n lêer in **`rootless.conf` gespesifiseer word maar tans nie bestaan nie**, dit geskep kan word. Malware kan dit benut om **volharding** op die stelsel te vestig. Byvoorbeeld, 'n kwaadwillige program kan 'n .plist-lêer in `/System/Library/LaunchDaemons` skep as dit in `rootless.conf` gelys is maar nie teenwoordig is nie.

### com.apple.rootless.install.heritable

{% hint style="danger" %}
Die reg **`com.apple.rootless.install.heritable`** stel in staat om SIP te omseil
{% endhint %}

#### [CVE-2019-8561](https://objective-see.org/blog/blog\_0x42.html) <a href="#cve" id="cve"></a>

Dit is ontdek dat dit moontlik was om **die installer-pakket te ruil nadat die stelsel sy kode** handtekening geverifieer het en dan sou die stelsel die kwaadwillige pakket in plaas van die oorspronklike installeer. Aangesien hierdie aksies deur **`system_installd`** uitgevoer is, sou dit SIP omseil.

#### [CVE-2020–9854](https://objective-see.org/blog/blog\_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

As 'n pakket van 'n gemonteerde beeld of eksterne skyf geïnstalleer is, sou die **installer** die binêre van **daardie lêerstelsel** **uitvoer** (in plaas van van 'n SIP-beskermde plek), wat **`system_installd`** dwing om 'n arbitrêre binêre uit te voer.

#### CVE-2021-30892 - Shrootless

[**Navorsers van hierdie blogpos**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) het 'n kwesbaarheid in macOS se Stelselintegriteitsbeskerming (SIP) meganisme ontdek, wat die 'Shrootless' kwesbaarheid genoem word. Hierdie kwesbaarheid sentreer rondom die **`system_installd`** daemon, wat 'n reg het, **`com.apple.rootless.install.heritable`**, wat enige van sy kindprosesse in staat stel om SIP se lêerstelselbeperkings te omseil.

**`system_installd`** daemon sal pakkette installeer wat deur **Apple** geteken is.

Navorsers het gevind dat tydens die installasie van 'n Apple-getekende pakket (.pkg-lêer), **`system_installd`** **uitvoer** enige **post-install** skripte wat in die pakket ingesluit is. Hierdie skripte word deur die standaard skulp, **`zsh`**, uitgevoer, wat outomaties **opdragte** van die **`/etc/zshenv`** lêer uitvoer, indien dit bestaan, selfs in nie-interaktiewe modus. Hierdie gedrag kan deur aanvallers benut word: deur 'n kwaadwillige `/etc/zshenv` lêer te skep en te wag vir **`system_installd` om `zsh`** aan te roep, kan hulle arbitrêre operasies op die toestel uitvoer.

Boonop is ontdek dat **`/etc/zshenv` as 'n algemene aanvalstegniek** gebruik kan word, nie net vir 'n SIP-omseiling nie. Elke gebruikersprofiel het 'n `~/.zshenv` lêer, wat dieselfde gedrag as `/etc/zshenv` vertoon, maar nie wortelregte vereis nie. Hierdie lêer kan as 'n volhardingsmeganisme gebruik word, wat elke keer wat `zsh` begin, geaktiveer word, of as 'n verhoging van regte meganisme. As 'n admin-gebruiker tot wortel verhoog met `sudo -s` of `sudo <opdrag>`, sal die `~/.zshenv` lêer geaktiveer word, wat effektief tot wortel verhoog.

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

In [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) is ontdek dat dieselfde **`system_installd`** proses steeds misbruik kon word omdat dit die **post-install skrip in 'n random naamgegewe gids wat deur SIP beskerm word binne `/tmp`** geplaas het. Die ding is dat **`/tmp` self nie deur SIP beskerm word nie**, so dit was moontlik om 'n **virtuele beeld daarop te monteer**, dan sou die **installer** die **post-install skrip** daar plaas, **ontmonteer** die virtuele beeld, **herstel** al die **gidse** en **voeg** die **post-installasie** skrip met die **payload** om uit te voer.

#### [fsck\_cs nut](https://www.theregister.com/2016/03/30/apple\_os\_x\_rootless/)

'n Kwesbaarheid is geïdentifiseer waar **`fsck_cs`** mislei is om 'n belangrike lêer te korrupteer, as gevolg van sy vermoë om **simboliese skakels** te volg. Spesifiek het aanvallers 'n skakel van _`/dev/diskX`_ na die lêer `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist` geskep. Die uitvoering van **`fsck_cs`** op _`/dev/diskX`_ het gelei tot die korrupsie van `Info.plist`. Die integriteit van hierdie lêer is noodsaaklik vir die bedryfstelsel se SIP (Stelselintegriteitsbeskerming), wat die laai van kernuitbreidings beheer. Sodra dit gekorrumpeer is, is SIP se vermoë om kernuitsluitings te bestuur, gecompromitteer.

Die opdragte om hierdie kwesbaarheid te benut is:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Die uitbuiting van hierdie kwesbaarheid het ernstige implikasies. Die `Info.plist`-lêer, wat normaalweg verantwoordelik is vir die bestuur van toestemmings vir kernuitbreidings, word ondoeltreffend. Dit sluit die onvermoë in om sekere uitbreidings, soos `AppleHWAccess.kext`, op 'n swartlys te plaas. Gevolglik, met die SIP se beheermeganisme buite werking, kan hierdie uitbreiding gelaai word, wat ongeoorloofde lees- en skryftoegang tot die stelsels se RAM bied.

#### [Mount oor SIP beskermde vouers](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Dit was moontlik om 'n nuwe lêerstelsel oor **SIP beskermde vouers te monteer om die beskerming te omseil**.
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Opgradering omseiling (2016)](https://objective-see.org/blog/blog\_0x14.html)

Die stelsel is ingestel om te boot vanaf 'n ingebedde installer skyfbeeld binne die `Install macOS Sierra.app` om die OS op te gradeer, met die gebruik van die `bless` nut. Die opdrag wat gebruik word is soos volg:
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Die sekuriteit van hierdie proses kan gecompromitteer word as 'n aanvaller die opgradering beeld (`InstallESD.dmg`) voor die opstart verander. Die strategie behels die vervanging van 'n dinamiese laaier (dyld) met 'n kwaadwillige weergawe (`libBaseIA.dylib`). Hierdie vervanging lei tot die uitvoering van die aanvaller se kode wanneer die installeerder geaktiveer word.

Die aanvaller se kode verkry beheer tydens die opgraderingsproses, wat die stelsel se vertroue in die installeerder benut. Die aanval vorder deur die `InstallESD.dmg` beeld te verander via metode swizzling, met spesifieke fokus op die `extractBootBits` metode. Dit stel die inspuiting van kwaadwillige kode voor die gebruik van die skyfbeeld in staat.

Boonop, binne die `InstallESD.dmg`, is daar 'n `BaseSystem.dmg`, wat as die wortel lêer stelsel van die opgradering kode dien. Die inspuiting van 'n dinamiese biblioteek hierin stel die kwaadwillige kode in staat om binne 'n proses te werk wat in staat is om OS-vlak lêers te verander, wat die potensiaal vir stelselskompromie aansienlik verhoog.

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

In hierdie praatjie van [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk), word gewys hoe **`systemmigrationd`** (wat SIP kan omseil) 'n **bash** en 'n **perl** skrip uitvoer, wat misbruik kan word via omgewing veranderlikes **`BASH_ENV`** en **`PERL5OPT`**.

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

Soos [**in hierdie blogpos gedetailleerd**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), het 'n `postinstall` skrip van `InstallAssistant.pkg` pakkette toegelaat om uit te voer:
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
and dit was moontlik om 'n symlink in `${SHARED_SUPPORT_PATH}/SharedSupport.dmg` te skep wat 'n gebruiker in staat sou stel om **enige lêer te ontneem, wat SIP-beskerming omseil**.

### **com.apple.rootless.install**

{% hint style="danger" %}
Die regte **`com.apple.rootless.install`** maak dit moontlik om SIP te omseil
{% endhint %}

Die regte `com.apple.rootless.install` is bekend om die Stelsels Integriteit Beskerming (SIP) op macOS te omseil. Dit is veral genoem in verband met [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).

In hierdie spesifieke geval het die stelsel XPC-diens geleë by `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` hierdie regte. Dit stel die verwante proses in staat om SIP-beperkings te omseil. Verder bied hierdie diens 'n metode wat die beweging van lêers toelaat sonder om enige sekuriteitsmaatreëls af te dwing.

## Geseëlde Stelsel Snapshot

Geseëlde Stelsel Snapshots is 'n kenmerk wat deur Apple in **macOS Big Sur (macOS 11)** bekendgestel is as deel van sy **Stelsels Integriteit Beskerming (SIP)** meganisme om 'n bykomende laag van sekuriteit en stelsels stabiliteit te bied. Hulle is essensieel lees-slegs weergawes van die stelselvolume.

Hier is 'n meer gedetailleerde kyk:

1. **Onveranderlike Stelsel**: Geseëlde Stelsel Snapshots maak die macOS stelselvolume "onveranderlik", wat beteken dat dit nie gewysig kan word nie. Dit voorkom enige ongeoorloofde of toevallige veranderinge aan die stelsel wat sekuriteit of stelsels stabiliteit kan benadeel.
2. **Stelsel Sagteware Opdaterings**: Wanneer jy macOS-opdaterings of opgraderings installeer, skep macOS 'n nuwe stelselsnapshot. Die macOS opstartvolume gebruik dan **APFS (Apple File System)** om na hierdie nuwe snapshot oor te skakel. Die hele proses van die toepas van opdaterings word veiliger en meer betroubaar aangesien die stelsel altyd na die vorige snapshot kan terugkeer as iets verkeerd gaan tydens die opdatering.
3. **Data Skeiding**: In samewerking met die konsep van Data en Stelsel volume skeiding wat in macOS Catalina bekendgestel is, maak die Geseëlde Stelsel Snapshot kenmerk seker dat al jou data en instellings op 'n aparte "**Data**" volume gestoor word. Hierdie skeiding maak jou data onafhanklik van die stelsel, wat die proses van stelselsopdaterings vereenvoudig en stelsels sekuriteit verbeter.

Onthou dat hierdie snapshots outomaties deur macOS bestuur word en nie addisionele spasie op jou skyf opneem nie, danksy die spasie deel vermoëns van APFS. Dit is ook belangrik om te noem dat hierdie snapshots verskillend is van **Time Machine snapshots**, wat gebruikers-toeganklike rugsteun van die hele stelsel is.

### Kontroleer Snapshots

Die opdrag **`diskutil apfs list`** lys die **besonderhede van die APFS volumes** en hul uitleg:

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

In die vorige uitvoer is dit moontlik om te sien dat **gebruikers-toeganklike plekke** gemonteer is onder `/System/Volumes/Data`.

Boonop is die **macOS Stelsel volume snapshot** gemonteer in `/` en dit is **geseal** (kriptografies onderteken deur die OS). So, as SIP omseil word en dit gewysig word, sal die **OS nie meer opstart nie**.

Dit is ook moontlik om te **verifieer dat die seël geaktiveer is** deur te loop:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Boonop is die snapshot skyf ook as **slegs-lees** gemonteer:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsieplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
