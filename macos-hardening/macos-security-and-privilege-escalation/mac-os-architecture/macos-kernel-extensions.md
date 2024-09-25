# macOS Kernel Extensions

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

## Basic Information

Kernel extensies (Kexts) is **pakkette** met 'n **`.kext`** uitbreiding wat **direk in die macOS-kernruimte gelaai** word, wat bykomende funksionaliteit aan die hoofbedryfstelsel bied.

### Requirements

Dit is duidelik dat dit so kragtig is dat dit **gekompliseerd is om 'n kernuitbreiding te laai**. Dit is die **vereistes** waaraan 'n kernuitbreiding moet voldoen om gelaai te word:

* Wanneer **herstelmodus betree** word, moet kern **uitbreidings toegelaat** word om gelaai te word:

<figure><img src="../../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

* Die kernuitbreiding moet **onderteken wees met 'n kernkode-ondertekeningssertifikaat**, wat slegs **deur Apple** toegestaan kan word. Wie die maatskappy en die redes waarom dit nodig is, in detail sal hersien.
* Die kernuitbreiding moet ook **notarized** wees, Apple sal dit vir malware kan nagaan.
* Dan is die **root** gebruiker die een wat die **kernuitbreiding kan laai** en die lêers binne die pakket moet **aan root behoort**.
* Tydens die oplaadproses moet die pakket in 'n **beskermde nie-root ligging** voorberei word: `/Library/StagedExtensions` (vereis die `com.apple.rootless.storage.KernelExtensionManagement` grant).
* Laastens, wanneer daar probeer word om dit te laai, sal die gebruiker [**'n bevestigingsversoek ontvang**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) en, indien aanvaar, moet die rekenaar **herbegin** word om dit te laai.

### Loading process

In Catalina was dit soos volg: Dit is interessant om op te let dat die **verifikasie** proses in **gebruikersland** plaasvind. Dit is egter slegs toepassings met die **`com.apple.private.security.kext-management`** grant wat die **kern kan vra om 'n uitbreiding te laai**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **begin** die **verifikasie** proses om 'n uitbreiding te laai
* Dit sal met **`kextd`** praat deur 'n **Mach-diens** te gebruik.
2. **`kextd`** sal verskeie dinge nagaan, soos die **handtekening**
* Dit sal met **`syspolicyd`** praat om te **kontroleer** of die uitbreiding gelaai kan word.
3. **`syspolicyd`** sal die **gebruiker** **vra** as die uitbreiding nie voorheen gelaai is nie.
* **`syspolicyd`** sal die resultaat aan **`kextd`** rapporteer
4. **`kextd`** sal uiteindelik in staat wees om die **kern te sê om** die uitbreiding te laai

As **`kextd`** nie beskikbaar is nie, kan **`kextutil`** dieselfde kontroles uitvoer.

### Enumeration (loaded kexts)
```bash
# Get loaded kernel extensions
kextstat

# Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
## Kernelcache

{% hint style="danger" %}
Alhoewel die kernel uitbreidings verwag word om in `/System/Library/Extensions/` te wees, as jy na hierdie gids gaan, **sal jy geen binêre vind**. Dit is as gevolg van die **kernelcache** en om een `.kext` te reverseer, moet jy 'n manier vind om dit te verkry.
{% endhint %}

Die **kernelcache** is 'n **vooraf-gecompileerde en vooraf-gekoppelde weergawe van die XNU-kern**, saam met noodsaaklike toestel **drywers** en **kernel uitbreidings**. Dit word in 'n **gecomprimeerde** formaat gestoor en word tydens die opstartproses in geheue gedecomprimeer. Die kernelcache fasiliteer 'n **sneller opstarttyd** deur 'n gereed-om-te-loop weergawe van die kern en belangrike drywers beskikbaar te hê, wat die tyd en hulpbronne verminder wat andersins aan die dinamiese laai en koppeling van hierdie komponente tydens opstart bestee sou word.

### Plaaslike Kernelcache

In iOS is dit geleë in **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** in macOS kan jy dit vind met: **`find / -name "kernelcache" 2>/dev/null`** \
In my geval in macOS het ek dit gevind in:

* `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

Die IMG4 lêerformaat is 'n houerformaat wat deur Apple in sy iOS en macOS toestelle gebruik word om firmware komponente veilig te **stoor en te verifieer** (soos **kernelcache**). Die IMG4 formaat sluit 'n kop en verskeie etikette in wat verskillende stukke data kapsuleer, insluitend die werklike payload (soos 'n kern of opstartlader), 'n handtekening, en 'n stel manifest eienskappe. Die formaat ondersteun kriptografiese verifikasie, wat die toestel toelaat om die egtheid en integriteit van die firmware komponent te bevestig voordat dit uitgevoer word.

Dit bestaan gewoonlik uit die volgende komponente:

* **Payload (IM4P)**:
* Gereeld gecomprimeer (LZFSE4, LZSS, …)
* Opsioneel versleuteld
* **Manifest (IM4M)**:
* Bevat Handtekening
* Bykomende Sleutel/Waarde woordeboek
* **Herstel Inligting (IM4R)**:
* Ook bekend as APNonce
* Voorkom die herhaling van sommige opdaterings
* OPSIONEEL: Gewoonlik word dit nie gevind nie

Decompress die Kernelcache:
```bash
# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Laai af&#x20;

* [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

In [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) is dit moontlik om al die kernel debug kits te vind. Jy kan dit aflaai, monteer, dit oopmaak met die [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html) hulpmiddel, toegang verkry tot die **`.kext`** gids en **uit te trek**.

Kontroleer dit vir simbole met:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
* [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Soms vry Apple **kernelcache** met **symbols**. Jy kan 'n paar firmware met symbols aflaai deur die skakels op daardie bladsye te volg. Die firmwares sal die **kernelcache** saam met ander lêers bevat.

Om die lêers te **onttrek**, begin deur die uitbreiding van `.ipsw` na `.zip` te verander en dit te **ontpak**.

Na die ontrekking van die firmware sal jy 'n lêer soos: **`kernelcache.release.iphone14`** kry. Dit is in **IMG4** formaat, jy kan die interessante inligting onttrek met:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:** 

{% code overflow="wrap" %}
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
{% endcode %}

[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Inspecting kernelcache

Kontroleer of die kernelcache simbole het met
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
Met dit kan ons nou **alle uitbreidings** of die **een waarin jy belangstel** **onttrek:**
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## Verwysings

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

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
