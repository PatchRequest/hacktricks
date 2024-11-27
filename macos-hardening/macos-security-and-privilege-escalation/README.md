# macOS Sekuriteit & Privilege Escalation

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Sluit aan by [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) bediener om te kommunikeer met ervare hackers en bug bounty jagters!

**Hacking Inligting**\
Betrek met inhoud wat die opwinding en uitdagings van hacking ondersoek

**Regte Tyd Hack Nuus**\
Bly op hoogte van die vinnig bewegende hacking wêreld deur regte tyd nuus en insigte

**Laaste Aankondigings**\
Bly ingelig oor die nuutste bug bounties wat bekendgestel word en belangrike platform opdaterings

**Sluit aan by ons op** [**Discord**](https://discord.com/invite/N3FrSbmwdy) en begin vandag saamwerk met top hackers!

## Basiese MacOS

As jy nie bekend is met macOS nie, moet jy begin om die basiese beginsels van macOS te leer:

* Spesiale macOS **lêers & toestemmings:**

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* Algemene macOS **gebruikers**

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* Die **argitektuur** van die k**ernel**

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Algemene macOS n**etwerk dienste & protokolle**

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
* Om 'n `tar.gz` te aflaai, verander 'n URL soos [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) na [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

In maatskappye gaan **macOS** stelsels hoogs waarskynlik **bestuur word met 'n MDM**. Daarom is dit vanuit die perspektief van 'n aanvaller interessant om te weet **hoe dit werk**:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - Inspekteer, Debugeer en Fuzz

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## MacOS Sekuriteit Beskermings

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Aanvaloppervlak

### Lêertoestemmings

As 'n **proses wat as root loop 'n lêer skryf** wat deur 'n gebruiker beheer kan word, kan die gebruiker dit misbruik om **privileges te verhoog**.\
Dit kan in die volgende situasies gebeur:

* Lêer wat gebruik is, is reeds deur 'n gebruiker geskep (besit deur die gebruiker)
* Lêer wat gebruik is, is skryfbaar deur die gebruiker as gevolg van 'n groep
* Lêer wat gebruik is, is binne 'n gids besit deur die gebruiker (die gebruiker kan die lêer skep)
* Lêer wat gebruik is, is binne 'n gids besit deur root, maar die gebruiker het skryftoegang daaroor as gevolg van 'n groep (die gebruiker kan die lêer skep)

In staat wees om 'n **lêer te skep** wat gaan **gebruik word deur root**, laat 'n gebruiker toe om **voordeel te trek uit sy inhoud** of selfs **symlinks/hardlinks** te skep om dit na 'n ander plek te wys.

Vir hierdie soort kwesbaarhede, moenie vergeet om **kwesbare `.pkg` installers** te kontroleer nie:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}

### Lêeruitbreiding & URL skema app handlers

Vreemde apps geregistreer deur lêeruitbreidings kan misbruik word en verskillende toepassings kan geregistreer word om spesifieke protokolle te open

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## macOS TCC / SIP Privilege Escalation

In macOS **toepassings en lêers kan toestemmings hê** om toegang te verkry tot gidsen of instellings wat hulle meer bevoorreg maak as ander.

Daarom, 'n aanvaller wat suksesvol 'n macOS masjien wil kompromitteer, sal moet **sy TCC privileges verhoog** (of selfs **SIP omseil**, afhangende van sy behoeftes).

Hierdie privileges word gewoonlik gegee in die vorm van **entitlements** waarmee die toepassing onderteken is, of die toepassing mag sekere toegang versoek het en nadat die **gebruiker dit goedgekeur het**, kan dit in die **TCC databasisse** gevind word. 'n Ander manier waarop 'n proses hierdie privileges kan verkry, is deur 'n **kind van 'n proses** met daardie **privileges** te wees, aangesien dit gewoonlik **geërf** word.

Volg hierdie skakels om verskillende maniere te vind om [**privileges in TCC te verhoog**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), om [**TCC te omseil**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) en hoe in die verlede [**SIP omseil is**](macos-security-protections/macos-sip.md#sip-bypasses).

## macOS Tradisionele Privilege Escalation

Natuurlik, vanuit 'n rooi span perspektief, moet jy ook belangstel om na root te verhoog. Kyk na die volgende pos vir 'n paar wenke:

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}

## macOS Nakoming

* [https://github.com/usnistgov/macos\_security](https://github.com/usnistgov/macos_security)

## Verwysings

* [**OS X Voorval Respons: Scripting en Analise**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Sluit aan by [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) bediener om te kommunikeer met ervare hackers en bug bounty jagters!

**Hacking Inligting**\
Betrek met inhoud wat die opwinding en uitdagings van hacking ondersoek

**Regte Tyd Hack Nuus**\
Bly op hoogte van die vinnig bewegende hacking wêreld deur regte tyd nuus en insigte

**Laaste Aankondigings**\
Bly ingelig oor die nuutste bug bounties wat bekendgestel word en belangrike platform opdaterings

**Sluit aan by ons op** [**Discord**](https://discord.com/invite/N3FrSbmwdy) en begin vandag saamwerk met top hackers!

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
