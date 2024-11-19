# macOS Bezbednost & Eskalacija Privilegija

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Pridružite se [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) serveru da komunicirate sa iskusnim hakerima i lovcima na greške!

**Hakerski Uvidi**\
Uključite se u sadržaj koji istražuje uzbuđenje i izazove hakovanja

**Vesti o Haku u Realnom Vremenu**\
Budite u toku sa brzim svetom hakovanja kroz vesti i uvide u realnom vremenu

**Najnovija Obaveštenja**\
Budite informisani o najnovijim nagradama za greške i ključnim ažuriranjima platforme

**Pridružite nam se na** [**Discordu**](https://discord.com/invite/N3FrSbmwdy) i počnite da sarađujete sa vrhunskim hakerima danas!

## Osnovni MacOS

Ako niste upoznati sa macOS, trebali biste početi da učite osnove macOS-a:

* Specijalni macOS **fajlovi i dozvole:**

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* Uobičajeni macOS **korisnici**

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* **Arhitektura** k**ernel-a**

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Uobičajene macOS n**etwork usluge i protokoli**

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **Otvoreni kod** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
* Da preuzmete `tar.gz`, promenite URL kao [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) u [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

U kompanijama **macOS** sistemi će verovatno biti **upravljani putem MDM-a**. Stoga, iz perspektive napadača, zanimljivo je znati **kako to funkcioniše**:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - Istraživanje, Debagovanje i Fuzzing

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## MacOS Bezbednosne Zaštite

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Površina Napada

### Dozvole Fajlova

Ako **proces koji se izvršava kao root piše** fajl koji može kontrolisati korisnik, korisnik bi to mogao zloupotrebiti da **escalira privilegije**.\
To se može dogoditi u sledećim situacijama:

* Fajl koji se koristi je već kreiran od strane korisnika (u vlasništvu korisnika)
* Fajl koji se koristi je zapisiv od strane korisnika zbog grupe
* Fajl koji se koristi je unutar direktorijuma koji je u vlasništvu korisnika (korisnik može kreirati fajl)
* Fajl koji se koristi je unutar direktorijuma koji je u vlasništvu root-a, ali korisnik ima pristup za pisanje zbog grupe (korisnik može kreirati fajl)

Mogućnost da **kreirate fajl** koji će biti **koristen od strane root-a**, omogućava korisniku da **iskoristi njegov sadržaj** ili čak kreira **symlinks/hardlinks** da ga usmeri na drugo mesto.

Za ovu vrstu ranjivosti ne zaboravite da **proverite ranjive `.pkg` instalere**:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}

### Ekstenzije Fajlova & URL sheme aplikacija

Čudne aplikacije registrovane po ekstenzijama fajlova mogle bi biti zloupotrebljene, a različite aplikacije mogu biti registrovane da otvore specifične protokole

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## macOS TCC / SIP Eskalacija Privilegija

U macOS **aplikacije i binarni fajlovi mogu imati dozvole** za pristup folderima ili podešavanjima koja ih čine privilegovanijim od drugih.

Stoga, napadač koji želi uspešno da kompromituje macOS mašinu moraće da **escalira svoje TCC privilegije** (ili čak **obiđe SIP**, u zavisnosti od njegovih potreba).

Ove privilegije se obično daju u obliku **entitlements** sa kojima je aplikacija potpisana, ili aplikacija može zatražiti neka pristupanja i nakon što **korisnik odobri** mogu se naći u **TCC bazama podataka**. Drugi način na koji proces može dobiti ove privilegije je da bude **dete procesa** sa tim **privilegijama** jer se obično **nasleđuju**.

Pratite ove linkove da pronađete različite načine za [**escalaciju privilegija u TCC**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), da [**obiđete TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) i kako je u prošlosti [**SIP bio zaobiđen**](macos-security-protections/macos-sip.md#sip-bypasses).

## macOS Tradicionalna Eskalacija Privilegija

Naravno, iz perspektive crvenih timova, trebali biste biti zainteresovani i za eskalaciju na root. Proverite sledeći post za neke savete:

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}

## macOS Usklađenost

* [https://github.com/usnistgov/macos\_security](https://github.com/usnistgov/macos\_security)

## Reference

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="/.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Pridružite se [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) serveru da komunicirate sa iskusnim hakerima i lovcima na greške!

**Hakerski Uvidi**\
Uključite se u sadržaj koji istražuje uzbuđenje i izazove hakovanja

**Vesti o Haku u Realnom Vremenu**\
Budite u toku sa brzim svetom hakovanja kroz vesti i uvide u realnom vremenu

**Najnovija Obaveštenja**\
Budite informisani o najnovijim nagradama za greške i ključnim ažuriranjima platforme

**Pridružite nam se na** [**Discordu**](https://discord.com/invite/N3FrSbmwdy) i počnite da sarađujete sa vrhunskim hakerima danas!

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
