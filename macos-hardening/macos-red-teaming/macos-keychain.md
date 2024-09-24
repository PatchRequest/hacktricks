# macOS Sleutelhanger

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Hoof Sleutelhangers

* Die **Gebruiker Sleutelhanger** (`~/Library/Keychains/login.keychain-db`), wat gebruik word om **gebruiker-spesifieke akrediteer** soos toepassingswagwoorde, internetwagwoorde, gebruiker-gegenereerde sertifikate, netwerkwagwoorde, en gebruiker-gegenereerde publieke/privaat sleutels te stoor.
* Die **Stelsel Sleutelhanger** (`/Library/Keychains/System.keychain`), wat **stelsel-wye akrediteer** soos WiFi wagwoorde, stelsel wortelsertifikate, stelsel privaat sleutels, en stelsel toepassingswagwoorde stoor.
* Dit is moontlik om ander komponente soos sertifikate in `/System/Library/Keychains/*` te vind.
* In **iOS** is daar slegs een **Sleutelhanger** geleë in `/private/var/Keychains/`. Hierdie gids bevat ook databasisse vir die `TrustStore`, sertifikaatowerhede (`caissuercache`) en OSCP inskrywings (`ocspache`).
* Toepassings sal in die sleutelhanger beperk wees tot hul private area gebaseer op hul toepassingsidentifiseerder.

### Wagwoord Sleutelhanger Toegang

Hierdie lêers, terwyl hulle nie inherente beskerming het nie en **afgelaai** kan word, is versleuteld en vereis die **gebruiker se platte wagwoord om ontcijfer** te word. 'n Gereedskap soos [**Chainbreaker**](https://github.com/n0fate/chainbreaker) kan gebruik word vir ontcijfering.

## Sleutelhanger Inskrywings Beskerming

### ACLs

Elke inskrywing in die sleutelhanger word gereguleer deur **Toegang Beheer Lyste (ACLs)** wat bepaal wie verskillende aksies op die sleutelhanger inskrywing kan uitvoer, insluitend:

* **ACLAuhtorizationExportClear**: Laat die houer toe om die duidelike teks van die geheim te verkry.
* **ACLAuhtorizationExportWrapped**: Laat die houer toe om die duidelike teks wat met 'n ander verskafde wagwoord versleuteld is, te verkry.
* **ACLAuhtorizationAny**: Laat die houer toe om enige aksie uit te voer.

Die ACLs word verder vergesel deur 'n **lys van vertroude toepassings** wat hierdie aksies kan uitvoer sonder om te vra. Dit kan wees:

* **N`il`** (geen toestemming vereis, **elkeen is vertrou**)
* 'n **leë** lys (**niemand** is vertrou)
* **Lys** van spesifieke **toepassings**.

Ook kan die inskrywing die sleutel **`ACLAuthorizationPartitionID`** bevat, wat gebruik word om die **teamid, apple,** en **cdhash** te identifiseer.

* As die **teamid** gespesifiseer is, dan om die **inskrywing** waarde **sonder** 'n **prompt** te **toegang**, moet die gebruikte toepassing die **selfde teamid** hê.
* As die **apple** gespesifiseer is, dan moet die app **onderteken** wees deur **Apple**.
* As die **cdhash** aangedui is, dan moet die **app** die spesifieke **cdhash** hê.

### Skep 'n Sleutelhanger Inskrywing

Wanneer 'n **nuwe** **inskrywing** geskep word met **`Keychain Access.app`**, geld die volgende reëls:

* Alle apps kan versleuteld.
* **Geen apps** kan uitvoer/ontcijfer (sonder om die gebruiker te vra).
* Alle apps kan die integriteitskontrole sien.
* Geen apps kan ACLs verander nie.
* Die **partitionID** is gestel op **`apple`**.

Wanneer 'n **toepassing 'n inskrywing in die sleutelhanger skep**, is die reëls effens anders:

* Alle apps kan versleuteld.
* Slegs die **skepende toepassing** (of enige ander apps wat eksplisiet bygevoeg is) kan uitvoer/ontcijfer (sonder om die gebruiker te vra).
* Alle apps kan die integriteitskontrole sien.
* Geen apps kan die ACLs verander nie.
* Die **partitionID** is gestel op **`teamid:[teamID hier]`**.

## Toegang tot die Sleutelhanger

### `security`
```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

{% hint style="success" %}
Die **keychain enumerasie en dumping** van geheime wat **nie 'n prompt sal genereer nie** kan gedoen word met die hulpmiddel [**LockSmith**](https://github.com/its-a-feature/LockSmith)

Ander API eindpunte kan gevind word in [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity\_keychain/libsecurity\_keychain-55017/lib/SecKeychain.h.auto.html) bronkode.
{% endhint %}

Lys en kry **inligting** oor elke keychain inskrywing met die **Security Framework** of jy kan ook die Apple se oopbron cli hulpmiddel [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Sommige API voorbeelde:

* Die API **`SecItemCopyMatching`** gee inligting oor elke inskrywing en daar is 'n paar eienskappe wat jy kan stel wanneer jy dit gebruik:
* **`kSecReturnData`**: As waar, sal dit probeer om die data te ontsleutel (stel op vals om potensiële pop-ups te vermy)
* **`kSecReturnRef`**: Kry ook verwysing na keychain item (stel op waar in geval jy later sien jy kan ontsleutel sonder pop-up)
* **`kSecReturnAttributes`**: Kry metadata oor inskrywings
* **`kSecMatchLimit`**: Hoeveel resultate om terug te gee
* **`kSecClass`**: Watter soort keychain inskrywing

Kry **ACLs** van elke inskrywing:

* Met die API **`SecAccessCopyACLList`** kan jy die **ACL vir die keychain item** kry, en dit sal 'n lys van ACLs teruggee (soos `ACLAuhtorizationExportClear` en die ander voorheen genoem) waar elke lys het:
* Beskrywing
* **Vertroude Toepassing Lys**. Dit kan wees:
* 'n app: /Applications/Slack.app
* 'n binêre: /usr/libexec/airportd
* 'n groep: group://AirPort

Eksporteer die data:

* Die API **`SecKeychainItemCopyContent`** kry die platte teks
* Die API **`SecItemExport`** eksporteer die sleutels en sertifikate maar jy mag dalk wagwoorde moet stel om die inhoud versleuteld te eksporteer

En dit is die **vereistes** om 'n **geheim sonder 'n prompt** te kan **eksporteer**:

* As **1+ vertroude** apps gelys:
* Nodig die toepaslike **autorisaties** (**`Nil`**, of wees **deel** van die toegelate lys van apps in die autorisasie om toegang tot die geheime inligting te verkry)
* Nodig kodehandtekening om te pas by **PartitionID**
* Nodig kodehandtekening om te pas by een **vertroude app** (of wees 'n lid van die regte KeychainAccessGroup)
* As **alle toepassings vertrou**:
* Nodig die toepaslike **autorisaties**
* Nodig kodehandtekening om te pas by **PartitionID**
* As **geen PartitionID**, dan is dit nie nodig nie

{% hint style="danger" %}
Daarom, as daar **1 toepassing gelys** is, moet jy **kode in daardie toepassing inspuit**.

As **apple** aangedui word in die **partitionID**, kan jy dit met **`osascript`** benader, so enigiets wat al die toepassings met apple in die partitionID vertrou. **`Python`** kan ook hiervoor gebruik word.
{% endhint %}

### Twee addisionele eienskappe

* **Onsigbaar**: Dit is 'n booleaanse vlag om die inskrywing van die **UI** Keychain app te **versteek**
* **Algemeen**: Dit is om **metadata** te stoor (so dit is NIE VERSPREKELD nie)
* Microsoft het al die verfrissingstokens in platte teks gestoor om toegang tot sensitiewe eindpunte te verkry.

## References

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
