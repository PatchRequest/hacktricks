# macOS Keychain

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Main Keychains

* **Korisnički ključ** (`~/Library/Keychains/login.keychain-db`), koji se koristi za čuvanje **korisničkih kredencijala** kao što su lozinke za aplikacije, lozinke za internet, korisnički generisani sertifikati, lozinke za mrežu i korisnički generisani javni/privatni ključevi.
* **Sistemski ključ** (`/Library/Keychains/System.keychain`), koji čuva **sistemske kredencijale** kao što su WiFi lozinke, sistemski root sertifikati, sistemski privatni ključevi i lozinke za sistemske aplikacije.
* Mogu se pronaći i drugi sastavni delovi kao što su sertifikati u `/System/Library/Keychains/*`
* U **iOS-u** postoji samo jedan **ključ** smešten u `/private/var/Keychains/`. Ova fascikla takođe sadrži baze podataka za `TrustStore`, sertifikacione autoritete (`caissuercache`) i OSCP unose (`ocspache`).
* Aplikacije će biti ograničene u ključu samo na njihovu privatnu oblast na osnovu njihovog identifikatora aplikacije.

### Pristup lozinkama u ključu

Ove datoteke, iako nemaju inherentnu zaštitu i mogu se **preuzeti**, su enkriptovane i zahtevaju **korisničku lozinku u čistom tekstu za dekripciju**. Alat kao što je [**Chainbreaker**](https://github.com/n0fate/chainbreaker) može se koristiti za dekripciju.

## Zaštita unosa u ključ

### ACLs

Svaki unos u ključu je regulisan **Listama kontrole pristupa (ACLs)** koje određuju ko može da izvrši različite radnje na unosu u ključ, uključujući:

* **ACLAuhtorizationExportClear**: Omogućava nosiocu da dobije čist tekst tajne.
* **ACLAuhtorizationExportWrapped**: Omogućava nosiocu da dobije čist tekst enkriptovan drugom datom lozinkom.
* **ACLAuhtorizationAny**: Omogućava nosiocu da izvrši bilo koju radnju.

ACL-ovi su dodatno praćeni **listom pouzdanih aplikacija** koje mogu izvršiti ove radnje bez traženja potvrde. Ovo može biti:

* **N`il`** (nije potrebna autorizacija, **svi su pouzdani**)
* **Prazna** lista (**niko** nije pouzdan)
* **Lista** specifičnih **aplikacija**.

Takođe, unos može sadržati ključ **`ACLAuthorizationPartitionID`,** koji se koristi za identifikaciju **teamid, apple,** i **cdhash.**

* Ako je **teamid** specificiran, tada da bi se **pristupilo** vrednosti unosa **bez** **potvrde** korišćena aplikacija mora imati **isti teamid**.
* Ako je **apple** specificiran, tada aplikacija mora biti **potpisana** od strane **Apple-a**.
* Ako je **cdhash** naznačen, tada **aplikacija** mora imati specifični **cdhash**.

### Kreiranje unosa u ključ

Kada se **novi** **unos** kreira koristeći **`Keychain Access.app`**, sledeća pravila se primenjuju:

* Sve aplikacije mogu enkriptovati.
* **Nijedna aplikacija** ne može izvesti/dekripovati (bez traženja potvrde od korisnika).
* Sve aplikacije mogu videti proveru integriteta.
* Nijedna aplikacija ne može menjati ACL-ove.
* **partitionID** je postavljen na **`apple`**.

Kada **aplikacija kreira unos u ključ**, pravila su malo drugačija:

* Sve aplikacije mogu enkriptovati.
* Samo **aplikacija koja kreira** (ili bilo koja druga aplikacija eksplicitno dodata) može izvesti/dekripovati (bez traženja potvrde od korisnika).
* Sve aplikacije mogu videti proveru integriteta.
* Nijedna aplikacija ne može menjati ACL-ove.
* **partitionID** je postavljen na **`teamid:[teamID ovde]`**.

## Pristupanje ključu

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
**Enumeracija i iskopavanje** tajni koje **neće generisati prompt** može se uraditi pomoću alata [**LockSmith**](https://github.com/its-a-feature/LockSmith)

Ostali API krajnji tačke mogu se naći u [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity\_keychain/libsecurity\_keychain-55017/lib/SecKeychain.h.auto.html) izvorni kod.
{% endhint %}

Lista i dobijanje **informacija** o svakom unosu u keychain koristeći **Security Framework** ili možete proveriti i Apple-ov open source cli alat [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Neki primeri API-ja:

* API **`SecItemCopyMatching`** daje informacije o svakom unosu i postoje neki atributi koje možete postaviti prilikom korišćenja:
* **`kSecReturnData`**: Ako je tačno, pokušaće da dekriptuje podatke (postavite na netačno da biste izbegli potencijalne iskačuće prozore)
* **`kSecReturnRef`**: Takođe dobijate referencu na unos u keychain (postavite na tačno u slučaju da kasnije vidite da možete dekriptovati bez iskačućeg prozora)
* **`kSecReturnAttributes`**: Dobijate metapodatke o unosima
* **`kSecMatchLimit`**: Koliko rezultata da vrati
* **`kSecClass`**: Koja vrsta unosa u keychain

Dobijte **ACL** svakog unosa:

* Sa API-jem **`SecAccessCopyACLList`** možete dobiti **ACL za unos u keychain**, i vratiće listu ACL-ova (kao što su `ACLAuhtorizationExportClear` i ostali prethodno pomenuti) gde svaka lista ima:
* Opis
* **Lista pouzdanih aplikacija**. Ovo može biti:
* Aplikacija: /Applications/Slack.app
* Binarni fajl: /usr/libexec/airportd
* Grupa: group://AirPort

Izvezite podatke:

* API **`SecKeychainItemCopyContent`** dobija običan tekst
* API **`SecItemExport`** izvozi ključeve i sertifikate, ali možda će biti potrebno postaviti lozinke za izvoz sadržaja šifrovanog

I ovo su **zahtevi** da biste mogli da **izvezete tajnu bez prompta**:

* Ako je **1+ pouzdana** aplikacija navedena:
* Potrebne su odgovarajuće **autorizacije** (**`Nil`**, ili biti **deo** dozvoljene liste aplikacija u autorizaciji za pristup tajnim informacijama)
* Potrebna je digitalna potpisna oznaka koja se poklapa sa **PartitionID**
* Potrebna je digitalna potpisna oznaka koja se poklapa sa jednom **pouzdanom aplikacijom** (ili biti član pravog KeychainAccessGroup)
* Ako su **sve aplikacije pouzdane**:
* Potrebne su odgovarajuće **autorizacije**
* Potrebna je digitalna potpisna oznaka koja se poklapa sa **PartitionID**
* Ako **nema PartitionID**, onda ovo nije potrebno

{% hint style="danger" %}
Dakle, ako postoji **1 aplikacija navedena**, potrebno je **ubaciti kod u tu aplikaciju**.

Ako je **apple** naznačen u **partitionID**, mogli biste mu pristupiti pomoću **`osascript`** tako da bilo šta što veruje svim aplikacijama sa apple u partitionID. **`Python`** se takođe može koristiti za ovo.
{% endhint %}

### Dva dodatna atributa

* **Nevidljivo**: To je boolean zastavica za **sakrivanje** unosa iz **UI** Keychain aplikacije
* **Opšte**: To je za čuvanje **metapodataka** (tako da nije ŠIFROVANO)
* Microsoft je čuvao u običnom tekstu sve osvežavajuće tokene za pristup osetljivim krajnjim tačkama.

## Reference

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podrška HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitter-u** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
