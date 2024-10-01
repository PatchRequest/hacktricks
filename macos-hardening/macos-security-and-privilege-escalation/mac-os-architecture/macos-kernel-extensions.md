# macOS Kernel Extensions & Debugging

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

Kernel extensions (Kexts) su **paketi** sa **`.kext`** ekstenzijom koji se **učitavaju direktno u macOS kernel prostor**, pružajući dodatnu funkcionalnost glavnom operativnom sistemu.

### Requirements

Očigledno, ovo je toliko moćno da je **komplikovano učitati kernel ekstenziju**. Ovo su **zahtevi** koje kernel ekstenzija mora ispuniti da bi bila učitana:

* Kada se **ulazi u režim oporavka**, kernel **ekstenzije moraju biti dozvoljene** za učitavanje:

<figure><img src="../../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

* Kernel ekstenzija mora biti **potpisana sa sertifikatom za potpisivanje kernel koda**, koji može biti **dodeljen samo od strane Apple-a**. Ko će detaljno pregledati kompaniju i razloge zašto je to potrebno.
* Kernel ekstenzija takođe mora biti **notarizovana**, Apple će moći da je proveri na malver.
* Zatim, **root** korisnik je taj koji može **učitati kernel ekstenziju** i datoteke unutar paketa moraju **pripadati root-u**.
* Tokom procesa učitavanja, paket mora biti pripremljen na **zaštićenoj lokaciji koja nije root**: `/Library/StagedExtensions` (zahteva `com.apple.rootless.storage.KernelExtensionManagement` dozvolu).
* Na kraju, kada se pokuša učitati, korisnik će [**dobiti zahtev za potvrdu**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) i, ako bude prihvaćen, računar mora biti **ponovo pokrenut** da bi se učitao.

### Loading process

U Catalini je to izgledalo ovako: Zanimljivo je napomenuti da se **proceso verifikacije** dešava u **userland-u**. Međutim, samo aplikacije sa **`com.apple.private.security.kext-management`** dozvolom mogu **zatražiti od kernela da učita ekstenziju**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **pokreće** **proceso verifikacije** za učitavanje ekstenzije
* Razgovaraće sa **`kextd`** slanjem putem **Mach servisa**.
2. **`kextd`** će proveriti nekoliko stvari, kao što su **potpis**
* Razgovaraće sa **`syspolicyd`** da bi **proverio** da li se ekstenzija može **učitati**.
3. **`syspolicyd`** će **pitati** **korisnika** ako ekstenzija nije prethodno učitana.
* **`syspolicyd`** će izvestiti rezultat **`kextd`**
4. **`kextd`** će konačno moći da **kaže kernelu da učita** ekstenziju

Ako **`kextd`** nije dostupan, **`kextutil`** može izvršiti iste provere.

### Enumeration (loaded kexts)
```bash
# Get loaded kernel extensions
kextstat

# Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
## Kernelcache

{% hint style="danger" %}
Iako se očekuje da su kernel ekstenzije u `/System/Library/Extensions/`, ako odete u ovu fasciklu **nećete pronaći nijedan binarni** fajl. To je zbog **kernelcache** i da biste obrnuli jedan `.kext` potrebno je da pronađete način da ga dobijete.
{% endhint %}

**Kernelcache** je **prekompajlirana i prelinkovana verzija XNU kernela**, zajedno sa osnovnim uređajskim **drajverima** i **kernel ekstenzijama**. Čuva se u **komprimovanom** formatu i dekompresuje se u memoriji tokom procesa pokretanja. Kernelcache omogućava **brže vreme pokretanja** tako što ima spremnu verziju kernela i ključnih drajvera, smanjujući vreme i resurse koji bi inače bili potrošeni na dinamičko učitavanje i povezivanje ovih komponenti prilikom pokretanja.

### Lokalni Kernelcache

U iOS-u se nalazi u **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**, u macOS-u ga možete pronaći sa: **`find / -name "kernelcache" 2>/dev/null`** \
U mom slučaju u macOS-u pronašao sam ga u:

* `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

IMG4 format fajla je kontejnerski format koji koristi Apple u svojim iOS i macOS uređajima za sigurno **čuvanje i verifikaciju firmware** komponenti (kao što je **kernelcache**). IMG4 format uključuje zaglavlje i nekoliko oznaka koje enkapsuliraju različite delove podataka uključujući stvarni payload (kao što je kernel ili bootloader), potpis i skup manifest svojstava. Format podržava kriptografsku verifikaciju, omogućavajući uređaju da potvrdi autentičnost i integritet firmware komponente pre nego što je izvrši.

Obično se sastoji od sledećih komponenti:

* **Payload (IM4P)**:
* Često komprimovan (LZFSE4, LZSS, …)
* Opcionalno enkriptovan
* **Manifest (IM4M)**:
* Sadrži potpis
* Dodatni ključ/vrednost rečnik
* **Restore Info (IM4R)**:
* Takođe poznat kao APNonce
* Sprečava ponavljanje nekih ažuriranja
* OPCIONALNO: Obično se ovo ne nalazi

Dekomprimujte Kernelcache:
```bash
# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Preuzimanje&#x20;

* [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

Na [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) je moguće pronaći sve kernel debug kitove. Možete ga preuzeti, montirati, otvoriti pomoću alata [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html), pristupiti **`.kext`** folderu i **izvući ga**.

Proverite ga za simbole sa:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
* [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Ponekad Apple objavljuje **kernelcache** sa **simbolima**. Možete preuzeti neke firmvere sa simbolima prateći linkove na tim stranicama. Firmveri će sadržati **kernelcache** među ostalim datotekama.

Da **izvucite** datoteke, počnite tako što ćete promeniti ekstenziju sa `.ipsw` na `.zip` i **raspakovati** je.

Nakon vađenja firmvera dobićete datoteku poput: **`kernelcache.release.iphone14`**. U **IMG4** formatu, možete izvući zanimljive informacije pomoću:

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

Proverite da li kernelcache ima simbole sa
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
Sa ovim možemo sada **izvući sve ekstenzije** ili **onu koja vas zanima:**
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
## Debugging



## Referencije

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
