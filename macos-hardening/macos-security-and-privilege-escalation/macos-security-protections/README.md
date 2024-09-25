# macOS Security Protections

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

## Gatekeeper

Gatekeeper se obično koristi da se odnosi na kombinaciju **Quarantine + Gatekeeper + XProtect**, 3 macOS sigurnosna modula koja će pokušati da **spreče korisnike da izvršavaju potencijalno zlonamerni softver preuzet**.

Više informacija u:

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## Processes Limitants

### MACF



### SIP - System Integrity Protection

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Sandbox

MacOS Sandbox **ograničava aplikacije** koje se izvršavaju unutar sandboks-a na **dozvoljene radnje navedene u Sandbox profilu** sa kojim aplikacija radi. Ovo pomaže da se osigura da **aplikacija pristupa samo očekivanim resursima**.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** je sigurnosni okvir. Dizajniran je da **upravlja dozvolama** aplikacija, posebno regulisanjem njihovog pristupa osetljivim funkcijama. Ovo uključuje elemente kao što su **usluge lokacije, kontakti, fotografije, mikrofon, kamera, pristupačnost i pristup celom disku**. TCC osigurava da aplikacije mogu pristupiti ovim funkcijama samo nakon dobijanja izričitog pristanka korisnika, čime se jača privatnost i kontrola nad ličnim podacima.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### Launch/Environment Constraints & Trust Cache

Ograničenja pokretanja u macOS-u su sigurnosna funkcija koja **reguliše inicijaciju procesa** definišući **ko može pokrenuti** proces, **kako** i **odakle**. Uvedena u macOS Ventura, klasifikuju sistemske binarne datoteke u kategorije ograničenja unutar **trust cache**. Svaka izvršna binarna datoteka ima postavljena **pravila** za svoje **pokretanje**, uključujući **self**, **parent** i **responsible** ograničenja. Proširena na aplikacije trećih strana kao **Environment** Constraints u macOS Sonoma, ove funkcije pomažu u ublažavanju potencijalnih sistemskih eksploatacija regulisanjem uslova pokretanja procesa.

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - Malware Removal Tool

Alat za uklanjanje zlonamernog softvera (MRT) je još jedan deo sigurnosne infrastrukture macOS-a. Kao što ime sugeriše, glavna funkcija MRT-a je da **ukloni poznati zlonamerni softver sa zaraženih sistema**.

Kada se zlonamerni softver otkrije na Mac-u (bilo putem XProtect-a ili nekim drugim sredstvima), MRT se može koristiti za automatsko **uklanjanje zlonamernog softvera**. MRT radi tiho u pozadini i obično se pokreće svaki put kada se sistem ažurira ili kada se preuzima nova definicija zlonamernog softvera (izgleda da su pravila koja MRT ima za otkrivanje zlonamernog softvera unutar binarne datoteke).

Dok su i XProtect i MRT deo sigurnosnih mera macOS-a, oni obavljaju različite funkcije:

* **XProtect** je preventivni alat. **Proverava datoteke dok se preuzimaju** (putem određenih aplikacija), i ako otkrije bilo koje poznate vrste zlonamernog softvera, **sprečava otvaranje datoteke**, čime sprečava zlonamerni softver da inficira vaš sistem u prvom redu.
* **MRT**, s druge strane, je **reaktivni alat**. Deluje nakon što je zlonamerni softver otkriven na sistemu, sa ciljem da ukloni problematični softver kako bi očistio sistem.

Aplikacija MRT se nalazi u **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Background Tasks Management

**macOS** sada **obaveštava** svaki put kada alat koristi dobro poznatu **tehniku za persistenciju izvršavanja koda** (kao što su Login Items, Daemons...), tako da korisnik bolje zna **koji softver persistira**.

<figure><img src="../../../.gitbook/assets/image (1183).png" alt=""><figcaption></figcaption></figure>

Ovo se pokreće sa **daemon-om** lociranim u `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` i **agentom** u `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`

Način na koji **`backgroundtaskmanagementd`** zna da je nešto instalirano u persistentnom folderu je **dobijanje FSEvents** i kreiranje nekih **handler-a** za njih.

Štaviše, postoji plist datoteka koja sadrži **dobro poznate aplikacije** koje često persistiraju, a koju održava Apple, locirana u: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### Enumeration

Moguće je **enumerisati sve** konfigurirane pozadinske stavke koristeći Apple cli alat:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Pored toga, takođe je moguće prikazati ove informacije pomoću [**DumpBTM**](https://github.com/objective-see/DumpBTM).
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Ove informacije se čuvaju u **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** i Terminalu je potrebna FDA.

### Manipulacija sa BTM

Kada se pronađe nova perzistencija, događa se događaj tipa **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Dakle, bilo koji način da se **spreči** slanje ovog **događaja** ili da **agent ne obavesti** korisnika će pomoći napadaču da _**zaobiđe**_ BTM.

* **Resetovanje baze podataka**: Pokretanje sledeće komande će resetovati bazu podataka (trebalo bi da je ponovo izgradi od nule), međutim, iz nekog razloga, nakon pokretanja ovoga, **nema nove perzistencije koja će biti obaveštena dok se sistem ne restartuje**.
* **root** je potreban.
```bash
# Reset the database
sfltool resettbtm
```
* **Zaustavite agenta**: Moguće je poslati signal za zaustavljanje agentu tako da **neće obaveštavati korisnika** kada se pronađu nova otkrića.
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
* **Greška**: Ako **proces koji je stvorio postojanost brzo nestane nakon njega**, demon će pokušati da **dobije informacije** o njemu, **neće uspeti** i **neće moći da pošalje događaj** koji ukazuje na to da nova stvar postojano traje.

Reference i **više informacija o BTM**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

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
