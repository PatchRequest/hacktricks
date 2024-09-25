# macOS Sekuriteitsbeskerming

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Gatekeeper

Gatekeeper word gewoonlik gebruik om te verwys na die kombinasie van **Quarantine + Gatekeeper + XProtect**, 3 macOS sekuriteitsmodules wat sal probeer om **gebruikers te verhoed om potensieel kwaadwillige sagteware wat afgelaai is, uit te voer**.

Meer inligting in:

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## Prosesse Beperkings

### MACF



### SIP - Stelselintegriteit Beskerming

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Sandbox

MacOS Sandbox **beperk toepassings** wat binne die sandbox loop tot die **toegelate aksies wat in die Sandbox-profiel gespesifiseer is** waarmee die app loop. Dit help om te verseker dat **die toepassing slegs verwagte hulpbronne sal benader**.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Deursigtigheid, Toestemming, en Beheer**

**TCC (Deursigtigheid, Toestemming, en Beheer)** is 'n sekuriteitsraamwerk. Dit is ontwerp om **die toestemmings** van toepassings te **bestuur**, spesifiek deur hul toegang tot sensitiewe funksies te reguleer. Dit sluit elemente soos **liggingsdienste, kontakte, foto's, mikrofoon, kamera, toeganklikheid, en volle skyf toegang** in. TCC verseker dat toepassings slegs toegang tot hierdie funksies kan verkry nadat hulle eksplisiete gebruikers toestemming verkry het, wat privaatheid en beheer oor persoonlike data versterk.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### Begin/Omgewing Beperkings & Vertroue Kas

Begin beperkings in macOS is 'n sekuriteitskenmerk om **prosesinisiëring te reguleer** deur te definieer **wie 'n proses kan begin**, **hoe**, en **van waar**. Ingevoerd in macOS Ventura, kategoriseer dit stelselbinaries in beperking kategorieë binne 'n **vertroue kas**. Elke uitvoerbare binêre het **reëls** vir sy **begin**, insluitend **self**, **ouer**, en **verantwoordelike** beperkings. Uitgebrei na derdeparty-apps as **Omgewing** Beperkings in macOS Sonoma, help hierdie kenmerke om potensiële stelselaanrandings te verminder deur prosesbeginvoorwaardes te regeer.

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - Kwaadwillige Sagteware Verwydering Gereedskap

Die Kwaadwillige Sagteware Verwydering Gereedskap (MRT) is 'n ander deel van macOS se sekuriteitsinfrastruktuur. Soos die naam aandui, is MRT se hooffunksie om **bekende kwaadwillige sagteware van besmette stelsels te verwyder**.

Sodra kwaadwillige sagteware op 'n Mac opgespoor word (of deur XProtect of deur 'n ander middel), kan MRT gebruik word om outomaties **die kwaadwillige sagteware te verwyder**. MRT werk stil in die agtergrond en loop tipies wanneer die stelsel opgedateer word of wanneer 'n nuwe kwaadwillige sagteware definisie afgelaai word (dit lyk of die reëls wat MRT het om kwaadwillige sagteware op te spoor binne die binêre is).

Terwyl beide XProtect en MRT deel van macOS se sekuriteitsmaatreëls is, voer hulle verskillende funksies uit:

* **XProtect** is 'n preventiewe hulpmiddel. Dit **kontroleer lêers soos hulle afgelaai word** (deur sekere toepassings), en as dit enige bekende tipes kwaadwillige sagteware opspoor, **verhoed dit dat die lêer oopgemaak word**, wat verhoed dat die kwaadwillige sagteware jou stelsel in die eerste plek besmet.
* **MRT**, aan die ander kant, is 'n **reaktiewe hulpmiddel**. Dit werk nadat kwaadwillige sagteware op 'n stelsel opgespoor is, met die doel om die oortredende sagteware te verwyder om die stelsel skoon te maak.

Die MRT-toepassing is geleë in **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Agtergrond Take Bestuur

**macOS** waarsku nou **elke keer** wanneer 'n hulpmiddel 'n bekende **tegniek gebruik om kode-uitvoering te volhard** (soos Login Items, Daemons...), sodat die gebruiker beter weet **watter sagteware volhard**.

<figure><img src="../../../.gitbook/assets/image (1183).png" alt=""><figcaption></figcaption></figure>

Dit werk met 'n **daemon** geleë in `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` en die **agent** in `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`

Die manier waarop **`backgroundtaskmanagementd`** weet dat iets in 'n volhardende gids geïnstalleer is, is deur **die FSEvents te verkry** en 'n paar **handlers** vir daardie te skep.

Boonop is daar 'n plist-lêer wat **goed bekende toepassings** bevat wat gereeld volhard, wat deur apple onderhou word, geleë in: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
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

Dit is moontlik om **alle** die geconfigureerde agtergronditems wat die Apple cli-gereedskap uitvoer, te **enumerate**:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Boonop is dit ook moontlik om hierdie inligting te lys met [**DumpBTM**](https://github.com/objective-see/DumpBTM).
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Hierdie inligting word gestoor in **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** en die Terminal benodig FDA.

### Meng met BTM

Wanneer 'n nuwe volharding gevind word, is daar 'n gebeurtenis van tipe **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Enige manier om hierdie **gebeurtenis** te **voorkom** of die **agent om die gebruiker te waarsku** sal 'n aanvaller help om _**te omseil**_ BTM.

* **Herstel die databasis**: Die uitvoering van die volgende opdrag sal die databasis herstel (moet dit van die grond af herbou), egter, om een of ander rede, na die uitvoering hiervan, **sal geen nuwe volharding gewaarsku word totdat die stelsel herbegin word**.
* **root** is vereis.
```bash
# Reset the database
sfltool resettbtm
```
* **Stop die Agent**: Dit is moontlik om 'n stopsein na die agent te stuur sodat dit **nie die gebruiker sal waarsku nie** wanneer nuwe opsporings gevind word.
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
* **Fout**: As die **proses wat die volharding geskep het, vinnig reg na dit bestaan**, sal die daemon probeer om **inligting** daaroor te **kry**, **misluk**, en **nie in staat wees om die gebeurtenis** te stuur wat aandui dat 'n nuwe ding volhard nie.

Verwysings en **meer inligting oor BTM**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsieplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
