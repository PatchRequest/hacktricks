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

Gatekeeper è solitamente usato per riferirsi alla combinazione di **Quarantine + Gatekeeper + XProtect**, 3 moduli di sicurezza di macOS che cercheranno di **prevenire gli utenti dall'eseguire software potenzialmente dannoso scaricato**.

More information in:

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

La Sandbox di macOS **limita le applicazioni** in esecuzione all'interno della sandbox alle **azioni consentite specificate nel profilo Sandbox** con cui l'app è in esecuzione. Questo aiuta a garantire che **l'applicazione accederà solo alle risorse previste**.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** è un framework di sicurezza. È progettato per **gestire le autorizzazioni** delle applicazioni, regolando specificamente il loro accesso a funzionalità sensibili. Questo include elementi come **servizi di localizzazione, contatti, foto, microfono, fotocamera, accessibilità e accesso completo al disco**. TCC garantisce che le app possano accedere a queste funzionalità solo dopo aver ottenuto il consenso esplicito dell'utente, rafforzando così la privacy e il controllo sui dati personali.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### Launch/Environment Constraints & Trust Cache

I vincoli di avvio in macOS sono una funzionalità di sicurezza per **regolare l'inizio dei processi** definendo **chi può avviare** un processo, **come** e **da dove**. Introdotti in macOS Ventura, categorizzano i binari di sistema in categorie di vincolo all'interno di un **trust cache**. Ogni binario eseguibile ha **regole** stabilite per il suo **avvio**, inclusi vincoli **self**, **parent** e **responsible**. Estesi alle app di terze parti come **Environment** Constraints in macOS Sonoma, queste funzionalità aiutano a mitigare potenziali sfruttamenti del sistema regolando le condizioni di avvio dei processi.

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - Malware Removal Tool

Il Malware Removal Tool (MRT) è un'altra parte dell'infrastruttura di sicurezza di macOS. Come suggerisce il nome, la funzione principale di MRT è **rimuovere malware conosciuti da sistemi infetti**.

Una volta che il malware viene rilevato su un Mac (sia da XProtect che da altri mezzi), MRT può essere utilizzato per **rimuovere automaticamente il malware**. MRT opera silenziosamente in background e di solito viene eseguito ogni volta che il sistema viene aggiornato o quando viene scaricata una nuova definizione di malware (sembra che le regole che MRT ha per rilevare il malware siano all'interno del binario).

Sebbene sia XProtect che MRT facciano parte delle misure di sicurezza di macOS, svolgono funzioni diverse:

* **XProtect** è uno strumento preventivo. **Controlla i file mentre vengono scaricati** (tramite determinate applicazioni) e, se rileva tipi noti di malware, **impedisce l'apertura del file**, prevenendo così l'infezione del sistema in primo luogo.
* **MRT**, d'altra parte, è uno **strumento reattivo**. Opera dopo che il malware è stato rilevato su un sistema, con l'obiettivo di rimuovere il software offensivo per ripulire il sistema.

L'applicazione MRT si trova in **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Background Tasks Management

**macOS** ora **avvisa** ogni volta che uno strumento utilizza una **tecnica ben nota per persistere nell'esecuzione del codice** (come Login Items, Daemons...), in modo che l'utente sappia meglio **quale software sta persistendo**.

<figure><img src="../../../.gitbook/assets/image (1183).png" alt=""><figcaption></figcaption></figure>

Questo funziona con un **daemon** situato in `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` e l'**agent** in `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`

Il modo in cui **`backgroundtaskmanagementd`** sa che qualcosa è installato in una cartella persistente è **ottenendo gli FSEvents** e creando alcuni **handler** per quelli.

Inoltre, c'è un file plist che contiene **applicazioni ben note** che persistono frequentemente mantenuto da Apple situato in: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
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
### Enumerazione

È possibile **enumerare tutti** gli elementi di background configurati utilizzando lo strumento cli di Apple:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Inoltre, è anche possibile elencare queste informazioni con [**DumpBTM**](https://github.com/objective-see/DumpBTM).
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Queste informazioni vengono memorizzate in **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** e il Terminale necessita di FDA.

### Manipolazione di BTM

Quando viene trovata una nuova persistenza, si verifica un evento di tipo **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Quindi, qualsiasi modo per **prevenire** che questo **evento** venga inviato o che l'**agente avvisi** l'utente aiuterà un attaccante a _**bypassare**_ BTM.

* **Ripristinare il database**: Eseguire il seguente comando ripristinerà il database (dovrebbe ricostruirlo da zero), tuttavia, per qualche motivo, dopo aver eseguito questo, **nessuna nuova persistenza verrà segnalata fino a quando il sistema non verrà riavviato**.
* È richiesto **root**.
```bash
# Reset the database
sfltool resettbtm
```
* **Ferma l'Agente**: È possibile inviare un segnale di arresto all'agente in modo che **non avvisi l'utente** quando vengono trovate nuove rilevazioni.
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
* **Bug**: Se il **processo che ha creato la persistenza esiste rapidamente dopo di esso**, il demone cercherà di **ottenere informazioni** su di esso, **fallirà** e **non sarà in grado di inviare l'evento** che indica che una nuova cosa sta persistendo.

Riferimenti e **ulteriori informazioni su BTM**:

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
