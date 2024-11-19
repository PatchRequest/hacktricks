# Sicurezza macOS e Escalation dei Privilegi

{% hint style="success" %}
Impara e pratica Hacking AWS:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica Hacking GCP: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Unisciti al [**server HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) per comunicare con hacker esperti e cacciatori di bug bounty!

**Approfondimenti sull'Hacking**\
Interagisci con contenuti che approfondiscono l'emozione e le sfide dell'hacking

**Notizie di Hacking in Tempo Reale**\
Rimani aggiornato con il mondo dell'hacking in rapida evoluzione attraverso notizie e approfondimenti in tempo reale

**Ultimi Annunci**\
Rimani informato sui nuovi bug bounty in partenza e aggiornamenti cruciali delle piattaforme

**Unisciti a noi su** [**Discord**](https://discord.com/invite/N3FrSbmwdy) e inizia a collaborare con i migliori hacker oggi stesso!

## MacOS di Base

Se non sei familiare con macOS, dovresti iniziare a imparare le basi di macOS:

* File e **permessi speciali di macOS:**

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* **Utenti comuni di macOS**

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* L'**architettura** del k**ernel**

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Servizi e **protocolli di rete comuni di macOS**

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
* Per scaricare un `tar.gz` cambia un URL come [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) in [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

Nelle aziende, i sistemi **macOS** saranno molto probabilmente **gestiti con un MDM**. Pertanto, dal punto di vista di un attaccante, è interessante sapere **come funziona**:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - Ispezione, Debugging e Fuzzing

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## Protezioni di Sicurezza macOS

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Superficie di Attacco

### Permessi dei File

Se un **processo in esecuzione come root scrive** un file che può essere controllato da un utente, l'utente potrebbe abusarne per **escalare i privilegi**.\
Questo potrebbe verificarsi nelle seguenti situazioni:

* Il file utilizzato era già stato creato da un utente (di proprietà dell'utente)
* Il file utilizzato è scrivibile dall'utente a causa di un gruppo
* Il file utilizzato si trova all'interno di una directory di proprietà dell'utente (l'utente potrebbe creare il file)
* Il file utilizzato si trova all'interno di una directory di proprietà di root ma l'utente ha accesso in scrittura su di essa a causa di un gruppo (l'utente potrebbe creare il file)

Essere in grado di **creare un file** che sarà **utilizzato da root**, consente a un utente di **sfruttare il suo contenuto** o persino creare **symlink/hardlink** per puntarlo in un'altra posizione.

Per questo tipo di vulnerabilità non dimenticare di **controllare gli installer `.pkg` vulnerabili**:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}

### Gestori di App per Estensione di File e Schema URL

App strane registrate da estensioni di file potrebbero essere abusate e diverse applicazioni possono essere registrate per aprire protocolli specifici

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## macOS TCC / SIP Escalation dei Privilegi

In macOS **le applicazioni e i binari possono avere permessi** per accedere a cartelle o impostazioni che li rendono più privilegiati di altri.

Pertanto, un attaccante che desidera compromettere con successo una macchina macOS dovrà **escalare i suoi privilegi TCC** (o persino **bypassare SIP**, a seconda delle sue necessità).

Questi privilegi sono solitamente concessi sotto forma di **diritti** con cui l'applicazione è firmata, oppure l'applicazione potrebbe richiedere alcuni accessi e dopo che **l'utente li approva** possono essere trovati nei **database TCC**. Un altro modo in cui un processo può ottenere questi privilegi è essendo un **figlio di un processo** con quei **privilegi** poiché di solito sono **ereditati**.

Segui questi link per trovare diversi modi per [**escalare i privilegi in TCC**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), per [**bypassare TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) e come in passato [**SIP è stato bypassato**](macos-security-protections/macos-sip.md#sip-bypasses).

## Escalation Tradizionale dei Privilegi in macOS

Certo, dal punto di vista di un red team, dovresti essere anche interessato a escalare a root. Controlla il seguente post per alcuni suggerimenti:

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}

## Conformità macOS

* [https://github.com/usnistgov/macos\_security](https://github.com/usnistgov/macos\_security)

## Riferimenti

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="/.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Unisciti al [**server HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) per comunicare con hacker esperti e cacciatori di bug bounty!

**Approfondimenti sull'Hacking**\
Interagisci con contenuti che approfondiscono l'emozione e le sfide dell'hacking

**Notizie di Hacking in Tempo Reale**\
Rimani aggiornato con il mondo dell'hacking in rapida evoluzione attraverso notizie e approfondimenti in tempo reale

**Ultimi Annunci**\
Rimani informato sui nuovi bug bounty in partenza e aggiornamenti cruciali delle piattaforme

**Unisciti a noi su** [**Discord**](https://discord.com/invite/N3FrSbmwdy) e inizia a collaborare con i migliori hacker oggi stesso!

{% hint style="success" %}
Impara e pratica Hacking AWS:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica Hacking GCP: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}
