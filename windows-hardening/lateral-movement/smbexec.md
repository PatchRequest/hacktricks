# SmbExec/ScExec

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Get a hacker's perspective on your web apps, network, and cloud

**Trova e segnala vulnerabilità critiche ed esploitabili con un reale impatto sul business.** Usa i nostri oltre 20 strumenti personalizzati per mappare la superficie di attacco, trovare problemi di sicurezza che ti permettono di elevare i privilegi e utilizzare exploit automatizzati per raccogliere prove essenziali, trasformando il tuo duro lavoro in report persuasivi.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## How it Works

**Smbexec** è uno strumento utilizzato per l'esecuzione remota di comandi su sistemi Windows, simile a **Psexec**, ma evita di posizionare file dannosi sul sistema target.

### Key Points about **SMBExec**

- Funziona creando un servizio temporaneo (ad esempio, "BTOBTO") sulla macchina target per eseguire comandi tramite cmd.exe (%COMSPEC%), senza scaricare alcun binario.
- Nonostante il suo approccio furtivo, genera registri di eventi per ogni comando eseguito, offrendo una forma di "shell" non interattiva.
- Il comando per connettersi utilizzando **Smbexec** appare così:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Esecuzione di Comandi Senza Binaries

- **Smbexec** consente l'esecuzione diretta di comandi attraverso i binPath dei servizi, eliminando la necessità di binaries fisici sul target.
- Questo metodo è utile per eseguire comandi una tantum su un target Windows. Ad esempio, abbinarlo al modulo `web_delivery` di Metasploit consente l'esecuzione di un payload Meterpreter inverso mirato a PowerShell.
- Creando un servizio remoto sulla macchina dell'attaccante con binPath impostato per eseguire il comando fornito tramite cmd.exe, è possibile eseguire con successo il payload, ottenendo callback ed esecuzione del payload con il listener di Metasploit, anche se si verificano errori di risposta del servizio.

### Esempio di Comandi

La creazione e l'avvio del servizio possono essere realizzati con i seguenti comandi:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
FOr further details check [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)


## Riferimenti
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Ottieni la prospettiva di un hacker sulle tue app web, rete e cloud

**Trova e segnala vulnerabilità critiche e sfruttabili con un reale impatto sul business.** Usa i nostri oltre 20 strumenti personalizzati per mappare la superficie di attacco, trovare problemi di sicurezza che ti permettano di elevare i privilegi e utilizzare exploit automatizzati per raccogliere prove essenziali, trasformando il tuo duro lavoro in report persuasivi.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{% hint style="success" %}
Impara e pratica AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}
