# PsExec/Winexec/ScExec

{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Usa [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) per costruire e **automatizzare flussi di lavoro** alimentati dagli **strumenti comunitari più avanzati** al mondo.\
Accedi oggi:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

## Come funzionano

Il processo è delineato nei passaggi seguenti, illustrando come i binari di servizio vengano manipolati per ottenere l'esecuzione remota su una macchina target tramite SMB:

1. **Copia del binario di un servizio nella condivisione ADMIN$ tramite SMB** viene eseguita.
2. **Creazione di un servizio sulla macchina remota** viene effettuata puntando al binario.
3. Il servizio viene **avviato remotamente**.
4. Al termine, il servizio viene **interrotto e il binario viene eliminato**.

### **Processo di Esecuzione Manuale di PsExec**

Assumendo che ci sia un payload eseguibile (creato con msfvenom e offuscato usando Veil per eludere la rilevazione antivirus), chiamato 'met8888.exe', che rappresenta un payload reverse_http di meterpreter, vengono eseguiti i seguenti passaggi:

- **Copia del binario**: L'eseguibile viene copiato nella condivisione ADMIN$ da un prompt dei comandi, anche se può essere posizionato ovunque nel filesystem per rimanere nascosto.

- **Creazione di un servizio**: Utilizzando il comando Windows `sc`, che consente di interrogare, creare ed eliminare servizi Windows da remoto, viene creato un servizio chiamato "meterpreter" per puntare al binario caricato.

- **Avvio del servizio**: L'ultimo passaggio comporta l'avvio del servizio, che probabilmente risulterà in un errore di "timeout" a causa del binario che non è un vero binario di servizio e non riesce a restituire il codice di risposta atteso. Questo errore è irrilevante poiché l'obiettivo principale è l'esecuzione del binario.

L'osservazione del listener di Metasploit rivelerà che la sessione è stata avviata con successo.

[Scopri di più sul comando `sc`](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Trova passaggi più dettagliati in: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Puoi anche usare il binario PsExec.exe di Windows Sysinternals:**

![](<../../.gitbook/assets/image (165).png>)

Puoi anche usare [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Usa [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) per costruire e **automatizzare flussi di lavoro** alimentati dagli **strumenti comunitari** più **avanzati** al mondo.\
Ottieni accesso oggi:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}
