# PsExec/Winexec/ScExec

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Verwenden Sie [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection), um einfach **Workflows** zu erstellen und zu **automatisieren**, die von den **fortschrittlichsten** Community-Tools der Welt unterstützt werden.\
Zugang heute erhalten:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

## Wie funktionieren sie

Der Prozess ist in den folgenden Schritten skizziert, die zeigen, wie Dienst-Binärdateien manipuliert werden, um eine Remote-Ausführung auf einem Zielcomputer über SMB zu erreichen:

1. **Kopieren einer Dienst-Binärdatei in den ADMIN$-Freigabe über SMB** wird durchgeführt.
2. **Erstellung eines Dienstes auf dem Remote-Computer** erfolgt durch Verweisen auf die Binärdatei.
3. Der Dienst wird **remote gestartet**.
4. Nach dem Beenden wird der Dienst **gestoppt und die Binärdatei gelöscht**.

### **Prozess der manuellen Ausführung von PsExec**

Angenommen, es gibt eine ausführbare Nutzlast (erstellt mit msfvenom und obfuskiert mit Veil, um die Erkennung durch Antivirenprogramme zu umgehen), die 'met8888.exe' heißt und eine meterpreter reverse_http-Nutzlast darstellt, werden die folgenden Schritte unternommen:

- **Kopieren der Binärdatei**: Die ausführbare Datei wird von einer Eingabeaufforderung in die ADMIN$-Freigabe kopiert, obwohl sie überall im Dateisystem platziert werden kann, um verborgen zu bleiben.

- **Erstellen eines Dienstes**: Mit dem Windows-Befehl `sc`, der das Abfragen, Erstellen und Löschen von Windows-Diensten aus der Ferne ermöglicht, wird ein Dienst namens "meterpreter" erstellt, der auf die hochgeladene Binärdatei verweist.

- **Starten des Dienstes**: Der letzte Schritt besteht darin, den Dienst zu starten, was wahrscheinlich zu einem "Zeitüberschreitung"-Fehler führen wird, da die Binärdatei keine echte Dienst-Binärdatei ist und nicht den erwarteten Antwortcode zurückgibt. Dieser Fehler ist unerheblich, da das Hauptziel die Ausführung der Binärdatei ist.

Die Beobachtung des Metasploit-Listeners wird zeigen, dass die Sitzung erfolgreich initiiert wurde.

[Erfahren Sie mehr über den `sc`-Befehl](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Finden Sie detailliertere Schritte unter: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Sie könnten auch die Windows Sysinternals-Binärdatei PsExec.exe verwenden:**

![](<../../.gitbook/assets/image (165).png>)

Sie könnten auch [**SharpLateral**](https://github.com/mertdas/SharpLateral) verwenden:

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Verwenden Sie [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection), um einfach **Workflows** zu erstellen und **zu automatisieren**, die von den **fortschrittlichsten** Community-Tools der Welt unterstützt werden.\
Zugang heute erhalten:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}
