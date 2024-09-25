# macOS Sicherheitsmaßnahmen

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}

## Gatekeeper

Gatekeeper wird normalerweise verwendet, um die Kombination von **Quarantäne + Gatekeeper + XProtect** zu bezeichnen, 3 macOS-Sicherheitsmodule, die versuchen, **zu verhindern, dass Benutzer potenziell schädliche Software ausführen, die heruntergeladen wurde**.

Mehr Informationen in:

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## Prozessbeschränkungen

### MACF



### SIP - System Integrity Protection

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Sandbox

Die macOS Sandbox **beschränkt Anwendungen**, die innerhalb der Sandbox ausgeführt werden, auf die **erlaubten Aktionen, die im Sandbox-Profil** festgelegt sind, mit dem die App ausgeführt wird. Dies hilft sicherzustellen, dass **die Anwendung nur auf erwartete Ressourcen zugreift**.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Transparenz, Zustimmung und Kontrolle**

**TCC (Transparenz, Zustimmung und Kontrolle)** ist ein Sicherheitsrahmen. Er wurde entwickelt, um **die Berechtigungen** von Anwendungen zu **verwalten**, indem er deren Zugriff auf sensible Funktionen reguliert. Dazu gehören Elemente wie **Standortdienste, Kontakte, Fotos, Mikrofon, Kamera, Barrierefreiheit und Vollzugriff auf die Festplatte**. TCC stellt sicher, dass Apps nur auf diese Funktionen zugreifen können, nachdem sie die ausdrückliche Zustimmung des Benutzers erhalten haben, wodurch die Privatsphäre und Kontrolle über persönliche Daten gestärkt wird.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### Start-/Umgebungsbeschränkungen & Vertrauenscache

Startbeschränkungen in macOS sind eine Sicherheitsfunktion, um **die Prozessinitiierung zu regulieren**, indem definiert wird, **wer einen Prozess starten kann**, **wie** und **von wo**. Eingeführt in macOS Ventura, kategorisieren sie System-Binärdateien in Beschränkungs-Kategorien innerhalb eines **Vertrauenscaches**. Jede ausführbare Binärdatei hat festgelegte **Regeln** für ihren **Start**, einschließlich **selbst**, **Eltern** und **verantwortlich**. Diese Funktionen wurden in macOS Sonoma auf Drittanbieter-Apps als **Umgebungs**-Beschränkungen ausgeweitet, um potenzielle Systemausnutzungen zu mindern, indem die Bedingungen für das Starten von Prozessen geregelt werden.

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - Malware Removal Tool

Das Malware Removal Tool (MRT) ist ein weiterer Teil der Sicherheitsinfrastruktur von macOS. Wie der Name schon sagt, besteht die Hauptfunktion von MRT darin, **bekannte Malware von infizierten Systemen zu entfernen**.

Sobald Malware auf einem Mac erkannt wird (entweder durch XProtect oder auf andere Weise), kann MRT verwendet werden, um automatisch **die Malware zu entfernen**. MRT arbeitet im Hintergrund und wird normalerweise ausgeführt, wenn das System aktualisiert wird oder wenn eine neue Malware-Definition heruntergeladen wird (es scheint, dass die Regeln, die MRT zur Erkennung von Malware hat, in der Binärdatei enthalten sind).

Während sowohl XProtect als auch MRT Teil der Sicherheitsmaßnahmen von macOS sind, erfüllen sie unterschiedliche Funktionen:

* **XProtect** ist ein präventives Tool. Es **überprüft Dateien, während sie heruntergeladen werden** (über bestimmte Anwendungen), und wenn es bekannte Malware erkennt, **verhindert es, dass die Datei geöffnet wird**, wodurch verhindert wird, dass die Malware dein System überhaupt infiziert.
* **MRT** hingegen ist ein **reaktives Tool**. Es arbeitet, nachdem Malware auf einem System erkannt wurde, mit dem Ziel, die schädliche Software zu entfernen, um das System zu bereinigen.

Die MRT-Anwendung befindet sich in **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Verwaltung von Hintergrundaufgaben

**macOS** warnt jetzt jedes Mal, wenn ein Tool eine bekannte **Technik zur Persistenz der Codeausführung** verwendet (wie Anmeldeobjekte, Daemons...), damit der Benutzer besser weiß, **welche Software persistiert**.

<figure><img src="../../../.gitbook/assets/image (1183).png" alt=""><figcaption></figcaption></figure>

Dies läuft mit einem **Daemon**, der sich in `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` befindet, und dem **Agenten** in `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`

Die Art und Weise, wie **`backgroundtaskmanagementd`** weiß, dass etwas in einem persistenten Ordner installiert ist, besteht darin, **die FSEvents abzurufen** und einige **Handler** dafür zu erstellen.

Darüber hinaus gibt es eine plist-Datei, die **bekannte Anwendungen** enthält, die häufig persistiert werden und von Apple verwaltet werden, die sich in: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist` befindet.
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

Es ist möglich, **alle** konfigurierten Hintergrundelemente, die das Apple-CLI-Tool ausführen, aufzulisten:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Darüber hinaus ist es auch möglich, diese Informationen mit [**DumpBTM**](https://github.com/objective-see/DumpBTM) aufzulisten.
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Diese Informationen werden in **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** gespeichert und das Terminal benötigt FDA.

### Manipulation mit BTM

Wenn eine neue Persistenz gefunden wird, wird ein Ereignis vom Typ **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** ausgelöst. Jede Möglichkeit, dieses **Ereignis** daran zu hindern, gesendet zu werden, oder den **Agenten daran zu hindern**, den Benutzer zu benachrichtigen, wird einem Angreifer helfen, BTM _**zu umgehen**_.

* **Datenbank zurücksetzen**: Das Ausführen des folgenden Befehls setzt die Datenbank zurück (sollte sie von Grund auf neu aufbauen), jedoch wird aus irgendeinem Grund nach dem Ausführen dieses Befehls **keine neue Persistenz benachrichtigt, bis das System neu gestartet wird**.
* **root** ist erforderlich.
```bash
# Reset the database
sfltool resettbtm
```
* **Stoppe den Agenten**: Es ist möglich, ein Stoppsignal an den Agenten zu senden, sodass er **den Benutzer nicht benachrichtigt**, wenn neue Erkennungen gefunden werden.
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
* **Fehler**: Wenn der **Prozess, der die Persistenz erstellt hat, direkt danach schnell existiert**, wird der Daemon versuchen, **Informationen darüber zu erhalten**, **fehlschlagen** und **nicht in der Lage sein, das Ereignis zu senden**, das anzeigt, dass eine neue Sache persistiert.

Referenzen und **weitere Informationen über BTM**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}
