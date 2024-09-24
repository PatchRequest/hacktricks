# macOS SIP

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

## **Grundinformationen**

**System Integrity Protection (SIP)** in macOS ist ein Mechanismus, der darauf abzielt, selbst die privilegiertesten Benutzer daran zu hindern, unbefugte Änderungen an wichtigen Systemordnern vorzunehmen. Diese Funktion spielt eine entscheidende Rolle bei der Aufrechterhaltung der Integrität des Systems, indem sie Aktionen wie das Hinzufügen, Ändern oder Löschen von Dateien in geschützten Bereichen einschränkt. Die wichtigsten Ordner, die durch SIP geschützt sind, umfassen:

* **/System**
* **/bin**
* **/sbin**
* **/usr**

Die Regeln, die das Verhalten von SIP steuern, sind in der Konfigurationsdatei unter **`/System/Library/Sandbox/rootless.conf`** definiert. Innerhalb dieser Datei werden Pfade, die mit einem Sternchen (\*) vorangestellt sind, als Ausnahmen von den ansonsten strengen SIP-Beschränkungen bezeichnet.

Betrachten Sie das folgende Beispiel:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Dieser Abschnitt impliziert, dass SIP im Allgemeinen das **`/usr`** Verzeichnis sichert, es jedoch spezifische Unterverzeichnisse (`/usr/libexec/cups`, `/usr/local` und `/usr/share/man`) gibt, in denen Änderungen zulässig sind, wie durch den Stern (\*) vor ihren Pfaden angezeigt.

Um zu überprüfen, ob ein Verzeichnis oder eine Datei durch SIP geschützt ist, können Sie den Befehl **`ls -lOd`** verwenden, um das Vorhandensein des **`restricted`** oder **`sunlnk`** Flags zu überprüfen. Zum Beispiel:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
In diesem Fall bedeutet das **`sunlnk`**-Flag, dass das Verzeichnis `/usr/libexec/cups` selbst **nicht gelöscht werden kann**, obwohl Dateien darin erstellt, geändert oder gelöscht werden können.

Andererseits:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Hier zeigt das **`restricted`** Flag an, dass das Verzeichnis `/usr/libexec` durch SIP geschützt ist. In einem SIP-geschützten Verzeichnis können keine Dateien erstellt, geändert oder gelöscht werden.

Darüber hinaus wird eine Datei, die das Attribut **`com.apple.rootless`** enthält, ebenfalls **durch SIP geschützt**.

{% hint style="success" %}
Beachten Sie, dass der **Sandbox** Hook **`hook_vnode_check_setextattr`** jeden Versuch verhindert, das erweiterte Attribut **`com.apple.rootless`** zu ändern.
{% endhint %}

**SIP beschränkt auch andere Root-Aktionen** wie:

* Laden von nicht vertrauenswürdigen Kernel-Erweiterungen
* Abrufen von Task-Ports für von Apple signierte Prozesse
* Ändern von NVRAM-Variablen
* Erlauben von Kernel-Debugging

Optionen werden in der NVRAM-Variablen als Bitflag gespeichert (`csr-active-config` auf Intel und `lp-sip0` wird aus dem gebooteten Device Tree für ARM gelesen). Sie können die Flags im XNU-Quellcode in `csr.sh` finden:

<figure><img src="../../../.gitbook/assets/image (1192).png" alt=""><figcaption></figcaption></figure>

### SIP-Status

Sie können überprüfen, ob SIP auf Ihrem System aktiviert ist, mit dem folgenden Befehl:
```bash
csrutil status
```
Wenn Sie SIP deaktivieren müssen, müssen Sie Ihren Computer im Wiederherstellungsmodus neu starten (indem Sie während des Startvorgangs Command+R drücken), und dann den folgenden Befehl ausführen:
```bash
csrutil disable
```
Wenn Sie SIP aktiviert lassen, aber die Debugging-Schutzmaßnahmen entfernen möchten, können Sie dies mit folgendem Befehl tun:
```bash
csrutil enable --without debug
```
### Other Restrictions

* **Verhindert das Laden von nicht signierten Kernel-Erweiterungen** (kexts), wodurch sichergestellt wird, dass nur verifizierte Erweiterungen mit dem Systemkernel interagieren.
* **Verhindert das Debugging** von macOS-Systemprozessen und schützt so die Kernkomponenten des Systems vor unbefugtem Zugriff und Modifikation.
* **Hemmung von Tools** wie dtrace, um Systemprozesse zu inspizieren, was die Integrität des Systembetriebs weiter schützt.

[**Erfahren Sie mehr über SIP-Informationen in diesem Vortrag**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**

### **SIP-bezogene Berechtigungen**

* `com.apple.rootless.xpc.bootstrap`: Steuerung von launchd
* `com.apple.rootless.install[.heritable]`: Zugriff auf das Dateisystem
* `com.apple.rootless.kext-management`: `kext_request`
* `com.apple.rootless.datavault.controller`: Verwaltung von UF\_DATAVAULT
* `com.apple.rootless.xpc.bootstrap`: XPC-Setup-Funktionen
* `com.apple.rootless.xpc.effective-root`: Root über launchd XPC
* `com.apple.rootless.restricted-block-devices`: Zugriff auf rohe Blockgeräte
* `com.apple.rootless.internal.installer-equivalent`: Ungehinderter Zugriff auf das Dateisystem
* `com.apple.rootless.restricted-nvram-variables[.heritable]`: Voller Zugriff auf NVRAM
* `com.apple.rootless.storage.label`: Ändern von Dateien, die durch com.apple.rootless xattr mit dem entsprechenden Label eingeschränkt sind
* `com.apple.rootless.volume.VM.label`: VM-Swap auf Volume beibehalten

## SIP Bypasses

Das Umgehen von SIP ermöglicht es einem Angreifer:

* **Zugriff auf Benutzerdaten**: Sensible Benutzerdaten wie E-Mails, Nachrichten und Safari-Verlauf aus allen Benutzerkonten lesen.
* **TCC-Umgehung**: Direkte Manipulation der TCC (Transparenz, Zustimmung und Kontrolle)-Datenbank, um unbefugten Zugriff auf die Webcam, das Mikrofon und andere Ressourcen zu gewähren.
* **Persistenz herstellen**: Malware an SIP-geschützten Orten platzieren, wodurch sie resistent gegen Entfernung ist, selbst durch Root-Rechte. Dies schließt auch die Möglichkeit ein, das Malware Removal Tool (MRT) zu manipulieren.
* **Kernel-Erweiterungen laden**: Obwohl es zusätzliche Schutzmaßnahmen gibt, vereinfacht das Umgehen von SIP den Prozess des Ladens nicht signierter Kernel-Erweiterungen.

### Installer-Pakete

**Installer-Pakete, die mit Apples Zertifikat signiert sind**, können die Schutzmaßnahmen umgehen. Das bedeutet, dass selbst Pakete, die von Standardentwicklern signiert sind, blockiert werden, wenn sie versuchen, SIP-geschützte Verzeichnisse zu ändern.

### Nicht vorhandene SIP-Datei

Ein potenzieller Schlupfloch besteht darin, dass, wenn eine Datei in **`rootless.conf` angegeben, aber derzeit nicht vorhanden ist**, sie erstellt werden kann. Malware könnte dies ausnutzen, um **Persistenz** im System herzustellen. Zum Beispiel könnte ein bösartiges Programm eine .plist-Datei in `/System/Library/LaunchDaemons` erstellen, wenn sie in `rootless.conf` aufgeführt, aber nicht vorhanden ist.

### com.apple.rootless.install.heritable

{% hint style="danger" %}
Die Berechtigung **`com.apple.rootless.install.heritable`** ermöglicht es, SIP zu umgehen.
{% endhint %}

#### [CVE-2019-8561](https://objective-see.org/blog/blog\_0x42.html) <a href="#cve" id="cve"></a>

Es wurde entdeckt, dass es möglich war, **das Installationspaket nach der Überprüfung der Codesignatur durch das System zu tauschen**, sodass das System das bösartige Paket anstelle des Originals installieren würde. Da diese Aktionen von **`system_installd`** durchgeführt wurden, würde dies das Umgehen von SIP ermöglichen.

#### [CVE-2020–9854](https://objective-see.org/blog/blog\_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Wenn ein Paket von einem gemounteten Image oder externen Laufwerk installiert wurde, würde der **Installer** die Binärdatei von **diesem Dateisystem** ausführen (anstatt von einem SIP-geschützten Ort), wodurch **`system_installd`** eine beliebige Binärdatei ausführen könnte.

#### CVE-2021-30892 - Shrootless

[**Forscher aus diesem Blogbeitrag**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) entdeckten eine Schwachstelle im Systemintegritätsschutz (SIP) von macOS, die als 'Shrootless'-Schwachstelle bezeichnet wird. Diese Schwachstelle konzentriert sich auf den **`system_installd`**-Daemon, der eine Berechtigung, **`com.apple.rootless.install.heritable`**, hat, die es einem seiner Kindprozesse ermöglicht, die Dateisystembeschränkungen von SIP zu umgehen.

Der **`system_installd`**-Daemon installiert Pakete, die von **Apple** signiert wurden.

Forscher fanden heraus, dass während der Installation eines von Apple signierten Pakets (.pkg-Datei) **`system_installd`** **alle** **Post-Installations**-Skripte ausführt, die im Paket enthalten sind. Diese Skripte werden von der Standard-Shell, **`zsh`**, ausgeführt, die automatisch **Befehle aus der Datei** **`/etc/zshenv`** ausführt, wenn sie existiert, selbst im nicht-interaktiven Modus. Dieses Verhalten könnte von Angreifern ausgenutzt werden: indem sie eine bösartige `/etc/zshenv`-Datei erstellen und auf **`system_installd` warten, um `zsh` aufzurufen**, könnten sie beliebige Operationen auf dem Gerät durchführen.

Darüber hinaus wurde entdeckt, dass **`/etc/zshenv` als allgemeine Angriffstechnik** verwendet werden könnte, nicht nur für eine SIP-Umgehung. Jedes Benutzerprofil hat eine `~/.zshenv`-Datei, die sich genauso verhält wie `/etc/zshenv`, aber keine Root-Rechte benötigt. Diese Datei könnte als Persistenzmechanismus verwendet werden, der jedes Mal ausgelöst wird, wenn `zsh` gestartet wird, oder als Mechanismus zur Erhöhung der Berechtigungen. Wenn ein Admin-Benutzer mit `sudo -s` oder `sudo <Befehl>` zu Root aufsteigt, würde die `~/.zshenv`-Datei ausgelöst, was effektiv zu Root-Rechten führt.

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

In [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) wurde entdeckt, dass der gleiche **`system_installd`**-Prozess weiterhin missbraucht werden konnte, da er das **Post-Installations-Skript in einen zufällig benannten Ordner, der durch SIP in `/tmp` geschützt ist,** legte. Das Problem ist, dass **`/tmp` selbst nicht durch SIP geschützt ist**, sodass es möglich war, ein **virtuelles Image darauf zu mounten**, dann würde der **Installer** das **Post-Installations-Skript** dort ablegen, das virtuelle Image **aushängen**, alle **Ordner** **neu erstellen** und das **Post-Installations**-Skript mit der **Payload** zum Ausführen hinzufügen.

#### [fsck\_cs utility](https://www.theregister.com/2016/03/30/apple\_os\_x\_rootless/)

Eine Schwachstelle wurde identifiziert, bei der **`fsck_cs`** in die Irre geführt wurde, um eine entscheidende Datei zu beschädigen, aufgrund seiner Fähigkeit, **symbolische Links** zu folgen. Angreifer erstellten speziell einen Link von _`/dev/diskX`_ zur Datei `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. Das Ausführen von **`fsck_cs`** auf _`/dev/diskX`_ führte zur Beschädigung von `Info.plist`. Die Integrität dieser Datei ist entscheidend für den SIP (System Integrity Protection) des Betriebssystems, der das Laden von Kernel-Erweiterungen steuert. Sobald sie beschädigt ist, ist die Fähigkeit von SIP, Kernel-Ausschlüsse zu verwalten, beeinträchtigt.

Die Befehle zur Ausnutzung dieser Schwachstelle sind:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Die Ausnutzung dieser Schwachstelle hat schwerwiegende Folgen. Die `Info.plist`-Datei, die normalerweise für die Verwaltung von Berechtigungen für Kernel-Erweiterungen verantwortlich ist, wird unwirksam. Dazu gehört die Unfähigkeit, bestimmte Erweiterungen wie `AppleHWAccess.kext` auf die schwarze Liste zu setzen. Folglich kann diese Erweiterung, da der Kontrollmechanismus des SIP außer Betrieb ist, geladen werden, was unbefugten Lese- und Schreibzugriff auf den RAM des Systems gewährt.

#### [Mount über SIP geschützte Ordner](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Es war möglich, ein neues Dateisystem über **SIP geschützte Ordner zu mounten, um den Schutz zu umgehen**.
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog\_0x14.html)

Das System ist so eingestellt, dass es von einem eingebetteten Installationsdisk-Image innerhalb von `Install macOS Sierra.app` bootet, um das Betriebssystem zu aktualisieren, wobei das `bless`-Dienstprogramm verwendet wird. Der verwendete Befehl lautet wie folgt:
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Die Sicherheit dieses Prozesses kann gefährdet werden, wenn ein Angreifer das Upgrade-Image (`InstallESD.dmg`) vor dem Booten verändert. Die Strategie besteht darin, einen dynamischen Loader (dyld) durch eine bösartige Version (`libBaseIA.dylib`) zu ersetzen. Dieser Austausch führt dazu, dass der Code des Angreifers ausgeführt wird, wenn der Installer gestartet wird.

Der Code des Angreifers erlangt während des Upgrade-Prozesses die Kontrolle und nutzt das Vertrauen des Systems in den Installer aus. Der Angriff erfolgt durch die Veränderung des `InstallESD.dmg`-Images mittels Method Swizzling, wobei insbesondere die Methode `extractBootBits` ins Visier genommen wird. Dies ermöglicht die Einspeisung von bösartigem Code, bevor das Disk-Image verwendet wird.

Darüber hinaus gibt es innerhalb des `InstallESD.dmg` ein `BaseSystem.dmg`, das als Wurzel-Dateisystem des Upgrade-Codes dient. Das Einspeisen einer dynamischen Bibliothek in dieses ermöglicht es dem bösartigen Code, innerhalb eines Prozesses zu arbeiten, der in der Lage ist, OS-Ebene-Dateien zu ändern, was das Potenzial für eine Systemkompromittierung erheblich erhöht.

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

In diesem Vortrag von [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk) wird gezeigt, wie **`systemmigrationd`** (das SIP umgehen kann) ein **bash**- und ein **perl**-Skript ausführt, das über Umgebungsvariablen **`BASH_ENV`** und **`PERL5OPT`** missbraucht werden kann.

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

Wie [**in diesem Blogbeitrag detailliert beschrieben**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), erlaubten `postinstall`-Skripte aus `InstallAssistant.pkg`-Paketen die Ausführung:
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
und es war möglich, einen Symlink in `${SHARED_SUPPORT_PATH}/SharedSupport.dmg` zu erstellen, der es einem Benutzer ermöglichen würde, **jede Datei zu entsperren und SIP-Schutz zu umgehen**.

### **com.apple.rootless.install**

{% hint style="danger" %}
Die Berechtigung **`com.apple.rootless.install`** ermöglicht es, SIP zu umgehen
{% endhint %}

Die Berechtigung `com.apple.rootless.install` ist bekannt dafür, den System Integrity Protection (SIP) auf macOS zu umgehen. Dies wurde insbesondere im Zusammenhang mit [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/) erwähnt.

In diesem speziellen Fall besitzt der System-XPC-Dienst, der sich unter `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` befindet, diese Berechtigung. Dies ermöglicht dem zugehörigen Prozess, SIP-Beschränkungen zu umgehen. Darüber hinaus bietet dieser Dienst bemerkenswerterweise eine Methode, die das Verschieben von Dateien ohne Durchsetzung von Sicherheitsmaßnahmen erlaubt.

## Versiegelte System-Snapshots

Versiegelte System-Snapshots sind ein von Apple in **macOS Big Sur (macOS 11)** eingeführtes Feature, das Teil des **System Integrity Protection (SIP)**-Mechanismus ist, um eine zusätzliche Sicherheitsebene und Systemstabilität zu bieten. Sie sind im Wesentlichen schreibgeschützte Versionen des Systemvolumens.

Hier ist ein detaillierterer Blick:

1. **Unveränderliches System**: Versiegelte System-Snapshots machen das macOS-Systemvolumen "unveränderlich", was bedeutet, dass es nicht modifiziert werden kann. Dies verhindert unbefugte oder versehentliche Änderungen am System, die die Sicherheit oder Systemstabilität gefährden könnten.
2. **Systemsoftware-Updates**: Wenn Sie macOS-Updates oder -Upgrades installieren, erstellt macOS einen neuen System-Snapshot. Das macOS-Startvolumen verwendet dann **APFS (Apple File System)**, um zu diesem neuen Snapshot zu wechseln. Der gesamte Prozess der Anwendung von Updates wird sicherer und zuverlässiger, da das System immer zum vorherigen Snapshot zurückkehren kann, wenn während des Updates etwas schiefgeht.
3. **Daten-Trennung**: In Verbindung mit dem Konzept der Trennung von Daten- und Systemvolumen, das in macOS Catalina eingeführt wurde, stellt die Funktion des versiegelten System-Snapshots sicher, dass alle Ihre Daten und Einstellungen auf einem separaten "**Daten**"-Volumen gespeichert werden. Diese Trennung macht Ihre Daten unabhängig vom System, was den Prozess der Systemupdates vereinfacht und die Systemsicherheit erhöht.

Denken Sie daran, dass diese Snapshots automatisch von macOS verwaltet werden und dank der Speicherfreigabefunktionen von APFS keinen zusätzlichen Speicherplatz auf Ihrer Festplatte beanspruchen. Es ist auch wichtig zu beachten, dass diese Snapshots sich von **Time Machine-Snapshots** unterscheiden, die benutzerzugängliche Backups des gesamten Systems sind.

### Snapshots überprüfen

Der Befehl **`diskutil apfs list`** listet die **Details der APFS-Volumes** und deren Layout auf:

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-&#x3C; Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Physical Store Disk:   disk0s2
|   |   Size:                       494384795648 B (494.4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Volume Disk (Role):   disk3s1 (System)
</strong>|   |   Name:                      Macintosh HD (Groß-/Kleinschreibung ignorierend)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12.8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Ja (Entsperrt)
|   |   Encrypted:                 Nein
|   |   |
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Ja
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Disk (Role):   disk3s5 (Daten)
|   Name:                      Macintosh HD - Daten (Groß-/Kleinschreibung ignorierend)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412.1 GB)
</strong>    |   Sealed:                    Nein
|   FileVault:                 Ja (Entsperrt)
</code></pre>

Im vorherigen Output ist zu sehen, dass **benutzerzugängliche Orte** unter `/System/Volumes/Data` gemountet sind.

Darüber hinaus ist der **macOS-Systemvolumensnapshot** unter `/` gemountet und ist **versiegelt** (kryptografisch vom OS signiert). Wenn SIP umgangen und modifiziert wird, wird das **OS nicht mehr booten**.

Es ist auch möglich, **zu überprüfen, ob das Siegel aktiviert ist**, indem Sie Folgendes ausführen:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Darüber hinaus wird die Snapshot-Disk ebenfalls als **schreibgeschützt** gemountet:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
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
