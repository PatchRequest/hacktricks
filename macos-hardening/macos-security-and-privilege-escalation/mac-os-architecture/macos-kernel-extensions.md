# macOS Kernel Extensions & Debugging

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

## Grundinformationen

Kernel-Erweiterungen (Kexts) sind **Pakete** mit einer **`.kext`**-Erweiterung, die **direkt in den macOS-Kernelraum geladen werden**, um zusätzliche Funktionalität zum Hauptbetriebssystem bereitzustellen.

### Anforderungen

Offensichtlich ist es so mächtig, dass es **kompliziert ist, eine Kernel-Erweiterung zu laden**. Dies sind die **Anforderungen**, die eine Kernel-Erweiterung erfüllen muss, um geladen zu werden:

* Beim **Eintreten in den Wiederherstellungsmodus** müssen Kernel-**Erweiterungen erlaubt** sein, geladen zu werden:

<figure><img src="../../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

* Die Kernel-Erweiterung muss **mit einem Kernel-Code-Signaturzertifikat signiert** sein, das nur von **Apple** **gewährt** werden kann. Wer wird das Unternehmen und die Gründe, warum es benötigt wird, im Detail überprüfen.
* Die Kernel-Erweiterung muss auch **notariell beglaubigt** sein, Apple wird in der Lage sein, sie auf Malware zu überprüfen.
* Dann ist der **Root**-Benutzer derjenige, der die **Kernel-Erweiterung laden** kann, und die Dateien im Paket müssen **dem Root gehören**.
* Während des Ladeprozesses muss das Paket an einem **geschützten Nicht-Root-Speicherort** vorbereitet werden: `/Library/StagedExtensions` (erfordert die Genehmigung `com.apple.rootless.storage.KernelExtensionManagement`).
* Schließlich erhält der Benutzer beim Versuch, sie zu laden, eine [**Bestätigungsanfrage**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) und, wenn akzeptiert, muss der Computer **neu gestartet** werden, um sie zu laden.

### Ladeprozess

In Catalina war es so: Es ist interessant zu beachten, dass der **Überprüfungs**prozess in **Userland** stattfindet. Allerdings können nur Anwendungen mit der Genehmigung **`com.apple.private.security.kext-management`** **die Kernel anfordern, eine Erweiterung zu laden**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** CLI **startet** den **Überprüfungs**prozess zum Laden einer Erweiterung
* Es wird mit **`kextd`** kommunizieren, indem es einen **Mach-Dienst** verwendet.
2. **`kextd`** wird mehrere Dinge überprüfen, wie die **Signatur**
* Es wird mit **`syspolicyd`** kommunizieren, um zu **überprüfen**, ob die Erweiterung **geladen** werden kann.
3. **`syspolicyd`** wird den **Benutzer** **auffordern**, wenn die Erweiterung nicht zuvor geladen wurde.
* **`syspolicyd`** wird das Ergebnis an **`kextd`** melden
4. **`kextd`** wird schließlich in der Lage sein, dem Kernel zu **sagen, die Erweiterung zu laden**

Wenn **`kextd`** nicht verfügbar ist, kann **`kextutil`** die gleichen Überprüfungen durchführen.

### Aufzählung (geladene Kexts)
```bash
# Get loaded kernel extensions
kextstat

# Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
## Kernelcache

{% hint style="danger" %}
Obwohl die Kernel-Erweiterungen in `/System/Library/Extensions/` erwartet werden, **werden Sie in diesem Ordner keine Binärdatei finden**. Dies liegt am **Kernelcache**, und um eine `.kext` zurückzuverfolgen, müssen Sie einen Weg finden, um sie zu erhalten.
{% endhint %}

Der **Kernelcache** ist eine **vorkompilierte und vorverlinkte Version des XNU-Kernels**, zusammen mit wesentlichen Geräte-**Treibern** und **Kernel-Erweiterungen**. Er wird in einem **komprimierten** Format gespeichert und während des Bootvorgangs in den Arbeitsspeicher dekomprimiert. Der Kernelcache ermöglicht eine **schnellere Bootzeit**, indem eine sofort einsatzbereite Version des Kernels und wichtiger Treiber verfügbar ist, wodurch die Zeit und Ressourcen reduziert werden, die sonst für das dynamische Laden und Verlinken dieser Komponenten beim Booten benötigt würden.

### Lokaler Kernelcache

In iOS befindet er sich in **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** in macOS können Sie ihn finden mit: **`find / -name "kernelcache" 2>/dev/null`** \
In meinem Fall habe ich ihn in macOS gefunden in:

* `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

Das IMG4-Dateiformat ist ein Containerformat, das von Apple in seinen iOS- und macOS-Geräten verwendet wird, um Firmware-Komponenten (wie **Kernelcache**) sicher zu **speichern und zu verifizieren**. Das IMG4-Format umfasst einen Header und mehrere Tags, die verschiedene Datenstücke kapseln, einschließlich der tatsächlichen Nutzlast (wie einen Kernel oder Bootloader), einer Signatur und einer Reihe von Manifest-Eigenschaften. Das Format unterstützt die kryptografische Verifizierung, die es dem Gerät ermöglicht, die Authentizität und Integrität der Firmware-Komponente vor der Ausführung zu bestätigen.

Es besteht normalerweise aus den folgenden Komponenten:

* **Nutzlast (IM4P)**:
* Oft komprimiert (LZFSE4, LZSS, …)
* Optional verschlüsselt
* **Manifest (IM4M)**:
* Enthält Signatur
* Zusätzliches Schlüssel/Wert-Wörterbuch
* **Wiederherstellungsinformationen (IM4R)**:
* Auch bekannt als APNonce
* Verhindert das Wiederholen einiger Updates
* OPTIONALE: Normalerweise wird dies nicht gefunden

Dekomprimieren Sie den Kernelcache:
```bash
# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Download&#x20;

* [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

In [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) ist es möglich, alle Kernel-Debug-Kits zu finden. Sie können es herunterladen, einbinden, mit dem [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html) Tool öffnen, auf den **`.kext`** Ordner zugreifen und **es extrahieren**.

Überprüfen Sie es auf Symbole mit:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
* [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Manchmal veröffentlicht Apple **kernelcache** mit **Symbols**. Sie können einige Firmwares mit Symbols über die Links auf diesen Seiten herunterladen. Die Firmwares enthalten den **kernelcache** neben anderen Dateien.

Um die Dateien zu **extrahieren**, ändern Sie zunächst die Erweiterung von `.ipsw` in `.zip` und **entpacken** Sie sie.

Nach dem Extrahieren der Firmware erhalten Sie eine Datei wie: **`kernelcache.release.iphone14`**. Sie ist im **IMG4**-Format, Sie können die interessanten Informationen mit:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:** 

{% code overflow="wrap" %}
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
{% endcode %}

[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Inspecting kernelcache

Überprüfen Sie, ob der kernelcache Symbole mit
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
Damit können wir jetzt **alle Erweiterungen extrahieren** oder die **eine, die Sie interessiert:**
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## Debugging



## Referenzen

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}
