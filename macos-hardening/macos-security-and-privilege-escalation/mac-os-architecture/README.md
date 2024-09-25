# macOS Kernel & System Extensions

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}

## XNU Kernel

Der **Kern von macOS ist XNU**, was für "X is Not Unix" steht. Dieser Kernel besteht grundlegend aus dem **Mach-Mikrokernel** (der später besprochen wird) und Elementen der Berkeley Software Distribution (**BSD**). XNU bietet auch eine Plattform für **Kernel-Treiber über ein System namens I/O Kit**. Der XNU-Kernel ist Teil des Darwin-Open-Source-Projekts, was bedeutet, dass **der Quellcode frei zugänglich ist**.

Aus der Perspektive eines Sicherheitsforschers oder Unix-Entwicklers kann **macOS** ziemlich **ähnlich** einem **FreeBSD**-System mit einer eleganten GUI und einer Vielzahl von benutzerdefinierten Anwendungen erscheinen. Die meisten Anwendungen, die für BSD entwickelt wurden, lassen sich ohne Modifikationen auf macOS kompilieren und ausführen, da die für Unix-Benutzer vertrauten Befehlszeilenwerkzeuge alle in macOS vorhanden sind. Da der XNU-Kernel jedoch Mach integriert, gibt es einige wesentliche Unterschiede zwischen einem traditionellen Unix-ähnlichen System und macOS, und diese Unterschiede können potenzielle Probleme verursachen oder einzigartige Vorteile bieten.

Open-Source-Version von XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach ist ein **Mikrokernel**, der **UNIX-kompatibel** sein soll. Eines seiner wichtigsten Entwurfsprinzipien war es, die Menge an **Code**, die im **Kernel**-Bereich läuft, zu **minimieren** und stattdessen viele typische Kernel-Funktionen, wie Dateisystem, Netzwerk und I/O, als **Benutzerebene-Aufgaben** auszuführen.

In XNU ist Mach **verantwortlich für viele der kritischen Low-Level-Operationen**, die ein Kernel typischerweise behandelt, wie Prozessorplanung, Multitasking und Verwaltung des virtuellen Speichers.

### BSD

Der XNU **Kernel** **integriert** auch eine erhebliche Menge an Code, der aus dem **FreeBSD**-Projekt stammt. Dieser Code **läuft als Teil des Kernels zusammen mit Mach** im selben Adressraum. Der FreeBSD-Code innerhalb von XNU kann jedoch erheblich vom ursprünglichen FreeBSD-Code abweichen, da Modifikationen erforderlich waren, um die Kompatibilität mit Mach sicherzustellen. FreeBSD trägt zu vielen Kernel-Operationen bei, einschließlich:

* Prozessmanagement
* Signalverarbeitung
* Grundlegende Sicherheitsmechanismen, einschließlich Benutzer- und Gruppenverwaltung
* Systemaufruf-Infrastruktur
* TCP/IP-Stack und Sockets
* Firewall und Paketfilterung

Das Verständnis der Interaktion zwischen BSD und Mach kann komplex sein, aufgrund ihrer unterschiedlichen konzeptionellen Rahmen. Zum Beispiel verwendet BSD Prozesse als seine grundlegende Ausführungseinheit, während Mach auf Threads basiert. Diese Diskrepanz wird in XNU durch **die Zuordnung jedes BSD-Prozesses zu einer Mach-Aufgabe** gelöst, die genau einen Mach-Thread enthält. Wenn der Fork()-Systemaufruf von BSD verwendet wird, nutzt der BSD-Code innerhalb des Kernels Mach-Funktionen, um eine Aufgabe und eine Thread-Struktur zu erstellen.

Darüber hinaus **pflegen Mach und BSD jeweils unterschiedliche Sicherheitsmodelle**: **Das Sicherheitsmodell von Mach** basiert auf **Port-Rechten**, während das Sicherheitsmodell von BSD auf **Prozesseigentum** basiert. Unterschiede zwischen diesen beiden Modellen haben gelegentlich zu lokalen Privilegieneskalationsanfälligkeiten geführt. Neben typischen Systemaufrufen gibt es auch **Mach-Traps, die es Benutzerspace-Programmen ermöglichen, mit dem Kernel zu interagieren**. Diese verschiedenen Elemente bilden zusammen die facettenreiche, hybride Architektur des macOS-Kernels.

### I/O Kit - Treiber

Das I/O Kit ist ein Open-Source, objektorientiertes **Gerätetreiber-Framework** im XNU-Kernel, das **dynamisch geladene Gerätetreiber** verwaltet. Es ermöglicht, modulare Codes zur Laufzeit in den Kernel einzufügen und unterstützt verschiedene Hardware.

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - Interprozesskommunikation

{% content-ref url="../macos-proces-abuse/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../macos-proces-abuse/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

## macOS Kernel-Erweiterungen

macOS ist **sehr restriktiv beim Laden von Kernel-Erweiterungen** (.kext) aufgrund der hohen Privilegien, mit denen der Code ausgeführt wird. Tatsächlich ist es standardmäßig nahezu unmöglich (es sei denn, es wird ein Bypass gefunden).

Auf der folgenden Seite kannst du auch sehen, wie du die `.kext` wiederherstellen kannst, die macOS in seinem **Kernelcache** lädt:

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### macOS Systemerweiterungen

Anstelle von Kernel-Erweiterungen hat macOS die Systemerweiterungen geschaffen, die in der Benutzerebene APIs bieten, um mit dem Kernel zu interagieren. Auf diese Weise können Entwickler auf die Verwendung von Kernel-Erweiterungen verzichten.

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## Referenzen

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}
