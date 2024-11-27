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

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Vertiefen Sie Ihr Fachwissen in **Mobilsicherheit** mit der 8kSec Academy. Meistern Sie die Sicherheit von iOS und Android durch unsere selbstgesteuerten Kurse und lassen Sie sich zertifizieren:

{% embed url="https://academy.8ksec.io/" %}

**Manipulation von Audio- und Videodateien** ist ein Grundpfeiler in **CTF-Forensik-Herausforderungen**, der **Steganographie** und Metadatenanalyse nutzt, um geheime Nachrichten zu verbergen oder offenzulegen. Werkzeuge wie **[mediainfo](https://mediaarea.net/en/MediaInfo)** und **`exiftool`** sind unerlässlich, um Dateimetadaten zu inspizieren und Inhaltstypen zu identifizieren.

Für Audioherausforderungen sticht **[Audacity](http://www.audacityteam.org/)** als erstklassiges Werkzeug hervor, um Wellenformen anzuzeigen und Spektrogramme zu analysieren, was entscheidend ist, um in Audio codierten Text aufzudecken. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** wird für die detaillierte Spektrogrammanalyse sehr empfohlen. **Audacity** ermöglicht die Manipulation von Audio, wie das Verlangsamen oder Umkehren von Tracks, um versteckte Nachrichten zu erkennen. **[Sox](http://sox.sourceforge.net/)**, ein Kommandozeilenwerkzeug, glänzt beim Konvertieren und Bearbeiten von Audiodateien.

**Least Significant Bits (LSB)**-Manipulation ist eine gängige Technik in der Audio- und Video-Steganographie, die die festen Größen von Mediendateien ausnutzt, um Daten diskret einzubetten. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** ist nützlich, um Nachrichten zu decodieren, die als **DTMF-Töne** oder **Morsecode** verborgen sind.

Videoherausforderungen beinhalten oft Containerformate, die Audio- und Videostreams bündeln. **[FFmpeg](http://ffmpeg.org/)** ist das bevorzugte Werkzeug zur Analyse und Manipulation dieser Formate, das in der Lage ist, Inhalte zu demultiplexen und wiederzugeben. Für Entwickler integriert **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** die Fähigkeiten von FFmpeg in Python für fortgeschrittene skriptbare Interaktionen.

Diese Vielzahl von Werkzeugen unterstreicht die Vielseitigkeit, die in CTF-Herausforderungen erforderlich ist, bei denen die Teilnehmer ein breites Spektrum an Analyse- und Manipulationstechniken einsetzen müssen, um versteckte Daten in Audio- und Videodateien aufzudecken.

## Referenzen
* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)


<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Vertiefen Sie Ihr Fachwissen in **Mobilsicherheit** mit der 8kSec Academy. Meistern Sie die Sicherheit von iOS und Android durch unsere selbstgesteuerten Kurse und lassen Sie sich zertifizieren:

{% embed url="https://academy.8ksec.io/" %}

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
