# macOS-Sicherheit & Privilegieneskalation

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Tritt dem [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) Server bei, um mit erfahrenen Hackern und Bug-Bounty-Jägern zu kommunizieren!

**Hacking Einblicke**\
Engagiere dich mit Inhalten, die in den Nervenkitzel und die Herausforderungen des Hackens eintauchen

**Echtzeit-Hack-Nachrichten**\
Bleibe auf dem Laufenden mit der schnelllebigen Hacking-Welt durch Echtzeit-Nachrichten und Einblicke

**Neueste Ankündigungen**\
Bleibe informiert über die neuesten Bug-Bounties und wichtige Plattform-Updates

**Tritt uns auf** [**Discord**](https://discord.com/invite/N3FrSbmwdy) bei und beginne noch heute mit den besten Hackern zusammenzuarbeiten!

## Grundlegendes zu macOS

Wenn du mit macOS nicht vertraut bist, solltest du die Grundlagen von macOS lernen:

* Besondere macOS **Dateien & Berechtigungen:**

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* Häufige macOS **Benutzer**

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* Die **Architektur** des k**ernels**

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Häufige macOS n**etzwerkdienste & Protokolle**

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **Open Source** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
* Um ein `tar.gz` herunterzuladen, ändere eine URL wie [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) zu [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### macOS MDM

In Unternehmen werden **macOS** Systeme höchstwahrscheinlich **mit einem MDM verwaltet**. Daher ist es aus der Perspektive eines Angreifers interessant zu wissen, **wie das funktioniert**:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### macOS - Inspektion, Debugging und Fuzzing

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## macOS Sicherheitsmaßnahmen

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Angriffsfläche

### Datei-Berechtigungen

Wenn ein **Prozess, der als root läuft,** eine Datei schreibt, die von einem Benutzer kontrolliert werden kann, könnte der Benutzer dies ausnutzen, um **Berechtigungen zu eskalieren**.\
Dies könnte in den folgenden Situationen auftreten:

* Die verwendete Datei wurde bereits von einem Benutzer erstellt (gehört dem Benutzer)
* Die verwendete Datei ist aufgrund einer Gruppe für den Benutzer beschreibbar
* Die verwendete Datei befindet sich in einem Verzeichnis, das dem Benutzer gehört (der Benutzer könnte die Datei erstellen)
* Die verwendete Datei befindet sich in einem Verzeichnis, das root gehört, aber der Benutzer hat aufgrund einer Gruppe Schreibzugriff darauf (der Benutzer könnte die Datei erstellen)

In der Lage zu sein, eine **Datei zu erstellen**, die von **root verwendet wird**, ermöglicht es einem Benutzer, **von ihrem Inhalt zu profitieren** oder sogar **Symlinks/Hartlinks** zu erstellen, um sie an einen anderen Ort zu verweisen.

Für diese Art von Schwachstellen vergiss nicht, **anfällige `.pkg`-Installer zu überprüfen**:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}

### Dateierweiterung & URL-Schema-App-Handler

Seltsame Apps, die durch Dateierweiterungen registriert sind, könnten missbraucht werden, und verschiedene Anwendungen können registriert werden, um spezifische Protokolle zu öffnen

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## macOS TCC / SIP Privilegieneskalation

In macOS **können Anwendungen und Binärdateien Berechtigungen** haben, um auf Ordner oder Einstellungen zuzugreifen, die sie privilegierter machen als andere.

Daher muss ein Angreifer, der eine macOS-Maschine erfolgreich kompromittieren möchte, seine **TCC-Berechtigungen eskalieren** (oder sogar **SIP umgehen**, je nach seinen Bedürfnissen).

Diese Berechtigungen werden normalerweise in Form von **Berechtigungen** vergeben, mit denen die Anwendung signiert ist, oder die Anwendung könnte einige Zugriffe angefordert haben, und nachdem der **Benutzer sie genehmigt hat**, können sie in den **TCC-Datenbanken** gefunden werden. Eine andere Möglichkeit, wie ein Prozess diese Berechtigungen erhalten kann, besteht darin, ein **Kind eines Prozesses** mit diesen **Berechtigungen** zu sein, da sie normalerweise **vererbt** werden.

Folge diesen Links, um verschiedene Möglichkeiten zu finden, [**Berechtigungen in TCC zu eskalieren**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), um [**TCC zu umgehen**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) und wie in der Vergangenheit [**SIP umgangen wurde**](macos-security-protections/macos-sip.md#sip-bypasses).

## macOS Traditionelle Privilegieneskalation

Natürlich solltest du aus der Perspektive eines Red Teams auch daran interessiert sein, zu root zu eskalieren. Überprüfe den folgenden Beitrag für einige Hinweise:

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}

## macOS Compliance

* [https://github.com/usnistgov/macos\_security](https://github.com/usnistgov/macos\_security)

## Referenzen

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="/.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Tritt dem [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) Server bei, um mit erfahrenen Hackern und Bug-Bounty-Jägern zu kommunizieren!

**Hacking Einblicke**\
Engagiere dich mit Inhalten, die in den Nervenkitzel und die Herausforderungen des Hackens eintauchen

**Echtzeit-Hack-Nachrichten**\
Bleibe auf dem Laufenden mit der schnelllebigen Hacking-Welt durch Echtzeit-Nachrichten und Einblicke

**Neueste Ankündigungen**\
Bleibe informiert über die neuesten Bug-Bounties und wichtige Plattform-Updates

**Tritt uns auf** [**Discord**](https://discord.com/invite/N3FrSbmwdy) bei und beginne noch heute mit den besten Hackern zusammenzuarbeiten!

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}
