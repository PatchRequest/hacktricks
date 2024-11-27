# Checklist - Linux Privilegieneskalation

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}

<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Tritt dem [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) Server bei, um mit erfahrenen Hackern und Bug-Bounty-Jägern zu kommunizieren!

**Hacking Einblicke**\
Engagiere dich mit Inhalten, die in den Nervenkitzel und die Herausforderungen des Hackens eintauchen

**Echtzeit Hack Nachrichten**\
Bleibe auf dem Laufenden mit der schnelllebigen Hack-Welt durch Echtzeit-Nachrichten und Einblicke

**Neueste Ankündigungen**\
Bleibe informiert über die neuesten Bug-Bounties und wichtige Plattform-Updates

**Tritt uns auf** [**Discord**](https://discord.com/invite/N3FrSbmwdy) bei und beginne noch heute mit den besten Hackern zusammenzuarbeiten!

### **Bestes Tool zur Suche nach lokalen Privilegieneskalationsvektoren in Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Systeminformationen](privilege-escalation/#system-information)

* [ ] Hole **Betriebssysteminformationen**
* [ ] Überprüfe den [**PATH**](privilege-escalation/#path), gibt es einen **beschreibbaren Ordner**?
* [ ] Überprüfe [**Umgebungsvariablen**](privilege-escalation/#env-info), gibt es sensible Details?
* [ ] Suche nach [**Kernel-Exploits**](privilege-escalation/#kernel-exploits) **mit Skripten** (DirtyCow?)
* [ ] **Überprüfe**, ob die [**sudo-Version** anfällig ist](privilege-escalation/#sudo-version)
* [ ] [**Dmesg** Signaturüberprüfung fehlgeschlagen](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] Weitere Systemenumeration ([Datum, Systemstatistiken, CPU-Informationen, Drucker](privilege-escalation/#more-system-enumeration))
* [ ] [**Weitere Abwehrmaßnahmen enumerieren**](privilege-escalation/#enumerate-possible-defenses)

### [Laufwerke](privilege-escalation/#drives)

* [ ] **Aufgelistete** Laufwerke
* [ ] **Gibt es ein nicht gemountetes Laufwerk?**
* [ ] **Gibt es Anmeldeinformationen in fstab?**

### [**Installierte Software**](privilege-escalation/#installed-software)

* [ ] **Überprüfe auf** [**nützliche Software**](privilege-escalation/#useful-software) **installiert**
* [ ] **Überprüfe auf** [**anfällige Software**](privilege-escalation/#vulnerable-software-installed) **installiert**

### [Prozesse](privilege-escalation/#processes)

* [ ] Läuft **irgendwelche unbekannte Software**?
* [ ] Läuft irgendeine Software mit **mehr Rechten als sie haben sollte**?
* [ ] Suche nach **Exploits von laufenden Prozessen** (insbesondere der laufenden Version).
* [ ] Kannst du die **Binärdatei** eines laufenden Prozesses **modifizieren**?
* [ ] **Überwache Prozesse** und überprüfe, ob ein interessanter Prozess häufig läuft.
* [ ] Kannst du **Speicher** eines interessanten **Prozesses lesen** (wo Passwörter gespeichert sein könnten)?

### [Geplante/Cron-Jobs?](privilege-escalation/#scheduled-jobs)

* [ ] Wird der [**PATH**](privilege-escalation/#cron-path) von einem Cron geändert und kannst du darin **schreiben**?
* [ ] Gibt es ein [**Wildcard**](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection) in einem Cron-Job?
* [ ] Wird ein [**modifizierbares Skript**](privilege-escalation/#cron-script-overwriting-and-symlink) **ausgeführt** oder befindet es sich in einem **modifizierbaren Ordner**?
* [ ] Hast du festgestellt, dass ein **Skript** sehr **häufig** [**ausgeführt** wird](privilege-escalation/#frequent-cron-jobs)? (alle 1, 2 oder 5 Minuten)

### [Dienste](privilege-escalation/#services)

* [ ] Gibt es eine **beschreibbare .service**-Datei?
* [ ] Gibt es eine **beschreibbare Binärdatei**, die von einem **Dienst** ausgeführt wird?
* [ ] Gibt es einen **beschreibbaren Ordner im systemd PATH**?

### [Timer](privilege-escalation/#timers)

* [ ] Gibt es einen **beschreibbaren Timer**?

### [Sockets](privilege-escalation/#sockets)

* [ ] Gibt es eine **beschreibbare .socket**-Datei?
* [ ] Kannst du mit **irgendeinem Socket kommunizieren**?
* [ ] **HTTP-Sockets** mit interessanten Informationen?

### [D-Bus](privilege-escalation/#d-bus)

* [ ] Kannst du mit **irgendeinem D-Bus kommunizieren**?

### [Netzwerk](privilege-escalation/#network)

* [ ] Enumere das Netzwerk, um zu wissen, wo du bist
* [ ] **Offene Ports, auf die du vorher keinen Zugriff hattest**, um eine Shell im Inneren der Maschine zu erhalten?
* [ ] Kannst du **Traffic sniffen** mit `tcpdump`?

### [Benutzer](privilege-escalation/#users)

* [ ] Generische Benutzer-/Gruppenumeration
* [ ] Hast du eine **sehr große UID**? Ist die **Maschine** **anfällig**?
* [ ] Kannst du [**Privilegien dank einer Gruppe**](privilege-escalation/interesting-groups-linux-pe/) erhöhen, zu der du gehörst?
* [ ] **Zwischenablage**-Daten?
* [ ] Passwort-Richtlinie?
* [ ] Versuche, **jedes bekannte Passwort**, das du zuvor entdeckt hast, zu verwenden, um dich **mit jedem** möglichen **Benutzer** anzumelden. Versuche auch, dich ohne Passwort anzumelden.

### [Beschreibbarer PATH](privilege-escalation/#writable-path-abuses)

* [ ] Wenn du **Schreibrechte über einen Ordner im PATH** hast, könntest du in der Lage sein, Privilegien zu erhöhen

### [SUDO und SUID-Befehle](privilege-escalation/#sudo-and-suid)

* [ ] Kannst du **irgendeinen Befehl mit sudo ausführen**? Kannst du es verwenden, um als root zu LESEN, ZU SCHREIBEN oder ETWAS AUSZUFÜHREN? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Gibt es eine **ausnutzbare SUID-Binärdatei**? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Sind [**sudo**-Befehle **durch den** **Pfad** **eingeschränkt**? Kannst du die Einschränkungen **umgehen**](privilege-escalation/#sudo-execution-bypassing-paths)?
* [ ] [**Sudo/SUID-Binärdatei ohne angegebenen Pfad**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
* [ ] [**SUID-Binärdatei mit angegebenem Pfad**](privilege-escalation/#suid-binary-with-command-path)? Umgehen
* [ ] [**LD\_PRELOAD vuln**](privilege-escalation/#ld_preload)
* [ ] [**Fehlende .so-Bibliothek in SUID-Binärdatei**](privilege-escalation/#suid-binary-so-injection) aus einem beschreibbaren Ordner?
* [ ] [**SUDO-Tokens verfügbar**](privilege-escalation/#reusing-sudo-tokens)? [**Kannst du ein SUDO-Token erstellen**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
* [ ] Kannst du [**sudoers-Dateien lesen oder modifizieren**](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
* [ ] Kannst du [**/etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d) modifizieren?
* [ ] [**OpenBSD DOAS**](privilege-escalation/#doas) Befehl

### [Fähigkeiten](privilege-escalation/#capabilities)

* [ ] Hat irgendeine Binärdatei eine **unerwartete Fähigkeit**?

### [ACLs](privilege-escalation/#acls)

* [ ] Hat irgendeine Datei eine **unerwartete ACL**?

### [Offene Shell-Sitzungen](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL Vorhersehbarer PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**SSH Interessante Konfigurationswerte**](privilege-escalation/#ssh-interesting-configuration-values)

### [Interessante Dateien](privilege-escalation/#interesting-files)

* [ ] **Profil-Dateien** - Sensible Daten lesen? In privesc schreiben?
* [ ] **passwd/shadow-Dateien** - Sensible Daten lesen? In privesc schreiben?
* [ ] **Überprüfe häufig interessante Ordner** auf sensible Daten
* [ ] **Seltsame Standort/Besitzdateien,** auf die du möglicherweise Zugriff hast oder ausführbare Dateien ändern kannst
* [ ] **In den letzten Minuten geändert**
* [ ] **Sqlite DB-Dateien**
* [ ] **Versteckte Dateien**
* [ ] **Skripte/Binärdateien im PATH**
* [ ] **Web-Dateien** (Passwörter?)
* [ ] **Backups**?
* [ ] **Bekannte Dateien, die Passwörter enthalten**: Verwende **Linpeas** und **LaZagne**
* [ ] **Generische Suche**

### [**Beschreibbare Dateien**](privilege-escalation/#writable-files)

* [ ] **Modifiziere die Python-Bibliothek**, um beliebige Befehle auszuführen?
* [ ] Kannst du **Protokolldateien modifizieren**? **Logtotten**-Exploits
* [ ] Kannst du **/etc/sysconfig/network-scripts/** modifizieren? Centos/Redhat-Exploits
* [ ] Kannst du [**in ini, int.d, systemd oder rc.d-Dateien schreiben**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Andere Tricks**](privilege-escalation/#other-tricks)

* [ ] Kannst du [**NFS ausnutzen, um Privilegien zu erhöhen**](privilege-escalation/#nfs-privilege-escalation)?
* [ ] Musst du [**aus einer restriktiven Shell entkommen**](privilege-escalation/#escaping-from-restricted-shells)?

<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Tritt dem [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) Server bei, um mit erfahrenen Hackern und Bug-Bounty-Jägern zu kommunizieren!

**Hacking Einblicke**\
Engagiere dich mit Inhalten, die in den Nervenkitzel und die Herausforderungen des Hackens eintauchen

**Echtzeit Hack Nachrichten**\
Bleibe auf dem Laufenden mit der schnelllebigen Hack-Welt durch Echtzeit-Nachrichten und Einblicke

**Neueste Ankündigungen**\
Bleibe informiert über die neuesten Bug-Bounties und wichtige Plattform-Updates

**Tritt uns auf** [**Discord**](https://discord.com/invite/N3FrSbmwdy) bei und beginne noch heute mit den besten Hackern zusammenzuarbeiten!

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}
