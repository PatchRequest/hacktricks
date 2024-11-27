# Checklist - Linux Privilege Escalation

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Sluit aan by [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) bediener om te kommunikeer met ervare hackers en bug bounty jagters!

**Hacking Inligting**\
Betrek met inhoud wat die opwinding en uitdagings van hacking ondersoek

**Regte Tyd Hack Nuus**\
Bly op hoogte van die vinnig bewegende hacking wêreld deur regte tyd nuus en insigte

**Laaste Aankondigings**\
Bly ingelig oor die nuutste bug bounties wat bekendgestel word en belangrike platform opdaterings

**Sluit by ons aan op** [**Discord**](https://discord.com/invite/N3FrSbmwdy) en begin vandag saamwerk met top hackers!

### **Beste hulpmiddel om na Linux plaaslike privilige eskalasie vektore te soek:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Stelselinligting](privilege-escalation/#system-information)

* [ ] Kry **OS inligting**
* [ ] Kyk na die [**PATH**](privilege-escalation/#path), enige **skryfbare gids**?
* [ ] Kyk [**omgewing veranderlikes**](privilege-escalation/#env-info), enige sensitiewe besonderhede?
* [ ] Soek na [**kernel exploits**](privilege-escalation/#kernel-exploits) **met behulp van skripte** (DirtyCow?)
* [ ] **Kyk** of die [**sudo weergawe** kwesbaar is](privilege-escalation/#sudo-version)
* [ ] [**Dmesg** handtekening verifikasie het misluk](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] Meer stelselinventaris ([datum, stelsels stats, cpu inligting, drukkers](privilege-escalation/#more-system-enumeration))
* [ ] [**Inventariseer meer verdediging**](privilege-escalation/#enumerate-possible-defenses)

### [Aandrywe](privilege-escalation/#drives)

* [ ] **Lys gemonteerde** aandrywe
* [ ] **Enige ongemonteerde aandrywe?**
* [ ] **Enige krediete in fstab?**

### [**Gemonteerde Sagteware**](privilege-escalation/#installed-software)

* [ ] **Kyk vir**[ **nuttige sagteware**](privilege-escalation/#useful-software) **geïnstalleer**
* [ ] **Kyk vir** [**kwesbare sagteware**](privilege-escalation/#vulnerable-software-installed) **geïnstalleer**

### [Prosesse](privilege-escalation/#processes)

* [ ] Is enige **onbekende sagteware aan die gang**?
* [ ] Is enige sagteware aan die gang met **meer privilige as wat dit behoort te hê**?
* [ ] Soek na **exploits van lopende prosesse** (veral die weergawe wat aan die gang is).
* [ ] Kan jy die **binaire** van enige lopende proses **wysig**?
* [ ] **Monitor prosesse** en kyk of enige interessante proses gereeld aan die gang is.
* [ ] Kan jy **lees** van 'n paar interessante **proses geheue** (waar wagwoorde gestoor kan word)?

### [Geskeduleerde/Cron werke?](privilege-escalation/#scheduled-jobs)

* [ ] Word die [**PATH** ](privilege-escalation/#cron-path) deur 'n cron gewysig en kan jy daarin **skryf**?
* [ ] Enige [**wildcard** ](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection) in 'n cron werk?
* [ ] Enige [**wysigbare skrip** ](privilege-escalation/#cron-script-overwriting-and-symlink) wat **uitgevoer** word of binne **wysigbare gids** is?
* [ ] Het jy opgemerk dat 'n **skrip** dalk of gereeld [**uitgevoer** word](privilege-escalation/#frequent-cron-jobs)? (elke 1, 2 of 5 minute)

### [Dienste](privilege-escalation/#services)

* [ ] Enige **skryfbare .service** lêer?
* [ ] Enige **skryfbare binaire** wat deur 'n **diens** uitgevoer word?
* [ ] Enige **skryfbare gids in systemd PATH**?

### [Timers](privilege-escalation/#timers)

* [ ] Enige **skryfbare timer**?

### [Sockets](privilege-escalation/#sockets)

* [ ] Enige **skryfbare .socket** lêer?
* [ ] Kan jy **kommunikeer met enige socket**?
* [ ] **HTTP sockets** met interessante inligting?

### [D-Bus](privilege-escalation/#d-bus)

* [ ] Kan jy **kommunikeer met enige D-Bus**?

### [Netwerk](privilege-escalation/#network)

* [ ] Inventariseer die netwerk om te weet waar jy is
* [ ] **Oop poorte wat jy nie voorheen kon toegang nie** om 'n shell binne die masjien te kry?
* [ ] Kan jy **verkeer afluister** met `tcpdump`?

### [Gebruikers](privilege-escalation/#users)

* [ ] Generiese gebruikers/groepe **inventarisering**
* [ ] Het jy 'n **baie groot UID**? Is die **masjien** **kwesbaar**?
* [ ] Kan jy [**privilege eskalasie danksy 'n groep**](privilege-escalation/interesting-groups-linux-pe/) waartoe jy behoort?
* [ ] **Clipboard** data?
* [ ] Wagwoordbeleid?
* [ ] Probeer om **elke bekende wagwoord** wat jy voorheen ontdek het te gebruik om in te log met **elke** moontlike **gebruiker**. Probeer ook om sonder 'n wagwoord in te log.

### [Skryfbare PATH](privilege-escalation/#writable-path-abuses)

* [ ] As jy **skryfregte oor 'n gids in PATH** het, kan jy dalk privilige eskalasie doen

### [SUDO en SUID opdragte](privilege-escalation/#sudo-and-suid)

* [ ] Kan jy **enige opdrag met sudo uitvoer**? Kan jy dit gebruik om IES, SKRYF of UITVOER enigiets as root? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Is enige **exploitable SUID binaire**? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Is [**sudo** opdragte **beperk** deur **pad**? kan jy die beperkings **omseil**](privilege-escalation/#sudo-execution-bypassing-paths)?
* [ ] [**Sudo/SUID binaire sonder pad aangedui**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
* [ ] [**SUID binaire wat pad spesifiseer**](privilege-escalation/#suid-binary-with-command-path)? Omseil
* [ ] [**LD\_PRELOAD kwesbaarheid**](privilege-escalation/#ld_preload)
* [ ] [**Gebrek aan .so biblioteek in SUID binaire**](privilege-escalation/#suid-binary-so-injection) van 'n skryfbare gids?
* [ ] [**SUDO tokens beskikbaar**](privilege-escalation/#reusing-sudo-tokens)? [**Kan jy 'n SUDO token skep**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
* [ ] Kan jy [**lees of wysig sudoers lêers**](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
* [ ] Kan jy [**wysig /etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d)?
* [ ] [**OpenBSD DOAS**](privilege-escalation/#doas) opdrag

### [Vermoeëns](privilege-escalation/#capabilities)

* [ ] Het enige binaire enige **onverwagte vermoë**?

### [ACLs](privilege-escalation/#acls)

* [ ] Het enige lêer enige **onverwagte ACL**?

### [Oop Shell sessies](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL Voorspelbare PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**SSH Interessante konfigurasiewaardes**](privilege-escalation/#ssh-interesting-configuration-values)

### [Interessante Lêers](privilege-escalation/#interesting-files)

* [ ] **Profiel lêers** - Lees sensitiewe data? Skryf na privesk?
* [ ] **passwd/shadow lêers** - Lees sensitiewe data? Skryf na privesk?
* [ ] **Kyk na algemeen interessante gidse** vir sensitiewe data
* [ ] **Vreemde Ligging/Eienaarskap lêers,** jy mag toegang hê tot of uitvoerbare lêers verander
* [ ] **Gewysig** in laaste minute
* [ ] **Sqlite DB lêers**
* [ ] **Versteekte lêers**
* [ ] **Skrip/Binaries in PATH**
* [ ] **Web lêers** (wagwoorde?)
* [ ] **Backups**?
* [ ] **Bekende lêers wat wagwoorde bevat**: Gebruik **Linpeas** en **LaZagne**
* [ ] **Generiese soektog**

### [**Skryfbare Lêers**](privilege-escalation/#writable-files)

* [ ] **Wysig python biblioteek** om arbitrêre opdragte uit te voer?
* [ ] Kan jy **wysig log lêers**? **Logtotten** kwesbaarheid
* [ ] Kan jy **wysig /etc/sysconfig/network-scripts/**? Centos/Redhat kwesbaarheid
* [ ] Kan jy [**skryf in ini, int.d, systemd of rc.d lêers**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Ander truuks**](privilege-escalation/#other-tricks)

* [ ] Kan jy [**NFS misbruik om privilige te eskaleer**](privilege-escalation/#nfs-privilege-escalation)?
* [ ] Het jy nodig om [**uit 'n beperkende shell te ontsnap**](privilege-escalation/#escaping-from-restricted-shells)?

<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Sluit aan by [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) bediener om te kommunikeer met ervare hackers en bug bounty jagters!

**Hacking Inligting**\
Betrek met inhoud wat die opwinding en uitdagings van hacking ondersoek

**Regte Tyd Hack Nuus**\
Bly op hoogte van die vinnig bewegende hacking wêreld deur regte tyd nuus en insigte

**Laaste Aankondigings**\
Bly ingelig oor die nuutste bug bounties wat bekendgestel word en belangrike platform opdaterings

**Sluit by ons aan op** [**Discord**](https://discord.com/invite/N3FrSbmwdy) en begin vandag saamwerk met top hackers!

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
