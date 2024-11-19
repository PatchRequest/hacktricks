# Lista - Linux Eskalacija Privilegija

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Pridružite se [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) serveru da komunicirate sa iskusnim hakerima i lovcima na greške!

**Hakerski Uvidi**\
Uključite se u sadržaj koji se bavi uzbuđenjem i izazovima hakovanja

**Vesti o Haku u Realnom Vremenu**\
Budite u toku sa brzim svetom hakovanja kroz vesti i uvide u realnom vremenu

**Najnovija Obaveštenja**\
Budite informisani o najnovijim nagradama za greške i važnim ažuriranjima platforme

**Pridružite nam se na** [**Discordu**](https://discord.com/invite/N3FrSbmwdy) i počnite da sarađujete sa vrhunskim hakerima danas!

### **Najbolji alat za traženje lokalnih vektora eskalacije privilegija na Linuxu:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informacije o sistemu](privilege-escalation/#system-information)

* [ ] Dobijte **informacije o OS-u**
* [ ] Proverite [**PATH**](privilege-escalation/#path), da li postoji **pisivačka fascikla**?
* [ ] Proverite [**env promenljive**](privilege-escalation/#env-info), da li postoji neka osetljiva informacija?
* [ ] Pretražite [**kernel exploite**](privilege-escalation/#kernel-exploits) **koristeći skripte** (DirtyCow?)
* [ ] **Proverite** da li je [**sudo verzija** ranjiva](privilege-escalation/#sudo-version)
* [ ] [**Dmesg** verifikacija potpisa nije uspela](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] Više sistemskih informacija ([datum, sistemske statistike, cpu informacije, štampači](privilege-escalation/#more-system-enumeration))
* [ ] [**Enumerisanje više odbrana**](privilege-escalation/#enumerate-possible-defenses)

### [Diskovi](privilege-escalation/#drives)

* [ ] **Lista montiranih** diskova
* [ ] **Da li postoji neki nemontirani disk?**
* [ ] **Da li postoje kredencijali u fstab?**

### [**Instalirani Softver**](privilege-escalation/#installed-software)

* [ ] **Proverite za** [**koristan softver**](privilege-escalation/#useful-software) **instaliran**
* [ ] **Proverite za** [**ranjiv softver**](privilege-escalation/#vulnerable-software-installed) **instaliran**

### [Procesi](privilege-escalation/#processes)

* [ ] Da li se pokreće neki **nepoznati softver**?
* [ ] Da li se neki softver pokreće sa **više privilegija nego što bi trebao**?
* [ ] Pretražite za **exploite pokrenutih procesa** (posebno verziju koja se pokreće).
* [ ] Možete li **modifikovati binarni** fajl nekog pokrenutog procesa?
* [ ] **Pratite procese** i proverite da li se neki zanimljiv proces često pokreće.
* [ ] Možete li **pročitati** neku zanimljivu **memoriju procesa** (gde bi lozinke mogle biti sačuvane)?

### [Zakazani/Cron poslovi?](privilege-escalation/#scheduled-jobs)

* [ ] Da li se [**PATH**](privilege-escalation/#cron-path) menja od strane nekog crona i možete li **pisati** u njega?
* [ ] Da li postoji neki [**wildcard**](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection) u cron poslu?
* [ ] Da li se neki [**modifikovani skript**](privilege-escalation/#cron-script-overwriting-and-symlink) izvršava ili se nalazi u **modifikovanoj fascikli**?
* [ ] Da li ste otkrili da se neki **skript** može ili se izvršava [**veoma često**](privilege-escalation/#frequent-cron-jobs)? (svakih 1, 2 ili 5 minuta)

### [Servisi](privilege-escalation/#services)

* [ ] Da li postoji neki **pisiv .service** fajl?
* [ ] Da li postoji neki **pisiv binarni** fajl koji izvršava **servis**?
* [ ] Da li postoji neka **pisiva fascikla u systemd PATH**?

### [Tajmeri](privilege-escalation/#timers)

* [ ] Da li postoji neki **pisiv tajmer**?

### [Soketi](privilege-escalation/#sockets)

* [ ] Da li postoji neki **pisiv .socket** fajl?
* [ ] Možete li **komunicirati sa nekim soketom**?
* [ ] **HTTP soketi** sa zanimljivim informacijama?

### [D-Bus](privilege-escalation/#d-bus)

* [ ] Možete li **komunicirati sa nekim D-Bus**?

### [Mreža](privilege-escalation/#network)

* [ ] Enumerisanje mreže da znate gde se nalazite
* [ ] **Otvoreni portovi koje niste mogli da pristupite pre** nego što ste dobili shell unutar mašine?
* [ ] Možete li **sniffovati saobraćaj** koristeći `tcpdump`?

### [Korisnici](privilege-escalation/#users)

* [ ] Generička **enumeracija korisnika/grupa**
* [ ] Da li imate **veoma veliki UID**? Da li je **mašina** **ranjiva**?
* [ ] Možete li [**eskalirati privilegije zahvaljujući grupi**](privilege-escalation/interesting-groups-linux-pe/) kojoj pripadate?
* [ ] **Clipboard** podaci?
* [ ] Politika lozinki?
* [ ] Pokušajte da **koristite** svaku **poznatu lozinku** koju ste prethodno otkrili da se prijavite **sa svakim** mogućim **korisnikom**. Pokušajte da se prijavite i bez lozinke.

### [Pisivi PATH](privilege-escalation/#writable-path-abuses)

* [ ] Ako imate **privilegije pisanja nad nekom fasciklom u PATH-u** možda ćete moći da eskalirate privilegije

### [SUDO i SUID komande](privilege-escalation/#sudo-and-suid)

* [ ] Možete li izvršiti **bilo koju komandu sa sudo**? Možete li je koristiti da ČITATE, PIŠETE ili IZVRŠAVATE bilo šta kao root? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Da li postoji neki **eksploatabilni SUID binarni**? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Da li su [**sudo** komande **ograničene** po **putanji**? Možete li **obići** ograničenja](privilege-escalation/#sudo-execution-bypassing-paths)?
* [ ] [**Sudo/SUID binarni bez naznačene putanje**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
* [ ] [**SUID binarni koji naznačava putanju**](privilege-escalation/#suid-binary-with-command-path)? Obilaženje
* [ ] [**LD\_PRELOAD ranjivost**](privilege-escalation/#ld\_preload)
* [ ] [**Nedostatak .so biblioteke u SUID binarnom**](privilege-escalation/#suid-binary-so-injection) iz pisive fascikle?
* [ ] [**SUDO tokeni dostupni**](privilege-escalation/#reusing-sudo-tokens)? [**Možete li kreirati SUDO token**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
* [ ] Možete li [**čitati ili modifikovati sudoers fajlove**](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
* [ ] Možete li [**modifikovati /etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d)?
* [ ] [**OpenBSD DOAS**](privilege-escalation/#doas) komanda

### [Kapaciteti](privilege-escalation/#capabilities)

* [ ] Da li neki binarni ima neku **neočekivanu sposobnost**?

### [ACL-ovi](privilege-escalation/#acls)

* [ ] Da li neki fajl ima neki **neočekivani ACL**?

### [Otvorene Shell sesije](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL Predvidljiv PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**SSH Zanimljive konfiguracione vrednosti**](privilege-escalation/#ssh-interesting-configuration-values)

### [Zanimljivi Fajlovi](privilege-escalation/#interesting-files)

* [ ] **Profilni fajlovi** - Pročitajte osetljive podatke? Pišite za privesc?
* [ ] **passwd/shadow fajlovi** - Pročitajte osetljive podatke? Pišite za privesc?
* [ ] **Proverite uobičajene zanimljive fascikle** za osetljive podatke
* [ ] **Čudne Lokacije/Posedovani fajlovi,** možda imate pristup ili možete da menjate izvršne fajlove
* [ ] **Izmenjeni** u poslednjih nekoliko minuta
* [ ] **Sqlite DB fajlovi**
* [ ] **Skriveni fajlovi**
* [ ] **Skripte/Binari u PATH-u**
* [ ] **Web fajlovi** (lozinke?)
* [ ] **Backup-i**?
* [ ] **Poznati fajlovi koji sadrže lozinke**: Koristite **Linpeas** i **LaZagne**
* [ ] **Generička pretraga**

### [**Pisivi Fajlovi**](privilege-escalation/#writable-files)

* [ ] **Modifikujte python biblioteku** da izvršite proizvoljne komande?
* [ ] Možete li **modifikovati log fajlove**? **Logtotten** exploit
* [ ] Možete li **modifikovati /etc/sysconfig/network-scripts/**? Centos/Redhat exploit
* [ ] Možete li [**pisati u ini, int.d, systemd ili rc.d fajlove**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Ostali trikovi**](privilege-escalation/#other-tricks)

* [ ] Možete li [**zloupotrebiti NFS da eskalirate privilegije**](privilege-escalation/#nfs-privilege-escalation)?
* [ ] Da li treba da [**pobegnete iz restriktivnog shell-a**](privilege-escalation/#escaping-from-restricted-shells)?

<figure><img src="/.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Pridružite se [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) serveru da komunicirate sa iskusnim hakerima i lovcima na greške!

**Hakerski Uvidi**\
Uključite se u sadržaj koji se bavi uzbuđenjem i izazovima hakovanja

**Vesti o Haku u Realnom Vremenu**\
Budite u toku sa brzim svetom hakovanja kroz vesti i uvide u realnom vremenu

**Najnovija Obaveštenja**\
Budite informisani o najnovijim nagradama za greške i važnim ažuriranjima platforme

**Pridružite nam se na** [**Discordu**](https://discord.com/invite/N3FrSbmwdy) i počnite da sarađujete sa vrhunskim hakerima danas!

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
