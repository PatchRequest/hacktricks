# User Namespace

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Basic Information

'n Gebruiker namespace is 'n Linux-kernfunksie wat **isolasie van gebruiker- en groep-ID-kaartings verskaf**, wat elke gebruiker namespace toelaat om sy **eie stel gebruiker- en groep-ID's** te hê. Hierdie isolasie stel prosesse wat in verskillende gebruiker namespaces loop in staat om **verskillende voorregte en eienaarskap te hê**, selfs al deel hulle dieselfde gebruiker- en groep-ID's numeries.

Gebruiker namespaces is veral nuttig in containerisering, waar elke houer sy eie onafhanklike stel gebruiker- en groep-ID's moet hê, wat beter sekuriteit en isolasie tussen houers en die gasheerstelsel moontlik maak.

### How it works:

1. Wanneer 'n nuwe gebruiker namespace geskep word, **begin dit met 'n leë stel van gebruiker- en groep-ID-kaartings**. Dit beteken dat enige proses wat in die nuwe gebruiker namespace loop, **aanvanklik geen voorregte buite die namespace sal hê**.
2. ID-kaartings kan gevestig word tussen die gebruiker- en groep-ID's in die nuwe namespace en dié in die ouer (of gasheer) namespace. Dit **laat prosesse in die nuwe namespace toe om voorregte en eienaarskap te hê wat ooreenstem met gebruiker- en groep-ID's in die ouer namespace**. Die ID-kaartings kan egter beperk word tot spesifieke reekse en substelle van ID's, wat fyn beheer oor die voorregte wat aan prosesse in die nuwe namespace toegeken word, moontlik maak.
3. Binne 'n gebruiker namespace kan **prosesse volle wortelvoorregte (UID 0) hê vir operasies binne die namespace**, terwyl hulle steeds beperkte voorregte buite die namespace het. Dit laat **houers toe om met wortelagtige vermoëns binne hul eie namespace te loop sonder om volle wortelvoorregte op die gasheerstelsel te hê**.
4. Prosesse kan tussen namespaces beweeg deur die `setns()` stelselskakel of nuwe namespaces te skep met die `unshare()` of `clone()` stelselskakels met die `CLONE_NEWUSER` vlag. Wanneer 'n proses na 'n nuwe namespace beweeg of een skep, sal dit begin om die gebruiker- en groep-ID-kaartings wat met daardie namespace geassosieer is, te gebruik.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
Deur 'n nuwe instansie van die `/proc` lêerstelsel te monteer as jy die parameter `--mount-proc` gebruik, verseker jy dat die nuwe monteernaamruimte 'n **akkurate en geïsoleerde siening van die prosesinligting spesifiek vir daardie naamruimte** het.

<details>

<summary>Fout: bash: fork: Kan nie geheue toewys nie</summary>

Wanneer `unshare` sonder die `-f` opsie uitgevoer word, word 'n fout ondervind weens die manier waarop Linux nuwe PID (Proses ID) naamruimtes hanteer. Die sleutelbesonderhede en die oplossing word hieronder uiteengesit:

1. **Probleemverklaring**:
- Die Linux-kern laat 'n proses toe om nuwe naamruimtes te skep met die `unshare` stelselaanroep. Die proses wat die skepping van 'n nuwe PID naamruimte inisieer (genoem die "unshare" proses) gaan egter nie in die nuwe naamruimte in nie; slegs sy kindproses gaan.
- Om `%unshare -p /bin/bash%` te loop, begin `/bin/bash` in dieselfde proses as `unshare`. Gevolglik is `/bin/bash` en sy kindproses in die oorspronklike PID naamruimte.
- Die eerste kindproses van `/bin/bash` in die nuwe naamruimte word PID 1. Wanneer hierdie proses verlaat, aktiveer dit die opruiming van die naamruimte as daar geen ander prosesse is nie, aangesien PID 1 die spesiale rol het om weeskindprosesse aan te neem. Die Linux-kern sal dan PID-toewysing in daardie naamruimte deaktiveer.

2. **Gevolg**:
- Die uitgang van PID 1 in 'n nuwe naamruimte lei tot die opruiming van die `PIDNS_HASH_ADDING` vlag. Dit lei tot die `alloc_pid` funksie wat misluk om 'n nuwe PID toe te wys wanneer 'n nuwe proses geskep word, wat die "Kan nie geheue toewys nie" fout produseer.

3. **Oplossing**:
- Die probleem kan opgelos word deur die `-f` opsie saam met `unshare` te gebruik. Hierdie opsie maak dat `unshare` 'n nuwe proses fork nadat die nuwe PID naamruimte geskep is.
- Om `%unshare -fp /bin/bash%` uit te voer, verseker dat die `unshare` opdrag self PID 1 in die nuwe naamruimte word. `/bin/bash` en sy kindproses is dan veilig binne hierdie nuwe naamruimte, wat die voortydige uitgang van PID 1 voorkom en normale PID-toewysing toelaat.

Deur te verseker dat `unshare` met die `-f` vlag loop, word die nuwe PID naamruimte korrek gehandhaaf, wat toelaat dat `/bin/bash` en sy sub-prosesse kan werk sonder om die geheue toewysing fout te ondervind.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
Om gebruikersnaamruimte te gebruik, moet die Docker-daemon begin word met **`--userns-remap=default`** (In ubuntu 14.04 kan dit gedoen word deur `/etc/default/docker` te wysig en dan `sudo service docker restart` uit te voer)

### &#x20;Kontroleer in watter naamruimte jou proses is
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
Dit is moontlik om die gebruikerskaart vanaf die docker-container te kontroleer met:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
Of van die gasheer met:
```bash
cat /proc/<pid>/uid_map
```
### Vind alle gebruikersname ruimtes

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Gaan binne 'n Gebruiker-namespace in
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Ook, jy kan slegs **in 'n ander prosesnaamruimte ingaan as jy root is**. En jy **kan nie** **ingaan** in 'n ander naamruimte **sonder 'n beskrywer** wat daarna verwys nie (soos `/proc/self/ns/user`).

### Skep nuwe Gebruiker naamruimte (met kaarte)

{% code overflow="wrap" %}
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```
{% endcode %}
```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### Herwinning van Vermoëns

In die geval van gebruikersname ruimtes, **wanneer 'n nuwe gebruikersnaam ruimte geskep word, word die proses wat in die naamruimte ingaan 'n volle stel vermoëns binne daardie naamruimte toegeken**. Hierdie vermoëns stel die proses in staat om bevoorregte operasies uit te voer soos **montage** **lêerstelsels**, die skep van toestelle, of die verandering van eienaarskap van lêers, maar **slegs binne die konteks van sy gebruikersnaam ruimte**.

Byvoorbeeld, wanneer jy die `CAP_SYS_ADMIN` vermoë binne 'n gebruikersnaam ruimte het, kan jy operasies uitvoer wat tipies hierdie vermoë vereis, soos die montage van lêerstelsels, maar slegs binne die konteks van jou gebruikersnaam ruimte. Enige operasies wat jy met hierdie vermoë uitvoer, sal nie die gasheerstelsel of ander naamruimtes beïnvloed nie.

{% hint style="warning" %}
Daarom, selfs al sal die verkryging van 'n nuwe proses binne 'n nuwe gebruikersnaam ruimte **jou al die vermoëns teruggee** (CapEff: 000001ffffffffff), kan jy eintlik **slegs diegene wat met die naamruimte verband hou** gebruik (montage byvoorbeeld) maar nie elkeen nie. So, dit op sigself is nie genoeg om uit 'n Docker houer te ontsnap nie.
{% endhint %}
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
```
{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
