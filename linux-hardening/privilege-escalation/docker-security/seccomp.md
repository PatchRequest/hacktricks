# Seccomp

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

## Basic Information

**Seccomp**, που σημαίνει Secure Computing mode, είναι μια λειτουργία ασφαλείας του **Linux kernel που έχει σχεδιαστεί για να φιλτράρει τις κλήσεις συστήματος**. Περιορίζει τις διαδικασίες σε ένα περιορισμένο σύνολο κλήσεων συστήματος (`exit()`, `sigreturn()`, `read()`, και `write()` για ήδη ανοιχτούς περιγραφείς αρχείων). Αν μια διαδικασία προσπαθήσει να καλέσει οτιδήποτε άλλο, τερματίζεται από τον πυρήνα χρησιμοποιώντας SIGKILL ή SIGSYS. Αυτός ο μηχανισμός δεν εικονικοποιεί τους πόρους αλλά απομονώνει τη διαδικασία από αυτούς.

Υπάρχουν δύο τρόποι για να ενεργοποιηθεί το seccomp: μέσω της κλήσης συστήματος `prctl(2)` με `PR_SET_SECCOMP`, ή για πυρήνες Linux 3.17 και άνω, η κλήση συστήματος `seccomp(2)`. Η παλαιότερη μέθοδος ενεργοποίησης του seccomp γράφοντας στο `/proc/self/seccomp` έχει καταργηθεί υπέρ του `prctl()`.

Μια βελτίωση, **seccomp-bpf**, προσθέτει τη δυνατότητα φιλτραρίσματος κλήσεων συστήματος με μια προσαρμόσιμη πολιτική, χρησιμοποιώντας κανόνες Berkeley Packet Filter (BPF). Αυτή η επέκταση αξιοποιείται από λογισμικό όπως το OpenSSH, το vsftpd και τους περιηγητές Chrome/Chromium σε Chrome OS και Linux για ευέλικτο και αποδοτικό φιλτράρισμα κλήσεων συστήματος, προσφέροντας μια εναλλακτική λύση στο πλέον μη υποστηριζόμενο systrace για Linux.

### **Original/Strict Mode**

Σε αυτή τη λειτουργία, το Seccomp **επιτρέπει μόνο τις κλήσεις συστήματος** `exit()`, `sigreturn()`, `read()` και `write()` σε ήδη ανοιχτούς περιγραφείς αρχείων. Αν γίνει οποιαδήποτε άλλη κλήση συστήματος, η διαδικασία σκοτώνεται χρησιμοποιώντας SIGKILL

{% code title="seccomp_strict.c" %}
```c
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>

//From https://sysdig.com/blog/selinux-seccomp-falco-technical-discussion/
//gcc seccomp_strict.c -o seccomp_strict

int main(int argc, char **argv)
{
int output = open("output.txt", O_WRONLY);
const char *val = "test";

//enables strict seccomp mode
printf("Calling prctl() to set seccomp strict mode...\n");
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);

//This is allowed as the file was already opened
printf("Writing to an already open file...\n");
write(output, val, strlen(val)+1);

//This isn't allowed
printf("Trying to open file for reading...\n");
int input = open("output.txt", O_RDONLY);

printf("You will not see this message--the process will be killed first\n");
}
```
{% endcode %}

### Seccomp-bpf

Αυτός ο τρόπος επιτρέπει **φιλτράρισμα των κλήσεων συστήματος χρησιμοποιώντας μια ρυθμιζόμενη πολιτική** που υλοποιείται χρησιμοποιώντας κανόνες Berkeley Packet Filter.

{% code title="seccomp_bpf.c" %}
```c
#include <seccomp.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

//https://security.stackexchange.com/questions/168452/how-is-sandboxing-implemented/175373
//gcc seccomp_bpf.c -o seccomp_bpf -lseccomp

void main(void) {
/* initialize the libseccomp context */
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);

/* allow exiting */
printf("Adding rule : Allow exit_group\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

/* allow getting the current pid */
//printf("Adding rule : Allow getpid\n");
//seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);

printf("Adding rule : Deny getpid\n");
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
/* allow changing data segment size, as required by glibc */
printf("Adding rule : Allow brk\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);

/* allow writing up to 512 bytes to fd 1 */
printf("Adding rule : Allow write upto 512 bytes to FD 1\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
SCMP_A0(SCMP_CMP_EQ, 1),
SCMP_A2(SCMP_CMP_LE, 512));

/* if writing to any other fd, return -EBADF */
printf("Adding rule : Deny write to any FD except 1 \n");
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
SCMP_A0(SCMP_CMP_NE, 1));

/* load and enforce the filters */
printf("Load rules and enforce \n");
seccomp_load(ctx);
seccomp_release(ctx);
//Get the getpid is denied, a weird number will be returned like
//this process is -9
printf("this process is %d\n", getpid());
}
```
{% endcode %}

## Seccomp στο Docker

**Seccomp-bpf** υποστηρίζεται από **Docker** για να περιορίσει τις **syscalls** από τα κοντέινερ, μειώνοντας αποτελεσματικά την επιφάνεια επίθεσης. Μπορείτε να βρείτε τις **syscalls που αποκλείονται** από **προεπιλογή** στο [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) και το **προφίλ seccomp προεπιλογής** μπορείτε να το βρείτε εδώ [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json).\
Μπορείτε να εκτελέσετε ένα κοντέινερ docker με μια **διαφορετική πολιτική seccomp** με:
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
Αν θέλετε για παράδειγμα να **απαγορεύσετε** σε ένα κοντέινερ να εκτελεί κάποιο **syscall** όπως το `uname`, μπορείτε να κατεβάσετε το προεπιλεγμένο προφίλ από [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) και απλά να **αφαιρέσετε τη συμβολοσειρά `uname` από τη λίστα**.\
Αν θέλετε να βεβαιωθείτε ότι **κάποιο δυαδικό αρχείο δεν λειτουργεί μέσα σε ένα κοντέινερ docker**, μπορείτε να χρησιμοποιήσετε το strace για να καταγράψετε τα syscalls που χρησιμοποιεί το δυαδικό αρχείο και στη συνέχεια να τα απαγορεύσετε.\
Στο παρακάτω παράδειγμα ανακαλύπτονται οι **syscalls** του `uname`:
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
{% hint style="info" %}
Αν χρησιμοποιείτε **Docker μόνο για να εκκινήσετε μια εφαρμογή**, μπορείτε να **προφίλετε** την με **`strace`** και **να επιτρέψετε μόνο τις syscalls** που χρειάζεται
{% endhint %}

### Παράδειγμα πολιτικής Seccomp

[Παράδειγμα από εδώ](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)

Για να απεικονίσουμε τη δυνατότητα Seccomp, ας δημιουργήσουμε ένα προφίλ Seccomp που απενεργοποιεί την κλήση συστήματος “chmod” όπως παρακάτω.
```json
{
"defaultAction": "SCMP_ACT_ALLOW",
"syscalls": [
{
"name": "chmod",
"action": "SCMP_ACT_ERRNO"
}
]
}
```
Στο παραπάνω προφίλ, έχουμε ορίσει την προεπιλεγμένη ενέργεια σε “allow” και έχουμε δημιουργήσει μια μαύρη λίστα για να απενεργοποιήσουμε το “chmod”. Για να είμαστε πιο ασφαλείς, μπορούμε να ορίσουμε την προεπιλεγμένη ενέργεια σε drop και να δημιουργήσουμε μια λευκή λίστα για να ενεργοποιούμε επιλεκτικά τις κλήσεις συστήματος.\
Η παρακάτω έξοδος δείχνει την κλήση “chmod” να επιστρέφει σφάλμα επειδή είναι απενεργοποιημένη στο προφίλ seccomp.
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
Ακολουθεί η έξοδος που δείχνει το “docker inspect” που εμφανίζει το προφίλ:
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
]
```
{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
