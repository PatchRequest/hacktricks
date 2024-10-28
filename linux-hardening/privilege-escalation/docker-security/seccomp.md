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

**Seccomp**, što znači Secure Computing mode, je bezbednosna funkcija **Linux jezgra dizajnirana da filtrira sistemske pozive**. Ograničava procese na ograničen skup sistemskih poziva (`exit()`, `sigreturn()`, `read()`, i `write()` za već otvorene deskriptore datoteka). Ako proces pokuša da pozove bilo šta drugo, kernel ga prekida koristeći SIGKILL ili SIGSYS. Ovaj mehanizam ne virtualizuje resurse, već izoluje proces od njih.

Postoje dva načina za aktiviranje seccomp-a: putem `prctl(2)` sistemskog poziva sa `PR_SET_SECCOMP`, ili za Linux jezgra 3.17 i novija, `seccomp(2)` sistemski poziv. Stariji metod omogućavanja seccomp-a pisanjem u `/proc/self/seccomp` je ukinut u korist `prctl()`.

Poboljšanje, **seccomp-bpf**, dodaje mogućnost filtriranja sistemskih poziva sa prilagodljivom politikom, koristeći Berkeley Packet Filter (BPF) pravila. Ova ekstenzija se koristi u softveru kao što su OpenSSH, vsftpd, i Chrome/Chromium pregledači na Chrome OS-u i Linux-u za fleksibilno i efikasno filtriranje sistemskih poziva, nudeći alternativu sada neodržavanom systrace-u za Linux.

### **Original/Strict Mode**

U ovom režimu Seccomp **dozvoljava samo sistemske pozive** `exit()`, `sigreturn()`, `read()` i `write()` za već otvorene deskriptore datoteka. Ako se napravi bilo koji drugi sistemski poziv, proces se ubija koristeći SIGKILL

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

Ovaj režim omogućava **filtriranje sistemskih poziva koristeći konfigurisanu politiku** implementiranu pomoću pravila Berkeley Packet Filter.

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

## Seccomp u Dockeru

**Seccomp-bpf** je podržan od strane **Docker-a** kako bi se ograničili **syscalls** iz kontejnera, efikasno smanjujući površinu napada. Možete pronaći **syscalls koje su blokirane** po **default-u** na [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) i **default seccomp profil** se može pronaći ovde [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json).\
Možete pokrenuti docker kontejner sa **drugom seccomp** politikom sa:
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
Ako želite, na primer, da **zabranite** kontejneru da izvršava neki **syscall** poput `uname`, možete preuzeti podrazumevani profil sa [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) i jednostavno **ukloniti `uname` string sa liste**.\
Ako želite da se uverite da **neki binarni program ne radi unutar docker kontejnera**, možete koristiti strace da navedete syscalls koje binarni program koristi i zatim ih zabraniti.\
U sledećem primeru otkrivaju se **syscalls** za `uname`:
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
{% hint style="info" %}
Ako koristite **Docker samo za pokretanje aplikacije**, možete **profilisati** to sa **`strace`** i **samo dozvoliti syscalls** koje su potrebne
{% endhint %}

### Primer Seccomp politike

[Primer odavde](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)

Da ilustrujemo Seccomp funkciju, hajde da kreiramo Seccomp profil koji onemogućava “chmod” sistemski poziv kao u nastavku.
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
U gornjem profilu, postavili smo podrazumevanu akciju na "dozvoli" i kreirali crnu listu da onemogućimo "chmod". Da bismo bili sigurniji, možemo postaviti podrazumevanu akciju na odbacivanje i kreirati belu listu da selektivno omogućimo sistemske pozive.\
Sledeći izlaz prikazuje "chmod" poziv koji vraća grešku jer je onemogućen u seccomp profilu.
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
Следећи излаз показује “docker inspect” који приказује профил:
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
]
```
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
