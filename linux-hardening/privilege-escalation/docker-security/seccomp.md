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

**Seccomp**, wat staan vir Secure Computing mode, is 'n sekuriteitskenmerk van die **Linux-kern wat ontwerp is om stelsels aanroep te filter**. Dit beperk prosesse tot 'n beperkte stel stelsels aanroep (`exit()`, `sigreturn()`, `read()`, en `write()` vir reeds-geopende lêer beskrywings). As 'n proses probeer om enigiets anders aan te roep, word dit deur die kern beëindig met SIGKILL of SIGSYS. Hierdie meganisme virtualiseer nie hulpbronne nie, maar isoleer die proses daarvan.

Daar is twee maniere om seccomp te aktiveer: deur die `prctl(2)` stelsels aanroep met `PR_SET_SECCOMP`, of vir Linux-kerns 3.17 en hoër, die `seccomp(2)` stelsels aanroep. Die ouer metode om seccomp in te skakel deur na `/proc/self/seccomp` te skryf, is verouderd ten gunste van `prctl()`.

'n Verbetering, **seccomp-bpf**, voeg die vermoë by om stelsels aanroep te filter met 'n aanpasbare beleid, met behulp van Berkeley Packet Filter (BPF) reëls. Hierdie uitbreiding word benut deur sagteware soos OpenSSH, vsftpd, en die Chrome/Chromium-browsers op Chrome OS en Linux vir buigsame en doeltreffende syscall-filtering, wat 'n alternatief bied vir die nou nie-ondersteunde systrace vir Linux.

### **Original/Strict Mode**

In hierdie modus laat Seccomp **slegs die syscalls** `exit()`, `sigreturn()`, `read()` en `write()` toe vir reeds-geopende lêer beskrywings. As enige ander syscall gemaak word, word die proses doodgemaak met SIGKILL

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

Hierdie modus laat **filtrering van stelselskille toe met 'n konfigureerbare beleid** wat geïmplementeer is met behulp van Berkeley Packet Filter-reëls.

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

## Seccomp in Docker

**Seccomp-bpf** word deur **Docker** ondersteun om die **syscalls** van die houers te beperk, wat effektief die oppervlakarea verminder. Jy kan die **syscalls wat geblokkeer** is **per standaard** vind in [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) en die **standaard seccomp-profiel** kan hier gevind word [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json).\
Jy kan 'n docker-houer met 'n **ander seccomp** beleid uitvoer met:
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
As jy byvoorbeeld wil **verbied** dat 'n houer sekere **syscall** soos `uname` uitvoer, kan jy die standaardprofiel aflaai van [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) en net die **`uname` string uit die lys **verwyder.\
As jy seker wil maak dat **'n sekere binêre nie binne 'n docker-houer werk nie**, kan jy strace gebruik om die syscalls wat die binêre gebruik, op te lys en hulle dan verbied.\
In die volgende voorbeeld word die **syscalls** van `uname` ontdek:
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
{% hint style="info" %}
As jy **Docker net gebruik om 'n toepassing te begin**, kan jy dit **profiel** met **`strace`** en **net die syscalls** toelaat wat dit benodig
{% endhint %}

### Voorbeeld Seccomp-beleid

[Voorbeeld hier vandaan](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)

Om die Seccomp-funksie te illustreer, kom ons skep 'n Seccomp-profiel wat die “chmod” stelselsoproep soos hieronder deaktiveer.
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
In die bogenoemde profiel het ons die standaard aksie op "toelaat" gestel en 'n swartlys geskep om "chmod" te deaktiveer. Om veiliger te wees, kan ons die standaard aksie op "verwerp" stel en 'n witlys skep om stelsels oproepe selektief te aktiveer.\
Die volgende uitvoer toon die "chmod" oproep wat 'n fout teruggee omdat dit in die seccomp profiel gedeaktiveer is.
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
Die volgende uitvoer toon die “docker inspect” wat die profiel vertoon:
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
]
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
{% endhint %}
