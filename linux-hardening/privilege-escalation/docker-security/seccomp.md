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

**Seccomp**, che sta per Secure Computing mode, è una funzionalità di sicurezza del **kernel Linux progettata per filtrare le chiamate di sistema**. Limita i processi a un insieme ristretto di chiamate di sistema (`exit()`, `sigreturn()`, `read()` e `write()` per i descrittori di file già aperti). Se un processo tenta di chiamare qualsiasi altra cosa, viene terminato dal kernel utilizzando SIGKILL o SIGSYS. Questo meccanismo non virtualizza le risorse ma isola il processo da esse.

Ci sono due modi per attivare seccomp: attraverso la chiamata di sistema `prctl(2)` con `PR_SET_SECCOMP`, o per i kernel Linux 3.17 e superiori, la chiamata di sistema `seccomp(2)`. Il metodo più vecchio di abilitare seccomp scrivendo in `/proc/self/seccomp` è stato deprecato a favore di `prctl()`.

Un miglioramento, **seccomp-bpf**, aggiunge la capacità di filtrare le chiamate di sistema con una politica personalizzabile, utilizzando regole Berkeley Packet Filter (BPF). Questa estensione è sfruttata da software come OpenSSH, vsftpd e i browser Chrome/Chromium su Chrome OS e Linux per un filtraggio delle syscall flessibile ed efficiente, offrendo un'alternativa al systrace ora non supportato per Linux.

### **Original/Strict Mode**

In questa modalità Seccomp **consente solo le syscall** `exit()`, `sigreturn()`, `read()` e `write()` per i descrittori di file già aperti. Se viene effettuata qualsiasi altra syscall, il processo viene terminato utilizzando SIGKILL

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

Questa modalità consente **il filtraggio delle chiamate di sistema utilizzando una politica configurabile** implementata utilizzando le regole del Berkeley Packet Filter.

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

**Seccomp-bpf** è supportato da **Docker** per limitare le **syscalls** dai container, riducendo efficacemente l'area di attacco. Puoi trovare le **syscalls bloccate** per **default** in [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) e il **profilo seccomp di default** può essere trovato qui [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json).\
Puoi eseguire un container docker con una **politica seccomp** **diversa** con:
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
Se vuoi, ad esempio, **vietare** a un container di eseguire alcune **syscall** come `uname`, puoi scaricare il profilo predefinito da [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) e semplicemente **rimuovere la stringa `uname` dalla lista**.\
Se vuoi assicurarti che **alcun binario non funzioni all'interno di un container docker**, puoi usare strace per elencare le syscall che il binario sta utilizzando e poi vietarle.\
Nell'esempio seguente vengono scoperte le **syscall** di `uname`:
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
{% hint style="info" %}
Se stai usando **Docker solo per avviare un'applicazione**, puoi **profilare** con **`strace`** e **consentire solo le syscalls** di cui ha bisogno
{% endhint %}

### Esempio di politica Seccomp

[Esempio da qui](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)

Per illustrare la funzionalità Seccomp, creiamo un profilo Seccomp che disabilita la chiamata di sistema “chmod” come di seguito.
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
Nel profilo sopra, abbiamo impostato l'azione predefinita su "allow" e creato una lista nera per disabilitare "chmod". Per essere più sicuri, possiamo impostare l'azione predefinita su drop e creare una lista bianca per abilitare selettivamente le chiamate di sistema.\
L'output seguente mostra la chiamata "chmod" che restituisce un errore perché è disabilitata nel profilo seccomp.
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
Il seguente output mostra il “docker inspect” che visualizza il profilo:
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
]
```
{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}
