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

**Seccomp**, що означає Secure Computing mode, є функцією безпеки **ядра Linux, призначеною для фільтрації системних викликів**. Вона обмежує процеси до обмеженого набору системних викликів (`exit()`, `sigreturn()`, `read()`, і `write()` для вже відкритих дескрипторів файлів). Якщо процес намагається викликати щось інше, він завершується ядром за допомогою SIGKILL або SIGSYS. Цей механізм не віртуалізує ресурси, а ізолює процес від них.

Існує два способи активувати seccomp: через системний виклик `prctl(2)` з `PR_SET_SECCOMP`, або для ядер Linux 3.17 і вище, системний виклик `seccomp(2)`. Старий метод активації seccomp шляхом запису в `/proc/self/seccomp` був застарілий на користь `prctl()`.

Покращення, **seccomp-bpf**, додає можливість фільтрувати системні виклики з налаштовуваною політикою, використовуючи правила Berkeley Packet Filter (BPF). Це розширення використовується програмним забезпеченням, таким як OpenSSH, vsftpd, і браузерами Chrome/Chromium на Chrome OS і Linux для гнучкого та ефективного фільтрування системних викликів, пропонуючи альтернативу тепер вже непідтримуваному systrace для Linux.

### **Original/Strict Mode**

У цьому режимі Seccomp **дозволяє лише системні виклики** `exit()`, `sigreturn()`, `read()` і `write()` для вже відкритих дескрипторів файлів. Якщо здійснюється будь-який інший системний виклик, процес завершується за допомогою SIGKILL

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

Цей режим дозволяє **фільтрувати системні виклики за допомогою налаштовуваної політики**, реалізованої за допомогою правил Berkeley Packet Filter.

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

## Seccomp в Docker

**Seccomp-bpf** підтримується **Docker** для обмеження **syscalls** з контейнерів, ефективно зменшуючи площу атаки. Ви можете знайти **syscalls, які заблоковані** за **замовчуванням** за адресою [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) і **профіль seccomp за замовчуванням** можна знайти тут [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json).\
Ви можете запустити контейнер docker з **іншою політикою seccomp** за допомогою:
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
Якщо ви хочете, наприклад, **заборонити** контейнеру виконувати деякі **syscall**, такі як `uname`, ви можете завантажити профіль за замовчуванням з [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) і просто **видалити рядок `uname` зі списку**.\
Якщо ви хочете впевнитися, що **якийсь бінарний файл не працює всередині контейнера docker**, ви можете використовувати strace, щоб перерахувати syscalls, які використовує бінарний файл, а потім заборонити їх.\
У наступному прикладі виявляються **syscalls** `uname`:
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
{% hint style="info" %}
Якщо ви використовуєте **Docker лише для запуску програми**, ви можете **профілювати** її за допомогою **`strace`** і **дозволити лише ті системні виклики**, які їй потрібні
{% endhint %}

### Приклад політики Seccomp

[Приклад звідси](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)

Щоб проілюструвати функцію Seccomp, давайте створимо профіль Seccomp, який відключає системний виклик “chmod”, як показано нижче.
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
У наведеному профілі ми встановили дію за замовчуванням на "дозволити" і створили чорний список для відключення "chmod". Щоб бути більш безпечними, ми можемо встановити дію за замовчуванням на "відкинути" і створити білий список для вибіркового дозволу системних викликів.\
Наступний вихід показує, що виклик "chmod" повертає помилку, оскільки він відключений у профілі seccomp.
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
Наступний вихід показує “docker inspect”, що відображає профіль:
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
]
```
{% hint style="success" %}
Вивчайте та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на github.

</details>
{% endhint %}
