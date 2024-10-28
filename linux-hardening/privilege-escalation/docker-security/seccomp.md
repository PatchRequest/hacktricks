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

## Temel Bilgiler

**Seccomp**, Güvenli Hesaplama modu anlamına gelir, **sistem çağrılarını filtrelemek için tasarlanmış bir Linux çekirdek güvenlik özelliğidir**. Süreçleri sınırlı bir sistem çağrısı kümesiyle (`exit()`, `sigreturn()`, `read()` ve `write()` zaten açık dosya tanımlayıcıları için) kısıtlar. Bir süreç başka bir şeyi çağırmaya çalışırsa, çekirdek tarafından SIGKILL veya SIGSYS kullanılarak sonlandırılır. Bu mekanizma kaynakları sanallaştırmaz, ancak süreci onlardan izole eder.

Seccomp'ı etkinleştirmenin iki yolu vardır: `PR_SET_SECCOMP` ile `prctl(2)` sistem çağrısı veya Linux çekirdekleri 3.17 ve üzeri için `seccomp(2)` sistem çağrısı. `/proc/self/seccomp` dosyasına yazarak seccomp'ı etkinleştirmenin eski yöntemi, `prctl()` lehine kullanımdan kaldırılmıştır.

Bir geliştirme olan **seccomp-bpf**, özelleştirilebilir bir politika ile sistem çağrılarını filtreleme yeteneği ekler ve Berkeley Paket Filtreleme (BPF) kurallarını kullanır. Bu uzantı, OpenSSH, vsftpd ve Chrome OS ile Linux'taki Chrome/Chromium tarayıcıları gibi yazılımlar tarafından esnek ve verimli sistem çağrı filtrelemesi için kullanılmaktadır ve artık desteklenmeyen systrace'a alternatif sunmaktadır.

### **Orijinal/Sıkı Mod**

Bu modda Seccomp **yalnızca sistem çağrılarına** `exit()`, `sigreturn()`, `read()` ve `write()` zaten açık dosya tanımlayıcıları için izin verir. Başka bir sistem çağrısı yapılırsa, süreç SIGKILL kullanılarak öldürülür.

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

Bu mod, **Berkeley Paket Filtreleme kuralları kullanılarak uygulanan yapılandırılabilir bir politika ile sistem çağrılarının filtrelenmesine** olanak tanır.

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

## Docker'da Seccomp

**Seccomp-bpf**, **Docker** tarafından konteynerlerden **syscall'ları** kısıtlamak için desteklenmektedir ve bu, yüzey alanını etkili bir şekilde azaltır. **Varsayılan** olarak **engellenen syscall'ları** [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) adresinde bulabilirsiniz ve **varsayılan seccomp profili** burada bulunmaktadır [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json).\
Farklı bir **seccomp** politikası ile bir docker konteyneri çalıştırabilirsiniz:
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
Eğer bir konteynerin bazı **syscall**'ları, örneğin `uname`'i **yasaklamak** istiyorsanız, [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) adresinden varsayılan profili indirebilir ve sadece **`uname` dizesini listeden kaldırabilirsiniz**.\
Eğer **bir ikili dosyanın bir docker konteyneri içinde çalışmadığından emin olmak** istiyorsanız, ikilinin kullandığı syscall'ları listelemek için strace kullanabilir ve ardından bunları yasaklayabilirsiniz.\
Aşağıdaki örnekte `uname`'in **syscall**'ları keşfedilmektedir:
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
{% hint style="info" %}
Eğer **Docker'ı sadece bir uygulamayı başlatmak için kullanıyorsanız**, onu **`strace`** ile **profil oluşturabilir** ve ihtiyaç duyduğu sistem çağrılarına **sadece izin verebilirsiniz.**
{% endhint %}

### Örnek Seccomp politikası

[Buradan örnek](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)

Seccomp özelliğini göstermek için, aşağıda “chmod” sistem çağrısını devre dışı bırakan bir Seccomp profili oluşturalım.
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
Yukarıdaki profilde, varsayılan eylemi "izin ver" olarak ayarladık ve "chmod"u devre dışı bırakmak için bir kara liste oluşturduk. Daha güvenli olmak için, varsayılan eylemi "düşür" olarak ayarlayabilir ve sistem çağrılarını seçici olarak etkinleştirmek için bir beyaz liste oluşturabiliriz.\
Aşağıdaki çıktı, "chmod" çağrısının, seccomp profilinde devre dışı bırakıldığı için hata döndürdüğünü göstermektedir.
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
Aşağıdaki çıktı, profilin görüntülendiği “docker inspect” komutunu göstermektedir:
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
]
```
{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
