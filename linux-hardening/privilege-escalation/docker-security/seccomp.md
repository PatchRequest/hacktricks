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

## 基本情報

**Seccomp**（セキュアコンピューティングモードの略）は、**システムコールをフィルタリングするために設計されたLinuxカーネルのセキュリティ機能**です。これは、プロセスを限られたセットのシステムコール（すでにオープンされたファイルディスクリプタに対する`exit()`、`sigreturn()`、`read()`、および`write()`）に制限します。プロセスが他のシステムコールを呼び出そうとすると、カーネルによってSIGKILLまたはSIGSYSで終了されます。このメカニズムはリソースを仮想化するのではなく、プロセスをそれらから隔離します。

seccompを有効にする方法は2つあります：`PR_SET_SECCOMP`を使用した`prctl(2)`システムコール、またはLinuxカーネル3.17以降の`seccomp(2)`システムコールです。`/proc/self/seccomp`に書き込む古い方法は、`prctl()`に取って代わられました。

拡張機能である**seccomp-bpf**は、Berkeley Packet Filter（BPF）ルールを使用してカスタマイズ可能なポリシーでシステムコールをフィルタリングする機能を追加します。この拡張は、OpenSSH、vsftpd、Chrome OSおよびLinux上のChrome/Chromiumブラウザなどのソフトウェアによって利用され、柔軟で効率的なシステムコールフィルタリングを提供し、現在サポートされていないLinux用のsystraceの代替手段を提供します。

### **オリジナル/厳格モード**

このモードでは、Seccompは**すでにオープンされたファイルディスクリプタに対してのみ`exit()`、`sigreturn()`、`read()`、および`write()`のシステムコールを許可します**。他のシステムコールが行われると、プロセスはSIGKILLで終了されます。

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

このモードは、**バークレー・パケット・フィルタールールを使用して実装された構成可能なポリシーを使用してシステムコールをフィルタリングすることを許可します**。

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

## DockerにおけるSeccomp

**Seccomp-bpf**は、**Docker**によってサポートされており、コンテナからの**syscalls**を制限することで、攻撃面を効果的に減少させます。**デフォルト**でブロックされている**syscalls**は[https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/)で確認でき、**デフォルトのseccompプロファイル**はここで見つけることができます[https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)。\
**異なるseccomp**ポリシーでdockerコンテナを実行するには、次のようにします:
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
もし、例えばコンテナが `uname` のような **syscall** を実行することを **禁止** したい場合は、[https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) からデフォルトプロファイルをダウンロードし、リストから **`uname` 文字列を削除** するだけです。\
もし **あるバイナリが Docker コンテナ内で動作しないことを確認** したい場合は、strace を使用してバイナリが使用している syscalls をリストし、それらを禁止することができます。\
次の例では、`uname` の **syscalls** が発見されます：
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
{% hint style="info" %}
アプリケーションを起動するためだけに**Docker**を使用している場合は、**`strace`**で**プロファイル**を作成し、必要なシステムコールのみを**許可**できます
{% endhint %}

### 例 Seccomp ポリシー

[こちらからの例](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)

Seccomp機能を示すために、以下のように「chmod」システムコールを無効にするSeccompプロファイルを作成します。
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
上記のプロファイルでは、デフォルトのアクションを「allow」に設定し、「chmod」を無効にするブラックリストを作成しました。より安全にするために、デフォルトのアクションをドロップに設定し、システムコールを選択的に有効にするホワイトリストを作成できます。\
次の出力は、「chmod」コールがseccompプロファイルで無効になっているため、エラーを返すことを示しています。
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
以下の出力は、プロファイルを表示する「docker inspect」を示しています：
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
]
```
{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングトリックを共有してください。**

</details>
{% endhint %}
