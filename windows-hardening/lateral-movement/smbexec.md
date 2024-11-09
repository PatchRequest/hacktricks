# SmbExec/ScExec

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

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**웹 앱, 네트워크 및 클라우드에 대한 해커의 관점을 얻으세요**

**실제 비즈니스에 영향을 미치는 중요한 취약점을 찾아보고 보고하세요.** 20개 이상의 맞춤형 도구를 사용하여 공격 표면을 매핑하고, 권한 상승을 허용하는 보안 문제를 찾아내며, 자동화된 익스플로잇을 사용하여 필수 증거를 수집하여 귀하의 노력을 설득력 있는 보고서로 전환하세요.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## 작동 방식

**Smbexec**는 Windows 시스템에서 원격 명령 실행에 사용되는 도구로, **Psexec**와 유사하지만 대상 시스템에 악성 파일을 배치하지 않습니다.

### **SMBExec**에 대한 주요 사항

- 명령을 cmd.exe (%COMSPEC%)를 통해 실행하기 위해 대상 머신에 임시 서비스를 생성하여 작동합니다(예: "BTOBTO"). 이 과정에서 이진 파일을 떨어뜨리지 않습니다.
- 은밀한 접근 방식에도 불구하고, 실행된 각 명령에 대한 이벤트 로그를 생성하여 비대화형 "셸"의 형태를 제공합니다.
- **Smbexec**를 사용하여 연결하는 명령은 다음과 같습니다:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### 이진 파일 없이 명령 실행하기

- **Smbexec**는 서비스 binPaths를 통해 직접 명령 실행을 가능하게 하여, 대상에 물리적 이진 파일이 필요 없게 합니다.
- 이 방법은 Windows 대상에서 일회성 명령을 실행하는 데 유용합니다. 예를 들어, Metasploit의 `web_delivery` 모듈과 결합하면 PowerShell을 대상으로 하는 역 Meterpreter 페이로드를 실행할 수 있습니다.
- cmd.exe를 통해 제공된 명령을 실행하도록 binPath가 설정된 원격 서비스를 공격자의 머신에서 생성함으로써, 서비스 응답 오류가 발생하더라도 Metasploit 리스너와 함께 콜백 및 페이로드 실행을 성공적으로 수행할 수 있습니다.

### 명령 예시

서비스를 생성하고 시작하는 것은 다음 명령으로 수행할 수 있습니다:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
FOr further details check [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## References
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**해커의 관점에서 웹 앱, 네트워크 및 클라우드를 분석하세요.**

**실제 비즈니스에 영향을 미치는 중요한 취약점을 찾아보고 보고하세요.** 20개 이상의 맞춤형 도구를 사용하여 공격 표면을 매핑하고, 권한 상승을 허용하는 보안 문제를 찾아내며, 자동화된 익스플로잇을 사용하여 필수 증거를 수집하여 귀하의 노력을 설득력 있는 보고서로 전환하세요.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}
