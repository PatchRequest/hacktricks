# Other Web Tricks

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

**웹 앱, 네트워크 및 클라우드에 대한 해커의 관점을 얻으세요.**

**실제 비즈니스에 영향을 미치는 중요한 취약점을 찾아보고 보고하세요.** 20개 이상의 맞춤형 도구를 사용하여 공격 표면을 매핑하고, 권한 상승을 허용하는 보안 문제를 찾아내며, 자동화된 익스플로잇을 사용하여 필수 증거를 수집하여 귀하의 노력을 설득력 있는 보고서로 전환하세요.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

### Host header

백엔드가 **Host header**를 신뢰하여 일부 작업을 수행하는 경우가 여러 번 있습니다. 예를 들어, 비밀번호 재설정을 위한 **도메인으로 그 값을 사용할 수 있습니다**. 따라서 비밀번호를 재설정하는 링크가 포함된 이메일을 받으면 사용되는 도메인은 Host header에 입력한 도메인입니다. 그러면 다른 사용자의 비밀번호 재설정을 요청하고 도메인을 귀하가 제어하는 도메인으로 변경하여 그들의 비밀번호 재설정 코드를 훔칠 수 있습니다. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
사용자가 비밀번호 재설정 링크를 클릭할 때까지 기다릴 필요가 없을 수도 있다는 점에 유의하세요. **스팸 필터나 다른 중개 장치/봇이 이를 클릭하여 분석할 수 있습니다.**
{% endhint %}

### Session booleans

어떤 경우에는 일부 검증을 올바르게 완료하면 백엔드가 **세션의 보안 속성에 "True"라는 값을 가진 부울을 추가합니다**. 그런 다음 다른 엔드포인트는 해당 검사를 성공적으로 통과했는지 알 수 있습니다.\
그러나 **검사를 통과하고** 세션이 보안 속성에 "True" 값을 부여받으면, **접근 권한이 없어야 하는 다른 리소스에 접근을 시도할 수 있습니다**. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Register functionality

이미 존재하는 사용자로 등록해 보세요. 동등한 문자(점, 많은 공백 및 유니코드)를 사용해 보세요.

### Takeover emails

이메일을 등록한 후, 확인하기 전에 이메일을 변경하세요. 그런 다음, 새로운 확인 이메일이 첫 번째 등록된 이메일로 전송되면, 어떤 이메일도 인수할 수 있습니다. 또는 두 번째 이메일이 첫 번째 이메일을 확인하도록 활성화할 수 있다면, 어떤 계정도 인수할 수 있습니다.

### Access Internal servicedesk of companies using atlassian

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### TRACE method

개발자는 프로덕션 환경에서 다양한 디버깅 옵션을 비활성화하는 것을 잊을 수 있습니다. 예를 들어, HTTP `TRACE` 메서드는 진단 목적으로 설계되었습니다. 활성화되면 웹 서버는 `TRACE` 메서드를 사용하는 요청에 대해 수신된 정확한 요청을 응답에 에코하여 응답합니다. 이 동작은 종종 무해하지만 때때로 내부 인증 헤더의 이름과 같은 정보 유출로 이어질 수 있습니다.![Image for post](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**웹 앱, 네트워크 및 클라우드에 대한 해커의 관점을 얻으세요.**

**실제 비즈니스에 영향을 미치는 중요한 취약점을 찾아보고 보고하세요.** 20개 이상의 맞춤형 도구를 사용하여 공격 표면을 매핑하고, 권한 상승을 허용하는 보안 문제를 찾아내며, 자동화된 익스플로잇을 사용하여 필수 증거를 수집하여 귀하의 노력을 설득력 있는 보고서로 전환하세요.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

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
