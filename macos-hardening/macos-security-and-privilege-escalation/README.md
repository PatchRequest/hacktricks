# macOS 보안 및 권한 상승

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

경험이 풍부한 해커 및 버그 바운티 헌터와 소통하기 위해 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 서버에 참여하세요!

**해킹 통찰력**\
해킹의 스릴과 도전에 대해 깊이 있는 콘텐츠에 참여하세요.

**실시간 해킹 뉴스**\
실시간 뉴스와 통찰력을 통해 빠르게 변화하는 해킹 세계의 최신 정보를 유지하세요.

**최신 발표**\
새로운 버그 바운티 출시 및 중요한 플랫폼 업데이트에 대한 정보를 유지하세요.

오늘 [**Discord**](https://discord.com/invite/N3FrSbmwdy)에 참여하여 최고의 해커들과 협업을 시작하세요!

## 기본 MacOS

macOS에 익숙하지 않다면 macOS의 기본을 배우기 시작해야 합니다:

* 특별한 macOS **파일 및 권한:**

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* 일반적인 macOS **사용자**

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* **커널**의 **아키텍처**

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* 일반적인 macOS n**etwork 서비스 및 프로토콜**

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **오픈소스** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
* `tar.gz`를 다운로드하려면 [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/)와 같은 URL을 [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)로 변경하세요.

### MacOS MDM

기업에서는 **macOS** 시스템이 **MDM으로 관리될 가능성이 높습니다**. 따라서 공격자의 관점에서 **그 작동 방식을 아는 것이 흥미롭습니다**:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - 검사, 디버깅 및 퍼징

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## MacOS 보안 보호

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## 공격 표면

### 파일 권한

**루트로 실행되는 프로세스가** 사용자가 제어할 수 있는 파일을 작성하면 사용자는 이를 악용하여 **권한을 상승시킬 수 있습니다**.\
이는 다음과 같은 상황에서 발생할 수 있습니다:

* 사용자가 이미 생성한 파일(사용자가 소유)
* 사용자가 그룹 때문에 쓸 수 있는 파일
* 사용자가 소유한 디렉토리 내의 파일(사용자가 파일을 생성할 수 있음)
* 루트가 소유한 디렉토리 내의 파일이지만 사용자가 그룹 때문에 쓰기 권한이 있는 경우(사용자가 파일을 생성할 수 있음)

**루트에 의해 사용될** 파일을 **생성할 수 있는** 것은 사용자가 **그 내용의 이점을 취하거나** 심지어 **심볼릭 링크/하드 링크**를 만들어 다른 위치를 가리키게 할 수 있게 합니다.

이러한 종류의 취약점에 대해서는 **취약한 `.pkg` 설치 프로그램을 확인하는 것을 잊지 마세요**:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}

### 파일 확장자 및 URL 스킴 앱 핸들러

파일 확장자로 등록된 이상한 앱은 악용될 수 있으며, 특정 프로토콜을 열기 위해 다양한 애플리케이션이 등록될 수 있습니다.

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## macOS TCC / SIP 권한 상승

macOS에서 **응용 프로그램 및 바이너리는** 폴더나 설정에 접근할 수 있는 권한을 가질 수 있으며, 이는 다른 것들보다 더 많은 권한을 부여합니다.

따라서 macOS 머신을 성공적으로 침해하려는 공격자는 **TCC 권한을 상승시켜야** 합니다(또는 필요에 따라 **SIP를 우회해야** 할 수도 있습니다).

이러한 권한은 일반적으로 응용 프로그램이 서명된 **권한**의 형태로 제공되거나, 응용 프로그램이 일부 접근을 요청하고 **사용자가 이를 승인한 후** **TCC 데이터베이스**에서 찾을 수 있습니다. 프로세스가 이러한 권한을 얻는 또 다른 방법은 **그 권한을 가진 프로세스의 자식**이 되는 것입니다. 이 권한은 일반적으로 **상속됩니다**.

다양한 방법으로 [**TCC에서 권한을 상승시키는 방법**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), [**TCC를 우회하는 방법**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) 및 과거에 [**SIP가 우회된 방법**](macos-security-protections/macos-sip.md#sip-bypasses)을 찾으려면 이 링크를 따라가세요.

## macOS 전통적인 권한 상승

물론 레드 팀의 관점에서 루트로 상승하는 것에도 관심이 있어야 합니다. 다음 게시물을 확인하여 몇 가지 힌트를 얻으세요:

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}

## macOS 준수

* [https://github.com/usnistgov/macos\_security](https://github.com/usnistgov/macos\_security)

## 참고 문헌

* [**OS X 사고 대응: 스크립팅 및 분석**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="/.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

경험이 풍부한 해커 및 버그 바운티 헌터와 소통하기 위해 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 서버에 참여하세요!

**해킹 통찰력**\
해킹의 스릴과 도전에 대해 깊이 있는 콘텐츠에 참여하세요.

**실시간 해킹 뉴스**\
실시간 뉴스와 통찰력을 통해 빠르게 변화하는 해킹 세계의 최신 정보를 유지하세요.

**최신 발표**\
새로운 버그 바운티 출시 및 중요한 플랫폼 업데이트에 대한 정보를 유지하세요.

오늘 [**Discord**](https://discord.com/invite/N3FrSbmwdy)에 참여하여 최고의 해커들과 협업을 시작하세요!

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}
