# macOS Kernel Extensions

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Basic Information

커널 확장(Kexts)은 **`.kext`** 확장자를 가진 **패키지**로, **macOS 커널 공간에 직접 로드**되어 운영 체제에 추가 기능을 제공합니다.

### Requirements

명백히, 이것은 매우 강력하여 **커널 확장을 로드하는 것이 복잡합니다**. 커널 확장이 로드되기 위해 충족해야 할 **요구 사항**은 다음과 같습니다:

* **복구 모드에 들어갈 때**, 커널 **확장이 로드될 수 있도록 허용되어야 합니다**:

<figure><img src="../../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

* 커널 확장은 **커널 코드 서명 인증서로 서명되어야 하며**, 이는 **Apple에 의해 부여될 수 있습니다**. 누가 회사와 그 필요성을 자세히 검토할 것입니다.
* 커널 확장은 또한 **노타리제이션**되어야 하며, Apple은 이를 악성 소프트웨어에 대해 검사할 수 있습니다.
* 그런 다음, **root** 사용자만이 **커널 확장을 로드할 수 있으며** 패키지 내의 파일은 **root에 속해야 합니다**.
* 업로드 과정 중에 패키지는 **보호된 비루트 위치**에 준비되어야 합니다: `/Library/StagedExtensions` (requires the `com.apple.rootless.storage.KernelExtensionManagement` grant).
* 마지막으로, 로드하려고 할 때 사용자는 [**확인 요청을 받게 됩니다**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) 그리고, 수락되면 컴퓨터는 **재시작**되어야 합니다.

### Loading process

카탈리나에서는 이렇게 진행되었습니다: **검증** 과정이 **사용자 공간**에서 발생한다는 점이 흥미롭습니다. 그러나 **`com.apple.private.security.kext-management`** 권한이 있는 애플리케이션만이 **커널에 확장을 로드하도록 요청할 수 있습니다**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** CLI가 **확장을 로드하기 위한 검증** 과정을 **시작합니다**
* **`kextd`**와 **Mach 서비스**를 사용하여 통신합니다.
2. **`kextd`**는 **서명**과 같은 여러 가지를 확인합니다.
* **`syspolicyd`**와 통신하여 확장이 **로드될 수 있는지 확인합니다**.
3. **`syspolicyd`**는 확장이 이전에 로드되지 않았다면 **사용자에게 요청**합니다.
* **`syspolicyd`**는 결과를 **`kextd`**에 보고합니다.
4. **`kextd`**는 마지막으로 **커널에 확장을 로드하라고 지시할 수 있습니다**.

**`kextd`**가 사용 불가능한 경우, **`kextutil`**이 동일한 검사를 수행할 수 있습니다.

### Enumeration (loaded kexts)
```bash
# Get loaded kernel extensions
kextstat

# Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
## Kernelcache

{% hint style="danger" %}
커널 확장 프로그램이 `/System/Library/Extensions/`에 있어야 하지만, 이 폴더에 가면 **이진 파일을 찾을 수 없습니다**. 이는 **kernelcache** 때문이며, 하나의 `.kext`를 리버스 엔지니어링하려면 이를 얻는 방법을 찾아야 합니다.
{% endhint %}

**kernelcache**는 **XNU 커널의 미리 컴파일되고 미리 링크된 버전**과 필수 장치 **드라이버** 및 **커널 확장 프로그램**을 포함합니다. 이는 **압축된** 형식으로 저장되며 부팅 과정 중 메모리로 압축 해제됩니다. kernelcache는 커널과 중요한 드라이버의 실행 준비가 된 버전을 제공하여 부팅 시간을 단축시키고, 부팅 시 이러한 구성 요소를 동적으로 로드하고 링크하는 데 소요되는 시간과 자원을 줄여줍니다.

### Local Kernelcache

iOS에서는 **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**에 위치하며, macOS에서는 **`find / -name "kernelcache" 2>/dev/null`**로 찾을 수 있습니다. \
제 경우 macOS에서 찾은 위치는:

* `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

IMG4 파일 형식은 Apple이 iOS 및 macOS 장치에서 펌웨어 구성 요소(예: **kernelcache**)를 안전하게 **저장하고 검증하기 위해** 사용하는 컨테이너 형식입니다. IMG4 형식은 헤더와 여러 태그를 포함하여 실제 페이로드(예: 커널 또는 부트로더), 서명 및 일련의 매니페스트 속성을 캡슐화합니다. 이 형식은 암호화 검증을 지원하여 장치가 실행하기 전에 펌웨어 구성 요소의 진위와 무결성을 확인할 수 있도록 합니다.

일반적으로 다음 구성 요소로 구성됩니다:

* **Payload (IM4P)**:
* 종종 압축됨 (LZFSE4, LZSS, …)
* 선택적으로 암호화됨
* **Manifest (IM4M)**:
* 서명 포함
* 추가 키/값 사전
* **Restore Info (IM4R)**:
* APNonce로도 알려짐
* 일부 업데이트의 재생을 방지
* 선택 사항: 일반적으로 발견되지 않음

Kernelcache 압축 해제:
```bash
# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### 다운로드&#x20;

* [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

[https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases)에서 모든 커널 디버그 키트를 찾을 수 있습니다. 다운로드하여 마운트한 후 [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html) 도구로 열고 **`.kext`** 폴더에 접근하여 **추출**할 수 있습니다.

다음으로 기호를 확인하세요:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
* [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

가끔 Apple은 **kernelcache**와 함께 **symbols**를 출시합니다. 해당 페이지의 링크를 따라가면 **symbols**가 포함된 일부 펌웨어를 다운로드할 수 있습니다. 펌웨어에는 다른 파일들 중에 **kernelcache**가 포함되어 있습니다.

파일을 **추출**하려면 `.ipsw` 확장자를 `.zip`으로 변경한 후 **압축을 풉니다**.

펌웨어를 추출한 후에는 **`kernelcache.release.iphone14`**와 같은 파일을 얻게 됩니다. 이 파일은 **IMG4** 형식이며, 다음을 사용하여 흥미로운 정보를 추출할 수 있습니다:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:** 

{% code overflow="wrap" %}
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
{% endcode %}

[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### 커널 캐시 검사

커널 캐시에 기호가 있는지 확인하십시오.
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
이제 **모든 확장** 또는 **관심 있는 확장**을 **추출할 수 있습니다:**
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## 참조

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}
