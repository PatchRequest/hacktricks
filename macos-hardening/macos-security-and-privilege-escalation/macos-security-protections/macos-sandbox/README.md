# macOS Sandbox

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Basic Information

MacOS Sandbox (초기에는 Seatbelt라고 불림) **는 샌드박스 내에서 실행되는 애플리케이션의** **허용된 작업을 샌드박스 프로필에 지정된 대로 제한**합니다. 이는 **애플리케이션이 예상된 리소스만 접근하도록 보장하는 데 도움**이 됩니다.

**`com.apple.security.app-sandbox`** 권한을 가진 모든 앱은 샌드박스 내에서 실행됩니다. **Apple 바이너리**는 일반적으로 샌드박스 내에서 실행되며, **App Store의 모든 애플리케이션은 해당 권한을 가집니다**. 따라서 여러 애플리케이션이 샌드박스 내에서 실행됩니다.

프로세스가 할 수 있는 것과 할 수 없는 것을 제어하기 위해 **샌드박스는** 프로세스가 시도할 수 있는 거의 모든 작업(대부분의 시스템 호출 포함)에 **MACF**를 사용하여 후크를 가지고 있습니다. 그러나 앱의 **권한**에 따라 샌드박스는 프로세스에 대해 더 관대할 수 있습니다.

샌드박스의 몇 가지 중요한 구성 요소는 다음과 같습니다:

* **커널 확장** `/System/Library/Extensions/Sandbox.kext`
* **프라이빗 프레임워크** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* 사용자 공간에서 실행되는 **데몬** `/usr/libexec/sandboxd`
* **컨테이너** `~/Library/Containers`

### Containers

모든 샌드박스 애플리케이션은 `~/Library/Containers/{CFBundleIdentifier}`에 고유한 컨테이너를 가집니다:
```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```
각 번들 ID 폴더 안에는 홈 폴더를 모방한 구조를 가진 **plist**와 앱의 **데이터 디렉토리**를 찾을 수 있습니다:
```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```
{% hint style="danger" %}
주의: 심볼릭 링크가 Sandbox에서 "탈출"하여 다른 폴더에 접근하기 위해 존재하더라도, 앱은 여전히 **접근 권한**이 필요합니다. 이 권한은 `RedirectablePaths`의 **`.plist`** 안에 있습니다.
{% endhint %}

**`SandboxProfileData`**는 B64로 이스케이프된 컴파일된 샌드박스 프로필 CFData입니다.
```bash
# Get container config
## You need FDA to access the file, not even just root can read it
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# Binary sandbox profile
<key>SandboxProfileData</key>
<data>
AAAhAboBAAAAAAgAAABZAO4B5AHjBMkEQAUPBSsGPwsgASABHgEgASABHwEf...

# In this file you can find the entitlements:
<key>Entitlements</key>
<dict>
<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
<true/>
<key>com.apple.accounts.appleaccount.fullaccess</key>
<true/>
<key>com.apple.appattest.spi</key>
<true/>
<key>keychain-access-groups</key>
<array>
<string>6N38VWS5BX.ru.keepcoder.Telegram</string>
<string>6N38VWS5BX.ru.keepcoder.TelegramShare</string>
</array>
[...]

# Some parameters
<key>Parameters</key>
<dict>
<key>_HOME</key>
<string>/Users/username</string>
<key>_UID</key>
<string>501</string>
<key>_USER</key>
<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
<array>
<string>/Users/username/Downloads</string>
<string>/Users/username/Documents</string>
<string>/Users/username/Library/Calendars</string>
<string>/Users/username/Desktop</string>
<key>RedirectedPaths</key>
<array/>
[...]
```
{% hint style="warning" %}
Sandboxed 애플리케이션에 의해 생성/수정된 모든 것은 **격리 속성**을 갖게 됩니다. 이는 샌드박스 앱이 **`open`**으로 무언가를 실행하려고 할 때 Gatekeeper를 트리거하여 샌드박스 공간을 방지합니다.
{% endhint %}

## 샌드박스 프로필

샌드박스 프로필은 해당 **샌드박스**에서 **허용/금지**될 사항을 나타내는 구성 파일입니다. 이는 [**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)) 프로그래밍 언어를 사용하는 **샌드박스 프로필 언어(SBPL)**를 사용합니다.

여기 예시를 찾을 수 있습니다:
```scheme
(version 1) ; First you get the version

(deny default) ; Then you shuold indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
(subpath "/Users/username/")
(literal "/tmp/afile")
(regex #"^/private/etc/.*")
)

(allow mach-lookup
(global-name "com.apple.analyticsd")
)
```
{% hint style="success" %}
이 [**연구**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)를 확인하여 허용되거나 거부될 수 있는 추가 작업을 확인하세요.

프로파일의 컴파일된 버전에서는 작업의 이름이 dylib와 kext에서 알려진 배열의 항목으로 대체되어 컴파일된 버전이 더 짧고 읽기 어렵게 됩니다.
{% endhint %}

중요한 **시스템 서비스**는 `mdnsresponder` 서비스와 같은 자체 맞춤 **샌드박스** 내에서 실행됩니다. 이러한 맞춤 **샌드박스 프로파일**은 다음 위치에서 확인할 수 있습니다:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**
* 다른 샌드박스 프로파일은 [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles)에서 확인할 수 있습니다.

**App Store** 앱은 **프로파일** **`/System/Library/Sandbox/Profiles/application.sb`**를 사용합니다. 이 프로파일에서 **`com.apple.security.network.server`**와 같은 권한이 프로세스가 네트워크를 사용할 수 있도록 허용하는 방법을 확인할 수 있습니다.

SIP는 /System/Library/Sandbox/rootless.conf에 있는 platform\_profile이라는 샌드박스 프로파일입니다.

### 샌드박스 프로파일 예시

특정 샌드박스 프로파일로 애플리케이션을 시작하려면 다음을 사용할 수 있습니다:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% tabs %}
{% tab title="touch" %}
{% code title="touch.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```
{% endcode %}
```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```
{% code title="touch2.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```
{% endcode %}

{% code title="touch3.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% hint style="info" %}
**Apple이 작성한** **소프트웨어**는 **Windows**에서 **추가적인 보안 조치**가 없으며, 애플리케이션 샌드박싱과 같은 기능이 없습니다.
{% endhint %}

우회 예시:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (그들은 `~$`로 시작하는 이름의 파일을 샌드박스 외부에 쓸 수 있습니다).

### 샌드박스 추적

#### 프로필을 통한

작업이 확인될 때마다 샌드박스가 수행하는 모든 검사를 추적할 수 있습니다. 이를 위해 다음 프로필을 생성하십시오:

{% code title="trace.sb" %}
```scheme
(version 1)
(trace /tmp/trace.out)
```
{% endcode %}

그런 다음 해당 프로필을 사용하여 무언가를 실행하십시오:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
In `/tmp/trace.out`에서는 호출될 때마다 수행된 각 샌드박스 검사를 볼 수 있습니다(즉, 많은 중복이 발생합니다).

**`-t`** 매개변수를 사용하여 샌드박스를 추적할 수도 있습니다: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### API를 통한 방법

`libsystem_sandbox.dylib`에서 내보낸 `sandbox_set_trace_path` 함수는 샌드박스 검사가 기록될 추적 파일 이름을 지정할 수 있게 해줍니다.\
`sandbox_vtrace_enable()`을 호출하고, 그 후 `sandbox_vtrace_report()`를 호출하여 버퍼에서 로그 오류를 가져오는 유사한 작업도 가능합니다.

### 샌드박스 검사

`libsandbox.dylib`는 프로세스의 샌드박스 상태 목록(확장 포함)을 제공하는 `sandbox_inspect_pid`라는 함수를 내보냅니다. 그러나 이 함수는 플랫폼 바이너리만 사용할 수 있습니다.

### MacOS 및 iOS 샌드박스 프로파일

MacOS는 시스템 샌드박스 프로파일을 두 위치에 저장합니다: **/usr/share/sandbox/** 및 **/System/Library/Sandbox/Profiles**.

그리고 서드파티 애플리케이션이 _**com.apple.security.app-sandbox**_ 권한을 가지고 있다면, 시스템은 해당 프로세스에 **/System/Library/Sandbox/Profiles/application.sb** 프로파일을 적용합니다.

iOS에서는 기본 프로파일이 **container**라고 하며, SBPL 텍스트 표현이 없습니다. 메모리에서 이 샌드박스는 샌드박스의 각 권한에 대해 허용/거부 이진 트리로 표현됩니다.

### App Store 앱의 사용자 정의 SBPL

회사가 **사용자 정의 샌드박스 프로파일**로 앱을 실행할 수 있는 가능성이 있습니다(기본 프로파일 대신). 그들은 Apple의 승인이 필요한 **`com.apple.security.temporary-exception.sbpl`** 권한을 사용해야 합니다.

이 권한의 정의는 **`/System/Library/Sandbox/Profiles/application.sb:`**에서 확인할 수 있습니다.
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
This will **eval the string after this entitlement** as an Sandbox profile.

### Compiling & decompiling a Sandbox Profile

The **`sandbox-exec`** tool uses the functions `sandbox_compile_*` from `libsandbox.dylib`. The main functions exported are: `sandbox_compile_file` (expects a file path, param `-f`), `sandbox_compile_string` (expects a string, param `-p`), `sandbox_compile_name` (expects a name of a container, param `-n`), `sandbox_compile_entitlements` (expects entitlements plist).

This reversed and [**open sourced version of the tool sandbox-exec**](https://newosxbook.com/src.jl?tree=listings\&file=/sandbox\_exec.c) allows to make **`sandbox-exec`** write into a file the compiled sandbox profile.

Moreover, to confine a process inside a container it might call `sandbox_spawnattrs_set[container/profilename]` and pass a container or pre-existing profile.

## Debug & Bypass Sandbox

On macOS, unlike iOS where processes are sandboxed from the start by the kernel, **processes must opt-in to the sandbox themselves**. This means on macOS, a process is not restricted by the sandbox until it actively decides to enter it, although App Store apps are always sandboxed.

Processes are automatically Sandboxed from userland when they start if they have the entitlement: `com.apple.security.app-sandbox`. For a detailed explanation of this process check:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

## **Sandbox Extensions**

Extensions allow to give further privileges to an object and are giving calling one of the functions:

* `sandbox_issue_extension`
* `sandbox_extension_issue_file[_with_new_type]`
* `sandbox_extension_issue_mach`
* `sandbox_extension_issue_iokit_user_client_class`
* `sandbox_extension_issue_iokit_registry_rentry_class`
* `sandbox_extension_issue_generic`
* `sandbox_extension_issue_posix_ipc`

The extensions are stored in the second MACF label slot accessible from the process credentials. The following **`sbtool`** can access this information.

Note that extensions are usually granted by allowed processes, for example, `tccd` will grant the extension token of `com.apple.tcc.kTCCServicePhotos` when a process tried to access the photos and was allowed in a XPC message. Then, the process will need to consume the extension token so it gets added to it.\
Note that the extension tokens are long hexadecimals that encode the granted permissions. However they don't have the allowed PID hardcoded which means that any process with access to the token might be **consumed by multiple processes**.

Note that extensions are very related to entitlements also, so having certain entitlements might automatically grant certain extensions.

### **Check PID Privileges**

[**According to this**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), the **`sandbox_check`** functions (it's a `__mac_syscall`), can check **if an operation is allowed or not** by the sandbox in a certain PID, audit token or unique ID.

The [**tool sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) (find it [compiled here](https://newosxbook.com/articles/hitsb.html)) can check if a PID can perform a certain actions:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

샌드박스를 일시 중지하고 다시 시작하는 것도 가능합니다. `libsystem_sandbox.dylib`의 `sandbox_suspend` 및 `sandbox_unsuspend` 함수를 사용합니다.

일시 중지 함수를 호출하려면 호출자가 이를 호출할 수 있도록 몇 가지 권한이 확인됩니다:

* com.apple.private.security.sandbox-manager
* com.apple.security.print
* com.apple.security.temporary-exception.audio-unit-host

## mac\_syscall

이 시스템 호출 (#381)은 첫 번째 인수로 실행할 모듈을 나타내는 문자열을 기대하며, 두 번째 인수로 실행할 함수를 나타내는 코드를 기대합니다. 세 번째 인수는 실행된 함수에 따라 달라집니다.

함수 `___sandbox_ms` 호출은 `mac_syscall`을 래핑하며 첫 번째 인수로 `"Sandbox"`를 나타냅니다. `___sandbox_msp`는 `mac_set_proc` (#387)의 래퍼입니다. 그런 다음 `___sandbox_ms`에서 지원되는 일부 코드는 다음 표에서 찾을 수 있습니다:

* **set\_profile (#0)**: 프로세스에 컴파일된 또는 명명된 프로파일을 적용합니다.
* **platform\_policy (#1)**: 플랫폼별 정책 검사를 시행합니다 (macOS와 iOS 간에 다름).
* **check\_sandbox (#2)**: 특정 샌드박스 작업의 수동 검사를 수행합니다.
* **note (#3)**: 샌드박스에 주석을 추가합니다.
* **container (#4)**: 일반적으로 디버깅 또는 식별을 위해 샌드박스에 주석을 첨부합니다.
* **extension\_issue (#5)**: 프로세스에 대한 새로운 확장을 생성합니다.
* **extension\_consume (#6)**: 주어진 확장을 사용합니다.
* **extension\_release (#7)**: 사용된 확장에 연결된 메모리를 해제합니다.
* **extension\_update\_file (#8)**: 샌드박스 내의 기존 파일 확장의 매개변수를 수정합니다.
* **extension\_twiddle (#9)**: 기존 파일 확장을 조정하거나 수정합니다 (예: TextEdit, rtf, rtfd).
* **suspend (#10)**: 모든 샌드박스 검사를 일시적으로 중지합니다 (적절한 권한 필요).
* **unsuspend (#11)**: 이전에 일시 중지된 모든 샌드박스 검사를 재개합니다.
* **passthrough\_access (#12)**: 샌드박스 검사를 우회하여 리소스에 대한 직접적인 패스스루 액세스를 허용합니다.
* **set\_container\_path (#13)**: (iOS 전용) 앱 그룹 또는 서명 ID에 대한 컨테이너 경로를 설정합니다.
* **container\_map (#14)**: (iOS 전용) `containermanagerd`에서 컨테이너 경로를 검색합니다.
* **sandbox\_user\_state\_item\_buffer\_send (#15)**: (iOS 10+) 샌드박스에서 사용자 모드 메타데이터를 설정합니다.
* **inspect (#16)**: 샌드박스화된 프로세스에 대한 디버그 정보를 제공합니다.
* **dump (#18)**: (macOS 11) 분석을 위해 샌드박스의 현재 프로파일을 덤프합니다.
* **vtrace (#19)**: 모니터링 또는 디버깅을 위한 샌드박스 작업을 추적합니다.
* **builtin\_profile\_deactivate (#20)**: (macOS < 11) 명명된 프로파일을 비활성화합니다 (예: `pe_i_can_has_debugger`).
* **check\_bulk (#21)**: 단일 호출에서 여러 `sandbox_check` 작업을 수행합니다.
* **reference\_retain\_by\_audit\_token (#28)**: 샌드박스 검사에 사용할 감사 토큰에 대한 참조를 생성합니다.
* **reference\_release (#29)**: 이전에 유지된 감사 토큰 참조를 해제합니다.
* **rootless\_allows\_task\_for\_pid (#30)**: `task_for_pid`가 허용되는지 확인합니다 (유사한 `csr` 검사).
* **rootless\_whitelist\_push (#31)**: (macOS) 시스템 무결성 보호(SIP) 매니페스트 파일을 적용합니다.
* **rootless\_whitelist\_check (preflight) (#32)**: 실행 전에 SIP 매니페스트 파일을 검사합니다.
* **rootless\_protected\_volume (#33)**: (macOS) 디스크 또는 파티션에 SIP 보호를 적용합니다.
* **rootless\_mkdir\_protected (#34)**: 디렉토리 생성 프로세스에 SIP/DataVault 보호를 적용합니다.

## Sandbox.kext

iOS에서는 커널 확장이 **모든 프로파일을 하드코딩**하여 `__TEXT.__const` 세그먼트 내에 포함되어 수정되지 않도록 합니다. 다음은 커널 확장에서 흥미로운 몇 가지 함수입니다:

* **`hook_policy_init`**: `mpo_policy_init`을 후킹하며 `mac_policy_register` 후에 호출됩니다. 샌드박스의 대부분 초기화를 수행합니다. SIP도 초기화합니다.
* **`hook_policy_initbsd`**: `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` 및 `security.mac.sandbox.debug_mode`를 등록하는 sysctl 인터페이스를 설정합니다 (PE_i_can_has_debugger로 부팅된 경우).
* **`hook_policy_syscall`**: "Sandbox"를 첫 번째 인수로 하고 두 번째 인수로 작업을 나타내는 코드와 함께 `mac_syscall`에 의해 호출됩니다. 요청된 코드에 따라 실행할 코드를 찾기 위해 스위치를 사용합니다.

### MACF Hooks

**`Sandbox.kext`**는 MACF를 통해 백 개 이상의 후킹을 사용합니다. 대부분의 후킹은 작업을 수행할 수 있는 사소한 경우를 확인하며, 그렇지 않은 경우 **`cred_sb_evalutate`**를 호출하여 MACF의 **자격 증명**과 수행할 **작업**에 해당하는 숫자 및 출력용 **버퍼**를 전달합니다.

그 좋은 예는 **`_mpo_file_check_mmap`** 함수로, **`mmap`**을 후킹하며 새로운 메모리가 쓰기 가능할지 확인한 후 (그렇지 않으면 실행을 허용하지 않음), dyld 공유 캐시에서 사용되는지 확인하고, 그렇다면 실행을 허용하며, 마지막으로 **`cred_sb_evalutate`**를 호출하여 추가 허용 검사를 수행합니다.

게다가, 샌드박스가 사용하는 수백 개의 후킹 중에서 특히 흥미로운 세 가지가 있습니다:

* `mpo_proc_check_for`: 필요할 경우 프로파일을 적용하며, 이전에 적용되지 않은 경우에만 적용합니다.
* `mpo_vnode_check_exec`: 프로세스가 관련 이진 파일을 로드할 때 호출되며, 프로파일 검사가 수행되고 SUID/SGID 실행을 금지하는 검사도 수행됩니다.
* `mpo_cred_label_update_execve`: 레이블이 할당될 때 호출됩니다. 이 함수는 이진 파일이 완전히 로드되었지만 아직 실행되지 않았을 때 호출되므로 가장 긴 함수입니다. 샌드박스 객체를 생성하고, kauth 자격 증명에 샌드박스 구조체를 첨부하고, mach 포트에 대한 액세스를 제거하는 등의 작업을 수행합니다.

**`cred_sb_evalutate`**는 **`sb_evaluate`**의 래퍼이며, 이 함수는 전달된 자격 증명을 가져온 후 **`eval`** 함수를 사용하여 평가를 수행합니다. 이 함수는 일반적으로 모든 프로세스에 기본적으로 적용되는 **플랫폼 프로파일**을 평가한 다음 **특정 프로세스 프로파일**을 평가합니다. 플랫폼 프로파일은 macOS의 **SIP**의 주요 구성 요소 중 하나입니다.

## Sandboxd

샌드박스는 XPC Mach 서비스 `com.apple.sandboxd`를 노출하는 사용자 데몬도 실행하며, 커널 확장이 통신하는 데 사용하는 특별한 포트 14 (`HOST_SEATBELT_PORT`)에 바인딩됩니다. MIG를 사용하여 일부 기능을 노출합니다.

## References

* [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
