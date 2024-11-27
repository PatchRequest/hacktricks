# euid, ruid, suid

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

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Deepen your expertise in **Mobile Security** with 8kSec Academy. Master iOS and Android security through our self-paced courses and get certified:

{% embed url="https://academy.8ksec.io/" %}


### 사용자 식별 변수

- **`ruid`**: **실제 사용자 ID**는 프로세스를 시작한 사용자를 나타냅니다.
- **`euid`**: **유효 사용자 ID**로 알려져 있으며, 시스템이 프로세스 권한을 확인하는 데 사용하는 사용자 ID를 나타냅니다. 일반적으로 `euid`는 `ruid`와 동일하지만, SetUID 바이너리 실행과 같은 경우에는 `euid`가 파일 소유자의 ID를 취하여 특정 작업 권한을 부여합니다.
- **`suid`**: 이 **저장된 사용자 ID**는 높은 권한의 프로세스(일반적으로 root로 실행)가 특정 작업을 수행하기 위해 일시적으로 권한을 포기해야 할 때 중요하며, 이후 다시 초기의 높은 상태를 회복합니다.

#### 중요 참고 사항
root로 실행되지 않는 프로세스는 현재 `ruid`, `euid` 또는 `suid`와 일치하도록 `euid`를 수정할 수 있습니다.

### set*uid 함수 이해하기

- **`setuid`**: 초기 가정과는 달리, `setuid`는 주로 `ruid`가 아닌 `euid`를 수정합니다. 특히, 권한이 있는 프로세스의 경우, 지정된 사용자(종종 root)와 함께 `ruid`, `euid`, `suid`를 정렬하여 이러한 ID를 강화합니다. 자세한 내용은 [setuid 매뉴얼 페이지](https://man7.org/linux/man-pages/man2/setuid.2.html)에서 확인할 수 있습니다.
- **`setreuid`** 및 **`setresuid`**: 이러한 함수는 `ruid`, `euid`, `suid`의 미세 조정을 허용합니다. 그러나 그 기능은 프로세스의 권한 수준에 따라 달라집니다. 비-root 프로세스의 경우, 수정은 현재 `ruid`, `euid`, `suid`의 값으로 제한됩니다. 반면, root 프로세스나 `CAP_SETUID` 권한이 있는 프로세스는 이러한 ID에 임의의 값을 할당할 수 있습니다. 더 많은 정보는 [setresuid 매뉴얼 페이지](https://man7.org/linux/man-pages/man2/setresuid.2.html)와 [setreuid 매뉴얼 페이지](https://man7.org/linux/man-pages/man2/setreuid.2.html)에서 확인할 수 있습니다.

이러한 기능은 보안 메커니즘이 아니라 프로그램이 다른 사용자의 ID를 채택하여 유효 사용자 ID를 변경하는 것과 같은 의도된 작업 흐름을 촉진하기 위해 설계되었습니다.

특히, `setuid`는 root로의 권한 상승을 위한 일반적인 방법일 수 있지만(모든 ID를 root로 정렬하므로), 이러한 함수 간의 차이를 이해하고 다양한 시나리오에서 사용자 ID 동작을 조작하는 것이 중요합니다.

### 리눅스에서 프로그램 실행 메커니즘

#### **`execve` 시스템 호출**
- **기능**: `execve`는 첫 번째 인수에 의해 결정된 프로그램을 시작합니다. 두 개의 배열 인수, `argv`(인수용)와 `envp`(환경용)를 사용합니다.
- **동작**: 호출자의 메모리 공간을 유지하지만 스택, 힙 및 데이터 세그먼트를 새로 고칩니다. 프로그램의 코드는 새 프로그램으로 대체됩니다.
- **사용자 ID 보존**:
- `ruid`, `euid` 및 추가 그룹 ID는 변경되지 않습니다.
- 새 프로그램에 SetUID 비트가 설정된 경우 `euid`에 미세한 변화가 있을 수 있습니다.
- 실행 후 `suid`는 `euid`에서 업데이트됩니다.
- **문서화**: 자세한 정보는 [`execve` 매뉴얼 페이지](https://man7.org/linux/man-pages/man2/execve.2.html)에서 확인할 수 있습니다.

#### **`system` 함수**
- **기능**: `execve`와 달리 `system`은 `fork`를 사용하여 자식 프로세스를 생성하고 해당 자식 프로세스 내에서 명령을 실행합니다.
- **명령 실행**: `sh`를 통해 명령을 실행하며, `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`를 사용합니다.
- **동작**: `execl`은 `execve`의 한 형태로, 새로운 자식 프로세스의 맥락에서 유사하게 작동합니다.
- **문서화**: 추가 정보는 [`system` 매뉴얼 페이지](https://man7.org/linux/man-pages/man3/system.3.html)에서 확인할 수 있습니다.

#### **SUID가 있는 `bash` 및 `sh`의 동작**
- **`bash`**:
- `euid`와 `ruid`의 처리 방식에 영향을 미치는 `-p` 옵션이 있습니다.
- `-p` 없이 `bash`는 `euid`가 `ruid`와 다를 경우 `euid`를 `ruid`로 설정합니다.
- `-p`가 있을 경우 초기 `euid`가 보존됩니다.
- 더 많은 세부정보는 [`bash` 매뉴얼 페이지](https://linux.die.net/man/1/bash)에서 확인할 수 있습니다.
- **`sh`**:
- `bash`의 `-p`와 유사한 메커니즘이 없습니다.
- 사용자 ID와 관련된 동작은 명시적으로 언급되지 않으며, `-i` 옵션 하에서 `euid`와 `ruid`의 동등성을 강조합니다.
- 추가 정보는 [`sh` 매뉴얼 페이지](https://man7.org/linux/man-pages/man1/sh.1p.html)에서 확인할 수 있습니다.

이러한 메커니즘은 작동 방식이 다르며, 프로그램을 실행하고 전환하는 데 다양한 옵션을 제공하며, 사용자 ID가 관리되고 보존되는 방식에 특정한 뉘앙스가 있습니다.

### 실행에서 사용자 ID 동작 테스트

예제는 https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail에서 가져왔으며, 추가 정보를 확인하세요.

#### 사례 1: `system`과 함께 `setuid` 사용

**목표**: `system`과 `bash`를 `sh`로 조합했을 때 `setuid`의 효과를 이해합니다.

**C 코드**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
system("id");
return 0;
}
```
**컴파일 및 권한:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**분석:**

* `ruid`와 `euid`는 각각 99 (nobody)와 1000 (frank)로 시작합니다.
* `setuid`는 둘 다 1000으로 맞춥니다.
* `system`은 sh에서 bash로의 심볼릭 링크로 인해 `/bin/bash -c id`를 실행합니다.
* `bash`는 `-p` 없이 `euid`를 `ruid`와 일치하도록 조정하여 둘 다 99 (nobody)가 됩니다.

#### 사례 2: system과 함께 setreuid 사용

**C 코드**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setreuid(1000, 1000);
system("id");
return 0;
}
```
**컴파일 및 권한:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**실행 및 결과:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**분석:**

* `setreuid`는 ruid와 euid를 모두 1000으로 설정합니다.
* `system`은 bash를 호출하며, 사용자 ID의 동등성으로 인해 이를 유지하여 사실상 frank로 작동합니다.

#### 사례 3: execve와 함께 setuid 사용
목표: setuid와 execve 간의 상호작용 탐색.
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/usr/bin/id", NULL, NULL);
return 0;
}
```
**실행 및 결과:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**분석:**

* `ruid`는 99로 유지되지만, euid는 setuid의 효과에 따라 1000으로 설정됩니다.

**C 코드 예제 2 (Bash 호출):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/bin/bash", NULL, NULL);
return 0;
}
```
**실행 및 결과:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**분석:**

* `euid`가 `setuid`에 의해 1000으로 설정되었지만, `bash`는 `-p`가 없기 때문에 `ruid`(99)로 `euid`를 재설정합니다.

**C 코드 예제 3 (bash -p 사용):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
setuid(1000);
execve(paramList[0], paramList, NULL);
return 0;
}
```
**실행 및 결과:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## References
* [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

**모바일 보안**에 대한 전문성을 심화하세요. 8kSec 아카데미를 통해 iOS 및 Android 보안을 마스터하고 인증을 받으세요:

{% embed url="https://academy.8ksec.io/" %}


{% hint style="success" %}
AWS 해킹을 배우고 연습하세요:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹을 배우고 연습하세요: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}
