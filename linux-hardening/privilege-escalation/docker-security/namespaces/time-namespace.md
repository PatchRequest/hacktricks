# Time Namespace

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
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Basic Information

Linux의 시간 네임스페이스는 시스템 단조 및 부팅 시간 시계에 대한 네임스페이스별 오프셋을 허용합니다. 이는 일반적으로 Linux 컨테이너에서 컨테이너 내의 날짜/시간을 변경하고 체크포인트 또는 스냅샷에서 복원한 후 시계를 조정하는 데 사용됩니다.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -T [--mount-proc] /bin/bash
```
새로운 인스턴스의 `/proc` 파일 시스템을 `--mount-proc` 매개변수를 사용하여 마운트하면, 새로운 마운트 네임스페이스가 **해당 네임스페이스에 특정한 프로세스 정보에 대한 정확하고 격리된 뷰를 갖도록 보장합니다**.

<details>

<summary>오류: bash: fork: 메모리를 할당할 수 없습니다</summary>

`unshare`가 `-f` 옵션 없이 실행될 때, Linux가 새로운 PID(프로세스 ID) 네임스페이스를 처리하는 방식 때문에 오류가 발생합니다. 주요 세부사항과 해결책은 아래에 설명되어 있습니다:

1. **문제 설명**:
- Linux 커널은 프로세스가 `unshare` 시스템 호출을 사용하여 새로운 네임스페이스를 생성할 수 있도록 허용합니다. 그러나 새로운 PID 네임스페이스를 생성하는 프로세스(이를 "unshare" 프로세스라고 함)는 새로운 네임스페이스에 들어가지 않으며, 오직 그 자식 프로세스만 들어갑니다.
- `%unshare -p /bin/bash%`를 실행하면 `/bin/bash`가 `unshare`와 동일한 프로세스에서 시작됩니다. 결과적으로 `/bin/bash`와 그 자식 프로세스는 원래 PID 네임스페이스에 있습니다.
- 새로운 네임스페이스에서 `/bin/bash`의 첫 번째 자식 프로세스는 PID 1이 됩니다. 이 프로세스가 종료되면, 다른 프로세스가 없을 경우 네임스페이스의 정리가 트리거됩니다. PID 1은 고아 프로세스를 입양하는 특별한 역할을 가지고 있습니다. 그러면 Linux 커널은 해당 네임스페이스에서 PID 할당을 비활성화합니다.

2. **결과**:
- 새로운 네임스페이스에서 PID 1의 종료는 `PIDNS_HASH_ADDING` 플래그의 정리를 초래합니다. 이로 인해 새로운 프로세스를 생성할 때 `alloc_pid` 함수가 새로운 PID를 할당하는 데 실패하여 "메모리를 할당할 수 없습니다" 오류가 발생합니다.

3. **해결책**:
- 이 문제는 `unshare`와 함께 `-f` 옵션을 사용하여 해결할 수 있습니다. 이 옵션은 `unshare`가 새로운 PID 네임스페이스를 생성한 후 새로운 프로세스를 포크하도록 만듭니다.
- `%unshare -fp /bin/bash%`를 실행하면 `unshare` 명령 자체가 새로운 네임스페이스에서 PID 1이 됩니다. `/bin/bash`와 그 자식 프로세스는 이 새로운 네임스페이스 내에서 안전하게 포함되어 PID 1의 조기 종료를 방지하고 정상적인 PID 할당을 허용합니다.

`unshare`가 `-f` 플래그와 함께 실행되도록 보장함으로써, 새로운 PID 네임스페이스가 올바르게 유지되어 `/bin/bash`와 그 하위 프로세스가 메모리 할당 오류 없이 작동할 수 있습니다.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;프로세스가 어떤 네임스페이스에 있는지 확인하기
```bash
ls -l /proc/self/ns/time
lrwxrwxrwx 1 root root 0 Apr  4 21:16 /proc/self/ns/time -> 'time:[4026531834]'
```
### 모든 시간 네임스페이스 찾기

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name time -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name time -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### 시간 네임스페이스에 들어가기
```bash
nsenter -T TARGET_PID --pid /bin/bash
```
{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.**

</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}해킹 트릭을 공유하세요.** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하세요.

{% endhint %}
</details>
{% endhint %}
