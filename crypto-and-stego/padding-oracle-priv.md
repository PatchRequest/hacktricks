# Padding Oracle

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

{% embed url="https://websec.nl/" %}

## CBC - Cipher Block Chaining

In CBC mode the **previous encrypted block is used as IV** to XOR with the next block:

![https://defuse.ca/images/cbc\_encryption.png](https://defuse.ca/images/cbc\_encryption.png)

To decrypt CBC the **opposite** **operations** are done:

![https://defuse.ca/images/cbc\_decryption.png](https://defuse.ca/images/cbc\_decryption.png)

Notice how it's needed to use an **encryption** **key** and an **IV**.

## Message Padding

As the encryption is performed in **fixed** **size** **blocks**, **padding** is usually needed in the **last** **block** to complete its length.\
Usually **PKCS7** is used, which generates a padding **repeating** the **number** of **bytes** **needed** to **complete** the block. For example, if the last block is missing 3 bytes, the padding will be `\x03\x03\x03`.

Let's look at more examples with a **2 blocks of length 8bytes**:

| byte #0 | byte #1 | byte #2 | byte #3 | byte #4 | byte #5 | byte #6 | byte #7 | byte #0  | byte #1  | byte #2  | byte #3  | byte #4  | byte #5  | byte #6  | byte #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Note how in the last example the **last block was full so another one was generated only with padding**.

## Padding Oracle

When an application decrypts encrypted data, it will first decrypt the data; then it will remove the padding. During the cleanup of the padding, if an **invalid padding triggers a detectable behaviour**, you have a **padding oracle vulnerability**. The detectable behaviour can be an **error**, a **lack of results**, or a **slower response**.

If you detect this behaviour, you can **decrypt the encrypted data** and even **encrypt any cleartext**.

### How to exploit

You could use [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) to exploit this kind of vulnerability or just do
```
sudo apt-get install padbuster
```
사이트의 쿠키가 취약한지 테스트하기 위해 다음을 시도할 수 있습니다:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**Encoding 0**는 **base64**가 사용된다는 것을 의미합니다 (하지만 다른 것도 사용 가능하니 도움말 메뉴를 확인하세요).

이 취약점을 **악용하여 새로운 데이터를 암호화할 수도 있습니다. 예를 들어, 쿠키의 내용이 "**_**user=MyUsername**_**"이라고 가정하면, 이를 "\_user=administrator\_"로 변경하여 애플리케이션 내에서 권한을 상승시킬 수 있습니다. `paduster`를 사용하여 -plaintext** 매개변수를 지정하여 이를 수행할 수도 있습니다:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
사이트가 취약한 경우 `padbuster`는 패딩 오류가 발생할 때를 자동으로 찾으려고 시도하지만, **-error** 매개변수를 사용하여 오류 메시지를 지정할 수도 있습니다.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
### 이론

**요약**하자면, 모든 **다양한 패딩**을 생성하는 데 사용할 수 있는 올바른 값을 추측하여 암호화된 데이터를 복호화하기 시작할 수 있습니다. 그런 다음 패딩 오라클 공격은 1, 2, 3 등의 패딩을 생성하는 올바른 값이 무엇인지 추측하면서 끝에서 시작으로 바이트를 복호화하기 시작합니다.

![](<../.gitbook/assets/image (561).png>)

암호화된 텍스트가 **E0에서 E15**까지의 바이트로 형성된 **2 블록**을 차지한다고 가정해 보겠습니다.\
**마지막** **블록**(**E8**에서 **E15**)을 **복호화**하기 위해 전체 블록은 "블록 암호 복호화"를 거쳐 **중간 바이트 I0에서 I15**를 생성합니다.\
마지막으로 각 중간 바이트는 이전의 암호화된 바이트(E0에서 E7)와 **XOR**됩니다. 따라서:

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

이제 **C15가 `0x01`이 될 때까지 `E7`을 수정하는 것이 가능**합니다. 이는 올바른 패딩이기도 합니다. 따라서 이 경우: `\x01 = I15 ^ E'7`

따라서 E'7을 찾으면 **I15를 계산할 수 있습니다**: `I15 = 0x01 ^ E'7`

이로 인해 **C15를 계산할 수 있습니다**: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

**C15**를 알면 이제 **C14를 계산할 수 있습니다**, 하지만 이번에는 패딩 `\x02\x02`를 브루트 포스해야 합니다.

이 BF는 이전 것만큼 복잡하며, 값이 0x02인 `E''15`를 계산할 수 있습니다: `E''7 = \x02 ^ I15` 따라서 **`C14`가 `0x02`가 되도록 생성하는 `E'14`**를 찾기만 하면 됩니다.\
그런 다음 C14를 복호화하기 위해 동일한 단계를 수행합니다: **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**이 체인을 따라 전체 암호화된 텍스트를 복호화할 때까지 진행하십시오.**

### 취약점 탐지

계정을 등록하고 이 계정으로 로그인하십시오.\
**여러 번 로그인**하고 항상 **같은 쿠키**를 받는다면, 애플리케이션에 **문제가 있을 가능성**이 높습니다. **로그인할 때마다 반환되는 쿠키는 고유해야** 합니다. 쿠키가 **항상** **같다면**, 아마도 항상 유효할 것이며 이를 **무효화할 방법이 없을 것입니다**.

이제 **쿠키를 수정**하려고 하면 애플리케이션에서 **오류**가 발생하는 것을 볼 수 있습니다.\
하지만 패딩을 BF하면(예: padbuster 사용) 다른 사용자에 대해 유효한 또 다른 쿠키를 얻을 수 있습니다. 이 시나리오는 padbuster에 대해 매우 취약할 가능성이 높습니다.

### 참고 문헌

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
AWS 해킹 배우고 연습하기:<img src="../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우고 연습하기: <img src="../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나 **Twitter**에서 **팔로우**하세요** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **해킹 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하세요.

</details>
{% endhint %}
