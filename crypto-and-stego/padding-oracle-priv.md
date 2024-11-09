# Padding Oracle

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

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

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
Щоб перевірити, чи вразливий кукі сайту, ви можете спробувати:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**Кодування 0** означає, що **base64** використовується (але доступні й інші, перевірте меню допомоги).

Ви також можете **зловживати цією вразливістю для шифрування нових даних. Наприклад, уявіть, що вміст cookie є "**_**user=MyUsername**_**", тоді ви можете змінити його на "\_user=administrator\_" і підвищити привілеї в додатку. Ви також можете зробити це, використовуючи `paduster`, вказуючи параметр -plaintext**:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
Якщо сайт вразливий, `padbuster` автоматично спробує знайти, коли виникає помилка заповнення, але ви також можете вказати повідомлення про помилку, використовуючи параметр **-error**.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
### Теорія

У **резюме**, ви можете почати розшифровувати зашифровані дані, вгадуючи правильні значення, які можна використовувати для створення всіх **різних заповнень**. Потім атака на заповнення оракула почне розшифровувати байти з кінця на початок, вгадуючи, яке буде правильне значення, що **створює заповнення 1, 2, 3 тощо**.

![](<../.gitbook/assets/image (561).png>)

Уявіть, що у вас є деякий зашифрований текст, який займає **2 блоки**, сформовані байтами з **E0 до E15**.\
Щоб **розшифрувати** **останній** **блок** (**E8** до **E15**), весь блок проходить через "дешифрування блочного шифру", генеруючи **проміжні байти I0 до I15**.\
Нарешті, кожен проміжний байт **XOR'иться** з попередніми зашифрованими байтами (E0 до E7). Отже:

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

Тепер можливо **модифікувати `E7`, поки `C15` не стане `0x01`**, що також буде правильним заповненням. Отже, в цьому випадку: `\x01 = I15 ^ E'7`

Отже, знайшовши E'7, **можливо обчислити I15**: `I15 = 0x01 ^ E'7`

Що дозволяє нам **обчислити C15**: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

Знаючи **C15**, тепер можливо **обчислити C14**, але цього разу методом грубої сили для заповнення `\x02\x02`.

Цей BF такий же складний, як і попередній, оскільки можливо обчислити `E''15`, значення якого 0x02: `E''7 = \x02 ^ I15`, тому потрібно лише знайти **`E'14`**, яке генерує **`C14`, що дорівнює `0x02`**.\
Потім виконайте ті ж кроки для розшифровки C14: **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Продовжуйте цю ланцюг, поки не розшифруєте весь зашифрований текст.**

### Виявлення вразливості

Зареєструйтеся та увійдіть з цим обліковим записом.\
Якщо ви **входите багато разів** і завжди отримуєте **один і той же cookie**, ймовірно, що в додатку є **щось** **неправильне**. **Cookie, що повертається, повинен бути унікальним** щоразу, коли ви входите. Якщо cookie **завжди** **однаковий**, він, ймовірно, завжди буде дійсним, і не буде способу його анулювати.

Тепер, якщо ви спробуєте **модифікувати** **cookie**, ви побачите, що отримуєте **помилку** від додатку.\
Але якщо ви BF заповнення (використовуючи padbuster, наприклад), ви зможете отримати інший cookie, дійсний для іншого користувача. Цей сценарій, ймовірно, вразливий до padbuster.

### Посилання

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Вчіться та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вчіться та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримати HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на github.

</details>
{% endhint %}
