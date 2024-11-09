# PsExec/Winexec/ScExec

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

## Як вони працюють

Процес описаний у наступних кроках, що ілюструють, як бінарні файли служб маніпулюються для досягнення віддаленого виконання на цільовій машині через SMB:

1. **Копіювання бінарного файлу служби до спільного доступу ADMIN$ через SMB** виконується.
2. **Створення служби на віддаленій машині** здійснюється шляхом вказівки на бінарний файл.
3. Служба **запускається віддалено**.
4. Після виходу служба **зупиняється, а бінарний файл видаляється**.

### **Процес ручного виконання PsExec**

Припустимо, що є виконуваний вантаж (створений за допомогою msfvenom і обфусцований за допомогою Veil для уникнення виявлення антивірусом), названий 'met8888.exe', що представляє вантаж meterpreter reverse_http, виконуються наступні кроки:

* **Копіювання бінарного файлу**: Виконуваний файл копіюється до спільного доступу ADMIN$ з командного рядка, хоча його можна розмістити в будь-якому місці файлової системи, щоб залишитися непоміченим.
* **Створення служби**: Використовуючи команду Windows `sc`, яка дозволяє запитувати, створювати та видаляти служби Windows віддалено, створюється служба з назвою "meterpreter", яка вказує на завантажений бінарний файл.
* **Запуск служби**: Останній крок полягає в запуску служби, що, ймовірно, призведе до помилки "time-out" через те, що бінарний файл не є справжнім бінарним файлом служби і не повертає очікуваний код відповіді. Ця помилка не має значення, оскільки основна мета - виконання бінарного файлу.

Спостереження за прослуховувачем Metasploit покаже, що сесія була успішно ініційована.

[Дізнайтеся більше про команду `sc`](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Знайдіть більш детальні кроки в: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Ви також можете використовувати бінарний файл Windows Sysinternals PsExec.exe:**

![](<../../.gitbook/assets/image (928).png>)

Ви також можете використовувати [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Вивчайте та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на github.

</details>
{% endhint %}
