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

#### Отримайте перспективу хакера щодо ваших веб-додатків, мережі та хмари

**Знайдіть і повідомте про критичні, експлуатовані вразливості з реальним бізнес-імпактом.** Використовуйте наші 20+ спеціальних інструментів для картографування атакуючої поверхні, знаходження проблем безпеки, які дозволяють вам підвищити привілеї, і використовуйте автоматизовані експлойти для збору важливих доказів, перетворюючи вашу важку працю на переконливі звіти.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## Як це працює

**Smbexec** - це інструмент, що використовується для віддаленого виконання команд на системах Windows, подібно до **Psexec**, але він уникає розміщення будь-яких шкідливих файлів на цільовій системі.

### Ключові моменти про **SMBExec**

- Він працює, створюючи тимчасову службу (наприклад, "BTOBTO") на цільовій машині для виконання команд через cmd.exe (%COMSPEC%), без скидання будь-яких бінарних файлів.
- Незважаючи на свій прихований підхід, він генерує журнали подій для кожної виконаної команди, пропонуючи форму неінтерактивної "оболонки".
- Команда для підключення за допомогою **Smbexec** виглядає так:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Виконання команд без бінарних файлів

- **Smbexec** дозволяє безпосереднє виконання команд через binPaths сервісу, усуваючи необхідність у фізичних бінарних файлах на цілі.
- Цей метод корисний для виконання одноразових команд на цільовій системі Windows. Наприклад, поєднання його з модулем `web_delivery` Metasploit дозволяє виконати зворотний Meterpreter payload, націлений на PowerShell.
- Створивши віддалений сервіс на машині зловмисника з binPath, налаштованим для виконання наданої команди через cmd.exe, можна успішно виконати payload, досягнувши зворотного виклику та виконання payload з прослуховувачем Metasploit, навіть якщо виникають помилки у відповіді сервісу.

### Приклад команд

Створення та запуск сервісу можна виконати за допомогою наступних команд:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
FOr further details check [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## References
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Отримайте перспективу хакера щодо ваших веб-додатків, мережі та хмари

**Знайдіть і повідомте про критичні, експлуатовані вразливості з реальним бізнес-імпактом.** Використовуйте наші 20+ спеціальних інструментів для картографування поверхні атаки, знаходження проблем безпеки, які дозволяють вам підвищити привілеї, і використовуйте автоматизовані експлойти для збору важливих доказів, перетворюючи вашу важку працю на переконливі звіти.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{% hint style="success" %}
Навчайтеся та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Навчайтеся та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, подаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}
