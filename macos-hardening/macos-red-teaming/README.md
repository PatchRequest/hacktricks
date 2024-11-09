# macOS Red Teaming

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Отримайте перспективу хакера на ваші веб-додатки, мережу та хмару

**Знайдіть і повідомте про критичні, експлуатовані вразливості з реальним бізнес-імпактом.** Використовуйте наші 20+ спеціальних інструментів для картографування атакуючої поверхні, знаходження проблем безпеки, які дозволяють вам підвищити привілеї, і використовуйте автоматизовані експлойти для збору важливих доказів, перетворюючи вашу важку працю на переконливі звіти.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## Зловживання MDM

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

Якщо вам вдасться **компрометувати облікові дані адміністратора** для доступу до платформи управління, ви можете **потенційно скомпрометувати всі комп'ютери**, розповсюджуючи ваше шкідливе ПЗ на машинах.

Для червоного тестування в середовищах MacOS настійно рекомендується мати певне розуміння того, як працюють MDM:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### Використання MDM як C2

MDM матиме дозвіл на установку, запит або видалення профілів, установку додатків, створення локальних облікових записів адміністратора, встановлення пароля прошивки, зміну ключа FileVault...

Щоб запустити свій власний MDM, вам потрібно **підписати ваш CSR у постачальника**, що ви можете спробувати отримати за допомогою [**https://mdmcert.download/**](https://mdmcert.download/). А щоб запустити свій власний MDM для пристроїв Apple, ви можете використовувати [**MicroMDM**](https://github.com/micromdm/micromdm).

Однак, щоб встановити додаток на зареєстрованому пристрої, вам все ще потрібно, щоб він був підписаний обліковим записом розробника... однак, під час реєстрації MDM **пристрій додає SSL сертифікат MDM як довірений CA**, тому ви тепер можете підписувати що завгодно.

Щоб зареєструвати пристрій в MDM, вам потрібно встановити файл **`mobileconfig`** як root, який можна доставити через файл **pkg** (ви можете стиснути його в zip, і коли його завантажать з safari, він буде розпакований).

**Mythic agent Orthrus** використовує цю техніку.

### Зловживання JAMF PRO

JAMF може виконувати **кастомні скрипти** (скрипти, розроблені системним адміністратором), **рідні корисні навантаження** (створення локальних облікових записів, встановлення пароля EFI, моніторинг файлів/процесів...) та **MDM** (конфігурації пристроїв, сертифікати пристроїв...).

#### Самостійна реєстрація JAMF

Перейдіть на сторінку, таку як `https://<company-name>.jamfcloud.com/enroll/`, щоб перевірити, чи мають вони **увімкнену самостійну реєстрацію**. Якщо так, це може **попросити облікові дані для доступу**.

Ви можете використовувати скрипт [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) для виконання атаки на підбор паролів.

Більше того, після знаходження відповідних облікових даних ви зможете брутфорсити інші імена користувачів за допомогою наступної форми:

![](<../../.gitbook/assets/image (107).png>)

#### Аутентифікація пристрою JAMF

<figure><img src="../../.gitbook/assets/image (167).png" alt=""><figcaption></figcaption></figure>

Бінарний файл **`jamf`** містив секрет для відкриття ключниці, який на момент виявлення був **спільним** серед усіх, і це було: **`jk23ucnq91jfu9aj`**.\
Більше того, jamf **постійно** існує як **LaunchDaemon** в **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Захоплення пристрою JAMF

URL **JSS** (Jamf Software Server), який використовуватиме **`jamf`**, знаходиться в **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Цей файл в основному містить URL:
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://halbornasd.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
{% endcode %}

Отже, зловмисник може встановити шкідливий пакет (`pkg`), який **перезаписує цей файл**, встановлюючи **URL для прослуховувача Mythic C2 з агента Typhon**, щоб тепер мати можливість зловживати JAMF як C2.

{% code overflow="wrap" %}
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### JAMF Імітація

Щоб **імітувати комунікацію** між пристроєм і JMF, вам потрібно:

* **UUID** пристрою: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* **JAMF ключ** з: `/Library/Application\ Support/Jamf/JAMF.keychain`, який містить сертифікат пристрою

З цією інформацією, **створіть ВМ** з **викраденим** апаратним **UUID** і з **вимкненим SIP**, скиньте **JAMF ключ**, **підключіть** агент Jamf і викрадіть його інформацію.

#### Викрадення секретів

<figure><img src="../../.gitbook/assets/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Ви також можете моніторити місце `/Library/Application Support/Jamf/tmp/` для **кастомних скриптів**, які адміністратори можуть захотіти виконати через Jamf, оскільки вони **розміщуються тут, виконуються і видаляються**. Ці скрипти **можуть містити облікові дані**.

Однак, **облікові дані** можуть передаватися цим скриптам як **параметри**, тому вам потрібно буде моніторити `ps aux | grep -i jamf` (навіть не будучи root).

Скрипт [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) може слухати нові файли, які додаються, і нові аргументи процесу.

### macOS Дистанційний доступ

А також про **MacOS** "спеціальні" **мережеві** **протоколи**:

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

В деяких випадках ви виявите, що **комп'ютер MacOS підключений до AD**. У цьому сценарії вам слід спробувати **перерахувати** активний каталог, як ви звикли. Знайдіть деяку **допомогу** на наступних сторінках:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

Деякий **локальний інструмент MacOS**, який також може вам допомогти, це `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Також є кілька інструментів, підготовлених для MacOS, щоб автоматично перераховувати AD та працювати з kerberos:

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound - це розширення до інструменту аудиту Bloodhound, що дозволяє збирати та імпортувати відносини Active Directory на MacOS хостах.
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost - це проект на Objective-C, призначений для взаємодії з API Heimdal krb5 на macOS. Мета проекту - забезпечити кращий тестування безпеки навколо Kerberos на пристроях macOS, використовуючи рідні API без необхідності в будь-яких інших фреймворках або пакетах на цільовому пристрої.
* [**Orchard**](https://github.com/its-a-feature/Orchard): JavaScript для автоматизації (JXA) інструмент для перерахунку Active Directory.

### Інформація про домен
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Користувачі

Три типи користувачів MacOS:

* **Локальні користувачі** — Керуються локальною службою OpenDirectory, вони не пов'язані жодним чином з Active Directory.
* **Мережеві користувачі** — Вразливі користувачі Active Directory, які потребують з'єднання з сервером DC для аутентифікації.
* **Мобільні користувачі** — Користувачі Active Directory з локальною резервною копією своїх облікових даних та файлів.

Локальна інформація про користувачів та групи зберігається у папці _/var/db/dslocal/nodes/Default._\
Наприклад, інформація про користувача з ім'ям _mark_ зберігається у _/var/db/dslocal/nodes/Default/users/mark.plist_, а інформація про групу _admin_ — у _/var/db/dslocal/nodes/Default/groups/admin.plist_.

На додаток до використання країв HasSession та AdminTo, **MacHound додає три нові краї** до бази даних Bloodhound:

* **CanSSH** - сутність, якій дозволено SSH до хоста
* **CanVNC** - сутність, якій дозволено VNC до хоста
* **CanAE** - сутність, якій дозволено виконувати скрипти AppleEvent на хості
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
Більше інформації в [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Computer$ пароль

Отримати паролі за допомогою:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
Можливо отримати пароль **`Computer$`** всередині системного ключа.

### Over-Pass-The-Hash

Отримати TGT для конкретного користувача та служби:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Якщо TGT зібрано, його можна ввести в поточну сесію за допомогою:
```bash
bifrost --action asktgt --username test_lab_admin \
--hash CF59D3256B62EE655F6430B0F80701EE05A0885B8B52E9C2480154AFA62E78 \
--enctype aes256 --domain test.lab.local
```
### Kerberoasting
```bash
bifrost --action asktgs --spn [service] --domain [domain.com] \
--username [user] --hash [hash] --enctype [enctype]
```
З отриманими сервісними квитками можна спробувати отримати доступ до спільних ресурсів на інших комп'ютерах:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Доступ до Ключниці

Ключниця, ймовірно, містить чутливу інформацію, доступ до якої без генерації запиту може допомогти просунутися в червоній командній вправі:

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## Зовнішні Сервіси

MacOS Red Teaming відрізняється від звичайного Windows Red Teaming, оскільки зазвичай **MacOS інтегровано з кількома зовнішніми платформами безпосередньо**. Загальна конфігурація MacOS полягає в доступі до комп'ютера за допомогою **синхронізованих облікових даних OneLogin та доступу до кількох зовнішніх сервісів** (як-от github, aws...) через OneLogin.

## Різні техніки червоної команди

### Safari

Коли файл завантажується в Safari, якщо це "безпечний" файл, він буде **автоматично відкритий**. Тож, наприклад, якщо ви **завантажите zip**, він буде автоматично розпакований:

<figure><img src="../../.gitbook/assets/image (226).png" alt=""><figcaption></figcaption></figure>

## Посилання

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

#### Отримайте перспективу хакера на ваші веб-додатки, мережу та хмару

**Знайдіть і повідомте про критичні, експлуатовані вразливості з реальним бізнес-імпактом.** Використовуйте наші 20+ спеціальних інструментів для картографування поверхні атаки, знаходження проблем безпеки, які дозволяють вам підвищити привілеї, і використовуйте автоматизовані експлойти для збору важливих доказів, перетворюючи вашу важку працю на переконливі звіти.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{% hint style="success" %}
Вчіться та практикуйте AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Вчіться та практикуйте GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на github.

</details>
{% endhint %}
