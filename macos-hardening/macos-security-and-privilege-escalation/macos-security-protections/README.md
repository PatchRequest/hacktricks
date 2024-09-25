# macOS Security Protections

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

## Gatekeeper

Gatekeeper зазвичай використовується для позначення комбінації **Quarantine + Gatekeeper + XProtect**, 3 модулів безпеки macOS, які намагаються **запобігти виконанню потенційно шкідливого програмного забезпечення, завантаженого користувачами**.

Більше інформації в:

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## Processes Limitants

### MACF



### SIP - System Integrity Protection

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Sandbox

MacOS Sandbox **обмежує програми**, що працюють всередині пісочниці, до **дозволених дій, зазначених у профілі Sandbox**, з яким працює програма. Це допомагає забезпечити, що **програма буде отримувати доступ лише до очікуваних ресурсів**.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** є безпековою структурою. Вона призначена для **управління дозволами** програм, зокрема, регулюючи їх доступ до чутливих функцій. Це включає елементи, такі як **сервіси геолокації, контакти, фотографії, мікрофон, камера, доступ до можливостей для людей з обмеженими можливостями та повний доступ до диска**. TCC забезпечує, що програми можуть отримувати доступ до цих функцій лише після отримання явної згоди користувача, тим самим зміцнюючи конфіденційність і контроль над особистими даними.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### Launch/Environment Constraints & Trust Cache

Обмеження запуску в macOS є функцією безпеки для **регулювання ініціації процесів**, визначаючи **хто може запустити** процес, **як** і **звідки**. Введені в macOS Ventura, вони класифікують системні двійкові файли в категорії обмежень у **кеші довіри**. Кожен виконуваний двійковий файл має встановлені **правила** для свого **запуску**, включаючи **себе**, **батька** та **відповідальні** обмеження. Розширені до сторонніх програм як **Environment** Constraints в macOS Sonoma, ці функції допомагають зменшити потенційні експлуатації системи, регулюючи умови запуску процесів.

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - Malware Removal Tool

Інструмент видалення шкідливих програм (MRT) є ще однією частиною інфраструктури безпеки macOS. Як випливає з назви, основна функція MRT полягає в **видаленні відомих шкідливих програм з заражених систем**.

Коли шкідливе програмне забезпечення виявляється на Mac (або за допомогою XProtect, або іншим способом), MRT може бути використано для автоматичного **видалення шкідливого програмного забезпечення**. MRT працює тихо у фоновому режимі і зазвичай запускається щоразу, коли система оновлюється або коли завантажується нове визначення шкідливого програмного забезпечення (схоже, що правила, які MRT має для виявлення шкідливого програмного забезпечення, знаходяться всередині двійкового файлу).

Хоча як XProtect, так і MRT є частинами заходів безпеки macOS, вони виконують різні функції:

* **XProtect** є профілактичним інструментом. Він **перевіряє файли під час їх завантаження** (через певні програми), і якщо виявляє будь-які відомі типи шкідливого програмного забезпечення, він **запобігає відкриттю файлу**, тим самим запобігаючи зараженню вашої системи з самого початку.
* **MRT**, з іншого боку, є **реактивним інструментом**. Він працює після виявлення шкідливого програмного забезпечення в системі, з метою видалення шкідливого програмного забезпечення для очищення системи.

Додаток MRT розташований у **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Background Tasks Management

**macOS** тепер **інформує** щоразу, коли інструмент використовує добре відому **техніку для збереження виконання коду** (таку як елементи входу, демонів...), щоб користувач краще знав, **яке програмне забезпечення зберігається**.

<figure><img src="../../../.gitbook/assets/image (1183).png" alt=""><figcaption></figcaption></figure>

Це працює з **демоном**, розташованим у `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd`, і **агентом** у `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`

Спосіб, яким **`backgroundtaskmanagementd`** дізнається, що щось встановлено в постійну папку, полягає в **отриманні FSEvents** і створенні деяких **обробників** для них.

Більше того, існує файл plist, який містить **добре відомі програми**, які часто зберігаються, що підтримується Apple, розташований у: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### Enumeration

Можливо **перерахувати всі** налаштовані фонові елементи, що працюють за допомогою інструмента Apple cli:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Крім того, також можливо вивести цю інформацію за допомогою [**DumpBTM**](https://github.com/objective-see/DumpBTM).
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Ця інформація зберігається в **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** і Терминал потребує FDA.

### Маніпуляції з BTM

Коли знаходиться нова персистентність, відбувається подія типу **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Отже, будь-який спосіб **запобігти** цій **події** відправленню або **агенту від сповіщення** користувача допоможе зловмиснику _**обійти**_ BTM.

* **Скидання бази даних**: Виконання наступної команди скине базу даних (повинно відновити її з нуля), однак, з якоїсь причини, після виконання цього, **жодна нова персистентність не буде сповіщена, поки система не буде перезавантажена**.
* **root** потрібен.
```bash
# Reset the database
sfltool resettbtm
```
* **Зупинити агента**: Можливо надіслати сигнал зупинки агенту, щоб він **не сповіщав користувача** про нові виявлення.
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
* **Помилка**: Якщо **процес, що створив постійність, існує швидко після нього**, демон спробує **отримати інформацію** про нього, **не вдасться** і **не зможе надіслати подію**, що вказує на те, що новий об'єкт зберігається.

Посилання та **додаткова інформація про BTM**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

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
