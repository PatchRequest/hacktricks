# macOS Security & Privilege Escalation

{% hint style="success" %}
Вивчайте та практикуйте AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримати HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Приєднуйтесь до [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) сервера, щоб спілкуватися з досвідченими хакерами та шукачами вразливостей!

**Хакерські інсайти**\
Залучайтеся до контенту, який занурюється в захоплення та виклики хакерства

**Новини хакерства в реальному часі**\
Будьте в курсі швидкоплинного світу хакерства через новини та інсайти в реальному часі

**Останні оголошення**\
Залишайтеся в курсі нових програм винагород за вразливості та важливих оновлень платформ

**Приєднуйтесь до нас на** [**Discord**](https://discord.com/invite/N3FrSbmwdy) і почніть співпрацювати з провідними хакерами вже сьогодні!

## Основи MacOS

Якщо ви не знайомі з macOS, вам слід почати вивчати основи macOS:

* Спеціальні **файли та дозволи** macOS:

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* Загальні **користувачі** macOS

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* **Архітектура** ядра

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Загальні **мережеві сервіси та протоколи** macOS

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **Відкритий код** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
* Щоб завантажити `tar.gz`, змініть URL, наприклад, [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) на [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

У компаніях системи **macOS** з великою ймовірністю будуть **керуватися через MDM**. Тому з точки зору атакуючого цікаво знати **як це працює**:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - Інспекція, налагодження та фуззинг

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## Захисти безпеки MacOS

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Поверхня атаки

### Дозволи на файли

Якщо **процес, що працює від імені root, записує** файл, який може контролюватися користувачем, користувач може зловживати цим для **ескалації привілеїв**.\
Це може статися в наступних ситуаціях:

* Використовуваний файл вже був створений користувачем (належить користувачу)
* Використовуваний файл доступний для запису користувачем через групу
* Використовуваний файл знаходиться в каталозі, що належить користувачу (користувач може створити файл)
* Використовуваний файл знаходиться в каталозі, що належить root, але користувач має доступ на запис через групу (користувач може створити файл)

Можливість **створити файл**, який буде **використовуватися root**, дозволяє користувачу **використовувати його вміст** або навіть створювати **символьні/жорсткі посилання** на інше місце.

Для таких вразливостей не забудьте **перевірити вразливі `.pkg` інсталяційні файли**:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}

### Обробники додатків за розширеннями файлів та схемами URL

Дивні додатки, зареєстровані за розширеннями файлів, можуть бути зловживані, і різні програми можуть бути зареєстровані для відкриття конкретних протоколів

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## macOS TCC / SIP Ескалація привілеїв

У macOS **додатки та бінарні файли можуть мати дозволи** на доступ до папок або налаштувань, які роблять їх більш привілейованими, ніж інші.

Тому атакуючий, який хоче успішно скомпрометувати машину macOS, повинен **ескалувати свої привілеї TCC** (або навіть **обійти SIP**, залежно від його потреб).

Ці привілеї зазвичай надаються у формі **прав**, з якими підписаний додаток, або додаток може запитати деякі доступи, і після **схвалення їх користувачем** вони можуть бути знайдені в **базах даних TCC**. Інший спосіб, яким процес може отримати ці привілеї, - це бути **дочірнім процесом** з такими **привілеями**, оскільки вони зазвичай **успадковуються**.

Слідуйте цим посиланням, щоб знайти різні способи [**ескалації привілеїв у TCC**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), [**обійти TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) і як у минулому [**SIP було обійдено**](macos-security-protections/macos-sip.md#sip-bypasses).

## Традиційна ескалація привілеїв macOS

Звичайно, з точки зору червоних команд, вам також слід бути зацікавленим в ескалації до root. Перевірте наступний пост для деяких підказок:

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}

## Відповідність macOS

* [https://github.com/usnistgov/macos\_security](https://github.com/usnistgov/macos\_security)

## Посилання

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="/.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Приєднуйтесь до [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) сервера, щоб спілкуватися з досвідченими хакерами та шукачами вразливостей!

**Хакерські інсайти**\
Залучайтеся до контенту, який занурюється в захоплення та виклики хакерства

**Новини хакерства в реальному часі**\
Будьте в курсі швидкоплинного світу хакерства через новини та інсайти в реальному часі

**Останні оголошення**\
Залишайтеся в курсі нових програм винагород за вразливості та важливих оновлень платформ

**Приєднуйтесь до нас на** [**Discord**](https://discord.com/invite/N3FrSbmwdy) і почніть співпрацювати з провідними хакерами вже сьогодні!

{% hint style="success" %}
Вивчайте та практикуйте AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримати HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}
