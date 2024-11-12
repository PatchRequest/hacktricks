# macOS Authorizations DB & Authd



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

## **Athorizarions DB**

База даних, розташована в `/var/db/auth.db`, використовується для зберігання дозволів на виконання чутливих операцій. Ці операції виконуються повністю в **просторі користувача** і зазвичай використовуються **XPC-сервісами**, які повинні перевірити **чи викликаний клієнт має право** виконувати певну дію, перевіряючи цю базу даних.

Спочатку ця база даних створюється з вмісту `/System/Library/Security/authorization.plist`. Потім деякі сервіси можуть додавати або змінювати цю базу даних, щоб додати до неї інші дозволи.

Правила зберігаються в таблиці `rules` всередині бази даних і містять такі стовпці:

* **id**: Унікальний ідентифікатор для кожного правила, автоматично збільшується і служить первинним ключем.
* **name**: Унікальна назва правила, що використовується для ідентифікації та посилання на нього в системі авторизації.
* **type**: Вказує тип правила, обмежений значеннями 1 або 2 для визначення його логіки авторизації.
* **class**: Класифікує правило в певний клас, забезпечуючи, щоб це було додатне ціле число.
* "allow" для дозволу, "deny" для відмови, "user", якщо властивість групи вказує на групу, членство в якій дозволяє доступ, "rule" вказує в масиві правило, яке потрібно виконати, "evaluate-mechanisms" за яким слідує масив `mechanisms`, який є або вбудованим, або назвою пакету всередині `/System/Library/CoreServices/SecurityAgentPlugins/` або /Library/Security//SecurityAgentPlugins
* **group**: Вказує на групу користувачів, пов'язану з правилом для авторизації на основі групи.
* **kofn**: Представляє параметр "k-of-n", що визначає, скільки підправил повинні бути виконані з загальної кількості.
* **timeout**: Визначає тривалість у секундах, перш ніж авторизація, надана правилом, закінчиться.
* **flags**: Містить різні прапори, які змінюють поведінку та характеристики правила.
* **tries**: Обмежує кількість дозволених спроб авторизації для підвищення безпеки.
* **version**: Відстежує версію правила для контролю версій та оновлень.
* **created**: Записує мітку часу, коли правило було створено для аудиту.
* **modified**: Зберігає мітку часу останньої модифікації правила.
* **hash**: Містить хеш-значення правила для забезпечення його цілісності та виявлення підробок.
* **identifier**: Надає унікальний рядковий ідентифікатор, наприклад UUID, для зовнішніх посилань на правило.
* **requirement**: Містить серіалізовані дані, що визначають специфічні вимоги та механізми авторизації правила.
* **comment**: Пропонує опис або коментар про правило для документації та ясності.

### Example
```bash
# List by name and comments
sudo sqlite3 /var/db/auth.db "select name, comment from rules"

# Get rules for com.apple.tcc.util.admin
security authorizationdb read com.apple.tcc.util.admin
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>rule</string>
<key>comment</key>
<string>For modification of TCC settings.</string>
<key>created</key>
<real>701369782.01043606</real>
<key>modified</key>
<real>701369782.01043606</real>
<key>rule</key>
<array>
<string>authenticate-admin-nonshared</string>
</array>
<key>version</key>
<integer>0</integer>
</dict>
</plist>
```
Крім того, на [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) можна побачити значення `authenticate-admin-nonshared`:
```json
{
'allow-root' : 'false',
'authenticate-user' : 'true',
'class' : 'user',
'comment' : 'Authenticate as an administrator.',
'group' : 'admin',
'session-owner' : 'false',
'shared' : 'false',
'timeout' : '30',
'tries' : '10000',
'version' : '1'
}
```
## Authd

Це демон, який отримуватиме запити на авторизацію клієнтів для виконання чутливих дій. Він працює як служба XPC, визначена в папці `XPCServices/`, і використовує для запису своїх журналів `/var/log/authd.log`.

Більше того, використовуючи інструмент безпеки, можна протестувати багато API `Security.framework`. Наприклад, `AuthorizationExecuteWithPrivileges`, запустивши: `security execute-with-privileges /bin/ls`

Це створить новий процес і виконає `/usr/libexec/security_authtrampoline /bin/ls` від імені root, що запитає дозволи в спливаючому вікні для виконання ls від імені root:

<figure><img src="../../../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

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
