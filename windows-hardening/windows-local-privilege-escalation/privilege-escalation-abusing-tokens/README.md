# Abusing Tokens

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

## Tokens

Se você **não sabe o que são Tokens de Acesso do Windows**, leia esta página antes de continuar:

{% content-ref url="../access-tokens.md" %}
[access-tokens.md](../access-tokens.md)
{% endcontent-ref %}

**Talvez você consiga escalar privilégios abusando dos tokens que já possui**

### SeImpersonatePrivilege

Este é um privilégio que é detido por qualquer processo que permite a impersonação (mas não a criação) de qualquer token, desde que um identificador para ele possa ser obtido. Um token privilegiado pode ser adquirido de um serviço do Windows (DCOM) induzindo-o a realizar autenticação NTLM contra um exploit, permitindo posteriormente a execução de um processo com privilégios de SYSTEM. Esta vulnerabilidade pode ser explorada usando várias ferramentas, como [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (que requer winrm desativado), [SweetPotato](https://github.com/CCob/SweetPotato), [EfsPotato](https://github.com/zcgonvh/EfsPotato), [DCOMPotato](https://github.com/zcgonvh/DCOMPotato) e [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{% content-ref url="../roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](../roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="../juicypotato.md" %}
[juicypotato.md](../juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege

É muito semelhante ao **SeImpersonatePrivilege**, usará o **mesmo método** para obter um token privilegiado.\
Então, este privilégio permite **atribuir um token primário** a um novo/processo suspenso. Com o token de impersonação privilegiado, você pode derivar um token primário (DuplicateTokenEx).\
Com o token, você pode criar um **novo processo** com 'CreateProcessAsUser' ou criar um processo suspenso e **definir o token** (em geral, você não pode modificar o token primário de um processo em execução).

### SeTcbPrivilege

Se você tiver este token ativado, pode usar **KERB\_S4U\_LOGON** para obter um **token de impersonação** para qualquer outro usuário sem conhecer as credenciais, **adicionar um grupo arbitrário** (administradores) ao token, definir o **nível de integridade** do token como "**médio**" e atribuir este token ao **thread atual** (SetThreadToken).

### SeBackupPrivilege

O sistema é induzido a **conceder todo o controle de acesso de leitura** a qualquer arquivo (limitado a operações de leitura) por este privilégio. É utilizado para **ler os hashes de senha das contas de Administrador local** do registro, após o que, ferramentas como "**psexec**" ou "**wmiexec**" podem ser usadas com o hash (técnica Pass-the-Hash). No entanto, esta técnica falha sob duas condições: quando a conta de Administrador Local está desativada ou quando uma política está em vigor que remove direitos administrativos de Administradores Locais conectando-se remotamente.\
Você pode **abusar deste privilégio** com:

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* seguindo **IppSec** em [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)
* Ou como explicado na seção **escalando privilégios com Operadores de Backup** de:

{% content-ref url="../../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege

Permissão para **acesso de gravação** a qualquer arquivo do sistema, independentemente da Lista de Controle de Acesso (ACL) do arquivo, é fornecida por este privilégio. Ele abre inúmeras possibilidades para escalonamento, incluindo a capacidade de **modificar serviços**, realizar DLL Hijacking e definir **debuggers** através de Opções de Execução de Arquivo de Imagem, entre várias outras técnicas.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege é uma permissão poderosa, especialmente útil quando um usuário possui a capacidade de impersonar tokens, mas também na ausência de SeImpersonatePrivilege. Esta capacidade depende da habilidade de impersonar um token que representa o mesmo usuário e cujo nível de integridade não excede o do processo atual.

**Pontos Chave:**
- **Impersonação sem SeImpersonatePrivilege:** É possível aproveitar SeCreateTokenPrivilege para EoP ao impersonar tokens sob condições específicas.
- **Condições para Impersonação de Token:** A impersonação bem-sucedida requer que o token alvo pertença ao mesmo usuário e tenha um nível de integridade que seja menor ou igual ao nível de integridade do processo que tenta a impersonação.
- **Criação e Modificação de Tokens de Impersonação:** Os usuários podem criar um token de impersonação e aprimorá-lo adicionando um SID (Identificador de Segurança) de um grupo privilegiado.

### SeLoadDriverPrivilege

Este privilégio permite **carregar e descarregar drivers de dispositivo** com a criação de uma entrada de registro com valores específicos para `ImagePath` e `Type`. Como o acesso de gravação direto ao `HKLM` (HKEY_LOCAL_MACHINE) é restrito, o `HKCU` (HKEY_CURRENT_USER) deve ser utilizado em vez disso. No entanto, para tornar o `HKCU` reconhecível pelo kernel para configuração de driver, um caminho específico deve ser seguido.

Este caminho é `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, onde `<RID>` é o Identificador Relativo do usuário atual. Dentro do `HKCU`, todo esse caminho deve ser criado, e dois valores precisam ser definidos:
- `ImagePath`, que é o caminho para o binário a ser executado
- `Type`, com um valor de `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Passos a Seguir:**
1. Acesse `HKCU` em vez de `HKLM` devido ao acesso de gravação restrito.
2. Crie o caminho `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` dentro do `HKCU`, onde `<RID>` representa o Identificador Relativo do usuário atual.
3. Defina o `ImagePath` para o caminho de execução do binário.
4. Atribua o `Type` como `SERVICE_KERNEL_DRIVER` (`0x00000001`).
```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```
Mais maneiras de abusar desse privilégio em [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Isso é semelhante ao **SeRestorePrivilege**. Sua função principal permite que um processo **assuma a propriedade de um objeto**, contornando a exigência de acesso discricionário explícito por meio da concessão de direitos de acesso WRITE_OWNER. O processo envolve primeiro garantir a propriedade da chave de registro pretendida para fins de gravação, e depois alterar o DACL para permitir operações de gravação.
```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```
### SeDebugPrivilege

Este privilégio permite **depurar outros processos**, incluindo ler e escrever na memória. Várias estratégias para injeção de memória, capazes de evadir a maioria das soluções de antivírus e prevenção de intrusões em hosts, podem ser empregadas com este privilégio.

#### Dump memory

Você pode usar [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) do [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) para **capturar a memória de um processo**. Especificamente, isso pode se aplicar ao processo **Local Security Authority Subsystem Service ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service))**, que é responsável por armazenar credenciais de usuário uma vez que um usuário tenha feito login com sucesso em um sistema.

Você pode então carregar este dump no mimikatz para obter senhas:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Se você quiser obter um shell `NT SYSTEM`, você pode usar:

* ****[**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)****
* ****[**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)****
* ****[**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)****
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

O `SeManageVolumePrivilege` é um direito de usuário do Windows que permite aos usuários gerenciar volumes de disco, incluindo a criação e exclusão deles. Embora seja destinado a administradores, se concedido a usuários não administradores, pode ser explorado para escalonamento de privilégios.

É possível aproveitar esse privilégio para manipular volumes, levando ao acesso total ao volume. O [SeManageVolumeExploit](https://github.com/CsEnox/SeManageVolumeExploit) pode ser usado para dar acesso total a todos os usuários para C:\

Além disso, o processo descrito [neste artigo do Medium](https://medium.com/@raphaeltzy13/exploiting-semanagevolumeprivilege-with-dll-hijacking-windows-privilege-escalation-1a4f28372d37) descreve o uso de DLL hijacking em conjunto com `SeManageVolumePrivilege` para escalar privilégios. Colocando um payload DLL `C:\Windows\System32\wbem\tzres.dll` e chamando `systeminfo`, a dll é executada.

## Check privileges
```
whoami /priv
```
Os **tokens que aparecem como Desativados** podem ser ativados, você realmente pode abusar de tokens _Ativados_ e _Desativados_.

### Ativar Todos os tokens

Se você tiver tokens desativados, pode usar o script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) para ativar todos os tokens:
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Or the **script** embed in this [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Full token privileges cheatsheet at [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), summary below will only list direct ways to exploit the privilege to obtain an admin session or read sensitive files.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"Isso permitiria que um usuário impersonasse tokens e privesc para o sistema nt usando ferramentas como potato.exe, rottenpotato.exe e juicypotato.exe"_                                                                                                                                                                                                      | Thank you [Aurélien Chalot](https://twitter.com/Defte\_) for the update. I will try to re-phrase it to something more recipe-like soon.                                                                                                                                                                                        |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Ler arquivos sensíveis com `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- Pode ser mais interessante se você puder ler %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (e robocopy) não é útil quando se trata de arquivos abertos.<br><br>- Robocopy requer tanto SeBackup quanto SeRestore para funcionar com o parâmetro /b.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Criar token arbitrário incluindo direitos de administrador local com `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicar o token `lsass.exe`.                                                                                                                                                                                                                                                                                                                   | Script to be found at [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Carregar driver de kernel com bugs como <code>szkg64.sys</code><br>2. Explorar a vulnerabilidade do driver<br><br>Alternativamente, o privilégio pode ser usado para descarregar drivers relacionados à segurança com o comando embutido <code>ftlMC</code>. i.e.: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. A vulnerabilidade <code>szkg64</code> está listada como <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. O <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">código de exploração</a> foi criado por <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Iniciar PowerShell/ISE com o privilégio SeRestore presente.<br>2. Habilitar o privilégio com <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Renomear utilman.exe para utilman.old<br>4. Renomear cmd.exe para utilman.exe<br>5. Bloquear o console e pressionar Win+U</p> | <p>O ataque pode ser detectado por alguns softwares antivírus.</p><p>Método alternativo depende de substituir binários de serviço armazenados em "Program Files" usando o mesmo privilégio</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Renomear cmd.exe para utilman.exe<br>4. Bloquear o console e pressionar Win+U</p>                                                                                                                                       | <p>O ataque pode ser detectado por alguns softwares antivírus.</p><p>Método alternativo depende de substituir binários de serviço armazenados em "Program Files" usando o mesmo privilégio.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipular tokens para ter direitos de administrador local incluídos. Pode exigir SeImpersonate.</p><p>A ser verificado.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Reference

* Take a look to this table defining Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* Take a look to [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt) about privesc with tokens.

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
