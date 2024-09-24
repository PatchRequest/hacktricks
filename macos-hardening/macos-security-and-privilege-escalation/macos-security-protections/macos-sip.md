# macOS SIP

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## **Temel Bilgiler**

**Sistem Bütünlüğü Koruması (SIP)**, macOS'ta ana sistem klasörlerinde yetkisiz değişikliklerin yapılmasını önlemek için tasarlanmış bir mekanizmadır. Bu özellik, korunan alanlarda dosya ekleme, değiştirme veya silme gibi eylemleri kısıtlayarak sistemin bütünlüğünü korumada kritik bir rol oynar. SIP tarafından korunan ana klasörler şunlardır:

* **/System**
* **/bin**
* **/sbin**
* **/usr**

SIP'nin davranışını yöneten kurallar, **`/System/Library/Sandbox/rootless.conf`** konumundaki yapılandırma dosyasında tanımlanmıştır. Bu dosyada, bir yıldız işareti (\*) ile başlayan yollar, aksi takdirde katı olan SIP kısıtlamalarına istisna olarak belirtilmiştir.

Aşağıdaki örneği düşünün:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Bu kesit, SIP'nin genel olarak **`/usr`** dizinini güvence altına aldığını, ancak belirli alt dizinlerde (`/usr/libexec/cups`, `/usr/local` ve `/usr/share/man`) değişikliklere izin verildiğini, yollarının önünde bulunan yıldız (\*) ile gösterdiğini ima etmektedir.

Bir dizinin veya dosyanın SIP tarafından korunup korunmadığını doğrulamak için, **`ls -lOd`** komutunu kullanarak **`restricted`** veya **`sunlnk`** bayrağının varlığını kontrol edebilirsiniz. Örneğin:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
Bu durumda, **`sunlnk`** bayrağı, `/usr/libexec/cups` dizininin kendisinin **silinemez** olduğunu belirtir, ancak içindeki dosyalar oluşturulabilir, değiştirilebilir veya silinebilir.

Diğer yandan:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Burada, **`restricted`** bayrağı `/usr/libexec` dizininin SIP tarafından korunduğunu gösterir. SIP ile korunan bir dizinde, dosyalar oluşturulamaz, değiştirilemez veya silinemez.

Ayrıca, bir dosya **`com.apple.rootless`** genişletilmiş **özelliğini** içeriyorsa, o dosya da **SIP tarafından korunacaktır**.

{% hint style="success" %}
**Sandbox** kancası **`hook_vnode_check_setextattr`**, genişletilmiş özellik **`com.apple.rootless`**'ı değiştirme girişimlerini engeller.
{% endhint %}

**SIP ayrıca diğer kök eylemlerini de sınırlar**:

* Güvenilmeyen çekirdek uzantılarını yükleme
* Apple imzalı süreçler için görev bağlantı noktalarını alma
* NVRAM değişkenlerini değiştirme
* Çekirdek hata ayıklamaya izin verme

Seçenekler, bir bit bayrağı olarak nvram değişkeninde saklanır (`csr-active-config` Intel için ve `lp-sip0` ARM için önyüklenen Aygıt Ağacından okunur). Bayrakları `csr.sh` dosyasında XNU kaynak kodunda bulabilirsiniz:

<figure><img src="../../../.gitbook/assets/image (1192).png" alt=""><figcaption></figcaption></figure>

### SIP Durumu

SIP'in sisteminizde etkin olup olmadığını aşağıdaki komutla kontrol edebilirsiniz:
```bash
csrutil status
```
Eğer SIP'yi devre dışı bırakmanız gerekiyorsa, bilgisayarınızı kurtarma modunda yeniden başlatmalısınız (başlangıçta Command+R tuşuna basarak), ardından aşağıdaki komutu çalıştırmalısınız:
```bash
csrutil disable
```
Eğer SIP'yi etkin tutmak ama hata ayıklama korumalarını kaldırmak istiyorsanız, bunu şu şekilde yapabilirsiniz:
```bash
csrutil enable --without debug
```
### Diğer Kısıtlamalar

* **İmzalanmamış çekirdek uzantılarının** (kexts) yüklenmesini engeller, yalnızca doğrulanmış uzantıların sistem çekirdeği ile etkileşimde bulunmasını sağlar.
* **macOS sistem süreçlerinin** hata ayıklanmasını engeller, temel sistem bileşenlerini yetkisiz erişim ve değişikliklerden korur.
* **dtrace gibi araçların** sistem süreçlerini incelemesini engeller, sistemin işleyişinin bütünlüğünü daha da korur.

[**Bu konuşmada SIP bilgileri hakkında daha fazla bilgi edinin**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**

### **SIP ile İlgili Yetkiler**

* `com.apple.rootless.xpc.bootstrap`: launchd kontrolü
* `com.apple.rootless.install[.heritable]`: Dosya sistemine erişim
* `com.apple.rootless.kext-management`: `kext_request`
* `com.apple.rootless.datavault.controller`: UF\_DATAVAULT yönetimi
* `com.apple.rootless.xpc.bootstrap`: XPC kurulum yetenekleri
* `com.apple.rootless.xpc.effective-root`: launchd XPC üzerinden root
* `com.apple.rootless.restricted-block-devices`: Ham blok cihazlarına erişim
* `com.apple.rootless.internal.installer-equivalent`: Sınırsız dosya sistemi erişimi
* `com.apple.rootless.restricted-nvram-variables[.heritable]`: NVRAM'a tam erişim
* `com.apple.rootless.storage.label`: İlgili etiketle com.apple.rootless xattr tarafından kısıtlanan dosyaları değiştirme
* `com.apple.rootless.volume.VM.label`: Hacimde VM takasını sürdürme

## SIP Aşmaları

SIP'yi aşmak, bir saldırgana:

* **Kullanıcı Verilerine Erişim**: Tüm kullanıcı hesaplarından hassas kullanıcı verilerini, örneğin e-posta, mesajlar ve Safari geçmişini okuma.
* **TCC Aşması**: TCC (Şeffaflık, Onay ve Kontrol) veritabanını doğrudan manipüle ederek, web kamerası, mikrofon ve diğer kaynaklara yetkisiz erişim sağlama.
* **Kalıcılık Sağlama**: SIP ile korunan alanlara kötü amaçlı yazılım yerleştirme, bu da kaldırılmasına karşı dirençli hale getirir, hatta root ayrıcalıklarıyla bile. Bu, Kötü Amaçlı Yazılım Kaldırma Aracı'nın (MRT) değiştirilmesi potansiyelini de içerir.
* **Çekirdek Uzantılarını Yükleme**: Ek korumalara rağmen, SIP'yi aşmak, imzalanmamış çekirdek uzantılarını yükleme sürecini basitleştirir.

### Yükleyici Paketleri

**Apple'ın sertifikasıyla imzalanmış yükleyici paketleri**, korumalarını aşabilir. Bu, standart geliştiriciler tarafından imzalanmış paketlerin bile, SIP ile korunan dizinleri değiştirmeye çalıştıklarında engelleneceği anlamına gelir.

### Mevcut Olmayan SIP Dosyası

Bir potansiyel açık, **`rootless.conf` içinde belirtilen ancak şu anda mevcut olmayan** bir dosyanın oluşturulabilmesidir. Kötü amaçlı yazılım, bunu kullanarak sistemde **kalıcılık sağlama** fırsatını değerlendirebilir. Örneğin, kötü niyetli bir program, `rootless.conf` içinde listelenmiş ancak mevcut olmayan bir .plist dosyasını `/System/Library/LaunchDaemons` içinde oluşturabilir.

### com.apple.rootless.install.heritable

{% hint style="danger" %}
Yetki **`com.apple.rootless.install.heritable`**, SIP'yi aşmayı sağlar.
{% endhint %}

#### [CVE-2019-8561](https://objective-see.org/blog/blog\_0x42.html) <a href="#cve" id="cve"></a>

Sistem, kod imzasını doğruladıktan sonra **yükleyici paketini değiştirme** olanağının bulunduğu keşfedildi ve ardından sistem, orijinal yerine kötü amaçlı paketi yükleyecekti. Bu eylemler **`system_installd`** tarafından gerçekleştirildiği için, SIP'yi aşmayı sağlıyordu.

#### [CVE-2020–9854](https://objective-see.org/blog/blog\_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Bir paket, bir montajlı görüntüden veya harici bir sürücüden yüklendiğinde, **yükleyici** **o dosya sisteminden** ikili dosyayı **çalıştırır** (SIP korumalı bir konumdan değil), bu da **`system_installd`**'nin keyfi bir ikili dosyayı çalıştırmasına neden olur.

#### CVE-2021-30892 - Shrootless

[**Bu blog yazısından araştırmacılar**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) macOS'un Sistem Bütünlüğü Koruma (SIP) mekanizmasında, 'Shrootless' olarak adlandırılan bir güvenlik açığı keşfettiler. Bu güvenlik açığı, **`system_installd`** daemon'u etrafında döner ve bu daemon'un, herhangi bir çocuk sürecinin SIP'nin dosya sistemi kısıtlamalarını aşmasına izin veren bir yetkisi vardır, **`com.apple.rootless.install.heritable`**.

**`system_installd`** daemon'u, **Apple** tarafından imzalanmış paketleri yükleyecektir.

Araştırmacılar, Apple imzalı bir paket (.pkg dosyası) yüklenirken, **`system_installd`** paket içindeki herhangi bir **kurulum sonrası** betiği **çalıştırdığını** buldular. Bu betikler, varsayılan kabuk olan **`zsh`** tarafından çalıştırılır ve eğer mevcutsa, **`/etc/zshenv`** dosyasından komutları otomatik olarak **çalıştırır**, hatta etkileşimli modda bile. Bu davranış, saldırganlar tarafından istismar edilebilir: kötü niyetli bir `/etc/zshenv` dosyası oluşturarak ve **`system_installd`'nin `zsh`'yi çağırmasını** bekleyerek, cihazda keyfi işlemler gerçekleştirebilirler.

Ayrıca, **`/etc/zshenv`'nin genel bir saldırı tekniği olarak kullanılabileceği** keşfedildi, sadece SIP aşması için değil. Her kullanıcı profili, `/etc/zshenv` ile aynı şekilde davranan bir `~/.zshenv` dosyasına sahiptir, ancak root izinleri gerektirmez. Bu dosya, `zsh` her başladığında tetiklenecek şekilde bir kalıcılık mekanizması olarak veya ayrıcalık yükseltme mekanizması olarak kullanılabilir. Eğer bir yönetici kullanıcı, `sudo -s` veya `sudo <komut>` kullanarak root'a yükselirse, `~/.zshenv` dosyası tetiklenecek ve etkili bir şekilde root'a yükselecektir.

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

[**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) içinde, aynı **`system_installd`** sürecinin hala kötüye kullanılabileceği keşfedildi çünkü **kurulum sonrası betiği SIP tarafından korunan rastgele adlandırılmış bir klasörün içine koyuyordu** ve bu klasör `/tmp` içindeydi. Sorun şu ki, **`/tmp` kendisi SIP tarafından korunmamaktadır**, bu nedenle **sanallaştırılmış bir görüntüyü** üzerine **monte etmek** mümkündü, ardından **yükleyici** oraya **kurulum sonrası betiği** koyacak, **sanallaştırılmış görüntüyü** **kaldıracak**, tüm **klasörleri** **yeniden oluşturacak** ve **yükleme sonrası** betiği **yüklemek için** **payload** ile ekleyecekti.

#### [fsck\_cs aracı](https://www.theregister.com/2016/03/30/apple\_os\_x\_rootless/)

**`fsck_cs`**'nin, **sembolik bağlantıları** takip etme yeteneği nedeniyle kritik bir dosyayı bozduğu bir güvenlik açığı tespit edildi. Özellikle, saldırganlar _`/dev/diskX`_'den `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist` dosyasına bir bağlantı oluşturdu. **`fsck_cs`**'yi _`/dev/diskX`_ üzerinde çalıştırmak, `Info.plist` dosyasının bozulmasına yol açtı. Bu dosyanın bütünlüğü, işletim sisteminin SIP'si (Sistem Bütünlüğü Koruma) için hayati öneme sahiptir ve çekirdek uzantılarının yüklenmesini kontrol eder. Bozulduğunda, SIP'nin çekirdek hariç tutmalarını yönetme yeteneği tehlikeye girer.

Bu güvenlik açığını istismar etmek için gereken komutlar:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Bu güvenlik açığının istismarı ciddi sonuçlar doğurmaktadır. `Info.plist` dosyası, normalde çekirdek uzantıları için izinleri yönetmekten sorumlu olan dosya, etkisiz hale gelir. Bu, `AppleHWAccess.kext` gibi belirli uzantıları kara listeye alma yeteneğinin kaybolmasını içerir. Sonuç olarak, SIP'nin kontrol mekanizması bozulduğunda, bu uzantı yüklenebilir ve sistemin RAM'ine yetkisiz okuma ve yazma erişimi sağlar.

#### [SIP korumalı klasörler üzerinde montaj yapma](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

**Koruma atlamak için SIP korumalı klasörler üzerinde yeni bir dosya sistemi montajı yapmak** mümkündü.
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Yükseltici atlatma (2016)](https://objective-see.org/blog/blog\_0x14.html)

Sistem, OS'u yükseltmek için `Install macOS Sierra.app` içindeki gömülü bir yükleyici disk görüntüsünden önyükleme yapacak şekilde ayarlanmıştır ve `bless` aracını kullanmaktadır. Kullanılan komut aşağıdaki gibidir:
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Bu sürecin güvenliği, bir saldırganın yükseltme görüntüsünü (`InstallESD.dmg`) önyüklemeden önce değiştirmesi durumunda tehlikeye girebilir. Strateji, dinamik bir yükleyiciyi (dyld) kötü niyetli bir sürümle (`libBaseIA.dylib`) değiştirmeyi içerir. Bu değişim, yükleyici başlatıldığında saldırganın kodunun çalıştırılmasına neden olur.

Saldırganın kodu, yükseltme süreci sırasında kontrolü ele geçirir ve sistemin yükleyiciye olan güvenini istismar eder. Saldırı, `InstallESD.dmg` görüntüsünü yöntem değiştirme (method swizzling) ile değiştirerek, özellikle `extractBootBits` yöntemini hedef alarak devam eder. Bu, disk görüntüsü kullanılmadan önce kötü niyetli kodun enjekte edilmesine olanak tanır.

Ayrıca, `InstallESD.dmg` içinde, yükseltme kodunun kök dosya sistemi olarak hizmet eden bir `BaseSystem.dmg` bulunmaktadır. Buna dinamik bir kütüphane enjekte etmek, kötü niyetli kodun OS düzeyindeki dosyaları değiştirebilen bir süreç içinde çalışmasına olanak tanır ve sistemin tehlikeye girme potansiyelini önemli ölçüde artırır.

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

[**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk) konuşmasında, **`systemmigrationd`** (SIP'yi atlayabilen) bir **bash** ve bir **perl** betiği çalıştırdığı gösterilmektedir; bu betikler **`BASH_ENV`** ve **`PERL5OPT`** ortam değişkenleri aracılığıyla kötüye kullanılabilir.

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

[**bu blog yazısında detaylı olarak açıklandığı gibi**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), `InstallAssistant.pkg` paketlerinden bir `postinstall` betiği çalıştırıyordu:
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
and it was possible to crate a symlink in `${SHARED_SUPPORT_PATH}/SharedSupport.dmg` that would allow a user to **unrestrict any file, bypassing SIP protection**.

### **com.apple.rootless.install**

{% hint style="danger" %}
Yetki **`com.apple.rootless.install`** SIP'yi atlatmaya izin verir.
{% endhint %}

Yetki `com.apple.rootless.install`, macOS'ta Sistem Bütünlüğü Koruması (SIP) atlatmak için bilinir. Bu, özellikle [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/) ile ilgili olarak belirtilmiştir.

Bu özel durumda, `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` konumundaki sistem XPC servisi bu yetkiye sahiptir. Bu, ilgili sürecin SIP kısıtlamalarını aşmasına olanak tanır. Ayrıca, bu hizmet, dosyaların herhangi bir güvenlik önlemi uygulanmadan taşınmasına izin veren bir yöntem sunar.

## Mühürlü Sistem Anlık Görüntüleri

Mühürlü Sistem Anlık Görüntüleri, Apple tarafından **macOS Big Sur (macOS 11)** ile tanıtılan bir özelliktir ve **Sistem Bütünlüğü Koruması (SIP)** mekanizmasının bir parçası olarak ek bir güvenlik ve sistem istikrarı katmanı sağlar. Temelde, sistem hacminin salt okunur sürümleridir.

Daha ayrıntılı bir bakış:

1. **Değiştirilemez Sistem**: Mühürlü Sistem Anlık Görüntüleri, macOS sistem hacmini "değiştirilemez" hale getirir, yani değiştirilemez. Bu, güvenliği veya sistem istikrarını tehlikeye atabilecek yetkisiz veya kazara değişiklikleri önler.
2. **Sistem Yazılımı Güncellemeleri**: macOS güncellemeleri veya yükseltmeleri yüklediğinizde, macOS yeni bir sistem anlık görüntüsü oluşturur. macOS başlangıç hacmi, bu yeni anlık görüntüye geçmek için **APFS (Apple Dosya Sistemi)** kullanır. Güncellemeleri uygulama süreci, sistemin güncelleme sırasında bir şeyler ters giderse her zaman önceki anlık görüntüye geri dönebilmesi nedeniyle daha güvenli ve daha güvenilir hale gelir.
3. **Veri Ayrımı**: macOS Catalina'da tanıtılan Veri ve Sistem hacmi ayrımı kavramıyla birlikte, Mühürlü Sistem Anlık Görüntüsü özelliği, tüm verilerinizin ve ayarlarınızın ayrı bir "**Veri**" hacminde saklandığından emin olur. Bu ayrım, verilerinizi sistemden bağımsız hale getirir, bu da sistem güncellemeleri sürecini basitleştirir ve sistem güvenliğini artırır.

Bu anlık görüntülerin macOS tarafından otomatik olarak yönetildiğini ve APFS'nin alan paylaşım yetenekleri sayesinde diskinizde ek alan kaplamadığını unutmayın. Ayrıca, bu anlık görüntülerin, tüm sistemin kullanıcı erişimine açık yedekleri olan **Time Machine anlık görüntülerinden** farklı olduğunu belirtmek önemlidir.

### Anlık Görüntüleri Kontrol Et

**`diskutil apfs list`** komutu, **APFS hacimlerinin** ayrıntılarını ve düzenini listeler:

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-&#x3C; Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Physical Store Disk:   disk0s2
|   |   Size:                       494384795648 B (494.4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Volume Disk (Role):   disk3s1 (Sistem)
</strong>|   |   Name:                      Macintosh HD (Büyük/küçük harf duyarsız)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12.8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Yes (Açık)
|   |   Encrypted:                 No
|   |   |
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Yes
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Disk (Role):   disk3s5 (Veri)
|   Name:                      Macintosh HD - Veri (Büyük/küçük harf duyarsız)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412.1 GB)
</strong>    |   Sealed:                    No
|   FileVault:                 Yes (Açık)
</code></pre>

Önceki çıktıda, **kullanıcı erişimine açık konumların** `/System/Volumes/Data` altında monte edildiğini görebilirsiniz.

Ayrıca, **macOS Sistem hacmi anlık görüntüsü** `/` altında monte edilmiştir ve **mühürlüdür** (OS tarafından kriptografik olarak imzalanmıştır). Bu nedenle, SIP atlatılır ve değiştirilirse, **OS artık başlatılamaz**.

Mühürlemenin etkin olduğunu **doğrulamak** için de çalıştırmak mümkündür:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Ayrıca, anlık görüntü diski de **salt okunur** olarak monte edilmiştir:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
