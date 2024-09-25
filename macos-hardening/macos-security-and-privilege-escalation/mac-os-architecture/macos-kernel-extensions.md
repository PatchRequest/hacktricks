# macOS Kernel Extensions

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

## Basic Information

Kernel uzantıları (Kexts), **macOS çekirdek alanına doğrudan yüklenen** ve ana işletim sistemine ek işlevsellik sağlayan **`.kext`** uzantısına sahip **paketlerdir**.

### Requirements

Açıkça, bu kadar güçlü olduğu için **bir çekirdek uzantısını yüklemek karmaşıktır**. Bir çekirdek uzantısının yüklenebilmesi için karşılaması gereken **gereksinimler** şunlardır:

* **Kurtarma moduna** girerken, çekirdek **uzantılarının yüklenmesine izin verilmelidir**:

<figure><img src="../../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

* Çekirdek uzantısı, yalnızca **Apple tarafından verilebilen** bir çekirdek kod imzalama sertifikası ile **imzalanmış olmalıdır**. Şirketin detaylı bir şekilde gözden geçireceği ve neden gerektiği.
* Çekirdek uzantısı ayrıca **notarize** edilmelidir, Apple bunu kötü amaçlı yazılım için kontrol edebilecektir.
* Ardından, **root** kullanıcısı **çekirdek uzantısını yükleyebilen** kişidir ve paket içindeki dosyalar **root'a ait olmalıdır**.
* Yükleme sürecinde, paket **korumalı bir kök olmayan konumda** hazırlanmalıdır: `/Library/StagedExtensions` (bu, `com.apple.rootless.storage.KernelExtensionManagement` iznini gerektirir).
* Son olarak, yüklemeye çalışırken, kullanıcı [**bir onay isteği alacaktır**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) ve kabul edilirse, bilgisayar **yeniden başlatılmalıdır**.

### Loading process

Catalina'da böyleydi: **Doğrulama** sürecinin **kullanıcı alanında** gerçekleştiğini belirtmek ilginçtir. Ancak, yalnızca **`com.apple.private.security.kext-management`** iznine sahip uygulamalar **çekirdekten bir uzantı yüklemesini isteyebilir**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **bir uzantının yüklenmesi için doğrulama** sürecini **başlatır**
* **`kextd`** ile bir **Mach servisi** kullanarak iletişim kuracaktır.
2. **`kextd`** birkaç şeyi kontrol edecektir, örneğin **imzayı**
* Uzantının **yüklenip yüklenemeyeceğini kontrol etmek için** **`syspolicyd`** ile iletişim kuracaktır.
3. **`syspolicyd`**, uzantı daha önce yüklenmemişse **kullanıcıya** **soracaktır**.
* **`syspolicyd`**, sonucu **`kextd`**'ye bildirecektir.
4. **`kextd`** nihayet **çekirdeğe uzantıyı yüklemesini** **söyleyebilecektir**.

Eğer **`kextd`** mevcut değilse, **`kextutil`** aynı kontrolleri gerçekleştirebilir.

### Enumeration (loaded kexts)
```bash
# Get loaded kernel extensions
kextstat

# Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
## Kernelcache

{% hint style="danger" %}
Kernel uzantılarının `/System/Library/Extensions/` içinde bulunması beklenmesine rağmen, bu klasöre giderseniz **hiçbir ikili dosya bulamayacaksınız**. Bunun nedeni **kernelcache**'dir ve bir `.kext` dosyasını tersine mühendislik yapmak için onu elde etmenin bir yolunu bulmanız gerekir.
{% endhint %}

**Kernelcache**, **XNU çekirdeğinin önceden derlenmiş ve önceden bağlantılı bir versiyonu** ile birlikte temel cihaz **sürücüleri** ve **kernel uzantıları** içerir. **Sıkıştırılmış** bir formatta depolanır ve önyükleme süreci sırasında belleğe açılır. Kernelcache, çekirdeğin ve kritik sürücülerin çalışmaya hazır bir versiyonunu bulundurarak **daha hızlı bir önyükleme süresi** sağlar; bu, bu bileşenlerin dinamik olarak yüklenmesi ve bağlantı kurulması için harcanacak zaman ve kaynakları azaltır.

### Yerel Kernelcache

iOS'ta **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** içinde bulunur, macOS'ta ise şu komutla bulabilirsiniz: **`find / -name "kernelcache" 2>/dev/null`** \
Benim durumumda macOS'ta şurada buldum:

* `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

IMG4 dosya formatı, Apple tarafından iOS ve macOS cihazlarında **firmware** bileşenlerini güvenli bir şekilde **saklamak ve doğrulamak** için kullanılan bir konteyner formatıdır (örneğin **kernelcache**). IMG4 formatı, gerçek yük (örneğin bir çekirdek veya önyükleyici), bir imza ve bir dizi manifest özelliklerini kapsayan bir başlık ve birkaç etiket içerir. Format, cihazın firmware bileşeninin özgünlüğünü ve bütünlüğünü doğrulamasına olanak tanıyan kriptografik doğrulamayı destekler.

Genellikle aşağıdaki bileşenlerden oluşur:

* **Payload (IM4P)**:
* Genellikle sıkıştırılmıştır (LZFSE4, LZSS, …)
* İsteğe bağlı olarak şifrelenmiş
* **Manifest (IM4M)**:
* İmza içerir
* Ek Anahtar/Değer sözlüğü
* **Restore Info (IM4R)**:
* APNonce olarak da bilinir
* Bazı güncellemelerin tekrar oynatılmasını engeller
* İSTEĞE BAĞLI: Genellikle bulunmaz

Kernelcache'i açın:
```bash
# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### İndir

* [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

[https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) adresinde tüm kernel hata ayıklama kitlerini bulmak mümkündür. Bunu indirebilir, bağlayabilir, [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html) aracıyla açabilir, **`.kext`** klasörüne erişebilir ve **çıkarabilirsiniz**.

Semboller için kontrol edin:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
* [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Bazen Apple **kernelcache** ile **semboller** yayınlar. Bu sayfalardaki bağlantıları takip ederek sembollü bazı firmware'leri indirebilirsiniz. Firmware'ler diğer dosyaların yanı sıra **kernelcache** içerecektir.

Dosyaları **çıkarmak** için uzantıyı `.ipsw`'den `.zip`'e değiştirin ve **açın**.

Firmware'i çıkardıktan sonra **`kernelcache.release.iphone14`** gibi bir dosya elde edeceksiniz. Bu **IMG4** formatındadır, ilginç bilgileri çıkarmak için:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**

{% code overflow="wrap" %}
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
{% endcode %}

[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Kernelcache'i İnceleme

Kernelcache'in sembollerinin olup olmadığını kontrol et
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
Bununla artık **tüm uzantıları** veya **ilginizi çeken uzantıyı** **çıkarabiliriz:**
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## Referanslar

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
