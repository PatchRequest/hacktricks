# macOS Güvenlik Koruma Önlemleri

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Ekip Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Ekip Uzmanı (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

## Gatekeeper

Gatekeeper genellikle **Quarantine + Gatekeeper + XProtect** kombinasyonunu ifade etmek için kullanılır; bu, kullanıcıların **potansiyel olarak zararlı yazılımları çalıştırmalarını engellemeye çalışan** 3 macOS güvenlik modülüdür.

Daha fazla bilgi için:

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## Süreç Sınırlamaları

### MACF



### SIP - Sistem Bütünlüğü Koruması

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Sandbox

MacOS Sandbox, uygulamaların sandbox içinde yalnızca **uygulamanın çalıştığı Sandbox profilinde belirtilen izin verilen eylemlerle** sınırlı olmasını sağlar. Bu, **uygulamanın yalnızca beklenen kaynaklara erişmesini** sağlamaya yardımcı olur.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Şeffaflık, Onay ve Kontrol**

**TCC (Şeffaflık, Onay ve Kontrol)** bir güvenlik çerçevesidir. Uygulamaların **izinlerini yönetmek** için tasarlanmıştır, özellikle de hassas özelliklere erişimlerini düzenleyerek. Bu, **konum hizmetleri, kişiler, fotoğraflar, mikrofon, kamera, erişilebilirlik ve tam disk erişimi** gibi unsurları içerir. TCC, uygulamaların bu özelliklere yalnızca açık kullanıcı onayı aldıktan sonra erişebileceğini garanti ederek, kişisel veriler üzerindeki gizliliği ve kontrolü artırır.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### Başlatma/Ortam Kısıtlamaları ve Güven Kapsayıcı

macOS'taki başlatma kısıtlamaları, bir sürecin **başlatılmasını düzenlemek** için bir güvenlik özelliğidir; **kimin** bir süreci başlatabileceğini, **nasıl** ve **nereden** tanımlar. macOS Ventura'da tanıtılan bu özellikler, sistem ikili dosyalarını bir **güven kapsayıcısı** içinde kısıtlama kategorilerine ayırır. Her yürütülebilir ikili dosya, **başlatma** için belirli **kurallara** sahiptir; bunlar arasında **kendisi**, **ebeveyn** ve **sorumlu** kısıtlamaları bulunur. Üçüncü taraf uygulamalara **Ortam** Kısıtlamaları olarak genişletilen bu özellikler, süreç başlatma koşullarını yöneterek potansiyel sistem istismarlarını azaltmaya yardımcı olur.

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - Kötü Amaçlı Yazılım Kaldırma Aracı

Kötü Amaçlı Yazılım Kaldırma Aracı (MRT), macOS'un güvenlik altyapısının bir parçasıdır. Adından da anlaşılacağı gibi, MRT'nin ana işlevi **bilinen kötü amaçlı yazılımları enfekte olmuş sistemlerden kaldırmaktır**.

Bir Mac'te kötü amaçlı yazılım tespit edildiğinde (ya XProtect ya da başka bir yöntemle), MRT otomatik olarak **kötü amaçlı yazılımı kaldırmak için** kullanılabilir. MRT, arka planda sessizce çalışır ve genellikle sistem güncellendiğinde veya yeni bir kötü amaçlı yazılım tanımı indirildiğinde çalışır (MRT'nin kötü amaçlı yazılımları tespit etme kurallarının ikili dosyanın içinde olduğu görünmektedir).

Hem XProtect hem de MRT, macOS'un güvenlik önlemlerinin bir parçası olmasına rağmen, farklı işlevler yerine getirir:

* **XProtect**, önleyici bir araçtır. Dosyalar **indirildiğinde** (belirli uygulamalar aracılığıyla) kontrol eder ve bilinen kötü amaçlı yazılım türlerinden herhangi birini tespit ederse, dosyanın açılmasını **engeller**, böylece kötü amaçlı yazılımın sisteminizi enfekte etmesini önler.
* **MRT** ise **reaktif bir araçtır**. Kötü amaçlı yazılım bir sistemde tespit edildikten sonra çalışır ve amacı, sistemin temizlenmesi için zararlı yazılımı kaldırmaktır.

MRT uygulaması **`/Library/Apple/System/Library/CoreServices/MRT.app`** konumundadır.

## Arka Plan Görevleri Yönetimi

**macOS**, artık bir aracın **kod yürütmesini sürdürmek için bilinen bir tekniği** kullandığında her seferinde **kullanıcıyı uyarır** (örneğin Giriş Öğeleri, Daemon'lar...), böylece kullanıcı **hangi yazılımın sürdüğünü** daha iyi bilir.

<figure><img src="../../../.gitbook/assets/image (1183).png" alt=""><figcaption></figcaption></figure>

Bu, `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` konumundaki bir **daemon** ile çalışır ve **ajan** `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app` konumundadır.

**`backgroundtaskmanagementd`**'nin bir şeyin kalıcı bir klasöre kurulu olduğunu bilme şekli, **FSEvents** alarak ve bunlar için bazı **işleyiciler** oluşturarak gerçekleşir.

Ayrıca, sıkça kalıcı olan **bilinen uygulamaları** içeren bir plist dosyası vardır; bu dosya Apple tarafından yönetilir ve `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist` konumundadır.
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### Enumeration

Apple cli aracını kullanarak **tüm** yapılandırılmış arka plan öğelerini listelemek mümkündür:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Ayrıca, bu bilgiyi [**DumpBTM**](https://github.com/objective-see/DumpBTM) ile listelemek de mümkündür.
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Bu bilgi **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** içinde saklanmaktadır ve Terminal FDA gerektirir.

### BTM ile Oynama

Yeni bir kalıcılık bulunduğunda **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** türünde bir olay meydana gelir. Bu nedenle, bu **olayın** gönderilmesini **önlemenin** veya **ajanın kullanıcıyı uyarmasını** engellemenin herhangi bir yolu, bir saldırgana BTM'yi _**bypass**_ etmesine yardımcı olacaktır.

* **Veritabanını sıfırlama**: Aşağıdaki komut veritabanını sıfırlayacaktır (temelden yeniden inşa edilmesi gerekir), ancak bir nedenle, bunu çalıştırdıktan sonra **sistemi yeniden başlatana kadar yeni bir kalıcılık uyarısı yapılmayacaktır**.
* **root** gereklidir.
```bash
# Reset the database
sfltool resettbtm
```
* **Ajansı Durdur**: Yeni tespitler bulunduğunda kullanıcının **uyarılmaması** için ajansa bir durdurma sinyali göndermek mümkündür.
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
* **Hata**: Eğer **kalıcılığı oluşturan süreç hemen ardından hızlıca mevcutsa**, daemon **hakkında bilgi almaya çalışacak**, **başarısız olacak** ve **yeni bir şeyin kalıcı olduğunu belirten olayı gönderemeyecek**.

BTM hakkında **daha fazla bilgi**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

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
