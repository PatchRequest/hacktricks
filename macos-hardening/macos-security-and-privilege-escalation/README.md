# macOS Güvenliği ve Yetki Yükseltme

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Ekip Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Ekip Uzmanı (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** bizi takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Deneyimli hackerlar ve bug bounty avcıları ile iletişim kurmak için [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) sunucusuna katılın!

**Hacking İçgörüleri**\
Hacking'in heyecanı ve zorluklarına dalan içeriklerle etkileşimde bulunun

**Gerçek Zamanlı Hack Haberleri**\
Hızla değişen hacking dünyasında gerçek zamanlı haberler ve içgörülerle güncel kalın

**Son Duyurular**\
Yeni başlayan bug bounty'ler ve kritik platform güncellemeleri hakkında bilgi sahibi olun

**Bize katılın** [**Discord**](https://discord.com/invite/N3FrSbmwdy) ve bugün en iyi hackerlarla işbirliği yapmaya başlayın!

## Temel MacOS

Eğer macOS ile tanışık değilseniz, macOS'un temellerini öğrenmeye başlamalısınız:

* Özel macOS **dosyaları ve izinleri:**

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* Yaygın macOS **kullanıcıları**

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* **kernel** mimarisi

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Yaygın macOS **ağ hizmetleri ve protokolleri**

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **Açık kaynak** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
* `tar.gz` indirmek için bir URL'yi [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) gibi [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) olarak değiştirin

### MacOS MDM

Şirketlerde **macOS** sistemlerinin büyük olasılıkla **bir MDM ile yönetileceği** düşünülmektedir. Bu nedenle, bir saldırgan açısından **nasıl çalıştığını** bilmek ilginçtir:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - İnceleme, Hata Ayıklama ve Fuzzing

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## MacOS Güvenlik Koruma Önlemleri

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Saldırı Yüzeyi

### Dosya İzinleri

Eğer bir **root olarak çalışan bir süreç** bir dosya yazıyorsa ve bu dosya bir kullanıcı tarafından kontrol edilebiliyorsa, kullanıcı bunu **yetkileri yükseltmek için** kötüye kullanabilir.\
Bu aşağıdaki durumlarda gerçekleşebilir:

* Kullanıcı tarafından zaten oluşturulmuş bir dosya kullanıldı (kullanıcıya ait)
* Kullanıcı tarafından bir grup nedeniyle yazılabilir bir dosya kullanıldı
* Kullanıcı tarafından oluşturulabilecek bir dosya, kullanıcının sahibi olduğu bir dizin içinde
* Kullanıcı tarafından oluşturulabilecek bir dosya, root'un sahibi olduğu bir dizin içinde ancak kullanıcı bir grup nedeniyle buna yazma erişimine sahip

**root** tarafından **kullanılacak bir dosya** oluşturabilmek, bir kullanıcının **içeriğinden faydalanmasına** veya hatta başka bir yere işaret etmek için **sembolik/sert bağlantılar** oluşturmasına olanak tanır.

Bu tür güvenlik açıkları için **kırılgan `.pkg` yükleyicilerini kontrol etmeyi** unutmayın:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}

### Dosya Uzantısı ve URL şeması uygulama işleyicileri

Dosya uzantılarıyla kaydedilen garip uygulamalar kötüye kullanılabilir ve farklı uygulamalar belirli protokolleri açmak için kaydedilebilir

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## macOS TCC / SIP Yetki Yükseltme

macOS'ta **uygulamalar ve ikili dosyalar**, diğerlerinden daha ayrıcalıklı olmalarını sağlayan klasörlere veya ayarlara erişim iznine sahip olabilir.

Bu nedenle, bir macOS makinesini başarılı bir şekilde tehlikeye atmak isteyen bir saldırgan, **TCC ayrıcalıklarını yükseltmek** (veya ihtiyaçlarına bağlı olarak **SIP'yi atlamak**) zorundadır.

Bu ayrıcalıklar genellikle uygulamanın imzalandığı **yetkilendirmeler** şeklinde verilir veya uygulama bazı erişimler talep edebilir ve **kullanıcı onayladıktan** sonra **TCC veritabanlarında** bulunabilir. Bir sürecin bu ayrıcalıkları elde etmenin bir diğer yolu, bu **ayrıcalıklara** sahip bir sürecin **çocuğu** olmaktır, çünkü genellikle **miras alınırlar**.

Farklı yolları bulmak için bu bağlantılara göz atın [**TCC'de yetki yükseltme**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), [**TCC'yi atlamak**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) ve geçmişte [**SIP'nin nasıl aşıldığı**](macos-security-protections/macos-sip.md#sip-bypasses).

## macOS Geleneksel Yetki Yükseltme

Elbette bir kırmızı ekip perspektifinden root'a yükseltme ile de ilgilenmelisiniz. Bazı ipuçları için aşağıdaki gönderiyi kontrol edin:

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}

## macOS Uyum

* [https://github.com/usnistgov/macos\_security](https://github.com/usnistgov/macos\_security)

## Referanslar

* [**OS X Olay Yanıtı: Betik ve Analiz**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="/.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Deneyimli hackerlar ve bug bounty avcıları ile iletişim kurmak için [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) sunucusuna katılın!

**Hacking İçgörüleri**\
Hacking'in heyecanı ve zorluklarına dalan içeriklerle etkileşimde bulunun

**Gerçek Zamanlı Hack Haberleri**\
Hızla değişen hacking dünyasında gerçek zamanlı haberler ve içgörülerle güncel kalın

**Son Duyurular**\
Yeni başlayan bug bounty'ler ve kritik platform güncellemeleri hakkında bilgi sahibi olun

**Bize katılın** [**Discord**](https://discord.com/invite/N3FrSbmwdy) ve bugün en iyi hackerlarla işbirliği yapmaya başlayın!

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Ekip Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Ekip Uzmanı (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** bizi takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
