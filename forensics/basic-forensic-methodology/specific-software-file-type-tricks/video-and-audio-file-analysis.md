{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'ı takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

**Ses ve video dosyası manipülasyonu**, **CTF adli bilişim zorlukları** için temel bir unsurdur ve gizli mesajları saklamak veya açığa çıkarmak için **steganografi** ve meta veri analizinden yararlanır. **[mediainfo](https://mediaarea.net/en/MediaInfo)** ve **`exiftool`** gibi araçlar, dosya meta verilerini incelemek ve içerik türlerini tanımlamak için gereklidir.

Ses zorlukları için, **[Audacity](http://www.audacityteam.org/)**, dalga formlarını görüntülemek ve ses spektrumlarını analiz etmek için öne çıkan bir araçtır ve ses içinde kodlanmış metinleri ortaya çıkarmak için gereklidir. **[Sonic Visualiser](http://www.sonicvisualiser.org/)**, detaylı spektrum analizi için şiddetle tavsiye edilir. **Audacity**, gizli mesajları tespit etmek için parçaları yavaşlatma veya tersine çevirme gibi ses manipülasyonlarına olanak tanır. **[Sox](http://sox.sourceforge.net/)**, ses dosyalarını dönüştürme ve düzenleme konusunda uzmanlaşmış bir komut satırı aracıdır.

**En Düşük Anlamlı Bitler (LSB)** manipülasyonu, ses ve video steganografisinde yaygın bir tekniktir ve medya dosyalarının sabit boyutlu parçalarını kullanarak verileri gizlice yerleştirir. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)**, **DTMF tonları** veya **Morse kodu** olarak gizlenmiş mesajları çözmek için faydalıdır.

Video zorlukları genellikle ses ve video akışlarını bir araya getiren konteyner formatlarını içerir. **[FFmpeg](http://ffmpeg.org/)**, bu formatları analiz etmek ve manipüle etmek için başvurulan araçtır ve içeriği ayırma ve oynatma yeteneğine sahiptir. Geliştiriciler için, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)**, FFmpeg'in yeteneklerini Python'a entegre ederek gelişmiş scriptable etkileşimler sağlar.

Bu araçlar dizisi, CTF zorluklarında gereken çok yönlülüğü vurgular; katılımcılar, ses ve video dosyalarında gizli verileri ortaya çıkarmak için geniş bir analiz ve manipülasyon tekniği yelpazesini kullanmalıdır.

## Referanslar
* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)


<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

**Mobil Güvenlik** alanındaki uzmanlığınızı 8kSec Akademisi ile derinleştirin. Kendi hızınıza uygun kurslarımızla iOS ve Android güvenliğini öğrenin ve sertifika alın:

{% embed url="https://academy.8ksec.io/" %}

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'ı takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
