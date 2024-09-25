# macOS Kernel & System Extensions

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'ı takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

## XNU Kernel

macOS'un **temeli XNU'dur**, bu "X is Not Unix" anlamına gelir. Bu kernel esasen **Mach mikro çekirdeği** (daha sonra tartışılacak) ve **Berkeley Yazılım Dağıtımı** (**BSD**) unsurlarından oluşur. XNU ayrıca **I/O Kit adı verilen bir sistem aracılığıyla kernel sürücüleri için bir platform sağlar**. XNU çekirdeği, **kaynak kodu serbestçe erişilebilir** olan Darwin açık kaynak projesinin bir parçasıdır.

Bir güvenlik araştırmacısı veya Unix geliştiricisi perspektifinden, **macOS** oldukça **benzer** bir **FreeBSD** sistemi gibi görünebilir; şık bir GUI ve birçok özel uygulama ile. BSD için geliştirilen çoğu uygulama, Unix kullanıcılarına aşina olan komut satırı araçları macOS'ta mevcut olduğundan, macOS'ta derlenip çalıştırılabilir. Ancak, XNU çekirdeği Mach'ı içerdiğinden, geleneksel bir Unix benzeri sistem ile macOS arasında bazı önemli farklılıklar vardır ve bu farklılıklar potansiyel sorunlara neden olabilir veya benzersiz avantajlar sağlayabilir.

XNU'nun açık kaynak versiyonu: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach, **UNIX uyumlu** olacak şekilde tasarlanmış bir **mikro çekirdek**'tir. Ana tasarım ilkelerinden biri, **çekirdek** alanında çalışan **kod** miktarını **minimize etmek** ve bunun yerine dosya sistemi, ağ ve I/O gibi birçok tipik çekirdek işlevinin **kullanıcı düzeyinde görevler olarak çalışmasına** izin vermekti.

XNU'da, Mach, bir çekirdeğin tipik olarak ele aldığı birçok kritik düşük seviyeli işlemin **sorumlusudur**, örneğin işlemci zamanlaması, çoklu görev ve sanal bellek yönetimi.

### BSD

XNU **çekirdeği**, **FreeBSD** projesinden türetilmiş önemli miktarda kodu da **içermektedir**. Bu kod, Mach ile birlikte aynı adres alanında **çekirdek parçası olarak çalışır**. Ancak, XNU içindeki FreeBSD kodu, Mach ile uyumluluğunu sağlamak için gerekli değişiklikler yapıldığından, orijinal FreeBSD kodundan önemli ölçüde farklı olabilir. FreeBSD, aşağıdaki gibi birçok çekirdek işlemi için katkıda bulunur:

* Süreç yönetimi
* Sinyal işleme
* Kullanıcı ve grup yönetimi de dahil olmak üzere temel güvenlik mekanizmaları
* Sistem çağrısı altyapısı
* TCP/IP yığını ve soketler
* Güvenlik duvarı ve paket filtreleme

BSD ve Mach arasındaki etkileşimi anlamak karmaşık olabilir, çünkü farklı kavramsal çerçevelere sahiptirler. Örneğin, BSD, temel yürütme birimi olarak süreçleri kullanırken, Mach, iş parçacıkları temelinde çalışır. Bu tutarsızlık, XNU'da **her BSD sürecini tam olarak bir Mach iş parçacığı içeren bir Mach görevi ile ilişkilendirerek** uzlaştırılır. BSD'nin fork() sistem çağrısı kullanıldığında, çekirdek içindeki BSD kodu, bir görev ve bir iş parçacığı yapısı oluşturmak için Mach işlevlerini kullanır.

Ayrıca, **Mach ve BSD her biri farklı güvenlik modellerini sürdürmektedir**: **Mach'ın** güvenlik modeli **port haklarına** dayanırken, BSD'nin güvenlik modeli **süreç sahipliğine** dayanır. Bu iki model arasındaki farklılıklar zaman zaman yerel ayrıcalık yükseltme güvenlik açıklarına neden olmuştur. Tipik sistem çağrılarının yanı sıra, **kullanıcı alanı programlarının çekirdek ile etkileşimde bulunmasına izin veren Mach tuzakları da vardır**. Bu farklı unsurlar bir araya gelerek macOS çekirdeğinin çok yönlü, hibrit mimarisini oluşturur.

### I/O Kit - Sürücüler

I/O Kit, XNU çekirdeğinde **dinamik olarak yüklenen cihaz sürücülerini** yöneten açık kaynaklı, nesne yönelimli bir **cihaz sürücü çerçevesidir**. Farklı donanımları destekleyerek çekirdeğe modüler kod eklenmesine olanak tanır.

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - Süreçler Arası İletişim

{% content-ref url="../macos-proces-abuse/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../macos-proces-abuse/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

## macOS Kernel Extensions

macOS, kodun yüksek ayrıcalıklarla çalışacağı için **Kernel Extensions** (.kext) yüklemeye **son derece kısıtlayıcıdır**. Aslında, varsayılan olarak neredeyse imkansızdır (bir bypass bulunmadıkça).

Aşağıdaki sayfada, macOS'un **kernelcache** içinde yüklediği `.kext`'i nasıl geri alacağınızı da görebilirsiniz:

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### macOS System Extensions

Kernel Extensions kullanmak yerine, macOS, çekirdek ile etkileşimde bulunmak için kullanıcı düzeyinde API'ler sunan System Extensions'ı oluşturmuştur. Bu şekilde, geliştiriciler kernel extensions kullanmaktan kaçınabilirler.

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## Referanslar

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'ı takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
