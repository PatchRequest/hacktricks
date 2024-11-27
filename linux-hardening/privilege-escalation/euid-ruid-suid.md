# euid, ruid, suid

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

**Mobil Güvenlik** alanındaki uzmanlığınızı 8kSec Akademisi ile derinleştirin. Kendi hızınıza uygun kurslarımızla iOS ve Android güvenliğini öğrenin ve sertifika kazanın:

{% embed url="https://academy.8ksec.io/" %}


### Kullanıcı Tanımlama Değişkenleri

- **`ruid`**: **gerçek kullanıcı kimliği**, süreci başlatan kullanıcıyı belirtir.
- **`euid`**: **etkili kullanıcı kimliği** olarak bilinir, sistemin süreç ayrıcalıklarını belirlemek için kullandığı kullanıcı kimliğini temsil eder. Genel olarak, `euid` `ruid` ile aynıdır, SetUID ikili yürütme gibi durumlar dışında, burada `euid` dosya sahibinin kimliğini alır ve böylece belirli operasyonel izinler verir.
- **`suid`**: Bu **kaydedilmiş kullanıcı kimliği**, yüksek ayrıcalıklı bir sürecin (genellikle root olarak çalışan) belirli görevleri yerine getirmek için geçici olarak ayrıcalıklarını bırakması gerektiğinde kritik öneme sahiptir, daha sonra başlangıçtaki yükseltilmiş durumunu geri alır.

#### Önemli Not
Root altında çalışmayan bir süreç yalnızca `euid`'sini mevcut `ruid`, `euid` veya `suid` ile eşleştirebilir.

### set*uid Fonksiyonlarını Anlamak

- **`setuid`**: İlk varsayımların aksine, `setuid` esasen `ruid` yerine `euid`'yi değiştirir. Özellikle ayrıcalıklı süreçler için, `ruid`, `euid` ve `suid`'yi belirtilen kullanıcı ile, genellikle root ile eşleştirir ve bu ID'leri `suid`'nin geçersiz kılması nedeniyle sağlamlaştırır. Ayrıntılı bilgiler [setuid man sayfasında](https://man7.org/linux/man-pages/man2/setuid.2.html) bulunabilir.
- **`setreuid`** ve **`setresuid`**: Bu fonksiyonlar `ruid`, `euid` ve `suid`'nin ince ayarını yapmaya olanak tanır. Ancak, yetenekleri sürecin ayrıcalık seviyesine bağlıdır. Root olmayan süreçler için değişiklikler mevcut `ruid`, `euid` ve `suid` değerleri ile sınırlıdır. Buna karşın, root süreçleri veya `CAP_SETUID` yeteneğine sahip olanlar bu ID'lere keyfi değerler atayabilir. Daha fazla bilgi [setresuid man sayfasında](https://man7.org/linux/man-pages/man2/setresuid.2.html) ve [setreuid man sayfasında](https://man7.org/linux/man-pages/man2/setreuid.2.html) bulunabilir.

Bu işlevler, bir güvenlik mekanizması olarak değil, bir programın etkili kullanıcı kimliğini değiştirerek başka bir kullanıcının kimliğini benimsemesi gibi istenen operasyonel akışı kolaylaştırmak için tasarlanmıştır.

Özellikle, `setuid` root'a ayrıcalık yükseltmek için yaygın bir yöntem olabilir (çünkü tüm ID'leri root ile eşleştirir), ancak bu fonksiyonlar arasındaki farkları ayırt etmek, farklı senaryolarda kullanıcı ID davranışlarını anlamak ve manipüle etmek için kritik öneme sahiptir.

### Linux'ta Program Yürütme Mekanizmaları

#### **`execve` Sistem Çağrısı**
- **Fonksiyon**: `execve`, ilk argümanla belirlenen bir programı başlatır. İki dizi argümanı alır, `argv` argümanlar için ve `envp` ortam için.
- **Davranış**: Çağıranın bellek alanını korur ancak yığın, yığın ve veri segmentlerini yeniler. Programın kodu yeni programla değiştirilir.
- **Kullanıcı Kimliği Koruma**:
- `ruid`, `euid` ve ek grup kimlikleri değişmeden kalır.
- Yeni program SetUID bitine sahipse `euid`'de ince değişiklikler olabilir.
- `suid`, yürütme sonrası `euid`'den güncellenir.
- **Dokümantasyon**: Ayrıntılı bilgi [`execve` man sayfasında](https://man7.org/linux/man-pages/man2/execve.2.html) bulunabilir.

#### **`system` Fonksiyonu**
- **Fonksiyon**: `execve`'nin aksine, `system` bir çocuk süreç oluşturur ve o çocuk süreç içinde bir komutu yürütür.
- **Komut Yürütme**: Komutu `sh` aracılığıyla `execl("/bin/sh", "sh", "-c", command, (char *) NULL);` ile yürütür.
- **Davranış**: `execl`, `execve`'nin bir biçimi olduğundan benzer şekilde çalışır ancak yeni bir çocuk sürecin bağlamında.
- **Dokümantasyon**: Daha fazla bilgi [`system` man sayfasında](https://man7.org/linux/man-pages/man3/system.3.html) bulunabilir.

#### **SUID ile `bash` ve `sh` Davranışı**
- **`bash`**:
- `euid` ve `ruid`'nin nasıl ele alındığını etkileyen bir `-p` seçeneğine sahiptir.
- `-p` olmadan, `bash` `euid`'yi `ruid` ile eşleştirir eğer başlangıçta farklılarsa.
- `-p` ile, başlangıçtaki `euid` korunur.
- Daha fazla ayrıntı [`bash` man sayfasında](https://linux.die.net/man/1/bash) bulunabilir.
- **`sh`**:
- `bash`'deki `-p` benzeri bir mekanizmaya sahip değildir.
- Kullanıcı kimlikleri ile ilgili davranış açıkça belirtilmemiştir, yalnızca `-i` seçeneği altında `euid` ve `ruid` eşitliğinin korunmasına vurgu yapılmaktadır.
- Ek bilgi [`sh` man sayfasında](https://man7.org/linux/man-pages/man1/sh.1p.html) bulunabilir.

Bu mekanizmalar, işleyişlerinde farklılık göstererek programları yürütmek ve geçiş yapmak için çok çeşitli seçenekler sunar, kullanıcı kimliklerinin nasıl yönetildiği ve korunduğu konusunda belirli nüanslarla birlikte.

### Yürütmelerde Kullanıcı ID Davranışlarını Test Etme

Örnekler https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail adresinden alınmıştır, daha fazla bilgi için kontrol edin.

#### Durum 1: `setuid` ile `system` Kullanımı

**Amaç**: `setuid`'nin `system` ve `bash` ile birlikte etkisini anlamak.

**C Kodu**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
system("id");
return 0;
}
```
**Derleme ve İzinler:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiz:**

* `ruid` ve `euid` başlangıçta sırasıyla 99 (nobody) ve 1000 (frank) olarak ayarlanır.
* `setuid` her ikisini de 1000'e ayarlar.
* `system`, sh'den bash'e olan symlink nedeniyle `/bin/bash -c id` komutunu çalıştırır.
* `bash`, `-p` olmadan, `euid`'yi `ruid` ile eşleştirir, bu da her ikisinin de 99 (nobody) olmasına neden olur.

#### Durum 2: system ile setreuid kullanma

**C Kodu**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setreuid(1000, 1000);
system("id");
return 0;
}
```
**Derleme ve İzinler:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**İcra ve Sonuç:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiz:**

* `setreuid`, hem ruid hem de euid'yi 1000 olarak ayarlar.
* `system`, kullanıcı kimliklerinin eşitliği nedeniyle bash'i çağırır ve bu da frank olarak etkili bir şekilde çalışır.

#### Durum 3: execve ile setuid kullanımı
Amaç: setuid ve execve arasındaki etkileşimi keşfetmek.
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/usr/bin/id", NULL, NULL);
return 0;
}
```
**İcra ve Sonuç:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiz:**

* `ruid` 99 olarak kalır, ancak euid 1000 olarak ayarlanır, setuid'nin etkisiyle uyumlu olarak.

**C Kod Örneği 2 (Bash Çağrısı):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/bin/bash", NULL, NULL);
return 0;
}
```
**İcra ve Sonuç:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiz:**

* `euid` `setuid` ile 1000 olarak ayarlandığında, `bash` `-p` eksikliği nedeniyle `euid`'yi `ruid` (99) olarak sıfırlar.

**C Kodu Örneği 3 (bash -p Kullanarak):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
setuid(1000);
execve(paramList[0], paramList, NULL);
return 0;
}
```
**İcra ve Sonuç:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## Referanslar
* [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

**Mobil Güvenlik** konusundaki uzmanlığınızı 8kSec Akademisi ile derinleştirin. Kendi hızınızda ilerleyerek iOS ve Android güvenliğini öğrenin ve sertifika kazanın:

{% embed url="https://academy.8ksec.io/" %}


{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
