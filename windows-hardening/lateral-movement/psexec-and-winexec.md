# PsExec/Winexec/ScExec

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **Bize katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya **bizi** **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Nasıl çalışırlar

Süreç, aşağıdaki adımlarda özetlenmiştir ve SMB üzerinden hedef makinede uzaktan yürütme sağlamak için hizmet ikili dosyalarının nasıl manipüle edildiğini göstermektedir:

1. **Bir hizmet ikili dosyasının ADMIN$ paylaşımına SMB üzerinden kopyalanması** gerçekleştirilir.
2. **Uzaktaki makinede bir hizmetin oluşturulması**, ikili dosyaya işaret edilerek yapılır.
3. Hizmet **uzaktan başlatılır**.
4. Çıkışta, hizmet **durdurulur ve ikili dosya silinir**.

### **PsExec'i Manuel Olarak Çalıştırma Süreci**

Antivirüs tespitinden kaçınmak için Veil kullanılarak obfuscate edilmiş, 'met8888.exe' adında bir yürütülebilir yük (msfvenom ile oluşturulmuş) olduğunu varsayalım; bu, bir meterpreter reverse_http yükünü temsil eder. Aşağıdaki adımlar izlenir:

* **İkili dosyanın kopyalanması**: Yürütülebilir dosya, bir komut istemcisinden ADMIN$ paylaşımına kopyalanır, ancak dosya sisteminde gizli kalmak için herhangi bir yere yerleştirilebilir.
* **Bir hizmet oluşturma**: Windows `sc` komutunu kullanarak, Windows hizmetlerini uzaktan sorgulama, oluşturma ve silme imkanı sağlayan bir hizmet "meterpreter" adıyla oluşturulur ve yüklenen ikili dosyaya işaret eder.
* **Hizmeti başlatma**: Son adım, hizmetin başlatılmasıdır; bu, ikili dosyanın gerçek bir hizmet ikili dosyası olmaması ve beklenen yanıt kodunu döndürmemesi nedeniyle muhtemelen bir "zaman aşımı" hatası ile sonuçlanacaktır. Bu hata önemsizdir çünkü asıl hedef ikili dosyanın yürütülmesidir.

Metasploit dinleyicisinin gözlemlenmesi, oturumun başarıyla başlatıldığını gösterecektir.

[`sc` komutu hakkında daha fazla bilgi edinin](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Daha ayrıntılı adımları burada bulabilirsiniz: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Windows Sysinternals ikili dosyası PsExec.exe'yi de kullanabilirsiniz:**

![](<../../.gitbook/assets/image (928).png>)

Ayrıca [**SharpLateral**](https://github.com/mertdas/SharpLateral) kullanabilirsiniz:

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
