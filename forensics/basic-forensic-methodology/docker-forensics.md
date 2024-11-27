# Docker Forensics

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

**Mobil Güvenlik** konusundaki uzmanlığınızı 8kSec Akademisi ile derinleştirin. Kendi hızınızda ilerleyerek iOS ve Android güvenliğini öğrenin ve sertifika alın:

{% embed url="https://academy.8ksec.io/" %}

## Konteyner değişikliği

Bazı docker konteynerlerinin tehlikeye atıldığına dair şüpheler var:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Bu konteynerdeki **görüntü ile ilgili yapılan değişiklikleri kolayca bulabilirsiniz**:
```bash
docker diff wordpress
C /var
C /var/lib
C /var/lib/mysql
A /var/lib/mysql/ib_logfile0
A /var/lib/mysql/ib_logfile1
A /var/lib/mysql/ibdata1
A /var/lib/mysql/mysql
A /var/lib/mysql/mysql/time_zone_leap_second.MYI
A /var/lib/mysql/mysql/general_log.CSV
...
```
Önceki komutta **C** **Değiştirildi** ve **A,** **Eklendi** anlamına gelir.\
Eğer `/etc/shadow` gibi ilginç bir dosyanın değiştirildiğini bulursanız, kötü niyetli etkinlikleri kontrol etmek için dosyayı konteynerden indirmek için:
```bash
docker cp wordpress:/etc/shadow.
```
Orijinal olanla **karşılaştırabilirsiniz** yeni bir konteyner çalıştırarak ve ondan dosyayı çıkararak:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Eğer **şüpheli bir dosyanın eklendiğini bulursanız** konteynıra erişip kontrol edebilirsiniz:
```bash
docker exec -it wordpress bash
```
## Görüntü değişiklikleri

Bir dışa aktarılmış docker görüntüsü (muhtemelen `.tar` formatında) verildiğinde, **değişikliklerin bir özetini çıkarmak için** [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) kullanabilirsiniz:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Sonra, görüntüyü **açabilir** ve şüpheli dosyaları değişiklik geçmişinde aramak için **bloblara** **erişebilirsiniz**:
```bash
tar -xf image.tar
```
### Temel Analiz

Görüntüden **temel bilgiler** alabilirsiniz:
```bash
docker inspect <image>
```
Aşağıdaki komutla **değişikliklerin geçmişi** hakkında bir özet alabilirsiniz:
```bash
docker history --no-trunc <image>
```
Bir görüntüden **dockerfile oluşturabilirsiniz**:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Docker görüntülerinde eklenmiş/değiştirilmiş dosyaları bulmak için [**dive**](https://github.com/wagoodman/dive) (bunu [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0) adresinden indirin) aracını da kullanabilirsiniz:
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Bu, **docker görüntülerinin farklı blob'ları arasında gezinmenizi** ve hangi dosyaların değiştirildiğini/eklendiğini kontrol etmenizi sağlar. **Kırmızı** eklenmiş anlamına gelir ve **sarı** değiştirilmiş anlamına gelir. Diğer görünüme geçmek için **tab** tuşunu kullanın ve klasörleri kapatmak/açmak için **space** tuşunu kullanın.

Die ile görüntünün farklı aşamalarının içeriğine erişemeyeceksiniz. Bunu yapmak için **her katmanı sıkıştırmanız ve erişmeniz** gerekecek.\
Görüntü sıkıştırıldığında, görüntüden tüm katmanları sıkıştırmak için şu dizinde çalıştırabilirsiniz:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Bellekten Kimlik Bilgileri

Bir docker konteynerini bir ana bilgisayar içinde çalıştırdığınızda **ana bilgisayardan konteynerde çalışan süreçleri görebileceğinizi** unutmayın, sadece `ps -ef` komutunu çalıştırarak.

Bu nedenle (root olarak) **ana bilgisayardan süreçlerin belleğini dökebilir** ve **kimlik bilgilerini** arayabilirsiniz, [**aşağıdaki örnekte olduğu gibi**](../../linux-hardening/privilege-escalation/#process-memory).

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

**Mobil Güvenlik** konusundaki uzmanlığınızı 8kSec Akademisi ile derinleştirin. Kendi hızınıza uygun kurslarımızla iOS ve Android güvenliğini öğrenin ve sertifika kazanın:

{% embed url="https://academy.8ksec.io/" %}

{% hint style="success" %}
AWS Hacking'i öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'ı takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
