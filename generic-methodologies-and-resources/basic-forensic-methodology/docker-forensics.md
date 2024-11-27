# Docker Forensics

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Deepen your expertise in **Mobile Security** with 8kSec Academy. Master iOS and Android security through our self-paced courses and get certified:

{% embed url="https://academy.8ksec.io/" %}

## Container modification

कुछ डॉकर कंटेनर के समझौता होने के संदेह हैं:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
आप आसानी से **इस कंटेनर में इमेज के संबंध में किए गए संशोधनों को ढूंढ सकते हैं**:
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
In the previous command **C** का मतलब **Changed** और **A,** **Added** है।\
यदि आप पाते हैं कि कुछ दिलचस्प फ़ाइल जैसे `/etc/shadow` को संशोधित किया गया है, तो आप इसे कंटेनर से डाउनलोड कर सकते हैं ताकि आप दुर्भावनापूर्ण गतिविधि की जांच कर सकें:
```bash
docker cp wordpress:/etc/shadow.
```
आप इसे **मूल के साथ तुलना कर सकते हैं** एक नया कंटेनर चलाकर और उससे फ़ाइल निकालकर:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
यदि आप पाते हैं कि **कुछ संदिग्ध फ़ाइल जोड़ी गई थी** तो आप कंटेनर में प्रवेश कर सकते हैं और इसे जांच सकते हैं:
```bash
docker exec -it wordpress bash
```
## Images modifications

जब आपको एक निर्यातित डॉकर इमेज (संभवतः `.tar` प्रारूप में) दी जाती है, तो आप [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) का उपयोग करके **संशोधनों का एक सारांश निकाल सकते हैं**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
फिर, आप **decompress** कर सकते हैं छवि को और **access the blobs** कर सकते हैं संदिग्ध फ़ाइलों की खोज करने के लिए जो आपने परिवर्तनों के इतिहास में पाई हो सकती हैं:
```bash
tar -xf image.tar
```
### Basic Analysis

आप छवि से **बुनियादी जानकारी** प्राप्त कर सकते हैं:
```bash
docker inspect <image>
```
आप **परिवर्तनों का इतिहास** का सारांश भी प्राप्त कर सकते हैं:
```bash
docker history --no-trunc <image>
```
आप एक **छवि से dockerfile** भी उत्पन्न कर सकते हैं:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

डॉकर इमेज में जोड़े गए/संशोधित फ़ाइलों को खोजने के लिए आप [**dive**](https://github.com/wagoodman/dive) (इसे [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0) से डाउनलोड करें) उपयोगिता का भी उपयोग कर सकते हैं:
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
यह आपको **डॉकर इमेज के विभिन्न ब्लॉब्स के माध्यम से नेविगेट करने** और यह जांचने की अनुमति देता है कि कौन से फ़ाइलें संशोधित/जोड़ी गई थीं। **लाल** का मतलब जोड़ा गया है और **पीला** का मतलब संशोधित है। **टैब** का उपयोग करके अन्य दृश्य पर जाएं और फ़ोल्डरों को संकुचित/खोलने के लिए **स्पेस** का उपयोग करें।

डाई के साथ, आप इमेज के विभिन्न चरणों की सामग्री तक पहुँच नहीं पाएंगे। ऐसा करने के लिए, आपको **प्रत्येक परत को डिकंप्रेस करना होगा और इसे एक्सेस करना होगा**।\
आप उस निर्देशिका से एक इमेज की सभी परतों को डिकंप्रेस कर सकते हैं जहाँ इमेज को डिकंप्रेस किया गया था:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## मेमोरी से क्रेडेंशियल्स

ध्यान दें कि जब आप एक डॉकर कंटेनर को एक होस्ट के अंदर चलाते हैं **तो आप होस्ट से कंटेनर पर चल रहे प्रोसेस को देख सकते हैं** बस `ps -ef` चलाकर।

इसलिए (रूट के रूप में) आप **होस्ट से प्रोसेस की मेमोरी को डंप कर सकते हैं** और **क्रेडेंशियल्स** के लिए खोज कर सकते हैं बस [**निम्नलिखित उदाहरण की तरह**](../../linux-hardening/privilege-escalation/#process-memory)।

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

**मोबाइल सुरक्षा** में अपनी विशेषज्ञता को 8kSec अकादमी के साथ गहरा करें। हमारे आत्म-गति पाठ्यक्रमों के माध्यम से iOS और Android सुरक्षा में महारत हासिल करें और प्रमाणित हों:

{% embed url="https://academy.8ksec.io/" %}

{% hint style="success" %}
AWS हैकिंग सीखें और अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाओं**](https://github.com/sponsors/carlospolop) की जांच करें!
* **हमारे** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में शामिल हों या **हमें** **ट्विटर** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** पर फॉलो करें।**
* **हैकिंग ट्रिक्स साझा करें और** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में PR सबमिट करें। 

</details>
{% endhint %}
