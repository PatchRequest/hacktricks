# Dış Recon Metodolojisi

{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter**'da **bizi takip edin** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

**Hacking kariyerine** ilgi duyuyorsanız ve hacklenemez olanı hack etmek istiyorsanız - **işe alıyoruz!** (_akıcı yazılı ve sözlü Lehçe gereklidir_).

{% embed url="https://www.stmcyber.com/careers" %}

## Varlık keşifleri

> Yani, bir şirkete ait her şeyin kapsamda olduğu söylendi ve bu şirketin aslında neye sahip olduğunu anlamak istiyorsunuz.

Bu aşamanın amacı, **ana şirketin sahip olduğu tüm şirketleri** ve ardından bu şirketlerin **varlıklarını** elde etmektir. Bunu yapmak için:

1. Ana şirketin satın almalarını bulmak, bu bize kapsam içindeki şirketleri verecektir.
2. Her şirketin ASN'sini (varsa) bulmak, bu bize her şirketin sahip olduğu IP aralıklarını verecektir.
3. İlkine bağlı diğer girişleri (organizasyon adları, alan adları...) aramak için ters whois sorgulamaları kullanmak (bu yinelemeli olarak yapılabilir).
4. Diğer varlıkları aramak için shodan `org` ve `ssl` filtreleri gibi diğer teknikleri kullanmak (bu `ssl` hilesi yinelemeli olarak yapılabilir).

### **Satın Almalar**

Öncelikle, **ana şirketin sahip olduğu diğer şirketleri** bilmemiz gerekiyor.\
Bir seçenek, [https://www.crunchbase.com/](https://www.crunchbase.com) adresini ziyaret etmek, **ana şirketi** **arama** yapmak ve "**satın almalar**" sekmesine **tıklamak**. Orada ana şirket tarafından satın alınan diğer şirketleri göreceksiniz.\
Diğer bir seçenek, ana şirketin **Wikipedia** sayfasını ziyaret etmek ve **satın almaları** aramaktır.

> Tamam, bu noktada kapsam içindeki tüm şirketleri bilmelisiniz. Şimdi varlıklarını nasıl bulacağımızı anlamaya çalışalım.

### **ASNs**

Otonom sistem numarası (**ASN**), **Internet Assigned Numbers Authority (IANA)** tarafından bir **otonom sisteme** (AS) atanan **benzersiz bir numaradır**.\
Bir **AS**, dış ağlara erişim için belirgin bir politikaya sahip olan ve tek bir organizasyon tarafından yönetilen **IP adresleri blokları** içerir, ancak birden fazla operatörden oluşabilir.

**Şirketin herhangi bir ASN atayıp atamadığını** bulmak, **IP aralıklarını** bulmak için ilginçtir. Kapsam içindeki tüm **hostlar** üzerinde bir **güvenlik testi** gerçekleştirmek ve bu IP'ler içindeki **alan adlarını** aramak ilginç olacaktır.\
[**https://bgp.he.net/**](https://bgp.he.net)** adresinde şirket **adı**, **IP** veya **alan adı** ile **arama** yapabilirsiniz.\
**Şirketin bulunduğu bölgeye bağlı olarak bu bağlantılar daha fazla veri toplamak için faydalı olabilir:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Kuzey Amerika),** [**APNIC**](https://www.apnic.net) **(Asya),** [**LACNIC**](https://www.lacnic.net) **(Latin Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Avrupa). Her neyse, muhtemelen tüm** faydalı bilgiler **(IP aralıkları ve Whois)** zaten ilk bağlantıda görünmektedir.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Ayrıca, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'nin** alt alan adları belirlemesi, taramanın sonunda ASN'leri otomatik olarak toplar ve özetler.
```bash
bbot -t tesla.com -f subdomain-enum
...
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS394161 | 8.244.131.0/24      | 5            | TESLA          | Tesla Motors, Inc.         | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS16509  | 54.148.0.0/15       | 4            | AMAZON-02      | Amazon.com, Inc.           | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS394161 | 8.45.124.0/24       | 3            | TESLA          | Tesla Motors, Inc.         | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS3356   | 8.32.0.0/12         | 1            | LEVEL3         | Level 3 Parent, LLC        | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS3356   | 8.0.0.0/9           | 1            | LEVEL3         | Level 3 Parent, LLC        | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+

```
You can find the IP ranges of an organisation also using [http://asnlookup.com/](http://asnlookup.com) (it has free API).\
You can find the IP and ASN of a domain using [http://ipv4info.com/](http://ipv4info.com).

### **Zafiyetleri Arama**

Bu noktada **kapsam içindeki tüm varlıkları** biliyoruz, bu yüzden izin verilirse tüm hostlar üzerinde bazı **zafiyet tarayıcıları** (Nessus, OpenVAS) başlatabilirsiniz.\
Ayrıca, bazı [**port taramaları**](../pentesting-network/#discovering-hosts-from-the-outside) **başlatabilir veya** shodan **gibi hizmetleri kullanarak** açık portları **bulabilirsiniz ve bulduklarınıza bağlı olarak bu kitapta çeşitli hizmetleri nasıl pentest edeceğinize bakmalısınız.**\
**Ayrıca, bazı** varsayılan kullanıcı adı **ve** şifre **listeleri hazırlamanın da faydalı olabileceğini ve** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) ile hizmetleri** brute force **denemesi yapabileceğinizi belirtmek gerekir.**

## Alan Adları

> Kapsam içindeki tüm şirketleri ve varlıklarını biliyoruz, şimdi kapsam içindeki alan adlarını bulma zamanı.

_Lütfen, aşağıda önerilen tekniklerde alt alan adlarını da bulabileceğinizi ve bu bilginin küçümsenmemesi gerektiğini unutmayın._

Öncelikle her şirketin **ana alan adı**(larını) aramalısınız. Örneğin, _Tesla Inc._ için _tesla.com_ olacaktır.

### **Ters DNS**

Alan adlarının tüm IP aralıklarını bulduğunuzda, bu **IP'ler üzerinde daha fazla alan adı bulmak için** **ters dns sorgulamaları** yapmayı deneyebilirsiniz. Kurbanın bazı dns sunucularını veya bazı iyi bilinen dns sunucularını (1.1.1.1, 8.8.8.8) kullanmaya çalışın.
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
For this to work, the administrator has to enable manually the PTR.\
You can also use a online tool for this info: [http://ptrarchive.com/](http://ptrarchive.com)

### **Reverse Whois (loop)**

Inside a **whois** you can find a lot of interesting **information** like **organisation name**, **address**, **emails**, phone numbers... But which is even more interesting is that you can find **more assets related to the company** if you perform **reverse whois lookups by any of those fields** (for example other whois registries where the same email appears).\
You can use online tools like:

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Ücretsiz**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Ücretsiz**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **Ücretsiz**
* [https://www.whoxy.com/](https://www.whoxy.com) - **Ücretsiz** web, ücretsiz API yok.
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Ücretsiz değil
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Ücretsiz Değil (sadece **100 ücretsiz** arama)
* [https://www.domainiq.com/](https://www.domainiq.com) - Ücretsiz Değil

You can automate this task using [**DomLink** ](https://github.com/vysecurity/DomLink)(requires a whoxy API key).\
You can also perform some automatic reverse whois discovery with [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Note that you can use this technique to discover more domain names every time you find a new domain.**

### **Trackers**

If find the **same ID of the same tracker** in 2 different pages you can suppose that **both pages** are **managed by the same team**.\
For example, if you see the same **Google Analytics ID** or the same **Adsense ID** on several pages.

There are some pages and tools that let you search by these trackers and more:

* [**Udon**](https://github.com/dhn/udon)
* [**BuiltWith**](https://builtwith.com)
* [**Sitesleuth**](https://www.sitesleuth.io)
* [**Publicwww**](https://publicwww.com)
* [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

Did you know that we can find related domains and sub domains to our target by looking for the same favicon icon hash? This is exactly what [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) tool made by [@m4ll0k2](https://twitter.com/m4ll0k2) does. Here’s how to use it:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - aynı favicon simgesi hash'ine sahip alanları keşfedin](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Basitçe söylemek gerekirse, favihash hedefimizle aynı favicon simgesi hash'ine sahip alanları keşfetmemizi sağlar.

Ayrıca, favicon hash'ini kullanarak teknolojileri arayabilirsiniz, [**bu blog yazısında**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139) açıklandığı gibi. Yani, eğer bir web teknolojisinin savunmasız bir versiyonunun **favicon hash'ini** biliyorsanız, shodan'da arama yapabilir ve **daha fazla savunmasız yer bulabilirsiniz**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Bu, bir web'in **favicon hash'ini** nasıl **hesaplayabileceğinizdir**:
```python
import mmh3
import requests
import codecs

def fav_hash(url):
response = requests.get(url)
favicon = codecs.encode(response.content,"base64")
fhash = mmh3.hash(favicon)
print(f"{url} : {fhash}")
return fhash
```
### **Copyright / Uniq string**

Web sayfalarında **aynı organizasyondaki farklı webler arasında paylaşılabilecek dizgiler** arayın. **Telif hakkı dizgisi** iyi bir örnek olabilir. Ardından bu dizgiyi **google**, diğer **tarayıcılar** veya hatta **shodan**'da arayın: `shodan search http.html:"Copyright string"`

### **CRT Time**

Bir cron job'a sahip olmak yaygındır.
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
to renew the all the domain certificates on the server. This means that even if the CA used for this doesn't set the time it was generated in the Validity time, it's possible to **find domains belonging to the same company in the certificate transparency logs**.\
Check out this [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### Mail DMARC bilgileri

You can use a web such as [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) or a tool such as [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) to find **aynı dmarc bilgilerini paylaşan alan adları ve alt alan adları**.

### **Pasif Ele Geçirme**

Görünüşe göre, insanların alt alan adlarını bulut sağlayıcılarına ait IP'lere ataması ve bir noktada **o IP adresini kaybetmesi ama DNS kaydını silmeyi unutmaları** yaygındır. Bu nedenle, sadece **bir VM oluşturmak** (Digital Ocean gibi) aslında **bazı alt alan adlarını ele geçireceksiniz**.

[**Bu yazı**](https://kmsec.uk/blog/passive-takeover/) bununla ilgili bir hikaye anlatıyor ve **DigitalOcean'da bir VM oluşturan**, **yeni makinenin** **IPv4'ünü alan** ve **buna işaret eden alt alan adı kayıtlarını Virustotal'da arayan** bir script öneriyor.

### **Diğer yollar**

**Bu tekniği, her yeni alan adı bulduğunuzda daha fazla alan adı keşfetmek için kullanabileceğinizi unutmayın.**

**Shodan**

Zaten IP alanına sahip olan kuruluşun adını biliyorsunuz. Bu veriyi shodan'da aramak için kullanabilirsiniz: `org:"Tesla, Inc."` Bulunan hostları TLS sertifikasında yeni beklenmedik alan adları için kontrol edin.

Ana web sayfasının **TLS sertifikasına** erişebilir, **Kuruluş adını** elde edebilir ve ardından **shodan** tarafından bilinen tüm web sayfalarının **TLS sertifikaları** içinde o adı arayabilirsiniz, filtre ile: `ssl:"Tesla Motors"` veya [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) gibi bir araç kullanabilirsiniz.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder), ana bir alan adı ile ilişkili **alan adlarını** ve **alt alan adlarını** arayan bir araçtır, oldukça etkileyici.

### **Zafiyet arama**

Bazı [alan adı ele geçirme](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) durumlarını kontrol edin. Belki bir şirket **bir alan adı kullanıyor** ama **sahipliğini kaybetti**. Sadece kaydedin (eğer yeterince ucuzsa) ve şirkete bildirin.

Eğer bulduğunuz varlık keşfindeki IP'lerden farklı bir IP'ye sahip herhangi bir **alan adı bulursanız**, **temel bir zafiyet taraması** (Nessus veya OpenVAS kullanarak) ve bazı [**port taramaları**](../pentesting-network/#discovering-hosts-from-the-outside) ile **nmap/masscan/shodan** yapmalısınız. Hangi hizmetlerin çalıştığına bağlı olarak, **bu kitapta "onlara saldırmak" için bazı ipuçları bulabilirsiniz**.\
_Domain'in, müşterinin kontrolünde olmayan bir IP içinde barındırıldığını unutmayın, bu nedenle kapsamda değildir, dikkatli olun._

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Hata ödülü ipucu**: **Intigriti'ye kaydolun**, **hackerlar tarafından, hackerlar için oluşturulmuş bir premium hata ödülü platformu**! Bugün [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) adresine katılın ve **$100,000**'a kadar ödüller kazanmaya başlayın!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Alt Alan Adları

> Kapsam içindeki tüm şirketleri, her şirketin tüm varlıklarını ve şirketlerle ilgili tüm alan adlarını biliyoruz.

Bulunan her alan adının tüm olası alt alan adlarını bulma zamanı.

{% hint style="success" %}
Alan adlarını bulmak için bazı araçların ve tekniklerin alt alan adlarını bulmaya da yardımcı olabileceğini unutmayın!
{% endhint %}

### **DNS**

**DNS** kayıtlarından **alt alan adlarını** almaya çalışalım. Ayrıca **Zone Transfer** için de denemeliyiz (Eğer zayıfsa, bunu bildirmelisiniz).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Birçok alt alan adı elde etmenin en hızlı yolu, dış kaynaklarda arama yapmaktır. En çok kullanılan **tools** şunlardır (daha iyi sonuçlar için API anahtarlarını yapılandırın):

* [**BBOT**](https://github.com/blacklanternsecurity/bbot)
```bash
# subdomains
bbot -t tesla.com -f subdomain-enum

# subdomains (passive only)
bbot -t tesla.com -f subdomain-enum -rf passive

# subdomains + port scan + web screenshots
bbot -t tesla.com -f subdomain-enum -m naabu gowitness -n my_scan -o .
```
* [**Amass**](https://github.com/OWASP/Amass)
```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains
```
* [**subfinder**](https://github.com/projectdiscovery/subfinder)
```bash
# Subfinder, use -silent to only have subdomains in the output
./subfinder-linux-amd64 -d tesla.com [-silent]
```
* [**findomain**](https://github.com/Edu4rdSHL/findomain/)
```bash
# findomain, use -silent to only have subdomains in the output
./findomain-linux -t tesla.com [--quiet]
```
* [**OneForAll**](https://github.com/shmilylty/OneForAll/tree/master/docs/en-us)
```bash
python3 oneforall.py --target tesla.com [--dns False] [--req False] [--brute False] run
```
* [**assetfinder**](https://github.com/tomnomnom/assetfinder)
```bash
assetfinder --subs-only <domain>
```
* [**Sudomy**](https://github.com/Screetsec/Sudomy)
```bash
# It requires that you create a sudomy.api file with API keys
sudomy -d tesla.com
```
* [**vita**](https://github.com/junnlikestea/vita)
```
vita -d tesla.com
```
* [**theHarvester**](https://github.com/laramies/theHarvester)
```bash
theHarvester -d tesla.com -b "anubis, baidu, bing, binaryedge, bingapi, bufferoverun, censys, certspotter, crtsh, dnsdumpster, duckduckgo, fullhunt, github-code, google, hackertarget, hunter, intelx, linkedin, linkedin_links, n45ht, omnisint, otx, pentesttools, projectdiscovery, qwant, rapiddns, rocketreach, securityTrails, spyse, sublist3r, threatcrowd, threatminer, trello, twitter, urlscan, virustotal, yahoo, zoomeye"
```
Diğer **ilginç araçlar/API'ler** doğrudan alt alan bulmaya özel olmasalar da alt alanları bulmak için faydalı olabilir, örneğin:

* [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Alt alanları elde etmek için [https://sonar.omnisint.io](https://sonar.omnisint.io) API'sini kullanır.
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
* [**JLDC ücretsiz API**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
* [**RapidDNS**](https://rapiddns.io) ücretsiz API
```bash
# Get Domains from rapiddns free API
rapiddns(){
curl -s "https://rapiddns.io/subdomain/$1?full=1" \
| grep -oE "[\.a-zA-Z0-9-]+\.$1" \
| sort -u
}
rapiddns tesla.com
```
* [**https://crt.sh/**](https://crt.sh)
```bash
# Get Domains from crt free API
crt(){
curl -s "https://crt.sh/?q=%25.$1" \
| grep -oE "[\.a-zA-Z0-9-]+\.$1" \
| sort -u
}
crt tesla.com
```
* [**gau**](https://github.com/lc/gau)**:** belirli bir alan adı için AlienVault'un Açık Tehdit Değişimi, Wayback Machine ve Common Crawl'dan bilinen URL'leri alır.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Web'den JS dosyalarını arayıp buradan alt alan adlarını çıkarırlar.
```bash
# Get only subdomains from SubDomainizer
python3 SubDomainizer.py -u https://tesla.com | grep tesla.com

# Get only subdomains from subscraper, this already perform recursion over the found results
python subscraper.py -u tesla.com | grep tesla.com | cut -d " " -f
```
* [**Shodan**](https://www.shodan.io/)
```bash
# Get info about the domain
shodan domain <domain>
# Get other pages with links to subdomains
shodan search "http.html:help.domain.com"
```
* [**Censys alt alan bulucu**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
* [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
* [**securitytrails.com**](https://securitytrails.com/) alt alanlar ve IP geçmişi aramak için ücretsiz bir API sunmaktadır.
* [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Bu proje, **bug-bounty programlarıyla ilgili tüm alt alanları ücretsiz olarak** sunmaktadır. Bu verilere [chaospy](https://github.com/dr-0x0x/chaospy) kullanarak da erişebilirsiniz veya bu projenin kullandığı kapsamı [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list) adresinden de erişebilirsiniz.

Bu araçların birçokunun **karşılaştırmasını** burada bulabilirsiniz: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Yeni **alt alanları** bulmak için olası alt alan adlarını kullanarak DNS sunucularını brute-force yapmayı deneyelim.

Bu işlem için bazı **yaygın alt alan kelime listelerine** ihtiyacınız olacak:

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Ayrıca iyi DNS çözümleyicilerin IP'lerine de ihtiyacınız var. Güvenilir DNS çözümleyicilerin bir listesini oluşturmak için [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) adresinden çözümleyicileri indirebilir ve bunları filtrelemek için [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) kullanabilirsiniz. Ya da şunu kullanabilirsiniz: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force için en çok önerilen araçlar şunlardır:

* [**massdns**](https://github.com/blechschmidt/massdns): Bu, etkili bir DNS brute-force gerçekleştiren ilk araçtır. Çok hızlıdır ancak yanlış pozitiflere eğilimlidir.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
* [**gobuster**](https://github.com/OJ/gobuster): Bence bu sadece 1 çözümleyici kullanıyor.
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
* [**shuffledns**](https://github.com/projectdiscovery/shuffledns) `massdns` etrafında yazılmış bir go sarmalayıcısıdır ve aktif brute force kullanarak geçerli alt alan adlarını listelemenizi sağlar, ayrıca alt alan adlarını wildcard yönetimi ve kolay girdi-çıktı desteği ile çözmenize olanak tanır.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
* [**puredns**](https://github.com/d3mondev/puredns): Ayrıca `massdns` kullanır.
```
puredns bruteforce all.txt domain.com
```
* [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) asenkron olarak alan adlarını zorlamak için asyncio kullanır.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### İkinci DNS Kaba Kuvvet Turu

Açık kaynaklar ve kaba kuvvet kullanarak alt alan adlarını bulduktan sonra, bulunan alt alan adlarının varyasyonlarını oluşturarak daha fazlasını bulmayı deneyebilirsiniz. Bu amaç için birkaç araç faydalıdır:

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Alan adları ve alt alan adları verildiğinde permütasyonlar oluşturur.
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): Alan adları ve alt alan adları verildiğinde permutasyonlar oluşturur.
* goaltdns permutasyonlarını **kelime listesi** olarak [**buradan**](https://github.com/subfinder/goaltdns/blob/master/words.txt) alabilirsiniz.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** Verilen alan adları ve alt alan adları için permutasyonlar oluşturur. Eğer permutasyon dosyası belirtilmemişse, gotator kendi dosyasını kullanacaktır.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns): Alt alan adı varyasyonları oluşturmanın yanı sıra, bunları çözmeye de çalışabilir (ancak daha önce bahsedilen araçları kullanmak daha iyidir).
* altdns varyasyonlarını **wordlist** olarak [**buradan**](https://github.com/infosec-au/altdns/blob/master/words.txt) alabilirsiniz.
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): Alt alan adlarının permütasyonlarını, mutasyonlarını ve değişikliklerini gerçekleştirmek için başka bir araç. Bu araç sonucu brute force ile deneyecektir (dns wild card'ı desteklemez).
* dmut permütasyonları kelime listesini [**buradan**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) alabilirsiniz.
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**:** Belirtilen kalıplara dayanarak bir alan adı üzerinden **yeni potansiyel alt alan adı isimleri üretir** ve daha fazla alt alan adı keşfetmeye çalışır.

#### Akıllı permütasyonlar üretimi

* [**regulator**](https://github.com/cramppet/regulator): Daha fazla bilgi için bu [**yazıyı**](https://cramppet.github.io/regulator/index.html) okuyun, ancak temelde **keşfedilen alt alan adlarının** **ana kısımlarını** alacak ve daha fazla alt alan adı bulmak için bunları karıştıracaktır.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_, son derece basit ama etkili bir DNS yanıtına dayalı algoritma ile birleştirilmiş bir alt alan brute-force fuzzer'dır. Özelleştirilmiş bir kelime listesi veya tarihsel DNS/TLS kayıtları gibi sağlanan bir girdi veri setini kullanarak, daha fazla ilgili alan adı sentezlemek ve bunları DNS taraması sırasında toplanan bilgilere dayalı olarak bir döngüde daha da genişletmek için kullanılır.
```
echo www | subzuf facebook.com
```
### **Alt Alan Keşif İş Akışı**

Bir alan adından **alt alan keşfini otomatikleştirme** hakkında yazdığım bu blog yazısını kontrol edin, böylece bilgisayarımda bir dizi aracı manuel olarak başlatmam gerekmiyor:

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/" %}

### **VHosts / Sanal Ana Bilgisayarlar**

Eğer bir IP adresinde **bir veya birkaç web sayfası** bulduysanız, **o IP'deki diğer alt alanları bulmaya çalışabilirsiniz**. Bunun için **OSINT kaynaklarında** bir IP'deki alan adlarını arayabilir veya **o IP'deki VHost alan adlarını brute-force ile deneyebilirsiniz**.

#### OSINT

Bazı **VHosts'ları IP'lerde bulmak için** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **veya diğer API'leri** kullanabilirsiniz.

**Brute Force**

Eğer bazı alt alanların bir web sunucusunda gizli olabileceğinden şüpheleniyorsanız, brute force denemesi yapabilirsiniz:
```bash
ffuf -c -w /path/to/wordlist -u http://victim.com -H "Host: FUZZ.victim.com"

gobuster vhost -u https://mysite.com -t 50 -w subdomains.txt

wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.example.com" -u http://example.com -t 100

#From https://github.com/allyshka/vhostbrute
vhostbrute.py --url="example.com" --remoteip="10.1.1.15" --base="www.example.com" --vhosts="vhosts_full.list"

#https://github.com/codingo/VHostScan
VHostScan -t example.com
```
{% hint style="info" %}
Bu teknikle, dahili/gizli uç noktalara erişim sağlayabilirsiniz.
{% endhint %}

### **CORS Brute Force**

Bazen, yalnızca geçerli bir alan/ad alanı _**Origin**_ başlığında ayarlandığında _**Access-Control-Allow-Origin**_ başlığını döndüren sayfalar bulabilirsiniz. Bu senaryolarda, bu davranışı **keşfetmek** için **yeni alt alan adları** bulmak amacıyla kötüye kullanabilirsiniz.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

**Alt alanlar** ararken, herhangi bir tür **bucket**'a **işaret edip etmediğine** dikkat edin ve bu durumda [**izinleri kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/)**.**\
Ayrıca, bu noktada kapsam içindeki tüm alan adlarını bildiğiniz için, [**mümkün olan bucket isimlerini brute force yapmayı ve izinleri kontrol etmeyi**](../../network-services-pentesting/pentesting-web/buckets/) deneyin.

### **Monitorization**

Bir alan adının **yeni alt alanları** oluşturulup oluşturulmadığını **Sertifika Şeffaflığı** Loglarını izleyerek **izleyebilirsiniz** [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Looking for vulnerabilities**

Mümkün olan [**alt alan devralmalarını**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) kontrol edin.\
Eğer **alt alan** bir **S3 bucket**'a işaret ediyorsa, [**izinleri kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/).

Eğer bulduğunuz **alt alanlardan IP'si farklı olan** bir tane bulursanız, **temel bir güvenlik taraması** (Nessus veya OpenVAS kullanarak) ve bazı [**port taramaları**](../pentesting-network/#discovering-hosts-from-the-outside) **nmap/masscan/shodan** ile gerçekleştirmelisiniz. Hangi hizmetlerin çalıştığına bağlı olarak, **bu kitapta "saldırmak" için bazı ipuçları bulabilirsiniz**.\
_Bazen alt alanın, müşterinin kontrolünde olmayan bir IP içinde barındırıldığını unutmayın, bu nedenle kapsamda değildir, dikkatli olun._

## IPs

Başlangıç adımlarında **bazı IP aralıkları, alan adları ve alt alanlar** bulmuş olabilirsiniz.\
Artık bu aralıklardan **tüm IP'leri toplama** ve **alan adları/alt alanlar (DNS sorguları)** için zamanı geldi.

Aşağıdaki **ücretsiz API'lerden** hizmetler kullanarak, **alan adları ve alt alanlar tarafından kullanılan önceki IP'leri** de bulabilirsiniz. Bu IP'ler hala müşteri tarafından sahiplenilmiş olabilir (ve [**CloudFlare bypass'larını**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) bulmanıza yardımcı olabilir)

* [**https://securitytrails.com/**](https://securitytrails.com/)

Ayrıca, belirli bir IP adresine işaret eden alan adlarını kontrol etmek için [**hakip2host**](https://github.com/hakluke/hakip2host) aracını kullanabilirsiniz.

### **Looking for vulnerabilities**

**CDN'lere ait olmayan tüm IP'leri port taraması yapın** (çünkü burada ilginç bir şey bulma olasılığınız çok düşük). Keşfedilen çalışan hizmetlerde **güvenlik açıkları bulma** şansınız olabilir.

**Host'ları tarama hakkında bir** [**kılavuz**](../pentesting-network/) **bulun.**

## Web sunucuları avı

> Tüm şirketleri ve varlıklarını bulduk ve kapsam içindeki IP aralıklarını, alan adlarını ve alt alanları biliyoruz. Web sunucularını arama zamanı.

Önceki adımlarda muhtemelen keşfedilen **IP'ler ve alan adları üzerinde bazı keşifler** yaptınız, bu nedenle **mümkün olan tüm web sunucularını** zaten bulmuş olabilirsiniz. Ancak, bulmadıysanız, şimdi kapsam içinde **web sunucularını aramak için bazı hızlı ipuçlarını** göreceğiz.

Lütfen, bunun **web uygulamaları keşfine yönelik** olacağını unutmayın, bu nedenle **güvenlik açığı** ve **port taraması** da yapmalısınız (**kapsam tarafından izin veriliyorsa**).

**Web** sunucularına ilişkin **açık portları** keşfetmek için [**masscan** kullanarak hızlı bir yöntem**](../pentesting-network/#http-port-discovery) bulabilirsiniz.\
Web sunucularını aramak için başka bir kullanıcı dostu araç [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) ve [**httpx**](https://github.com/projectdiscovery/httpx)'dir. Sadece bir alan adı listesi geçiyorsunuz ve port 80 (http) ve 443 (https) ile bağlantı kurmaya çalışıyor. Ayrıca, diğer portları denemesi için belirtebilirsiniz:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Ekran Görüntüleri**

Artık **kapsamda bulunan tüm web sunucularını** (şirketin **IP'leri** ve tüm **alan adları** ve **alt alan adları** arasında) keşfettiğinize göre, muhtemelen **nereden başlayacağınızı bilmiyorsunuz**. Bu yüzden, bunu basit tutalım ve hepsinin ekran görüntülerini alarak başlayalım. Sadece **ana sayfaya bakarak**, daha **savunmasız** olma eğiliminde olan **garip** uç noktalar bulabilirsiniz.

Önerilen fikri gerçekleştirmek için [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) veya [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**'i** kullanabilirsiniz.

Ayrıca, [**eyeballer**](https://github.com/BishopFox/eyeballer) kullanarak tüm **ekran görüntülerini** tarayabilir ve **hangi noktaların muhtemelen zafiyet içerebileceğini** belirleyebilirsiniz.

## Kamu Bulut Varlıkları

Bir şirkete ait potansiyel bulut varlıklarını bulmak için, o şirketi tanımlayan **anahtar kelimelerle bir listeye başlamalısınız**. Örneğin, bir kripto şirketi için şu kelimeleri kullanabilirsiniz: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Ayrıca, **kova** içinde kullanılan **yaygın kelimelerin** kelime listelerine de ihtiyacınız olacak:

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Sonra, bu kelimelerle **permutasyonlar** oluşturmalısınız (daha fazla bilgi için [**İkinci Tur DNS Kaba Kuvvet**](./#second-dns-bruteforce-round) bölümüne bakın).

Elde edilen kelime listeleriyle [**cloud\_enum**](https://github.com/initstring/cloud\_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ve** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** gibi araçları kullanabilirsiniz.**

Bulut Varlıkları ararken, **AWS'deki kovalardan daha fazlasını aramalısınız**.

### **Zafiyet Arama**

**Açık kova veya bulut fonksiyonları** gibi şeyler bulursanız, bunlara **erişmeli** ve size ne sunduklarını görmeli ve bunları kötüye kullanıp kullanamayacağınızı denemelisiniz.

## E-postalar

Kapsamdaki **alan adları** ve **alt alan adları** ile, **e-postaları aramaya başlamak için gereken her şeye** sahipsiniz. Bir şirketin e-postalarını bulmak için en iyi çalışan **API'ler** ve **araçlar** şunlardır:

* [**theHarvester**](https://github.com/laramies/theHarvester) - API'lerle
* [**https://hunter.io/**](https://hunter.io/) API'si (ücretsiz sürüm)
* [**https://app.snov.io/**](https://app.snov.io/) API'si (ücretsiz sürüm)
* [**https://minelead.io/**](https://minelead.io/) API'si (ücretsiz sürüm)

### **Zafiyet Arama**

E-postalar, daha sonra **web girişlerini ve kimlik doğrulama hizmetlerini** (SSH gibi) **kaba kuvvetle** kırmak için faydalı olacaktır. Ayrıca, **phishing** için de gereklidir. Ayrıca, bu API'ler, e-posta sahibinin arkasındaki kişi hakkında daha fazla **bilgi** sağlayacaktır, bu da phishing kampanyası için faydalıdır.

## Kimlik Bilgisi Sızıntıları

**Alan adları**, **alt alan adları** ve **e-postalar** ile, geçmişte bu e-postalara ait sızdırılmış kimlik bilgilerini aramaya başlayabilirsiniz:

* [https://leak-lookup.com](https://leak-lookup.com/account/login)
* [https://www.dehashed.com/](https://www.dehashed.com/)

### **Zafiyet Arama**

**Geçerli sızdırılmış** kimlik bilgileri bulursanız, bu çok kolay bir kazanımdır.

## Gizli Bilgiler Sızıntıları

Kimlik bilgisi sızıntıları, **hassas bilgilerin sızdırıldığı ve satıldığı** şirketlerin hacklenmesiyle ilgilidir. Ancak, şirketler, bu veritabanlarında yer almayan **diğer sızıntılardan** da etkilenebilir:

### Github Sızıntıları

Kimlik bilgileri ve API'ler, **şirketin** veya o github şirketinde çalışan **kullanıcıların** **açık havuzlarında** sızdırılmış olabilir.\
**Leakos** adlı aracı kullanarak bir **kuruluşun** ve onun **geliştiricilerinin** tüm **açık havuzlarını** **indirebilir** ve bunlar üzerinde otomatik olarak [**gitleaks**](https://github.com/zricethezav/gitleaks) çalıştırabilirsiniz.

**Leakos**, bazen **web sayfalarının da gizli bilgiler içerebileceği** için, kendisine **verilen URL'ler** üzerinden **gitleaks** çalıştırmak için de kullanılabilir.

#### Github Dorks

Ayrıca, saldırdığınız kuruluşta arayabileceğiniz potansiyel **github dorks** için bu **sayfayı** kontrol edin:

{% content-ref url="github-leaked-secrets.md" %}
[github-leaked-secrets.md](github-leaked-secrets.md)
{% endcontent-ref %}

### Paste Sızıntıları

Bazen saldırganlar veya sadece çalışanlar, **şirket içeriğini bir paste sitesinde yayınlayabilir**. Bu, **hassas bilgiler** içerebilir veya içermeyebilir, ancak aramak için çok ilginçtir.\
Birden fazla paste sitesinde aynı anda arama yapmak için [**Pastos**](https://github.com/carlospolop/Pastos) aracını kullanabilirsiniz.

### Google Dorks

Eski ama altın değerinde google dorks, **orada olmaması gereken** **açık bilgileri** bulmak için her zaman faydalıdır. Tek sorun, [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) içinde manuel olarak çalıştıramayacağınız birkaç **binlerce** olası sorgu bulunmasıdır. Bu nedenle, en sevdiğiniz 10 tanesini alabilir veya hepsini çalıştırmak için [**Gorks**](https://github.com/carlospolop/Gorks) gibi bir **araç** kullanabilirsiniz.

_Not: Tüm veritabanını düzenli Google tarayıcısını kullanarak çalıştırmayı bekleyen araçlar asla sona ermeyecek, çünkü Google sizi çok kısa sürede engelleyecektir._

### **Zafiyet Arama**

**Geçerli sızdırılmış** kimlik bilgileri veya API jetonları bulursanız, bu çok kolay bir kazanımdır.

## Kamu Kodu Zafiyetleri

Eğer şirketin **açık kaynak kodu** olduğunu bulduysanız, bunu **analiz edebilir** ve üzerinde **zafiyetler** arayabilirsiniz.

**Dile bağlı olarak**, kullanabileceğiniz farklı **araçlar** vardır:

{% content-ref url="../../network-services-pentesting/pentesting-web/code-review-tools.md" %}
[code-review-tools.md](../../network-services-pentesting/pentesting-web/code-review-tools.md)
{% endcontent-ref %}

Ayrıca, **açık havuzları taramanıza** olanak tanıyan ücretsiz hizmetler de vardır, örneğin:

* [**Snyk**](https://app.snyk.io/)

## [**Web Pentesting Metodolojisi**](../../network-services-pentesting/pentesting-web/)

**Hata avcıları tarafından bulunan zafiyetlerin** çoğunluğu **web uygulamalarında** yer almaktadır, bu nedenle bu noktada bir **web uygulaması test metodolojisi** hakkında konuşmak istiyorum ve bu bilgiyi [**burada bulabilirsiniz**](../../network-services-pentesting/pentesting-web/).

Ayrıca, **çok hassas zafiyetler** bulmanızı beklememeniz gereken [**Web Otomatik Tarayıcıları açık kaynak araçları**](../../network-services-pentesting/pentesting-web/#automatic-scanners) bölümüne özel bir atıfta bulunmak istiyorum, çünkü bunlar, **ilk web bilgilerini elde etmek için iş akışlarına** entegre etmek için faydalıdır.

## Tekrar

> Tebrikler! Bu noktada **tüm temel numaralandırmayı** gerçekleştirdiniz. Evet, bu temel çünkü daha fazla numaralandırma yapılabilir (daha fazla ipucu göreceğiz).

Yani, zaten şunları buldunuz:

1. Kapsamdaki tüm **şirketleri** buldunuz
2. Şirketlere ait tüm **varlıkları** buldunuz (ve kapsamda bazı zafiyet taramaları gerçekleştirdiniz)
3. Şirketlere ait tüm **alan adlarını** buldunuz
4. Alan adlarının tüm **alt alan adlarını** buldunuz (herhangi bir alt alan devralma?)
5. Kapsamdaki tüm **IP'leri** (CDN'lerden ve **CDN'lerden olmayan**) buldunuz.
6. Tüm **web sunucularını** buldunuz ve bunların **ekran görüntülerini** aldınız (daha derin bir incelemeyi gerektiren garip bir şey var mı?)
7. Şirkete ait tüm **potansiyel kamu bulut varlıklarını** buldunuz.
8. **E-postalar**, **kimlik bilgisi sızıntıları** ve **gizli sızıntılar** size **çok kolay bir büyük kazanç** sağlayabilir.
9. Bulduğunuz tüm web sitelerini **pentest ettiniz**

## **Tam Recon Otomatik Araçlar**

Belirli bir kapsamda önerilen eylemlerin bir kısmını gerçekleştirecek birkaç araç bulunmaktadır.

* [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
* [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
* [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
* [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Biraz eski ve güncellenmemiş

## **Referanslar**

* [**@Jhaddix**](https://twitter.com/Jhaddix) tarafından sunulan tüm ücretsiz kurslar, örneğin [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

**Hackleme kariyerine** ve hacklenemez olanı hacklemeye ilgi duyuyorsanız - **işe alıyoruz!** (_akıcı Lehçe yazılı ve sözlü gereklidir_).

{% embed url="https://www.stmcyber.com/careers" %}

{% hint style="success" %}
AWS Hackleme öğrenin ve pratik yapın:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hackleme öğrenin ve pratik yapın: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hackleme ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
