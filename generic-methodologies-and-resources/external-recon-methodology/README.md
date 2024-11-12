# External Recon Methodology

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

If you are interested in **hacking career** and hack the unhackable - **we are hiring!** (_fluent polish written and spoken required_).

{% embed url="https://www.stmcyber.com/careers" %}

## 자산 발견

> 어떤 회사에 속한 모든 것이 범위 내에 있다고 들었고, 이 회사가 실제로 소유하고 있는 것이 무엇인지 알아내고 싶습니다.

이 단계의 목표는 **주요 회사가 소유한 모든 회사**와 이 회사들의 **자산**을 얻는 것입니다. 이를 위해 우리는 다음을 수행할 것입니다:

1. 주요 회사의 인수 목록을 찾습니다. 이는 범위 내의 회사를 알려줍니다.
2. 각 회사의 ASN(있는 경우)을 찾아, 각 회사가 소유한 IP 범위를 알아냅니다.
3. 역 Whois 조회를 사용하여 첫 번째와 관련된 다른 항목(조직 이름, 도메인 등)을 검색합니다(재귀적으로 수행할 수 있습니다).
4. shodan `org` 및 `ssl` 필터와 같은 다른 기술을 사용하여 다른 자산을 검색합니다(`ssl` 트릭은 재귀적으로 수행할 수 있습니다).

### **인수**

우선, **주요 회사가 소유한 다른 회사**를 알아야 합니다.\
한 가지 방법은 [https://www.crunchbase.com/](https://www.crunchbase.com)를 방문하여 **주요 회사**를 **검색**하고 "**인수**"를 클릭하는 것입니다. 거기서 주요 회사가 인수한 다른 회사를 볼 수 있습니다.\
또 다른 방법은 주요 회사의 **위키피디아** 페이지를 방문하여 **인수**를 검색하는 것입니다.

> 좋습니다. 이 시점에서 범위 내의 모든 회사를 알아야 합니다. 이제 그들의 자산을 찾는 방법을 알아봅시다.

### **ASN**

자율 시스템 번호(**ASN**)는 **인터넷 할당 번호 관리 기관(IANA)**에 의해 **자율 시스템**(AS)에 할당된 **고유 번호**입니다.\
**AS**는 외부 네트워크에 접근하기 위한 명확하게 정의된 정책을 가진 **IP 주소**의 **블록**으로 구성되며, 단일 조직에 의해 관리되지만 여러 운영자로 구성될 수 있습니다.

회사가 **할당된 ASN**이 있는지 확인하여 **IP 범위**를 찾는 것이 흥미롭습니다. **범위** 내의 모든 **호스트**에 대해 **취약성 테스트**를 수행하고 이러한 IP 내의 **도메인**을 찾아보는 것이 좋습니다.\
[**https://bgp.he.net/**](https://bgp.he.net)에서 회사 **이름**, **IP** 또는 **도메인**으로 **검색**할 수 있습니다.\
**회사의 지역에 따라 이 링크가 더 많은 데이터를 수집하는 데 유용할 수 있습니다:** [**AFRINIC**](https://www.afrinic.net) **(아프리카),** [**Arin**](https://www.arin.net/about/welcome/region/)**(북미),** [**APNIC**](https://www.apnic.net) **(아시아),** [**LACNIC**](https://www.lacnic.net) **(라틴 아메리카),** [**RIPE NCC**](https://www.ripe.net) **(유럽). 어쨌든, 아마도 모든** 유용한 정보 **(IP 범위 및 Whois)**는 첫 번째 링크에 이미 나타납니다.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
또한, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**의** 서브도메인 열거는 스캔이 끝날 때 ASNs를 자동으로 집계하고 요약합니다.
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

### **취약점 찾기**

이 시점에서 우리는 **범위 내 모든 자산**을 알고 있으므로, 허용된다면 모든 호스트에 대해 **취약점 스캐너**(Nessus, OpenVAS)를 실행할 수 있습니다.\
또한, [**포트 스캔**](../pentesting-network/#discovering-hosts-from-the-outside)을 실행하거나 shodan과 같은 서비스를 사용하여 **열려 있는 포트를 찾고, 발견한 내용에 따라 이 책을 참고하여 여러 가능한 서비스에 대한 펜테스트 방법을 살펴봐야 합니다.**\
**또한, 기본 사용자 이름과** 비밀번호 **목록을 준비하고 [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray)로 서비스를 브루트포스 시도하는 것도 가치가 있을 수 있습니다.**

## 도메인

> 우리는 범위 내 모든 회사와 그 자산을 알고 있으므로, 범위 내 도메인을 찾을 시간입니다.

_다음에 제안된 기술에서는 서브도메인도 찾을 수 있으며, 그 정보는 과소평가해서는 안 됩니다._

먼저 각 회사의 **주 도메인**(들)을 찾아야 합니다. 예를 들어, _Tesla Inc._의 경우 _tesla.com_이 될 것입니다.

### **역 DNS**

도메인의 모든 IP 범위를 찾았으므로, **범위 내 더 많은 도메인을 찾기 위해 해당 IP에 대해 역 DNS 조회를 수행할 수 있습니다.** 피해자의 DNS 서버나 잘 알려진 DNS 서버(1.1.1.1, 8.8.8.8)를 사용해 보세요.
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

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **무료**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **무료**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **무료**
* [https://www.whoxy.com/](https://www.whoxy.com) - **무료** 웹, 무료 API 아님.
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - 무료 아님
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 무료 아님 (단 **100 무료** 검색)
* [https://www.domainiq.com/](https://www.domainiq.com) - 무료 아님

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
![favihash - 동일한 파비콘 아이콘 해시를 가진 도메인 발견](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

간단히 말해, favihash는 우리의 타겟과 동일한 파비콘 아이콘 해시를 가진 도메인을 발견할 수 있게 해줍니다.

게다가, [**이 블로그 포스트**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)에서 설명한 대로 파비콘 해시를 사용하여 기술을 검색할 수도 있습니다. 즉, **취약한 버전의 웹 기술의 파비콘 해시를 알고 있다면** shodan에서 검색하여 **더 많은 취약한 장소를 찾을 수 있습니다**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
이것은 웹의 **파비콘 해시**를 계산하는 방법입니다:
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

웹 페이지 내에서 **같은 조직의 서로 다른 웹에서 공유될 수 있는 문자열**을 검색합니다. **저작권 문자열**이 좋은 예가 될 수 있습니다. 그런 다음 **구글**, 다른 **브라우저** 또는 **shodan**에서 해당 문자열을 검색합니다: `shodan search http.html:"Copyright string"`

### **CRT Time**

크론 작업이 있는 것이 일반적입니다.
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
to renew the all the domain certificates on the server. This means that even if the CA used for this doesn't set the time it was generated in the Validity time, it's possible to **find domains belonging to the same company in the certificate transparency logs**.\
Check out this [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### Mail DMARC 정보

You can use a web such as [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) or a tool such as [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) to find **domains and subdomain sharing the same dmarc information**.

### **수동 인수**

Apparently is common for people to assign subdomains to IPs that belongs to cloud providers and at some point **lose that IP address but forget about removing the DNS record**. Therefore, just **spawning a VM** in a cloud (like Digital Ocean) you will be actually **taking over some subdomains(s)**.

[**이 게시물**](https://kmsec.uk/blog/passive-takeover/) explains a store about it and propose a script that **spawns a VM in DigitalOcean**, **gets** the **IPv4** of the new machine, and **searches in Virustotal for subdomain records** pointing to it.

### **기타 방법**

**Note that you can use this technique to discover more domain names every time you find a new domain.**

**Shodan**

As you already know the name of the organisation owning the IP space. You can search by that data in shodan using: `org:"Tesla, Inc."` Check the found hosts for new unexpected domains in the TLS certificate.

You could access the **TLS certificate** of the main web page, obtain the **Organisation name** and then search for that name inside the **TLS certificates** of all the web pages known by **shodan** with the filter : `ssl:"Tesla Motors"` or use a tool like [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)is a tool that look for **domains related** with a main domain and **subdomains** of them, pretty amazing.

### **취약점 찾기**

Check for some [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Maybe some company is **using some a domain** but they **lost the ownership**. Just register it (if cheap enough) and let know the company.

If you find any **domain with an IP different** from the ones you already found in the assets discovery, you should perform a **basic vulnerability scan** (using Nessus or OpenVAS) and some [**port scan**](../pentesting-network/#discovering-hosts-from-the-outside) with **nmap/masscan/shodan**. Depending on which services are running you can find in **this book some tricks to "attack" them**.\
_Note that sometimes the domain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**버그 바운티 팁**: **가입하세요** **Intigriti**, 해커를 위해 만들어진 프리미엄 **버그 바운티 플랫폼**! 오늘 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)에서 저희와 함께하고 최대 **$100,000**의 보상을 받기 시작하세요!

{% embed url="https://go.intigriti.com/hacktricks" %}

## 서브도메인

> We know all the companies inside the scope, all the assets of each company and all the domains related to the companies.

It's time to find all the possible subdomains of each found domain.

{% hint style="success" %}
Note that some of the tools and techniques to find domains can also help to find subdomains!
{% endhint %}

### **DNS**

Let's try to get **subdomains** from the **DNS** records. We should also try for **Zone Transfer** (If vulnerable, you should report it).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

많은 서브도메인을 빠르게 얻는 방법은 외부 소스에서 검색하는 것입니다. 가장 많이 사용되는 **도구**는 다음과 같습니다 (더 나은 결과를 위해 API 키를 구성하세요):

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
다른 **흥미로운 도구/API**가 있으며, 이들은 서브도메인을 찾는 데 직접적으로 특화되어 있지 않더라도 서브도메인을 찾는 데 유용할 수 있습니다. 예를 들어:

* [**Crobat**](https://github.com/cgboal/sonarsearch)**:** API [https://sonar.omnisint.io](https://sonar.omnisint.io)를 사용하여 서브도메인을 얻습니다.
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
* [**JLDC 무료 API**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
* [**RapidDNS**](https://rapiddns.io) 무료 API
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
* [**gau**](https://github.com/lc/gau)**:** 주어진 도메인에 대해 AlienVault의 Open Threat Exchange, Wayback Machine 및 Common Crawl에서 알려진 URL을 가져옵니다.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): 이들은 웹을 스크랩하여 JS 파일을 찾고 그곳에서 서브도메인을 추출합니다.
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
* [**Censys 서브도메인 찾기**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
* [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
* [**securitytrails.com**](https://securitytrails.com/)은 서브도메인 및 IP 기록을 검색할 수 있는 무료 API를 제공합니다.
* [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

이 프로젝트는 **버그 바운티 프로그램과 관련된 모든 서브도메인**을 무료로 제공합니다. 이 데이터를 [chaospy](https://github.com/dr-0x0x/chaospy)를 사용하여 접근할 수 있으며, 이 프로젝트에서 사용된 범위에 접근할 수도 있습니다: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

여기에서 이러한 도구들의 **비교**를 찾을 수 있습니다: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS 브루트 포스**

가능한 서브도메인 이름을 사용하여 DNS 서버를 브루트 포스하여 새로운 **서브도메인**을 찾아보겠습니다.

이 작업을 위해서는 다음과 같은 **일반 서브도메인 단어 목록**이 필요합니다:

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

또한 좋은 DNS 해석기의 IP도 필요합니다. 신뢰할 수 있는 DNS 해석기 목록을 생성하기 위해 [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt)에서 해석기를 다운로드하고 [**dnsvalidator**](https://github.com/vortexau/dnsvalidator)를 사용하여 필터링할 수 있습니다. 또는 다음을 사용할 수 있습니다: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS 브루트 포스에 가장 추천되는 도구는 다음과 같습니다:

* [**massdns**](https://github.com/blechschmidt/massdns): 이는 효과적인 DNS 브루트 포스를 수행한 첫 번째 도구입니다. 매우 빠르지만 잘못된 긍정 반응이 발생할 수 있습니다.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
* [**gobuster**](https://github.com/OJ/gobuster): 이 도구는 1개의 리졸버만 사용하는 것 같습니다.
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
* [**shuffledns**](https://github.com/projectdiscovery/shuffledns)는 `massdns`를 감싸는 도구로, Go로 작성되어 있으며, 능동적인 브루트포스를 사용하여 유효한 서브도메인을 열거하고, 와일드카드 처리를 통해 서브도메인을 해결하며, 간편한 입력-출력 지원을 제공합니다.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
* [**puredns**](https://github.com/d3mondev/puredns): `massdns`도 사용합니다.
```
puredns bruteforce all.txt domain.com
```
* [**aiodnsbrute**](https://github.com/blark/aiodnsbrute)는 asyncio를 사용하여 도메인 이름을 비동기적으로 무차별 대입합니다.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### 두 번째 DNS 브루트 포스 라운드

오픈 소스를 사용하고 브루트 포싱을 통해 서브 도메인을 찾은 후, 발견된 서브 도메인의 변형을 생성하여 더 많은 서브 도메인을 찾으려고 할 수 있습니다. 이 목적을 위해 여러 도구가 유용합니다:

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** 도메인과 서브 도메인을 주면 순열을 생성합니다.
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): 도메인과 서브도메인을 기반으로 순열을 생성합니다.
* [**여기**](https://github.com/subfinder/goaltdns/blob/master/words.txt)에서 goaltdns 순열 **단어 목록**을 얻을 수 있습니다.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** 도메인과 서브도메인을 기반으로 순열을 생성합니다. 순열 파일이 지정되지 않은 경우 gotator는 자체 파일을 사용합니다.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns): 서브도메인 조합을 생성하는 것 외에도, 이를 해결하려고 시도할 수 있습니다(하지만 이전에 언급된 도구를 사용하는 것이 더 좋습니다).
* altdns 조합 **단어 목록**은 [**여기**](https://github.com/infosec-au/altdns/blob/master/words.txt)에서 얻을 수 있습니다.
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): 서브도메인의 순열, 변형 및 변경을 수행하는 또 다른 도구입니다. 이 도구는 결과를 무작위로 시도합니다( dns 와일드카드를 지원하지 않습니다).
* dmut 순열 단어 목록은 [**여기**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)에서 얻을 수 있습니다.
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**:** 주어진 도메인을 기반으로 **지정된 패턴에 따라 새로운 잠재적 서브도메인 이름을 생성**하여 더 많은 서브도메인을 발견하려고 시도합니다.

#### 스마트 순열 생성

* [**regulator**](https://github.com/cramppet/regulator): 더 많은 정보는 이 [**게시물**](https://cramppet.github.io/regulator/index.html)를 읽어보세요. 기본적으로 **발견된 서브도메인**의 **주요 부분**을 가져와서 이를 혼합하여 더 많은 서브도메인을 찾습니다.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_는 매우 간단하지만 효과적인 DNS 응답 유도 알고리즘과 결합된 서브도메인 브루트포스 퍼저입니다. 맞춤형 단어 목록이나 역사적인 DNS/TLS 기록과 같은 제공된 입력 데이터를 활용하여 더 많은 해당 도메인 이름을 정확하게 합성하고 DNS 스캔 중에 수집된 정보를 기반으로 루프에서 이를 더욱 확장합니다.
```
echo www | subzuf facebook.com
```
### **서브도메인 발견 워크플로우**

도메인에서 **서브도메인 발견을 자동화하는 방법**에 대해 제가 쓴 블로그 게시물을 확인해 보세요. **Trickest 워크플로우**를 사용하여 제 컴퓨터에서 여러 도구를 수동으로 실행할 필요가 없습니다:

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/" %}

### **VHosts / 가상 호스트**

서브도메인에 속하는 **하나 이상의 웹 페이지**를 포함하는 IP 주소를 찾았다면, **OSINT 소스**에서 IP의 도메인을 찾거나 **해당 IP에서 VHost 도메인 이름을 브루트 포스**하여 **다른 서브도메인**을 찾을 수 있습니다.

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **또는 기타 API를 사용하여 IP에서 일부 VHosts를 찾을 수 있습니다.**

**브루트 포스**

어떤 서브도메인이 웹 서버에 숨겨져 있다고 의심되면 브루트 포스를 시도할 수 있습니다:
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
이 기술을 사용하면 내부/숨겨진 엔드포인트에 접근할 수도 있습니다.
{% endhint %}

### **CORS Brute Force**

때때로 유효한 도메인/서브도메인이 _**Origin**_ 헤더에 설정될 때만 _**Access-Control-Allow-Origin**_ 헤더를 반환하는 페이지를 발견할 수 있습니다. 이러한 시나리오에서는 이 동작을 악용하여 **새로운** **서브도메인**을 **발견**할 수 있습니다.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **버킷 무차별 대입**

**서브도메인**을 찾는 동안 **버킷**으로 **포인팅**되는지 주의 깊게 살펴보세요. 그런 경우 [**권한을 확인하세요**](../../network-services-pentesting/pentesting-web/buckets/)**.**\
또한, 이 시점에서 범위 내의 모든 도메인을 알게 되었으므로 [**가능한 버킷 이름을 무차별 대입하고 권한을 확인하세요**](../../network-services-pentesting/pentesting-web/buckets/).

### **모니터링**

도메인의 **새 서브도메인**이 생성되는지 **Certificate Transparency** 로그를 모니터링하여 확인할 수 있습니다. [**sublert**](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)가 이를 수행합니다.

### **취약점 찾기**

가능한 [**서브도메인 탈취**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)를 확인하세요.\
**서브도메인**이 어떤 **S3 버킷**으로 **포인팅**되고 있다면, [**권한을 확인하세요**](../../network-services-pentesting/pentesting-web/buckets/).

자산 탐색에서 이미 발견한 것과 다른 **IP를 가진 서브도메인**을 발견하면, **기본 취약점 스캔**(Nessus 또는 OpenVAS 사용)과 **포트 스캔**(nmap/masscan/shodan 사용)을 수행해야 합니다. 실행 중인 서비스에 따라 **이 책에서 "공격"하는 몇 가지 요령을 찾을 수 있습니다**.\
_서브도메인이 클라이언트가 제어하지 않는 IP 내에 호스팅되는 경우가 있으므로, 범위에 포함되지 않을 수 있습니다. 주의하세요._

## IPs

초기 단계에서 **일부 IP 범위, 도메인 및 서브도메인**을 **발견했을 수 있습니다**.\
이제 **그 범위에서 모든 IP를 수집할** 시간입니다. **도메인/서브도메인(DNS 쿼리)**에 대한 IP도 포함됩니다.

다음 **무료 API** 서비스를 사용하여 **도메인과 서브도메인에서 사용된 이전 IP**를 찾을 수 있습니다. 이 IP는 여전히 클라이언트가 소유하고 있을 수 있으며, [**CloudFlare 우회**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)를 찾는 데 도움이 될 수 있습니다.

* [**https://securitytrails.com/**](https://securitytrails.com/)

특정 IP 주소를 가리키는 도메인을 확인하려면 [**hakip2host**](https://github.com/hakluke/hakip2host) 도구를 사용할 수 있습니다.

### **취약점 찾기**

**CDN에 속하지 않는 모든 IP에 대해 포트 스캔을 수행하세요**(여기서는 흥미로운 것을 찾지 못할 가능성이 높습니다). 발견된 실행 중인 서비스에서 **취약점을 찾을 수 있을지도 모릅니다**.

**호스트 스캔 방법에 대한** [**가이드를 찾으세요**](../pentesting-network/).

## 웹 서버 탐색

> 우리는 모든 회사와 그 자산을 찾았고, 범위 내의 IP 범위, 도메인 및 서브도메인을 알고 있습니다. 이제 웹 서버를 검색할 시간입니다.

이전 단계에서 이미 발견된 **IP와 도메인에 대한 일부 재콘을 수행했을 가능성이 높으므로**, **모든 가능한 웹 서버를 이미 찾았을 수 있습니다**. 그러나 찾지 못했다면 이제 범위 내에서 웹 서버를 검색하기 위한 **빠른 요령**을 살펴보겠습니다.

이것은 **웹 앱 발견**을 위한 **지향적**인 것이므로, **취약점** 및 **포트 스캔**도 수행해야 합니다(**범위에서 허용되는 경우**).

[**masscan**을 사용하여 **웹** 서버와 관련된 **열려 있는 포트를 발견하는 빠른 방법**은 여기에서 찾을 수 있습니다](../pentesting-network/#http-port-discovery).\
웹 서버를 찾기 위한 또 다른 유용한 도구는 [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) 및 [**httpx**](https://github.com/projectdiscovery/httpx)입니다. 도메인 목록을 전달하면 포트 80(http) 및 443(https)에 연결을 시도합니다. 추가로 다른 포트를 시도하도록 지정할 수 있습니다:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **스크린샷**

이제 **범위 내의 모든 웹 서버**를 발견했으므로 (**회사의 **IP**와 모든 **도메인** 및 **서브도메인** 중에서) 아마도 **어디서 시작해야 할지 모를 것입니다**. 그러니 간단하게 시작하여 모든 웹 서버의 스크린샷을 찍어보세요. **메인 페이지**를 **살펴보는 것만으로도** **이상한** 엔드포인트를 발견할 수 있으며, 이는 더 **취약**할 가능성이 높습니다.

제안된 아이디어를 수행하기 위해 [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) 또는 [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**를 사용할 수 있습니다.**

또한, [**eyeballer**](https://github.com/BishopFox/eyeballer)를 사용하여 모든 **스크린샷**을 분석하여 **취약점이 있을 가능성이 있는 것**과 그렇지 않은 것을 알려줄 수 있습니다.

## 퍼블릭 클라우드 자산

회사의 잠재적인 클라우드 자산을 찾기 위해서는 **회사를 식별하는 키워드 목록**으로 시작해야 합니다. 예를 들어, 암호화폐 회사의 경우 다음과 같은 단어를 사용할 수 있습니다: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

또한 **버킷에서 사용되는 일반 단어**의 단어 목록이 필요합니다:

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

그런 다음, 이러한 단어로 **순열**을 생성해야 합니다 (자세한 내용은 [**두 번째 라운드 DNS 브루트포스**](./#second-dns-bruteforce-round)를 참조하세요).

결과로 얻은 단어 목록을 사용하여 [**cloud\_enum**](https://github.com/initstring/cloud\_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **또는** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**와 같은 도구를 사용할 수 있습니다.**

클라우드 자산을 찾을 때는 **AWS의 버킷 이상으로 찾아야 한다는 점을 기억하세요**.

### **취약점 찾기**

**열린 버킷이나 노출된 클라우드 기능**과 같은 것을 발견하면 **접속하여** 제공하는 내용을 확인하고 이를 악용할 수 있는지 확인해야 합니다.

## 이메일

범위 내의 **도메인**과 **서브도메인**을 통해 **이메일 검색을 시작하는 데 필요한 모든 것**을 갖추게 됩니다. 다음은 회사의 이메일을 찾는 데 가장 효과적이었던 **API**와 **도구**입니다:

* [**theHarvester**](https://github.com/laramies/theHarvester) - API 사용
* [**https://hunter.io/**](https://hunter.io/)의 API (무료 버전)
* [**https://app.snov.io/**](https://app.snov.io/)의 API (무료 버전)
* [**https://minelead.io/**](https://minelead.io/)의 API (무료 버전)

### **취약점 찾기**

이메일은 나중에 **웹 로그인 및 인증 서비스**(예: SSH)에 대한 **브루트포스 공격**에 유용합니다. 또한, **피싱**에도 필요합니다. 게다가, 이러한 API는 이메일 뒤에 있는 **사람에 대한 더 많은 정보**를 제공하므로 피싱 캠페인에 유용합니다.

## 자격 증명 유출

**도메인**, **서브도메인**, 및 **이메일**을 통해 과거에 유출된 자격 증명을 찾기 시작할 수 있습니다:

* [https://leak-lookup.com](https://leak-lookup.com/account/login)
* [https://www.dehashed.com/](https://www.dehashed.com/)

### **취약점 찾기**

**유효한 유출된** 자격 증명을 발견하면, 이는 매우 쉬운 승리입니다.

## 비밀 유출

자격 증명 유출은 **민감한 정보가 유출되어 판매된** 회사의 해킹과 관련이 있습니다. 그러나 회사는 이러한 데이터베이스에 없는 **다른 유출**로 인해 영향을 받을 수 있습니다:

### 깃허브 유출

자격 증명 및 API는 **회사의 공개 리포지토리** 또는 해당 깃허브 회사에서 일하는 **사용자**의 공개 리포지토리에 유출될 수 있습니다.\
**Leakos**라는 **도구**를 사용하여 **조직** 및 그 **개발자**의 모든 **공개 리포**를 **다운로드**하고 자동으로 [**gitleaks**](https://github.com/zricethezav/gitleaks)를 실행할 수 있습니다.

**Leakos**는 또한 제공된 **URL**에 대해 **gitleaks**를 실행하는 데 사용할 수 있으며, 때때로 **웹 페이지에도 비밀이 포함되어 있습니다**.

#### 깃허브 도크

공격 중인 조직에서 검색할 수 있는 잠재적인 **깃허브 도크**에 대한 **페이지**도 확인하세요:

{% content-ref url="github-leaked-secrets.md" %}
[github-leaked-secrets.md](github-leaked-secrets.md)
{% endcontent-ref %}

### 페이스트 유출

때때로 공격자나 단순한 직원이 **회사 콘텐츠를 페이스트 사이트에 게시**합니다. 이는 **민감한 정보**를 포함할 수도 있고 포함하지 않을 수도 있지만, 검색할 가치가 있습니다.\
[**Pastos**](https://github.com/carlospolop/Pastos)라는 도구를 사용하여 동시에 80개 이상의 페이스트 사이트에서 검색할 수 있습니다.

### 구글 도크

오래되었지만 여전히 유용한 구글 도크는 **거기에 있어서는 안 되는 노출된 정보를 찾는 데 항상 유용합니다**. 유일한 문제는 [**구글 해킹 데이터베이스**](https://www.exploit-db.com/google-hacking-database)에 수천 개의 가능한 쿼리가 포함되어 있어 수동으로 실행할 수 없다는 것입니다. 따라서 좋아하는 10개를 선택하거나 [**Gorks**](https://github.com/carlospolop/Gorks)와 같은 **도구를 사용하여 모두 실행할 수 있습니다**.

_정기적인 Google 브라우저를 사용하여 모든 데이터베이스를 실행하려는 도구는 매우 빨리 차단되므로 결코 끝나지 않을 것입니다._

### **취약점 찾기**

**유효한 유출된** 자격 증명이나 API 토큰을 발견하면, 이는 매우 쉬운 승리입니다.

## 공개 코드 취약점

회사가 **오픈 소스 코드**를 가지고 있다면 이를 **분석**하고 **취약점**을 검색할 수 있습니다.

**언어에 따라** 사용할 수 있는 다양한 **도구**가 있습니다:

{% content-ref url="../../network-services-pentesting/pentesting-web/code-review-tools.md" %}
[code-review-tools.md](../../network-services-pentesting/pentesting-web/code-review-tools.md)
{% endcontent-ref %}

또한 **공개 리포지토리**를 **스캔**할 수 있는 무료 서비스도 있습니다:

* [**Snyk**](https://app.snyk.io/)

## [**웹 펜테스팅 방법론**](../../network-services-pentesting/pentesting-web/)

**버그 헌터**가 발견한 **대부분의 취약점**은 **웹 애플리케이션** 내에 존재하므로, 이 시점에서 **웹 애플리케이션 테스트 방법론**에 대해 이야기하고 싶습니다. [**여기에서 이 정보를 찾을 수 있습니다**](../../network-services-pentesting/pentesting-web/).

또한 [**웹 자동 스캐너 오픈 소스 도구**](../../network-services-pentesting/pentesting-web/#automatic-scanners) 섹션에 특별히 언급하고 싶습니다. 이 도구들은 매우 민감한 취약점을 찾는 데 기대하지 말아야 하지만, **초기 웹 정보를 얻기 위한 워크플로우에 구현하는 데 유용합니다**.

## 요약

> 축하합니다! 이 시점에서 **모든 기본 열거 작업**을 수행했습니다. 네, 기본적입니다. 더 많은 열거 작업이 가능하니까요 (나중에 더 많은 트릭을 볼 것입니다).

따라서 이미 다음을 수행했습니다:

1. 범위 내의 모든 **회사**를 찾았습니다.
2. 회사에 속하는 모든 **자산**을 찾았습니다 (범위 내에서 취약점 스캔 수행).
3. 회사에 속하는 모든 **도메인**을 찾았습니다.
4. 도메인의 모든 **서브도메인**을 찾았습니다 (서브도메인 탈취 가능성은 있나요?).
5. 범위 내의 모든 **IP**를 찾았습니다 (CDN에서 온 것과 아닌 것).
6. 모든 **웹 서버**를 찾고 **스크린샷**을 찍었습니다 (더 깊이 살펴볼 가치가 있는 이상한 점이 있나요?).
7. 회사에 속하는 모든 **잠재적인 공개 클라우드 자산**을 찾았습니다.
8. **이메일**, **자격 증명 유출**, 및 **비밀 유출**로 인해 **매우 쉽게 큰 승리를 얻을 수 있습니다**.
9. 발견한 모든 웹을 **펜테스팅**했습니다.

## **전체 재콘 자동 도구**

주어진 범위에 대해 제안된 작업의 일부를 수행하는 여러 도구가 있습니다.

* [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
* [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
* [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
* [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 조금 오래되었고 업데이트되지 않음

## **참고 문헌**

* [**@Jhaddix**](https://twitter.com/Jhaddix)의 모든 무료 강좌, 예를 들어 [**버그 헌터의 방법론 v4.0 - 재콘 에디션**](https://www.youtube.com/watch?v=p4JgIu1mceI)

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

**해킹 경력**에 관심이 있고 해킹할 수 없는 것을 해킹하고 싶다면 - **우리는 채용 중입니다!** (_유창한 폴란드어 필기 및 구사 필요_).

{% embed url="https://www.stmcyber.com/careers" %}

{% hint style="success" %}
AWS 해킹 배우고 연습하기:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우고 연습하기: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter**에서 **팔로우**하세요** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>
{% endhint %}
