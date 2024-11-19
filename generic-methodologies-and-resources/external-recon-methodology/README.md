# 外部侦察方法论

{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

如果你对 **黑客职业** 感兴趣并想要攻克不可攻克的目标 - **我们正在招聘！** (_需要流利的波兰语书写和口语能力_).

{% embed url="https://www.stmcyber.com/careers" %}

## 资产发现

> 所以你被告知某家公司所有的东西都在范围内，你想弄清楚这家公司实际上拥有什么。

这个阶段的目标是获取**主要公司拥有的所有公司**，然后获取这些公司的所有**资产**。为此，我们将：

1. 找到主要公司的收购，这将给我们提供范围内的公司。
2. 找到每个公司的 ASN（如果有的话），这将给我们提供每个公司拥有的 IP 范围。
3. 使用反向 whois 查询搜索与第一个相关的其他条目（组织名称、域名...）（这可以递归进行）。
4. 使用其他技术，如 shodan `org` 和 `ssl` 过滤器来搜索其他资产（`ssl` 技巧可以递归进行）。

### **收购**

首先，我们需要知道**主要公司拥有的其他公司**。\
一个选项是访问 [https://www.crunchbase.com/](https://www.crunchbase.com)，**搜索** **主要公司**，并**点击**“**收购**”。在那里你将看到主要公司收购的其他公司。\
另一个选项是访问主要公司的 **维基百科** 页面并搜索 **收购**。

> 好吧，到这个时候你应该知道范围内的所有公司。让我们弄清楚如何找到它们的资产。

### **ASNs**

自治系统编号（**ASN**）是由 **互联网分配号码管理局（IANA）** 分配给 **自治系统**（AS）的 **唯一编号**。\
一个 **AS** 由 **IP 地址块** 组成，这些地址块有明确的政策来访问外部网络，并由单一组织管理，但可能由多个运营商组成。

找出**公司是否分配了任何 ASN** 以找到其 **IP 范围** 是很有趣的。对所有**范围内的主机**进行 **漏洞测试** 并 **查找这些 IP 内的域名** 将是很有意义的。\
你可以在 [**https://bgp.he.net/**](https://bgp.he.net)** 中按公司 **名称**、**IP** 或 **域名** 进行 **搜索**。\
**根据公司的地区，这些链接可能对收集更多数据有用：** [**AFRINIC**](https://www.afrinic.net) **（非洲），** [**Arin**](https://www.arin.net/about/welcome/region/)**（北美），** [**APNIC**](https://www.apnic.net) **（亚洲），** [**LACNIC**](https://www.lacnic.net) **（拉丁美洲），** [**RIPE NCC**](https://www.ripe.net) **（欧洲）。无论如何，所有的** 有用信息 **（IP 范围和 Whois）** 可能已经在第一个链接中出现。
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
此外，**[BBOT](https://github.com/blacklanternsecurity/bbot)**的子域名枚举会在扫描结束时自动聚合和总结ASN。
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
您可以使用 [http://asnlookup.com/](http://asnlookup.com) 查找组织的 IP 范围（它有免费的 API）。\
您可以使用 [http://ipv4info.com/](http://ipv4info.com) 查找域名的 IP 和 ASN。

### **寻找漏洞**

在这一点上，我们知道 **范围内的所有资产**，所以如果您被允许，可以对所有主机启动一些 **漏洞扫描器**（Nessus, OpenVAS）。\
此外，您可以启动一些 [**端口扫描**](../pentesting-network/#discovering-hosts-from-the-outside) **或使用像** shodan **这样的服务来查找** 开放端口 **，根据您发现的内容，您应该** 查看本书以了解如何对多个可能运行的服务进行渗透测试。\
**此外，值得一提的是，您还可以准备一些** 默认用户名 **和** 密码 **列表，并尝试使用 [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) 进行** 暴力破解服务**。

## 域名

> 我们知道范围内的所有公司及其资产，现在是时候查找范围内的域名了。

_请注意，在以下提出的技术中，您还可以找到子域名，这些信息不应被低估。_

首先，您应该查找每个公司的 **主域名**。例如，对于 _Tesla Inc._，主域名将是 _tesla.com_。

### **反向 DNS**

由于您已经找到了域名的所有 IP 范围，您可以尝试对这些 **IP 执行反向 DNS 查找，以查找范围内的更多域名**。尝试使用受害者的一些 DNS 服务器或一些知名的 DNS 服务器（1.1.1.1, 8.8.8.8）。
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
为了使其工作，管理员必须手动启用 PTR。\
您还可以使用在线工具获取此信息：[http://ptrarchive.com/](http://ptrarchive.com)

### **反向 Whois（循环）**

在 **whois** 中，您可以找到很多有趣的 **信息**，例如 **组织名称**、**地址**、**电子邮件**、电话号码……但更有趣的是，如果您通过这些字段中的任何一个执行 **反向 whois 查询**，您可以找到 **与公司相关的更多资产**（例如，其他 whois 注册处中出现相同电子邮件的情况）。\
您可以使用在线工具，例如：

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **免费**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **免费**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **免费**
* [https://www.whoxy.com/](https://www.whoxy.com) - **免费**网页，不免费API。
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - 不免费
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 不免费（仅 **100 次免费** 查询）
* [https://www.domainiq.com/](https://www.domainiq.com) - 不免费

您可以使用 [**DomLink** ](https://github.com/vysecurity/DomLink) 自动化此任务（需要 whoxy API 密钥）。\
您还可以使用 [amass](https://github.com/OWASP/Amass) 执行一些自动反向 whois 发现：`amass intel -d tesla.com -whois`

**请注意，每次找到新域名时，您可以使用此技术发现更多域名。**

### **跟踪器**

如果在两个不同页面中找到 **相同的跟踪器 ID**，您可以推测 **这两个页面** 是 **由同一团队管理**。\
例如，如果您在多个页面上看到相同的 **Google Analytics ID** 或相同的 **Adsense ID**。

有一些页面和工具可以让您通过这些跟踪器和更多内容进行搜索：

* [**Udon**](https://github.com/dhn/udon)
* [**BuiltWith**](https://builtwith.com)
* [**Sitesleuth**](https://www.sitesleuth.io)
* [**Publicwww**](https://publicwww.com)
* [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

您知道我们可以通过查找相同的 favicon 图标哈希来找到与目标相关的域名和子域名吗？这正是 [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) 工具由 [@m4ll0k2](https://twitter.com/m4ll0k2) 制作的功能。以下是如何使用它：
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - 发现具有相同 favicon 图标哈希的域](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

简单来说，favihash 允许我们发现与我们的目标具有相同 favicon 图标哈希的域。

此外，您还可以使用 favicon 哈希搜索技术，如 [**这篇博客文章**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139) 中所述。这意味着如果您知道 **易受攻击的 web 技术的 favicon 哈希**，您可以在 shodan 中搜索并 **找到更多易受攻击的地方**：
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
这是您如何**计算网页的 favicon 哈希**：
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
### **版权 / 唯一字符串**

在网页中搜索**可能在同一组织的不同网站之间共享的字符串**。**版权字符串**可能是一个很好的例子。然后在**谷歌**、其他**浏览器**或甚至在**shodan**中搜索该字符串：`shodan search http.html:"Copyright string"`

### **CRT时间**

通常会有一个cron作业，例如
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
to renew the all the domain certificates on the server. This means that even if the CA used for this doesn't set the time it was generated in the Validity time, it's possible to **find domains belonging to the same company in the certificate transparency logs**.\
Check out this [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### Mail DMARC information

You can use a web such as [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) or a tool such as [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) to find **共享相同 DMARC 信息的域名和子域名**.

### **Passive Takeover**

Apparently is common for people to assign subdomains to IPs that belongs to cloud providers and at some point **失去该 IP 地址但忘记删除 DNS 记录**. Therefore, just **在云中创建一个虚拟机** (like Digital Ocean) you will be actually **接管一些子域名**.

[**This post**](https://kmsec.uk/blog/passive-takeover/) explains a store about it and propose a script that **在 DigitalOcean 中创建一个虚拟机**, **获取** the **IPv4** of the new machine, and **在 Virustotal 中搜索指向它的子域名记录**.

### **Other ways**

**Note that you can use this technique to discover more domain names every time you find a new domain.**

**Shodan**

As you already know the name of the organisation owning the IP space. You can search by that data in shodan using: `org:"Tesla, Inc."` Check the found hosts for new unexpected domains in the TLS certificate.

You could access the **TLS certificate** of the main web page, obtain the **组织名称** and then search for that name inside the **TLS certificates** of all the web pages known by **shodan** with the filter : `ssl:"Tesla Motors"` or use a tool like [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)是一个查找与主域名相关的**域名**和它们的**子域名**的工具，真是太棒了。

### **Looking for vulnerabilities**

Check for some [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Maybe some company is **使用某个域名** but they **失去了所有权**. Just register it (if cheap enough) and let know the company.

If you find any **域名的 IP 地址与您在资产发现中找到的不同**, you should perform a **基本漏洞扫描** (using Nessus or OpenVAS) and some [**端口扫描**](../pentesting-network/#discovering-hosts-from-the-outside) with **nmap/masscan/shodan**. Depending on which services are running you can find in **this book some tricks to "attack" them**.\
_Note that sometimes the domain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Bug bounty tip**: **注册** **Intigriti**, 一个由黑客为黑客创建的高级**漏洞赏金平台**！今天加入我们 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)，开始赚取高达 **$100,000** 的赏金！

{% embed url="https://go.intigriti.com/hacktricks" %}

## Subdomains

> We know all the companies inside the scope, all the assets of each company and all the domains related to the companies.

It's time to find all the possible subdomains of each found domain.

{% hint style="success" %}
Note that some of the tools and techniques to find domains can also help to find subdomains!
{% endhint %}

### **DNS**

Let's try to get **子域名** from the **DNS** records. We should also try for **区域传输** (If vulnerable, you should report it).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

获取大量子域名的最快方法是搜索外部来源。最常用的 **tools** 如下（为了获得更好的结果，请配置 API 密钥）：

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
还有一些**其他有趣的工具/API**，即使它们并不是专门用于查找子域名，也可能对查找子域名有用，例如：

* [**Crobat**](https://github.com/cgboal/sonarsearch)**:** 使用API [https://sonar.omnisint.io](https://sonar.omnisint.io) 来获取子域名
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
* [**JLDC 免费 API**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
* [**RapidDNS**](https://rapiddns.io) 免费API
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
* [**gau**](https://github.com/lc/gau)**:** 从AlienVault的开放威胁交换、Wayback Machine和Common Crawl获取任何给定域的已知URL。
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper)：它们在网上抓取JS文件并从中提取子域名。
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
* [**Censys 子域名查找器**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
* [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
* [**securitytrails.com**](https://securitytrails.com/) 提供免费的 API 用于搜索子域名和 IP 历史
* [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

该项目提供 **与漏洞悬赏计划相关的所有子域名** 的免费访问。您还可以使用 [chaospy](https://github.com/dr-0x0x/chaospy) 访问这些数据，甚至可以访问该项目使用的范围 [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

您可以在这里找到许多这些工具的 **比较**: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS 暴力破解**

让我们尝试通过暴力破解 DNS 服务器来查找新的 **子域名**，使用可能的子域名名称。

为此操作，您需要一些 **常见子域名字典，如**:

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

还需要一些好的 DNS 解析器的 IP。为了生成可信的 DNS 解析器列表，您可以从 [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) 下载解析器，并使用 [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) 进行过滤。或者您可以使用: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

最推荐的 DNS 暴力破解工具是:

* [**massdns**](https://github.com/blechschmidt/massdns): 这是第一个执行有效 DNS 暴力破解的工具。它非常快速，但容易产生误报。
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
* [**gobuster**](https://github.com/OJ/gobuster): 我认为这个只使用了一个解析器
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
* [**shuffledns**](https://github.com/projectdiscovery/shuffledns) 是一个围绕 `massdns` 的包装器，使用 Go 编写，允许您通过主动暴力破解枚举有效的子域名，并支持通配符处理和简单的输入输出。
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
* [**puredns**](https://github.com/d3mondev/puredns): 它也使用 `massdns`。
```
puredns bruteforce all.txt domain.com
```
* [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) 使用 asyncio 异步暴力破解域名。
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### 第二轮 DNS 暴力破解

在使用开放源和暴力破解找到子域名后，您可以生成找到的子域名的变体，以尝试找到更多。以下工具对此目的非常有用：

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** 给定域名和子域名生成排列。
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): 给定域名和子域名生成排列。
* 你可以在 [**这里**](https://github.com/subfinder/goaltdns/blob/master/words.txt) 获取 goaltdns 排列 **字典**。
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** 给定域名和子域名生成排列。如果没有指示排列文件，gotator 将使用自己的文件。
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns): 除了生成子域名排列，它还可以尝试解析它们（但最好使用之前提到的工具）。
* 你可以在 [**这里**](https://github.com/infosec-au/altdns/blob/master/words.txt) 获取 altdns 排列的 **wordlist**。
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): 另一个用于执行子域名的排列、变异和修改的工具。该工具将对结果进行暴力破解（不支持 DNS 通配符）。
* 您可以在 [**这里**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) 获取 dmut 排列词表。
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**:** 基于域名，它 **生成新的潜在子域名**，基于指示的模式以尝试发现更多子域名。

#### 智能排列生成

* [**regulator**](https://github.com/cramppet/regulator): 更多信息请阅读这篇 [**文章**](https://cramppet.github.io/regulator/index.html)，但它基本上会从 **发现的子域名** 中提取 **主要部分** 并进行混合以找到更多子域名。
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ 是一个子域名暴力破解模糊器，结合了一个极其简单但有效的 DNS 响应引导算法。它利用提供的一组输入数据，如定制的词汇表或历史 DNS/TLS 记录，准确合成更多相应的域名，并根据在 DNS 扫描期间收集的信息进一步扩展它们。
```
echo www | subzuf facebook.com
```
### **子域发现工作流程**

查看我写的这篇博客文章，关于如何使用 **Trickest workflows** **自动化子域发现**，这样我就不需要在我的电脑上手动启动一堆工具：

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/" %}

### **虚拟主机 / VHosts**

如果你发现一个包含 **一个或多个网页** 的 IP 地址属于子域，你可以尝试通过在 **OSINT 来源** 中查找该 IP 的域名，或者通过 **暴力破解该 IP 的 VHost 域名** 来 **寻找其他子域**。

#### OSINT

你可以使用 [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **或其他 API** 找到一些 **IP 中的 VHosts**。

**暴力破解**

如果你怀疑某个子域可能隐藏在一个网络服务器中，你可以尝试进行暴力破解：
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
使用此技术，您甚至可能能够访问内部/隐藏的端点。
{% endhint %}

### **CORS 暴力破解**

有时您会发现页面仅在有效的域/子域设置在 _**Origin**_ 头时返回头部 _**Access-Control-Allow-Origin**_。在这些情况下，您可以利用这种行为来 **发现** 新的 **子域**。
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

在寻找 **subdomains** 时，注意是否指向任何类型的 **bucket**，在这种情况下 [**检查权限**](../../network-services-pentesting/pentesting-web/buckets/)**.**\
此外，由于此时您将知道所有在范围内的域名，请尝试 [**暴力破解可能的 bucket 名称并检查权限**](../../network-services-pentesting/pentesting-web/buckets/)。

### **Monitorization**

您可以通过监控 **证书透明度** 日志来 **监控** 是否创建了域的新 **subdomains**，[**sublert**](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) 可以做到这一点。

### **Looking for vulnerabilities**

检查可能的 [**subdomain 接管**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)。\
如果 **subdomain** 指向某个 **S3 bucket**，[**检查权限**](../../network-services-pentesting/pentesting-web/buckets/)。

如果您发现任何 **subdomain 的 IP 与您在资产发现中找到的不同**，您应该执行 **基本漏洞扫描**（使用 Nessus 或 OpenVAS）和一些 [**端口扫描**](../pentesting-network/#discovering-hosts-from-the-outside) 使用 **nmap/masscan/shodan**。根据运行的服务，您可以在 **本书中找到一些“攻击”它们的技巧**。\
_请注意，有时 subdomain 托管在不受客户控制的 IP 内，因此不在范围内，请小心。_

## IPs

在初始步骤中，您可能已经 **找到了一些 IP 范围、域名和 subdomains**。\
现在是 **收集这些范围内的所有 IP** 和 **域名/subdomains（DNS 查询）**的时候。

使用以下 **免费 API** 的服务，您还可以找到 **域名和 subdomains 使用过的先前 IP**。这些 IP 可能仍然归客户所有（并可能让您找到 [**CloudFlare 绕过**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)）

* [**https://securitytrails.com/**](https://securitytrails.com/)

您还可以使用工具 [**hakip2host**](https://github.com/hakluke/hakip2host) 检查指向特定 IP 地址的域名。

### **Looking for vulnerabilities**

**对所有不属于 CDN 的 IP 进行端口扫描**（因为您很可能不会在其中找到任何有趣的东西）。在发现的运行服务中，您可能 **能够找到漏洞**。

**查找一个** [**指南**](../pentesting-network/) **关于如何扫描主机。**

## Web servers hunting

> 我们已经找到了所有公司及其资产，并且知道范围内的 IP 范围、域名和 subdomains。现在是搜索 web 服务器的时候了。

在之前的步骤中，您可能已经对发现的 **IPs 和域名** 进行了某些 **侦察**，因此您可能 **已经找到了所有可能的 web 服务器**。但是，如果您还没有，我们现在将看到一些 **快速技巧来搜索范围内的 web 服务器**。

请注意，这将是 **面向 web 应用程序发现** 的，因此您还应该 **执行漏洞** 和 **端口扫描**（如果范围允许）。

一种 **快速方法** 是使用 [**masscan** 在此处发现与 **web** 服务器相关的 **开放端口**](../pentesting-network/#http-port-discovery)。\
另一个友好的工具来查找 web 服务器是 [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) 和 [**httpx**](https://github.com/projectdiscovery/httpx)。您只需传递一个域名列表，它将尝试连接到 80（http）和 443（https）端口。此外，您可以指示尝试其他端口：
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **截图**

现在您已经发现了范围内的**所有网络服务器**（在公司的**IP**和所有**域名**及**子域名**中），您可能**不知道从哪里开始**。所以，让我们简单一点，先对它们进行截图。仅通过**查看****主页**，您就可以找到更**容易**被**利用**的**奇怪**端点。

要执行所提议的想法，您可以使用 [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/)、[**Gowitness**](https://github.com/sensepost/gowitness) 或 [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**。**

此外，您还可以使用 [**eyeballer**](https://github.com/BishopFox/eyeballer) 来分析所有的**截图**，告诉您**哪些可能包含漏洞**，哪些则不然。

## 公有云资产

为了找到属于公司的潜在云资产，您应该**从一份识别该公司的关键词列表开始**。例如，对于一家加密公司，您可以使用以下词汇：“`"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`”。

您还需要**常用词汇的字典**，用于存储桶：

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

然后，使用这些词汇生成**排列组合**（有关更多信息，请查看 [**第二轮DNS暴力破解**](./#second-dns-bruteforce-round)）。

使用生成的字典，您可以使用工具，如 [**cloud\_enum**](https://github.com/initstring/cloud\_enum)**、** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**、** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **或** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**。**

请记住，在寻找云资产时，您应该**寻找的不仅仅是AWS中的存储桶**。

### **寻找漏洞**

如果您发现**开放的存储桶或暴露的云函数**，您应该**访问它们**，看看它们提供了什么，以及您是否可以利用它们。

## 电子邮件

通过范围内的**域名**和**子域名**，您基本上拥有了**开始搜索电子邮件**所需的所有信息。这些是我找到公司电子邮件时效果最好的**API**和**工具**：

* [**theHarvester**](https://github.com/laramies/theHarvester) - 使用API
* [**https://hunter.io/**](https://hunter.io/) 的API（免费版）
* [**https://app.snov.io/**](https://app.snov.io/) 的API（免费版）
* [**https://minelead.io/**](https://minelead.io/) 的API（免费版）

### **寻找漏洞**

电子邮件在后续将对**暴力破解网络登录和身份验证服务**（如SSH）非常有用。此外，它们在**钓鱼**中也是必需的。此外，这些API还会提供有关电子邮件背后**个人**的更多**信息**，这对钓鱼活动非常有用。

## 凭证泄露

通过**域名**、**子域名**和**电子邮件**，您可以开始寻找过去泄露的与这些电子邮件相关的凭证：

* [https://leak-lookup.com](https://leak-lookup.com/account/login)
* [https://www.dehashed.com/](https://www.dehashed.com/)

### **寻找漏洞**

如果您发现**有效的泄露**凭证，这将是一个非常简单的胜利。

## 秘密泄露

凭证泄露与公司被黑客攻击时**敏感信息被泄露和出售**有关。然而，公司可能还会受到**其他泄露**的影响，这些信息不在那些数据库中：

### Github泄露

凭证和API可能在**公司**或在该github公司工作的**用户**的**公共仓库**中泄露。\
您可以使用**工具** [**Leakos**](https://github.com/carlospolop/Leakos) 来**下载**一个**组织**及其**开发者**的所有**公共仓库**，并自动运行 [**gitleaks**](https://github.com/zricethezav/gitleaks)。

**Leakos** 还可以用于对所有**文本**提供的**URL**运行**gitleaks**，因为有时**网页中也包含秘密**。

#### Github Dorks

还可以查看此**页面**，寻找您可以在攻击的组织中搜索的潜在**github dorks**：

{% content-ref url="github-leaked-secrets.md" %}
[github-leaked-secrets.md](github-leaked-secrets.md)
{% endcontent-ref %}

### Paste泄露

有时攻击者或仅仅是员工会在**粘贴网站**上**发布公司内容**。这可能包含或不包含**敏感信息**，但搜索它非常有趣。\
您可以使用工具 [**Pastos**](https://github.com/carlospolop/Pastos) 在80多个粘贴网站上同时搜索。

### Google Dorks

老而金贵的google dorks始终对寻找**不应存在的暴露信息**非常有用。唯一的问题是 [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) 包含数千个您无法手动运行的可能查询。因此，您可以选择您最喜欢的10个，或者使用**工具，如** [**Gorks**](https://github.com/carlospolop/Gorks) **来运行它们所有**。

_请注意，期望使用常规Google浏览器运行所有数据库的工具将永远无法完成，因为Google会很快阻止您。_

### **寻找漏洞**

如果您发现**有效的泄露**凭证或API令牌，这将是一个非常简单的胜利。

## 公共代码漏洞

如果您发现公司有**开源代码**，您可以**分析**它并搜索其中的**漏洞**。

**根据语言**的不同，您可以使用不同的**工具**：

{% content-ref url="../../network-services-pentesting/pentesting-web/code-review-tools.md" %}
[code-review-tools.md](../../network-services-pentesting/pentesting-web/code-review-tools.md)
{% endcontent-ref %}

还有一些免费服务允许您**扫描公共仓库**，例如：

* [**Snyk**](https://app.snyk.io/)

## [**网络渗透测试方法**](../../network-services-pentesting/pentesting-web/)

**大多数漏洞**由漏洞猎人发现，存在于**网络应用程序**中，因此在这一点上，我想谈谈**网络应用程序测试方法**，您可以在 [**这里找到此信息**](../../network-services-pentesting/pentesting-web/)。

我还想特别提到[**Web自动扫描器开源工具**](../../network-services-pentesting/pentesting-web/#automatic-scanners)部分，因为如果您不应该期望它们找到非常敏感的漏洞，但它们在**工作流程中实现一些初步网络信息**时非常有用。

## 综述

> 恭喜！到目前为止，您已经完成了**所有基本枚举**。是的，这很基础，因为可以进行更多的枚举（稍后会看到更多技巧）。

所以您已经：

1. 找到了范围内的**所有公司**
2. 找到了属于公司的**所有资产**（并在范围内进行了一些漏洞扫描）
3. 找到了属于公司的**所有域名**
4. 找到了域名的**所有子域名**（是否有子域名接管？）
5. 找到了范围内的**所有IP**（来自和**不来自CDN**的IP）。
6. 找到了**所有网络服务器**并对它们进行了**截图**（是否有任何奇怪的地方值得深入研究？）
7. 找到了属于公司的**所有潜在公共云资产**。
8. **电子邮件**、**凭证泄露**和**秘密泄露**，可能会给您带来**非常轻松的重大胜利**。
9. **渗透测试您找到的所有网站**

## **全面侦查自动化工具**

有几种工具可以执行针对给定范围的部分提议操作。

* [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
* [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
* [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
* [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 有点旧且未更新

## **参考资料**

* 所有免费的 [**@Jhaddix**](https://twitter.com/Jhaddix) 课程，如 [**漏洞猎人的方法论 v4.0 - 侦查版**](https://www.youtube.com/watch?v=p4JgIu1mceI)

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

如果您对**黑客职业**和破解不可破解的东西感兴趣 - **我们正在招聘！**（_需要流利的波兰语书写和口语能力_）。

{% embed url="https://www.stmcyber.com/careers" %}

{% hint style="success" %}
学习和实践AWS黑客攻击：<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks培训AWS红队专家（ARTE）**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践GCP黑客攻击：<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks培训GCP红队专家（GRTE）**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **在Twitter上关注** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享黑客技巧。

</details>
{% endhint %}
