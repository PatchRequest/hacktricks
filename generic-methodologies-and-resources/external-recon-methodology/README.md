# 外部リコンメソドロジー

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを送信してください。**

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

**ハッキングキャリア**に興味があり、ハッキング不可能なものをハッキングしたい方 - **私たちは採用しています！** (_流暢なポーランド語の読み書きが必要です_)。

{% embed url="https://www.stmcyber.com/careers" %}

## 資産の発見

> ある会社に属するすべてのものがスコープ内にあると言われ、その会社が実際に所有しているものを把握したいと思っています。

このフェーズの目標は、**主要な会社が所有するすべての会社**を取得し、次にこれらの会社の**資産**を取得することです。そのために、私たちは以下を行います：

1. 主要な会社の買収を見つけます。これにより、スコープ内の会社がわかります。
2. 各会社のASN（あれば）を見つけます。これにより、各会社が所有するIP範囲がわかります。
3. 逆Whois検索を使用して、最初のものに関連する他のエントリ（組織名、ドメインなど）を検索します（これは再帰的に行うことができます）。
4. shodanの`org`および`ssl`フィルターなどの他の技術を使用して、他の資産を検索します（`ssl`トリックは再帰的に行うことができます）。

### **買収**

まず、**主要な会社が所有する他の会社**を知る必要があります。\
1つのオプションは、[https://www.crunchbase.com/](https://www.crunchbase.com)を訪れ、**主要な会社**を**検索**し、**「買収」**を**クリック**することです。そこでは、主要な会社によって取得された他の会社が表示されます。\
もう1つのオプションは、主要な会社の**Wikipedia**ページを訪れ、**買収**を検索することです。

> さて、この時点でスコープ内のすべての会社を知っているはずです。彼らの資産を見つける方法を考えましょう。

### **ASNs**

自律システム番号（**ASN**）は、**インターネット番号割り当て機関（IANA）**によって**自律システム**（AS）に割り当てられた**ユニークな番号**です。\
**AS**は、外部ネットワークへのアクセスに対して明確に定義されたポリシーを持つ**IPアドレス**の**ブロック**で構成され、単一の組織によって管理されますが、複数のオペレーターで構成される場合があります。

**会社が割り当てたASN**を見つけて、その**IP範囲**を特定することは興味深いです。**スコープ内のすべてのホスト**に対して**脆弱性テスト**を実施し、これらのIP内の**ドメイン**を探すことが興味深いでしょう。\
[**https://bgp.he.net/**](https://bgp.he.net)で会社の**名前**、**IP**、または**ドメイン**で**検索**できます。\
**会社の地域によっては、次のリンクがデータ収集に役立つかもしれません：** [**AFRINIC**](https://www.afrinic.net) **（アフリカ）、** [**Arin**](https://www.arin.net/about/welcome/region/) **（北アメリカ）、** [**APNIC**](https://www.apnic.net) **（アジア）、** [**LACNIC**](https://www.lacnic.net) **（ラテンアメリカ）、** [**RIPE NCC**](https://www.ripe.net) **（ヨーロッパ）。とにかく、恐らくすべての**有用な情報**（IP範囲とWhois）は最初のリンクにすでに表示されています。**
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
また、[**BBOT**](https://github.com/blacklanternsecurity/bbot)**の**サブドメイン列挙は、スキャンの最後にASNを自動的に集約し要約します。
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

### **脆弱性の探索**

この時点で、**スコープ内のすべての資産**を把握しているので、許可されている場合は、すべてのホストに対して**脆弱性スキャナー**（Nessus、OpenVAS）を実行することができます。\
また、いくつかの[**ポートスキャン**](../pentesting-network/#discovering-hosts-from-the-outside)を実行するか、shodanのようなサービスを使用して**オープンポート**を見つけ、見つけたものに応じて、この本を参照して実行中のさまざまなサービスをペンテストする方法を確認するべきです。\
**また、デフォルトのユーザー名**と**パスワード**リストを準備し、[https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray)を使用してサービスをブルートフォースすることも価値があるかもしれません。

## ドメイン

> スコープ内のすべての企業とその資産を把握したので、スコープ内のドメインを見つける時が来ました。

_以下の提案された技術では、サブドメインも見つけることができ、その情報は過小評価すべきではありません。_

まず、各企業の**主要なドメイン**を探すべきです。たとえば、_Tesla Inc._の主要なドメインは_tesla.com_です。

### **逆引きDNS**

ドメインのIP範囲をすべて見つけたので、これらの**IPに対して逆引きDNSルックアップ**を実行して、**スコープ内のさらに多くのドメインを見つける**ことができます。被害者のDNSサーバーまたは一般的なDNSサーバー（1.1.1.1、8.8.8.8）を使用してみてください。
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

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **無料**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **無料**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **無料**
* [https://www.whoxy.com/](https://www.whoxy.com) - **無料** web, not free API.
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - 無料ではない
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 無料ではない (only **100 free** searches)
* [https://www.domainiq.com/](https://www.domainiq.com) - 無料ではない

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
![favihash - 同じファビコンアイコンハッシュを持つドメインを発見する](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

簡単に言うと、favihashはターゲットと同じファビコンアイコンハッシュを持つドメインを発見することを可能にします。

さらに、[**このブログ記事**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)で説明されているように、ファビコンハッシュを使用して技術を検索することもできます。つまり、**脆弱なバージョンのウェブ技術のファビコンのハッシュ**を知っていれば、shodanで検索して**より多くの脆弱な場所を見つける**ことができます。
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
これはウェブの**ファビコンハッシュ**を計算する方法です：
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

異なるウェブサイト間で**同じ組織内で共有される可能性のある文字列**をウェブページ内で検索します。**著作権文字列**は良い例です。その後、**google**、他の**ブラウザ**、または**shodan**でその文字列を検索します: `shodan search http.html:"Copyright string"`

### **CRT Time**

cronジョブを持つことは一般的です。
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
to renew the all the domain certificates on the server. This means that even if the CA used for this doesn't set the time it was generated in the Validity time, it's possible to **find domains belonging to the same company in the certificate transparency logs**.\
Check out this [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### Mail DMARC情報

You can use a web such as [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) or a tool such as [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) to find **同じdmarc情報を共有するドメインとサブドメイン**.

### **パッシブテイクオーバー**

Apparently is common for people to assign subdomains to IPs that belongs to cloud providers and at some point **lose that IP address but forget about removing the DNS record**. Therefore, just **spawning a VM** in a cloud (like Digital Ocean) you will be actually **taking over some subdomains(s)**.

[**この投稿**](https://kmsec.uk/blog/passive-takeover/) explains a store about it and propose a script that **spawns a VM in DigitalOcean**, **gets** the **IPv4** of the new machine, and **searches in Virustotal for subdomain records** pointing to it.

### **他の方法**

**Note that you can use this technique to discover more domain names every time you find a new domain.**

**Shodan**

As you already know the name of the organisation owning the IP space. You can search by that data in shodan using: `org:"Tesla, Inc."` Check the found hosts for new unexpected domains in the TLS certificate.

You could access the **TLS certificate** of the main web page, obtain the **Organisation name** and then search for that name inside the **TLS certificates** of all the web pages known by **shodan** with the filter : `ssl:"Tesla Motors"` or use a tool like [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)is a tool that look for **メインドメインに関連するドメイン**とその**サブドメイン**を探す、非常に素晴らしいです。

### **脆弱性の探索**

Check for some [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Maybe some company is **using some a domain** but they **lost the ownership**. Just register it (if cheap enough) and let know the company.

If you find any **domain with an IP different** from the ones you already found in the assets discovery, you should perform a **basic vulnerability scan** (using Nessus or OpenVAS) and some [**port scan**](../pentesting-network/#discovering-hosts-from-the-outside) with **nmap/masscan/shodan**. Depending on which services are running you can find in **this book some tricks to "attack" them**.\
_Note that sometimes the domain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**バグバウンティのヒント**: **サインアップ**して**Intigriti**に参加しましょう。ハッカーによって、ハッカーのために作られたプレミアム**バグバウンティプラットフォーム**です！今日、[**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)に参加して、最大**$100,000**の報酬を得始めましょう！

{% embed url="https://go.intigriti.com/hacktricks" %}

## サブドメイン

> We know all the companies inside the scope, all the assets of each company and all the domains related to the companies.

It's time to find all the possible subdomains of each found domain.

{% hint style="success" %}
Note that some of the tools and techniques to find domains can also help to find subdomains!
{% endhint %}

### **DNS**

Let's try to get **サブドメイン** from the **DNS** records. We should also try for **ゾーン転送** (If vulnerable, you should report it).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

多くのサブドメインを迅速に取得する最も簡単な方法は、外部ソースを検索することです。最も使用される**ツール**は以下の通りです（より良い結果を得るためにAPIキーを設定してください）：

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
他にも**興味深いツール/API**があり、サブドメインを見つけることに特化していなくても、サブドメインを見つけるのに役立つかもしれません。例えば：

* [**Crobat**](https://github.com/cgboal/sonarsearch)**:** API [https://sonar.omnisint.io](https://sonar.omnisint.io)を使用してサブドメインを取得します。
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
* [**JLDC無料API**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
* [**RapidDNS**](https://rapiddns.io) 無料API
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
* [**gau**](https://github.com/lc/gau)**:** 任意のドメインに対して、AlienVaultのOpen Threat Exchange、Wayback Machine、およびCommon Crawlから既知のURLを取得します。
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): これらはウェブをスクレイピングしてJSファイルを探し、そこからサブドメインを抽出します。
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
* [**Censysサブドメインファインダー**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
* [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
* [**securitytrails.com**](https://securitytrails.com/) は、サブドメインとIP履歴を検索するための無料APIを提供しています
* [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

このプロジェクトは、**バグバウンティプログラムに関連するすべてのサブドメインを無料で提供**しています。このデータには、[chaospy](https://github.com/dr-0x0x/chaospy)を使用してアクセスすることもできますし、このプロジェクトで使用されているスコープにアクセスすることもできます [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

これらのツールの**比較**はここで見つけることができます: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNSブルートフォース**

可能なサブドメイン名を使用してDNSサーバーをブルートフォースして新しい**サブドメイン**を見つけてみましょう。

このアクションには、いくつかの**一般的なサブドメインのワードリスト**が必要です:

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

また、良好なDNSリゾルバのIPも必要です。信頼できるDNSリゾルバのリストを生成するために、[https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt)からリゾルバをダウンロードし、[**dnsvalidator**](https://github.com/vortexau/dnsvalidator)を使用してフィルタリングすることができます。または、[https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)を使用することもできます。

DNSブルートフォースに最も推奨されるツールは次のとおりです:

* [**massdns**](https://github.com/blechschmidt/massdns): これは効果的なDNSブルートフォースを実行した最初のツールです。非常に高速ですが、誤検知が発生しやすいです。
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
* [**gobuster**](https://github.com/OJ/gobuster): これは1つのリゾルバを使用していると思います。
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
* [**shuffledns**](https://github.com/projectdiscovery/shuffledns) は、`massdns` のラッパーで、Go で書かれており、アクティブブルートフォースを使用して有効なサブドメインを列挙することができ、ワイルドカード処理と簡単な入出力サポートを使用してサブドメインを解決することができます。
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
* [**puredns**](https://github.com/d3mondev/puredns): それは `massdns` も使用します。
```
puredns bruteforce all.txt domain.com
```
* [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) は、非同期にドメイン名をブルートフォースするために asyncio を使用します。
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### 第二のDNSブルートフォースラウンド

オープンソースとブルートフォースを使用してサブドメインを見つけた後、見つけたサブドメインの変種を生成してさらに多くを見つけることができます。この目的のために役立つツールがいくつかあります：

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** ドメインとサブドメインを与えると、順列を生成します。
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): ドメインとサブドメインを与えると、順列を生成します。
* goaltdnsの順列**ワードリスト**は[**こちら**](https://github.com/subfinder/goaltdns/blob/master/words.txt)で入手できます。
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** ドメインとサブドメインを与えると、順列を生成します。順列ファイルが指定されていない場合、gotatorは独自のファイルを使用します。
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns): サブドメインの順列を生成するだけでなく、それらを解決しようとすることもできます（ただし、前述のツールを使用する方が良いです）。
* altdnsの順列の**wordlist**は[**こちら**](https://github.com/infosec-au/altdns/blob/master/words.txt)で入手できます。
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): サブドメインの順列、変異、変更を行うための別のツール。このツールは結果をブルートフォースします（DNSワイルドカードはサポートしていません）。
* dmutの順列ワードリストは[**こちら**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)から取得できます。
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**:** 指定されたパターンに基づいて、**新しい潜在的なサブドメイン名を生成**し、より多くのサブドメインを発見しようとします。

#### スマートな順列生成

* [**regulator**](https://github.com/cramppet/regulator): 詳細についてはこの[**投稿**](https://cramppet.github.io/regulator/index.html)を読んでくださいが、基本的には**発見されたサブドメイン**の**主要部分**を取得し、それらを混ぜてより多くのサブドメインを見つけます。
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ は、非常にシンプルで効果的なDNS応答ガイドアルゴリズムと組み合わされたサブドメインブルートフォースファズザーです。提供された入力データセット（カスタマイズされた単語リストや過去のDNS/TLSレコードなど）を利用して、より対応するドメイン名を正確に合成し、DNSスキャン中に収集した情報に基づいてループ内でさらに拡張します。
```
echo www | subzuf facebook.com
```
### **サブドメイン発見ワークフロー**

私が書いたブログ記事をチェックしてください。**Trickestワークフロー**を使用してドメインから**サブドメイン発見を自動化する**方法について説明しています。これにより、コンピュータでツールを手動で起動する必要がなくなります：

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/" %}

### **VHosts / バーチャルホスト**

サブドメインに属する**1つまたは複数のウェブページ**を含むIPアドレスを見つけた場合、そのIP内の**ウェブがある他のサブドメインを見つける**ために、**OSINTソース**でIP内のドメインを探すか、**そのIP内のVHostドメイン名をブルートフォースする**ことを試みることができます。

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **や他のAPIを使用してIP内のいくつかのVHostsを見つけることができます**。

**ブルートフォース**

ウェブサーバーに隠されたサブドメインがあると疑う場合、それをブルートフォースすることを試みることができます：
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
この技術を使うことで、内部/隠れたエンドポイントにアクセスできる場合があります。
{% endhint %}

### **CORSブルートフォース**

時には、_**Origin**_ ヘッダーに有効なドメイン/サブドメインが設定されている場合にのみ、_**Access-Control-Allow-Origin**_ ヘッダーを返すページを見つけることがあります。このようなシナリオでは、この動作を悪用して新しい **サブドメイン** を **発見** することができます。
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **バケットブルートフォース**

**サブドメイン**を探しているときは、**バケット**のいずれかに**ポイント**しているかどうかに注意し、その場合は[**権限を確認**](../../network-services-pentesting/pentesting-web/buckets/)**してください。**\
また、この時点でスコープ内のすべてのドメインを知っているので、[**可能なバケット名をブルートフォースし、権限を確認**](../../network-services-pentesting/pentesting-web/buckets/)してみてください。

### **モニタリング**

**新しいサブドメイン**が作成されたかどうかを監視するには、**Certificate Transparency**ログを監視することができます。[**sublert**](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)がそれを行います。

### **脆弱性の検索**

可能な[**サブドメインテイクオーバー**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)を確認してください。\
もし**サブドメイン**が**S3バケット**を指している場合は、[**権限を確認**](../../network-services-pentesting/pentesting-web/buckets/)してください。

もし**資産発見**で見つけたものとは異なるIPを持つ**サブドメイン**を見つけた場合は、**基本的な脆弱性スキャン**（NessusやOpenVASを使用）と、**ポートスキャン**（**nmap/masscan/shodan**を使用）を実行する必要があります。実行中のサービスに応じて、**この本で「攻撃」するためのいくつかのトリックを見つけることができます**。\
_サブドメインがクライアントによって制御されていないIP内にホストされていることがあるため、スコープ外であることに注意してください。_

## IPs

初期のステップで**いくつかのIP範囲、ドメイン、サブドメイン**を**見つけたかもしれません**。\
これらの範囲から**すべてのIPを収集**し、**ドメイン/サブドメイン（DNSクエリ）**のための時間です。

以下の**無料API**のサービスを使用すると、**ドメインとサブドメインによって使用された以前のIP**も見つけることができます。これらのIPはクライアントによってまだ所有されている可能性があり、[**CloudFlareのバイパス**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)を見つける手助けになるかもしれません。

* [**https://securitytrails.com/**](https://securitytrails.com/)

特定のIPアドレスを指すドメインを確認するには、[**hakip2host**](https://github.com/hakluke/hakip2host)ツールを使用できます。

### **脆弱性の検索**

**CDNに属さないすべてのIPをポートスキャン**してください（そこでは興味深いものは見つからない可能性が高いです）。発見された実行中のサービスで**脆弱性を見つけることができるかもしれません**。

**ホストをスキャンする方法についての**[**ガイド**](../pentesting-network/)**を見つけてください。**

## ウェブサーバーハンティング

> すべての企業とその資産を見つけ、スコープ内のIP範囲、ドメイン、サブドメインを知っています。ウェブサーバーを探す時間です。

前のステップで、**発見されたIPとドメインのいくつかのリコンをすでに実行しているかもしれません**ので、**すでにすべての可能なウェブサーバーを見つけているかもしれません**。しかし、見つけていない場合は、スコープ内のウェブサーバーを検索するための**迅速なトリック**を見ていきます。

これは**ウェブアプリの発見**に向けられているため、**脆弱性**と**ポートスキャン**も実行する必要があります（**スコープによって許可されている場合**）。

**ウェブ**サーバーに関連する**オープンポート**を発見するための**迅速な方法**は、[**masscan**を使用してここにあります](../pentesting-network/#http-port-discovery)。\
ウェブサーバーを探すためのもう一つの便利なツールは、[**httprobe**](https://github.com/tomnomnom/httprobe)**、**[**fprobe**](https://github.com/theblackturtle/fprobe)および[**httpx**](https://github.com/projectdiscovery/httpx)です。ドメインのリストを渡すだけで、ポート80（http）と443（https）に接続しようとします。さらに、他のポートを試すように指示することもできます：
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **スクリーンショット**

スコープ内に存在する**すべてのウェブサーバー**（会社の**IP**やすべての**ドメイン**、**サブドメイン**の中から）を発見したので、どこから始めればよいかわからないかもしれません。そこで、シンプルにして、すべてのサーバーのスクリーンショットを撮ることから始めましょう。**メインページ**を**見るだけ**で、**脆弱性**がある可能性の高い**奇妙な**エンドポイントを見つけることができます。

提案されたアイデアを実行するには、[**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/)、[**Gowitness**](https://github.com/sensepost/gowitness)または[**webscreenshot**](https://github.com/maaaaz/webscreenshot)**を使用できます。**

さらに、[**eyeballer**](https://github.com/BishopFox/eyeballer)を使用して、すべての**スクリーンショット**を確認し、**脆弱性を含む可能性が高いもの**とそうでないものを教えてもらうことができます。

## パブリッククラウド資産

会社に属する潜在的なクラウド資産を見つけるためには、**その会社を特定するキーワードのリストから始めるべきです**。たとえば、暗号会社の場合、次のような単語を使用することがあります：`"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`。

**バケットで使用される一般的な単語のワードリスト**も必要です：

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

次に、それらの単語を使用して**順列**を生成する必要があります（詳細については[**第二ラウンドDNSブルートフォース**](./#second-dns-bruteforce-round)を確認してください）。

得られたワードリストを使用して、[**cloud\_enum**](https://github.com/initstring/cloud\_enum)**、**[**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**、**[**cloudlist**](https://github.com/projectdiscovery/cloudlist) **または** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**を使用できます。**

クラウド資産を探す際には、**AWSのバケットだけでなく、他のものも探すべきです**。

### **脆弱性の検索**

**オープンバケットや公開されたクラウド機能**などを見つけた場合は、それに**アクセスして**、何を提供しているのか、悪用できるかどうかを確認するべきです。

## メール

スコープ内の**ドメイン**と**サブドメイン**を持っているので、**メールを検索するために必要なすべてのものがあります**。これらは、会社のメールを見つけるために私が最も効果的だと感じた**API**と**ツール**です：

* [**theHarvester**](https://github.com/laramies/theHarvester) - APIを使用
* [**https://hunter.io/**](https://hunter.io/)のAPI（無料版）
* [**https://app.snov.io/**](https://app.snov.io/)のAPI（無料版）
* [**https://minelead.io/**](https://minelead.io/)のAPI（無料版）

### **脆弱性の検索**

メールは後で**ウェブログインや認証サービス**（SSHなど）を**ブルートフォース**するのに役立ちます。また、**フィッシング**にも必要です。さらに、これらのAPIは、フィッシングキャンペーンに役立つ**メールの背後にいる人物に関する情報**をさらに提供します。

## 資格情報の漏洩

**ドメイン、** **サブドメイン、** **メール**を使用して、過去に漏洩した資格情報を探し始めることができます：

* [https://leak-lookup.com](https://leak-lookup.com/account/login)
* [https://www.dehashed.com/](https://www.dehashed.com/)

### **脆弱性の検索**

**有効な漏洩した**資格情報を見つけた場合、これは非常に簡単な勝利です。

## 秘密の漏洩

資格情報の漏洩は、**機密情報が漏洩して販売された**企業のハッキングに関連しています。ただし、企業は、これらのデータベースに情報がない**他の漏洩**の影響を受ける可能性があります：

### Githubの漏洩

資格情報やAPIは、**会社**やその**ユーザー**の**公開リポジトリ**で漏洩する可能性があります。\
**Leakos**という**ツール**を使用して、**組織**とその**開発者**のすべての**公開リポジトリ**を**ダウンロード**し、自動的に[**gitleaks**](https://github.com/zricethezav/gitleaks)を実行できます。

**Leakos**は、提供された**URL**に対して**gitleaks**を実行するためにも使用でき、時には**ウェブページにも秘密が含まれている**ことがあります。

#### Github Dorks

攻撃している組織で検索できる潜在的な**github dorks**については、この**ページ**も確認してください：

{% content-ref url="github-leaked-secrets.md" %}
[github-leaked-secrets.md](github-leaked-secrets.md)
{% endcontent-ref %}

### ペーストの漏洩

時には攻撃者や単なる従業員が**会社のコンテンツをペーストサイトに公開**します。これには**機密情報**が含まれている場合もあれば、含まれていない場合もありますが、検索するのは非常に興味深いです。\
[**Pastos**](https://github.com/carlospolop/Pastos)というツールを使用して、80以上のペーストサイトを同時に検索できます。

### Google Dorks

古くても金の価値があるGoogle Dorksは、**そこにあるべきでない情報を見つける**のに常に役立ちます。唯一の問題は、[**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)に、手動で実行できない**数千**の可能なクエリが含まれていることです。したがって、お気に入りの10個を取得するか、[**Gorks**](https://github.com/carlospolop/Gorks)のような**ツールを使用してすべてを実行**することができます。

_すべてのデータベースを通常のGoogleブラウザを使用して実行しようとするツールは、Googleが非常に早くブロックするため、決して終わらないことに注意してください。_

### **脆弱性の検索**

**有効な漏洩した**資格情報やAPIトークンを見つけた場合、これは非常に簡単な勝利です。

## 公開コードの脆弱性

会社が**オープンソースコード**を持っていることがわかった場合、それを**分析**して**脆弱性**を探すことができます。

**言語によって**異なる**ツール**を使用できます：

{% content-ref url="../../network-services-pentesting/pentesting-web/code-review-tools.md" %}
[code-review-tools.md](../../network-services-pentesting/pentesting-web/code-review-tools.md)
{% endcontent-ref %}

また、**公開リポジトリをスキャン**するための無料サービスもあります：

* [**Snyk**](https://app.snyk.io/)

## [**ウェブペンテスト手法**](../../network-services-pentesting/pentesting-web/)

**バグハンターによって見つかった脆弱性の大多数**は**ウェブアプリケーション**内に存在するため、この時点で**ウェブアプリケーションテスト手法**について話したいと思います。詳細は[**こちらで確認できます**](../../network-services-pentesting/pentesting-web/)。

また、[**Web Automated Scannersオープンソースツール**](../../network-services-pentesting/pentesting-web/#automatic-scanners)のセクションにも特別な言及をしたいと思います。非常に機密性の高い脆弱性を見つけることを期待すべきではありませんが、**初期のウェブ情報を得るためのワークフローに実装するのに役立ちます**。

## 再確認

> おめでとうございます！この時点で、**すべての基本的な列挙**をすでに実行しています。はい、基本的なことです。さらに多くの列挙が可能です（後でさらにトリックを見ていきます）。

したがって、すでに次のことを行いました：

1. スコープ内のすべての**会社**を見つけた
2. 会社に属するすべての**資産**を見つけた（スコープ内で脆弱性スキャンを実行）
3. 会社に属するすべての**ドメイン**を見つけた
4. ドメインのすべての**サブドメイン**を見つけた（サブドメインの乗っ取りはありますか？）
5. スコープ内のすべての**IP**（CDNからのものとそうでないもの）を見つけた
6. すべての**ウェブサーバー**を見つけ、**スクリーンショット**を撮った（より深く見る価値のある奇妙なものはありますか？）
7. 会社に属するすべての**潜在的なパブリッククラウド資産**を見つけた
8. **メール**、**資格情報の漏洩**、および**秘密の漏洩**があり、**非常に簡単に大きな勝利を得ることができる**。
9. **見つけたすべてのウェブをペンテストする**

## **フルリコン自動ツール**

特定のスコープに対して提案されたアクションの一部を実行するツールがいくつかあります。

* [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
* [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
* [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
* [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 少し古く、更新されていません

## **参考文献**

* [**@Jhaddix**](https://twitter.com/Jhaddix)のすべての無料コース、例えば[**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

**ハッキングキャリア**に興味があり、ハッキング不可能なものをハッキングしたい方 - **私たちは採用しています！**（_流暢なポーランド語の読み書きが必要_）。

{% embed url="https://www.stmcyber.com/careers" %}

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で**フォロー**してください 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングトリックを共有するために、** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}
