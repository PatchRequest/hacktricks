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

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

If you are interested in **hacking career** and hack the unhackable - **we are hiring!** (_polonais courant écrit et parlé requis_).

{% embed url="https://www.stmcyber.com/careers" %}

## Découvertes d'actifs

> On vous a dit que tout ce qui appartient à une entreprise est dans le champ d'application, et vous voulez découvrir ce que cette entreprise possède réellement.

L'objectif de cette phase est d'obtenir toutes les **entreprises possédées par la société principale** et ensuite tous les **actifs** de ces entreprises. Pour ce faire, nous allons :

1. Trouver les acquisitions de la société principale, cela nous donnera les entreprises dans le champ d'application.
2. Trouver l'ASN (s'il y en a un) de chaque entreprise, cela nous donnera les plages IP possédées par chaque entreprise.
3. Utiliser des recherches whois inversées pour rechercher d'autres entrées (noms d'organisation, domaines...) liées à la première (cela peut être fait de manière récursive).
4. Utiliser d'autres techniques comme les filtres shodan `org` et `ssl` pour rechercher d'autres actifs (le truc `ssl` peut être fait de manière récursive).

### **Acquisitions**

Tout d'abord, nous devons savoir quelles **autres entreprises sont possédées par la société principale**.\
Une option est de visiter [https://www.crunchbase.com/](https://www.crunchbase.com), **chercher** la **société principale**, et **cliquer** sur "**acquisitions**". Là, vous verrez d'autres entreprises acquises par la principale.\
Une autre option est de visiter la page **Wikipedia** de la société principale et de rechercher les **acquisitions**.

> D'accord, à ce stade, vous devriez connaître toutes les entreprises dans le champ d'application. Découvrons comment trouver leurs actifs.

### **ASNs**

Un numéro de système autonome (**ASN**) est un **numéro unique** attribué à un **système autonome** (AS) par l'**Internet Assigned Numbers Authority (IANA)**.\
Un **AS** se compose de **blocs** d'**adresses IP** qui ont une politique clairement définie pour accéder aux réseaux externes et sont administrés par une seule organisation mais peuvent être composés de plusieurs opérateurs.

Il est intéressant de trouver si la **société a attribué un ASN** pour trouver ses **plages IP.** Il sera intéressant de réaliser un **test de vulnérabilité** contre tous les **hôtes** dans le **champ d'application** et **chercher des domaines** dans ces IP.\
Vous pouvez **chercher** par **nom d'entreprise**, par **IP** ou par **domaine** sur [**https://bgp.he.net/**](https://bgp.he.net)**.**\
**Selon la région de l'entreprise, ces liens pourraient être utiles pour rassembler plus de données :** [**AFRINIC**](https://www.afrinic.net) **(Afrique),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Amérique du Nord),** [**APNIC**](https://www.apnic.net) **(Asie),** [**LACNIC**](https://www.lacnic.net) **(Amérique Latine),** [**RIPE NCC**](https://www.ripe.net) **(Europe). Quoi qu'il en soit, probablement toutes les** informations utiles **(plages IP et Whois)** apparaissent déjà dans le premier lien.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Aussi, l'**énumération de sous-domaines de [**BBOT**](https://github.com/blacklanternsecurity/bbot)** agrège et résume automatiquement les ASN à la fin du scan.
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
Vous pouvez trouver les plages IP d'une organisation également en utilisant [http://asnlookup.com/](http://asnlookup.com) (il a une API gratuite).\
Vous pouvez trouver l'IP et l'ASN d'un domaine en utilisant [http://ipv4info.com/](http://ipv4info.com).

### **Recherche de vulnérabilités**

À ce stade, nous connaissons **tous les actifs à l'intérieur du périmètre**, donc si vous y êtes autorisé, vous pourriez lancer un **scanner de vulnérabilités** (Nessus, OpenVAS) sur tous les hôtes.\
De plus, vous pourriez lancer des [**scans de ports**](../pentesting-network/#discovering-hosts-from-the-outside) **ou utiliser des services comme** shodan **pour trouver** des ports ouverts **et selon ce que vous trouvez, vous devriez** consulter ce livre pour savoir comment pentester plusieurs services possibles en cours d'exécution.\
**De plus, il pourrait être utile de mentionner que vous pouvez également préparer des listes de** noms d'utilisateur par défaut **et** mots de passe **et essayer de** bruteforcer des services avec [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domaines

> Nous connaissons toutes les entreprises à l'intérieur du périmètre et leurs actifs, il est temps de trouver les domaines à l'intérieur du périmètre.

_Veuillez noter que dans les techniques proposées suivantes, vous pouvez également trouver des sous-domaines et que cette information ne doit pas être sous-estimée._

Tout d'abord, vous devriez rechercher le(s) **domaine(s) principal(aux)** de chaque entreprise. Par exemple, pour _Tesla Inc._, cela sera _tesla.com_.

### **DNS inversé**

Comme vous avez trouvé toutes les plages IP des domaines, vous pourriez essayer d'effectuer des **recherches DNS inversées** sur ces **IPs pour trouver plus de domaines à l'intérieur du périmètre**. Essayez d'utiliser un serveur DNS de la victime ou un serveur DNS bien connu (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Pour que cela fonctionne, l'administrateur doit activer manuellement le PTR.\
Vous pouvez également utiliser un outil en ligne pour ces informations : [http://ptrarchive.com/](http://ptrarchive.com)

### **Reverse Whois (loop)**

Dans un **whois**, vous pouvez trouver beaucoup d'**informations** intéressantes comme le **nom de l'organisation**, **adresse**, **emails**, numéros de téléphone... Mais ce qui est encore plus intéressant, c'est que vous pouvez trouver **plus d'actifs liés à l'entreprise** si vous effectuez des **recherches whois inversées par l'un de ces champs** (par exemple, d'autres registres whois où le même email apparaît).\
Vous pouvez utiliser des outils en ligne comme :

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Gratuit**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Gratuit**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **Gratuit**
* [https://www.whoxy.com/](https://www.whoxy.com) - **Gratuit** web, API non gratuite.
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Non gratuit
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Non gratuit (seulement **100 recherches gratuites**)
* [https://www.domainiq.com/](https://www.domainiq.com) - Non gratuit

Vous pouvez automatiser cette tâche en utilisant [**DomLink** ](https://github.com/vysecurity/DomLink) (nécessite une clé API whoxy).\
Vous pouvez également effectuer une découverte automatique de whois inversé avec [amass](https://github.com/OWASP/Amass) : `amass intel -d tesla.com -whois`

**Notez que vous pouvez utiliser cette technique pour découvrir plus de noms de domaine chaque fois que vous trouvez un nouveau domaine.**

### **Trackers**

Si vous trouvez le **même ID du même tracker** sur 2 pages différentes, vous pouvez supposer que **les deux pages** sont **gérées par la même équipe**.\
Par exemple, si vous voyez le même **ID Google Analytics** ou le même **ID Adsense** sur plusieurs pages.

Il existe certaines pages et outils qui vous permettent de rechercher par ces trackers et plus :

* [**Udon**](https://github.com/dhn/udon)
* [**BuiltWith**](https://builtwith.com)
* [**Sitesleuth**](https://www.sitesleuth.io)
* [**Publicwww**](https://publicwww.com)
* [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

Saviez-vous que nous pouvons trouver des domaines et sous-domaines liés à notre cible en recherchant le même hash d'icône favicon ? C'est exactement ce que fait l'outil [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) créé par [@m4ll0k2](https://twitter.com/m4ll0k2). Voici comment l'utiliser :
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - découvrir des domaines avec le même hash d'icône favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

En termes simples, favihash nous permettra de découvrir des domaines qui ont le même hash d'icône favicon que notre cible.

De plus, vous pouvez également rechercher des technologies en utilisant le hash favicon comme expliqué dans [**cet article de blog**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Cela signifie que si vous connaissez le **hash de l'icône favicon d'une version vulnérable d'une technologie web**, vous pouvez rechercher sur shodan et **trouver plus d'endroits vulnérables** :
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
C'est ainsi que vous pouvez **calculer le hash du favicon** d'un web :
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

Recherchez dans les pages web **des chaînes qui pourraient être partagées entre différents sites de la même organisation**. La **chaîne de copyright** pourrait être un bon exemple. Ensuite, recherchez cette chaîne dans **google**, dans d'autres **navigateurs** ou même dans **shodan** : `shodan search http.html:"Copyright string"`

### **CRT Time**

Il est courant d'avoir un cron job tel que
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
pour renouveler tous les certificats de domaine sur le serveur. Cela signifie que même si l'AC utilisée pour cela ne fixe pas le moment où il a été généré dans le temps de validité, il est possible de **trouver des domaines appartenant à la même entreprise dans les journaux de transparence des certificats**.\
Consultez ce [**rapport pour plus d'informations**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### Informations sur le Mail DMARC

Vous pouvez utiliser un site web tel que [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) ou un outil tel que [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) pour trouver des **domaines et sous-domaines partageant les mêmes informations DMARC**.

### **Prise de contrôle passive**

Apparemment, il est courant que des personnes assignent des sous-domaines à des IP appartenant à des fournisseurs de cloud et à un moment donné **perdent cette adresse IP mais oublient de supprimer l'enregistrement DNS**. Par conséquent, en **créant une VM** dans un cloud (comme Digital Ocean), vous allez en fait **prendre le contrôle de certains sous-domaines**.

[**Ce post**](https://kmsec.uk/blog/passive-takeover/) explique une histoire à ce sujet et propose un script qui **crée une VM dans DigitalOcean**, **obtient** l'**IPv4** de la nouvelle machine, et **cherche dans Virustotal des enregistrements de sous-domaines** pointant vers elle.

### **Autres méthodes**

**Notez que vous pouvez utiliser cette technique pour découvrir plus de noms de domaine chaque fois que vous trouvez un nouveau domaine.**

**Shodan**

Comme vous connaissez déjà le nom de l'organisation propriétaire de l'espace IP. Vous pouvez rechercher ces données dans Shodan en utilisant : `org:"Tesla, Inc."` Vérifiez les hôtes trouvés pour de nouveaux domaines inattendus dans le certificat TLS.

Vous pourriez accéder au **certificat TLS** de la page web principale, obtenir le **nom de l'organisation** et ensuite rechercher ce nom dans les **certificats TLS** de toutes les pages web connues par **Shodan** avec le filtre : `ssl:"Tesla Motors"` ou utiliser un outil comme [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) est un outil qui recherche des **domaines liés** à un domaine principal et ses **sous-domaines**, assez incroyable.

### **Recherche de vulnérabilités**

Vérifiez certains [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Peut-être qu'une entreprise **utilise un domaine** mais qu'elle **a perdu la propriété**. Il suffit de l'enregistrer (si assez bon marché) et d'informer l'entreprise.

Si vous trouvez un **domaine avec une IP différente** de celles que vous avez déjà trouvées dans la découverte d'actifs, vous devriez effectuer un **scan de vulnérabilités de base** (en utilisant Nessus ou OpenVAS) et un [**scan de ports**](../pentesting-network/#discovering-hosts-from-the-outside) avec **nmap/masscan/shodan**. Selon les services qui fonctionnent, vous pouvez trouver dans **ce livre quelques astuces pour "les attaquer"**.\
_Notez que parfois le domaine est hébergé à l'intérieur d'une IP qui n'est pas contrôlée par le client, donc ce n'est pas dans le périmètre, soyez prudent._

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Astuce bug bounty** : **inscrivez-vous** sur **Intigriti**, une plateforme de **bug bounty premium créée par des hackers, pour des hackers** ! Rejoignez-nous sur [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) aujourd'hui, et commencez à gagner des primes allant jusqu'à **100 000 $** !

{% embed url="https://go.intigriti.com/hacktricks" %}

## Sous-domaines

> Nous connaissons toutes les entreprises dans le périmètre, tous les actifs de chaque entreprise et tous les domaines liés aux entreprises.

Il est temps de trouver tous les sous-domaines possibles de chaque domaine trouvé.

{% hint style="success" %}
Notez que certains des outils et techniques pour trouver des domaines peuvent également aider à trouver des sous-domaines !
{% endhint %}

### **DNS**

Essayons d'obtenir des **sous-domaines** à partir des enregistrements **DNS**. Nous devrions également essayer pour un **Transfert de Zone** (s'il est vulnérable, vous devriez le signaler).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Le moyen le plus rapide d'obtenir de nombreux sous-domaines est de rechercher dans des sources externes. Les **outils** les plus utilisés sont les suivants (pour de meilleurs résultats, configurez les clés API) :

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
* [**OneForAll**](https://github.com/shmilylty/OneForAll/tree/master/docs/fr)
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
Il existe **d'autres outils/API intéressants** qui, même s'ils ne sont pas directement spécialisés dans la recherche de sous-domaines, pourraient être utiles pour trouver des sous-domaines, comme :

* [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Utilise l'API [https://sonar.omnisint.io](https://sonar.omnisint.io) pour obtenir des sous-domaines
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
* [**API gratuite JLDC**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
* [**RapidDNS**](https://rapiddns.io) API gratuite
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
* [**gau**](https://github.com/lc/gau)**:** récupère les URL connues de l'Open Threat Exchange d'AlienVault, de la Wayback Machine et de Common Crawl pour un domaine donné.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper) : Ils parcourent le web à la recherche de fichiers JS et extraient des sous-domaines à partir de là.
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
* [**Censys subdomain finder**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
* [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
* [**securitytrails.com**](https://securitytrails.com/) a une API gratuite pour rechercher des sous-domaines et l'historique des IP
* [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Ce projet offre **gratuitement tous les sous-domaines liés aux programmes de bug-bounty**. Vous pouvez également accéder à ces données en utilisant [chaospy](https://github.com/dr-0x0x/chaospy) ou même accéder à la portée utilisée par ce projet [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Vous pouvez trouver une **comparaison** de nombreux outils ici : [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Essayons de trouver de nouveaux **sous-domaines** en effectuant un brute-force sur les serveurs DNS en utilisant des noms de sous-domaines possibles.

Pour cette action, vous aurez besoin de quelques **listes de mots de sous-domaines courants comme** :

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Et aussi des IP de bons résolveurs DNS. Pour générer une liste de résolveurs DNS de confiance, vous pouvez télécharger les résolveurs depuis [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) et utiliser [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) pour les filtrer. Ou vous pourriez utiliser : [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Les outils les plus recommandés pour le brute-force DNS sont :

* [**massdns**](https://github.com/blechschmidt/massdns) : C'était le premier outil à effectuer un brute-force DNS efficace. Il est très rapide, cependant, il est sujet à des faux positifs.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
* [**gobuster**](https://github.com/OJ/gobuster): Je pense que celui-ci utilise juste 1 résolveur
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
* [**shuffledns**](https://github.com/projectdiscovery/shuffledns) est un wrapper autour de `massdns`, écrit en go, qui vous permet d'énumérer des sous-domaines valides en utilisant un bruteforce actif, ainsi que de résoudre des sous-domaines avec gestion des jokers et un support facile d'entrée-sortie.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
* [**puredns**](https://github.com/d3mondev/puredns) : Il utilise également `massdns`.
```
puredns bruteforce all.txt domain.com
```
* [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) utilise asyncio pour forcer des noms de domaine de manière asynchrone.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Deuxième Round de Brute-Force DNS

Après avoir trouvé des sous-domaines en utilisant des sources ouvertes et le brute-forcing, vous pourriez générer des altérations des sous-domaines trouvés pour essayer d'en trouver encore plus. Plusieurs outils sont utiles à cet effet :

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Étant donné les domaines et sous-domaines, génère des permutations.
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): Étant donné les domaines et sous-domaines, générez des permutations.
* Vous pouvez obtenir les permutations de goaltdns **wordlist** [**ici**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** Étant donné les domaines et sous-domaines, génère des permutations. Si aucun fichier de permutations n'est indiqué, gotator utilisera le sien.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns) : En plus de générer des permutations de sous-domaines, il peut également essayer de les résoudre (mais il est préférable d'utiliser les outils commentés précédemment).
* Vous pouvez obtenir les permutations altdns **wordlist** [**ici**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): Un autre outil pour effectuer des permutations, des mutations et des altérations de sous-domaines. Cet outil va forcer le résultat (il ne prend pas en charge les jokers DNS).
* Vous pouvez obtenir la liste de mots de permutations d'dmut [**ici**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**:** Basé sur un domaine, il **génère de nouveaux noms de sous-domaines potentiels** en fonction des modèles indiqués pour essayer de découvrir plus de sous-domaines.

#### Génération de permutations intelligentes

* [**regulator**](https://github.com/cramppet/regulator): Pour plus d'infos, lisez ce [**post**](https://cramppet.github.io/regulator/index.html) mais il obtiendra essentiellement les **principales parties** des **sous-domaines découverts** et les mélangera pour trouver plus de sous-domaines.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ est un fuzzer de brute-force de sous-domaines associé à un algorithme guidé par la réponse DNS, immensément simple mais efficace. Il utilise un ensemble de données d'entrée fournies, comme une liste de mots sur mesure ou des enregistrements DNS/TLS historiques, pour synthétiser avec précision des noms de domaine correspondants et les étendre encore plus dans une boucle basée sur les informations recueillies lors de l'analyse DNS.
```
echo www | subzuf facebook.com
```
### **Flux de travail de découverte de sous-domaines**

Consultez cet article de blog que j'ai écrit sur la façon d'**automatiser la découverte de sous-domaines** à partir d'un domaine en utilisant **les flux de travail Trickest** afin de ne pas avoir à lancer manuellement une multitude d'outils sur mon ordinateur :

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/" %}

### **VHosts / Hôtes virtuels**

Si vous avez trouvé une adresse IP contenant **une ou plusieurs pages web** appartenant à des sous-domaines, vous pourriez essayer de **trouver d'autres sous-domaines avec des sites sur cette IP** en recherchant dans **des sources OSINT** des domaines dans une IP ou en **bruteforçant les noms de domaine VHost dans cette IP**.

#### OSINT

Vous pouvez trouver quelques **VHosts dans des IPs en utilisant** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ou d'autres API**.

**Brute Force**

Si vous soupçonnez qu'un sous-domaine peut être caché sur un serveur web, vous pourriez essayer de le brute forcer :
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
Avec cette technique, vous pourrez même accéder à des points de terminaison internes/cachés.
{% endhint %}

### **CORS Brute Force**

Parfois, vous trouverez des pages qui ne renvoient l'en-tête _**Access-Control-Allow-Origin**_ que lorsqu'un domaine/sous-domaine valide est défini dans l'en-tête _**Origin**_. Dans ces scénarios, vous pouvez abuser de ce comportement pour **découvrir** de nouveaux **sous-domaines**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Brute Force des Buckets**

Tout en cherchant des **sous-domaines**, gardez un œil pour voir s'il **pointe** vers un type de **bucket**, et dans ce cas, [**vérifiez les permissions**](../../network-services-pentesting/pentesting-web/buckets/)**.**\
De plus, à ce stade, vous connaîtrez tous les domaines dans le périmètre, essayez de [**brute forcer les noms de buckets possibles et de vérifier les permissions**](../../network-services-pentesting/pentesting-web/buckets/).

### **Surveillance**

Vous pouvez **surveiller** si de **nouveaux sous-domaines** d'un domaine sont créés en surveillant les **logs de transparence des certificats** que [**sublert**](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) fait.

### **Recherche de vulnérabilités**

Vérifiez les possibles [**prises de contrôle de sous-domaines**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Si le **sous-domaine** pointe vers un **bucket S3**, [**vérifiez les permissions**](../../network-services-pentesting/pentesting-web/buckets/).

Si vous trouvez un **sous-domaine avec une IP différente** de celles que vous avez déjà trouvées lors de la découverte des actifs, vous devriez effectuer un **scan de vulnérabilités de base** (en utilisant Nessus ou OpenVAS) et un [**scan de ports**](../pentesting-network/#discovering-hosts-from-the-outside) avec **nmap/masscan/shodan**. Selon les services qui fonctionnent, vous pouvez trouver dans **ce livre quelques astuces pour les "attaquer"**.\
_Remarque : parfois, le sous-domaine est hébergé sur une IP qui n'est pas contrôlée par le client, donc ce n'est pas dans le périmètre, soyez prudent._

## IPs

Dans les étapes initiales, vous avez peut-être **trouvé des plages d'IP, des domaines et des sous-domaines**.\
Il est temps de **rassembler toutes les IPs de ces plages** et pour les **domaines/sous-domaines (requêtes DNS).**

En utilisant les services des **API gratuites** suivantes, vous pouvez également trouver des **IP précédemment utilisées par des domaines et sous-domaines**. Ces IP peuvent encore appartenir au client (et peuvent vous permettre de trouver des [**bypass CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

* [**https://securitytrails.com/**](https://securitytrails.com/)

Vous pouvez également vérifier les domaines pointant vers une adresse IP spécifique en utilisant l'outil [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Recherche de vulnérabilités**

**Scannez tous les ports des IP qui n'appartiennent pas aux CDN** (car vous ne trouverez probablement rien d'intéressant là-dedans). Dans les services en cours d'exécution découverts, vous pourriez être **capable de trouver des vulnérabilités**.

**Trouvez un** [**guide**](../pentesting-network/) **sur la façon de scanner les hôtes.**

## Chasse aux serveurs web

> Nous avons trouvé toutes les entreprises et leurs actifs et nous connaissons les plages d'IP, les domaines et les sous-domaines dans le périmètre. Il est temps de rechercher des serveurs web.

Dans les étapes précédentes, vous avez probablement déjà effectué une **reconnaissance des IP et des domaines découverts**, donc vous avez peut-être **déjà trouvé tous les serveurs web possibles**. Cependant, si ce n'est pas le cas, nous allons maintenant voir quelques **astuces rapides pour rechercher des serveurs web** dans le périmètre.

Veuillez noter que cela sera **orienté vers la découverte d'applications web**, donc vous devriez également **effectuer le scan de vulnérabilités** et **le scan de ports** aussi (**si autorisé** par le périmètre).

Une **méthode rapide** pour découvrir les **ports ouverts** liés aux **serveurs** web en utilisant [**masscan** peut être trouvée ici](../pentesting-network/#http-port-discovery).\
Un autre outil convivial pour rechercher des serveurs web est [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) et [**httpx**](https://github.com/projectdiscovery/httpx). Vous passez simplement une liste de domaines et il essaiera de se connecter au port 80 (http) et 443 (https). De plus, vous pouvez indiquer d'essayer d'autres ports :
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Captures d'écran**

Maintenant que vous avez découvert **tous les serveurs web** présents dans le périmètre (parmi les **IPs** de l'entreprise et tous les **domaines** et **sous-domaines**), vous ne savez probablement **pas par où commencer**. Alors, simplifions les choses et commençons simplement par prendre des captures d'écran de tous. En **jetant un œil** à la **page principale**, vous pouvez trouver des **points de terminaison** **bizarres** qui sont plus **susceptibles** d'être **vulnérables**.

Pour réaliser l'idée proposée, vous pouvez utiliser [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) ou [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

De plus, vous pourriez ensuite utiliser [**eyeballer**](https://github.com/BishopFox/eyeballer) pour passer en revue toutes les **captures d'écran** afin de vous dire **ce qui est susceptible de contenir des vulnérabilités**, et ce qui ne l'est pas.

## Actifs Cloud Publics

Pour trouver des actifs cloud potentiels appartenant à une entreprise, vous devriez **commencer par une liste de mots-clés qui identifient cette entreprise**. Par exemple, pour une entreprise de crypto, vous pourriez utiliser des mots tels que : `"crypto", "wallet", "dao", "<nom_de_domaine>", <"noms_de_sous_domaine">`.

Vous aurez également besoin de listes de mots de **mots courants utilisés dans les buckets** :

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Ensuite, avec ces mots, vous devriez générer des **permutations** (voir le [**Deuxième Tour de Brute-Force DNS**](./#second-dns-bruteforce-round) pour plus d'infos).

Avec les listes de mots résultantes, vous pourriez utiliser des outils tels que [**cloud\_enum**](https://github.com/initstring/cloud\_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ou** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

N'oubliez pas que lorsque vous recherchez des actifs Cloud, vous devriez **chercher plus que de simples buckets dans AWS**.

### **Recherche de vulnérabilités**

Si vous trouvez des choses telles que des **buckets ouverts ou des fonctions cloud exposées**, vous devriez **y accéder** et essayer de voir ce qu'elles vous offrent et si vous pouvez en abuser.

## Emails

Avec les **domaines** et **sous-domaines** dans le périmètre, vous avez essentiellement tout ce dont vous **avez besoin pour commencer à rechercher des emails**. Voici les **API** et **outils** qui ont le mieux fonctionné pour moi pour trouver des emails d'une entreprise :

* [**theHarvester**](https://github.com/laramies/theHarvester) - avec des API
* API de [**https://hunter.io/**](https://hunter.io/) (version gratuite)
* API de [**https://app.snov.io/**](https://app.snov.io/) (version gratuite)
* API de [**https://minelead.io/**](https://minelead.io/) (version gratuite)

### **Recherche de vulnérabilités**

Les emails seront utiles plus tard pour **brute-forcer les connexions web et les services d'authentification** (comme SSH). De plus, ils sont nécessaires pour les **phishings**. De plus, ces API vous donneront encore plus d'**informations sur la personne** derrière l'email, ce qui est utile pour la campagne de phishing.

## Fuites de Credentials

Avec les **domaines**, **sous-domaines** et **emails**, vous pouvez commencer à rechercher des credentials fuités dans le passé appartenant à ces emails :

* [https://leak-lookup.com](https://leak-lookup.com/account/login)
* [https://www.dehashed.com/](https://www.dehashed.com/)

### **Recherche de vulnérabilités**

Si vous trouvez des credentials **fuités valides**, c'est une victoire très facile.

## Fuites de Secrets

Les fuites de credentials sont liées aux hacks d'entreprises où **des informations sensibles ont été divulguées et vendues**. Cependant, les entreprises peuvent être affectées par **d'autres fuites** dont les informations ne figurent pas dans ces bases de données :

### Fuites Github

Les credentials et les API peuvent être divulgués dans les **dépôts publics** de l'**entreprise** ou des **utilisateurs** travaillant pour cette entreprise sur github.\
Vous pouvez utiliser l'**outil** [**Leakos**](https://github.com/carlospolop/Leakos) pour **télécharger** tous les **dépôts publics** d'une **organisation** et de ses **développeurs** et exécuter [**gitleaks**](https://github.com/zricethezav/gitleaks) automatiquement sur eux.

**Leakos** peut également être utilisé pour exécuter **gitleaks** contre tout le **texte** fourni par les **URLs passées** à celui-ci, car parfois **les pages web contiennent également des secrets**.

#### Dorks Github

Vérifiez également cette **page** pour des **dorks github** potentiels que vous pourriez également rechercher dans l'organisation que vous attaquez :

{% content-ref url="github-leaked-secrets.md" %}
[github-leaked-secrets.md](github-leaked-secrets.md)
{% endcontent-ref %}

### Fuites de Pastes

Parfois, des attaquants ou simplement des employés publieront **du contenu d'entreprise sur un site de paste**. Cela peut ou non contenir des **informations sensibles**, mais il est très intéressant de le rechercher.\
Vous pouvez utiliser l'outil [**Pastos**](https://github.com/carlospolop/Pastos) pour rechercher dans plus de 80 sites de paste en même temps.

### Dorks Google

Les dorks google, vieux mais efficaces, sont toujours utiles pour trouver des **informations exposées qui ne devraient pas être là**. Le seul problème est que la [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contient plusieurs **milliers** de requêtes possibles que vous ne pouvez pas exécuter manuellement. Donc, vous pouvez prendre vos 10 préférées ou vous pourriez utiliser un **outil tel que** [**Gorks**](https://github.com/carlospolop/Gorks) **pour les exécuter toutes**.

_Remarque : les outils qui s'attendent à exécuter toute la base de données en utilisant le navigateur Google régulier ne finiront jamais, car Google vous bloquera très rapidement._

### **Recherche de vulnérabilités**

Si vous trouvez des credentials ou des tokens API **fuités valides**, c'est une victoire très facile.

## Vulnérabilités de Code Public

Si vous avez découvert que l'entreprise a du **code open-source**, vous pouvez **l'analyser** et rechercher des **vulnérabilités**.

**Selon le langage**, il existe différents **outils** que vous pouvez utiliser :

{% content-ref url="../../network-services-pentesting/pentesting-web/code-review-tools.md" %}
[code-review-tools.md](../../network-services-pentesting/pentesting-web/code-review-tools.md)
{% endcontent-ref %}

Il existe également des services gratuits qui vous permettent de **scanner des dépôts publics**, tels que :

* [**Snyk**](https://app.snyk.io/)

## [**Méthodologie de Pentesting Web**](../../network-services-pentesting/pentesting-web/)

La **majorité des vulnérabilités** trouvées par les chasseurs de bugs se trouvent dans les **applications web**, donc à ce stade, je voudrais parler d'une **méthodologie de test d'application web**, et vous pouvez [**trouver cette information ici**](../../network-services-pentesting/pentesting-web/).

Je veux également faire une mention spéciale à la section [**Outils open source de scanners automatisés web**](../../network-services-pentesting/pentesting-web/#automatic-scanners), car, même si vous ne devriez pas vous attendre à ce qu'ils trouvent des vulnérabilités très sensibles, ils sont utiles pour les intégrer dans des **flux de travail pour avoir des informations web initiales.**

## Récapitulation

> Félicitations ! À ce stade, vous avez déjà effectué **toute l'énumération de base**. Oui, c'est basique car beaucoup plus d'énumération peut être faite (nous verrons plus d'astuces plus tard).

Donc, vous avez déjà :

1. Trouvé toutes les **entreprises** dans le périmètre
2. Trouvé tous les **actifs** appartenant aux entreprises (et effectué quelques scans de vulnérabilités si dans le périmètre)
3. Trouvé tous les **domaines** appartenant aux entreprises
4. Trouvé tous les **sous-domaines** des domaines (prise de contrôle de sous-domaine ?)
5. Trouvé toutes les **IPs** (provenant et **non provenant des CDN**) dans le périmètre.
6. Trouvé tous les **serveurs web** et pris une **capture d'écran** d'eux (quelque chose de bizarre qui mérite un examen plus approfondi ?)
7. Trouvé tous les **actifs cloud publics potentiels** appartenant à l'entreprise.
8. **Emails**, **fuites de credentials**, et **fuites de secrets** qui pourraient vous donner une **grande victoire très facilement**.
9. **Pentesting tous les sites que vous avez trouvés**

## **Outils Automatiques de Reconnaissance Complète**

Il existe plusieurs outils qui effectueront une partie des actions proposées contre un périmètre donné.

* [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
* [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
* [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
* [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Un peu ancien et pas mis à jour

## **Références**

* Tous les cours gratuits de [**@Jhaddix**](https://twitter.com/Jhaddix) comme [**La Méthodologie du Chasseur de Bugs v4.0 - Édition Recon**](https://www.youtube.com/watch?v=p4JgIu1mceI)

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Si vous êtes intéressé par une **carrière de hacking** et que vous voulez hacker l'inhackable - **nous recrutons !** (_polonais courant écrit et parlé requis_).

{% embed url="https://www.stmcyber.com/careers" %}

{% hint style="success" %}
Apprenez et pratiquez le Hacking AWS :<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le Hacking GCP : <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
