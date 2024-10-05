# Sertifikate

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=certificates) om maklik te bou en **werkvloei te outomatiseer** wat deur die wêreld se **mees gevorderde** gemeenskap gereedskap aangedryf word.\
Kry Toegang Vandag:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=certificates" %}

## Wat is 'n Sertifikaat

'n **Publieke sleutelsertifikaat** is 'n digitale ID wat in kriptografie gebruik word om te bewys dat iemand 'n publieke sleutel besit. Dit sluit die sleutel se besonderhede, die eienaar se identiteit (die onderwerp), en 'n digitale handtekening van 'n vertroude gesag (die uitreiker) in. As die sagteware die uitreiker vertrou en die handtekening geldig is, is veilige kommunikasie met die sleutel se eienaar moontlik.

Sertifikate word meestal uitgereik deur [sertifikaatowerhede](https://en.wikipedia.org/wiki/Certificate\_authority) (CAs) in 'n [publieke sleutel infrastruktuur](https://en.wikipedia.org/wiki/Public-key\_infrastructure) (PKI) opstelling. 'n Ander metode is die [web van vertroue](https://en.wikipedia.org/wiki/Web\_of\_trust), waar gebruikers mekaar se sleutels direk verifieer. Die algemene formaat vir sertifikate is [X.509](https://en.wikipedia.org/wiki/X.509), wat aangepas kan word vir spesifieke behoeftes soos uiteengesit in RFC 5280.

## x509 Algemene Velde

### **Algemene Velde in x509 Sertifikate**

In x509 sertifikate speel verskeie **velde** kritieke rolle in die versekerings van die sertifikaat se geldigheid en sekuriteit. Hier is 'n uiteensetting van hierdie velde:

* **Weergawe Nommer** dui die x509 formaat se weergawe aan.
* **Serienommer** identifiseer die sertifikaat uniek binne 'n Sertifikaatowerheid se (CA) stelsel, hoofsaaklik vir herroepingopsporing.
* Die **Onderwerp** veld verteenwoordig die sertifikaat se eienaar, wat 'n masjien, 'n individu, of 'n organisasie kan wees. Dit sluit gedetailleerde identifikasie in soos:
* **Algemene Naam (CN)**: Domeine wat deur die sertifikaat gedek word.
* **Land (C)**, **Plaaslikeheid (L)**, **Staat of Provinsie (ST, S, of P)**, **Organisasie (O)**, en **Organisatoriese Eenheid (OU)** verskaf geografiese en organisatoriese besonderhede.
* **Gekenneteerde Naam (DN)** sluit die volle onderwerp identifikasie in.
* **Uitreiker** gee besonderhede oor wie die sertifikaat geverifieer en onderteken het, insluitend soortgelyke subvelde soos die Onderwerp vir die CA.
* **Geldigheidsperiode** word gemerk deur **Nie Voor** en **Nie Na** tydstempels, wat verseker dat die sertifikaat nie voor of na 'n sekere datum gebruik word nie.
* Die **Publieke Sleutel** afdeling, wat van kardinale belang is vir die sertifikaat se sekuriteit, spesifiseer die algoritme, grootte, en ander tegniese besonderhede van die publieke sleutel.
* **x509v3 uitbreidings** verbeter die sertifikaat se funksionaliteit, wat **Sleutel Gebruik**, **Verlengde Sleutel Gebruik**, **Onderwerp Alternatiewe Naam**, en ander eienskappe spesifiseer om die sertifikaat se toepassing te verfyn.

#### **Sleutel Gebruik en Uitbreidings**

* **Sleutel Gebruik** identifiseer kriptografiese toepassings van die publieke sleutel, soos digitale handtekening of sleutel versleuteling.
* **Verlengde Sleutel Gebruik** beperk verder die sertifikaat se gebruiksgevalle, bv. vir TLS bediener verifikasie.
* **Onderwerp Alternatiewe Naam** en **Basiese Beperking** definieer addisionele gasheername wat deur die sertifikaat gedek word en of dit 'n CA of eindentiteit sertifikaat is, onderskeidelik.
* Identifiseerders soos **Onderwerp Sleutel Identifiseerder** en **Gesags Sleutel Identifiseerder** verseker uniekheid en opspoorbaarheid van sleutels.
* **Gesags Inligting Toegang** en **CRL Verspreidingspunte** bied paaie om die uitreikende CA te verifieer en die sertifikaat se herroepingstatus te kontroleer.
* **CT Precertificate SCTs** bied deursigtigheid logs, wat van kardinale belang is vir publieke vertroue in die sertifikaat.
```python
# Example of accessing and using x509 certificate fields programmatically:
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Load an x509 certificate (assuming cert.pem is a certificate file)
with open("cert.pem", "rb") as file:
cert_data = file.read()
certificate = x509.load_pem_x509_certificate(cert_data, default_backend())

# Accessing fields
serial_number = certificate.serial_number
issuer = certificate.issuer
subject = certificate.subject
public_key = certificate.public_key()

print(f"Serial Number: {serial_number}")
print(f"Issuer: {issuer}")
print(f"Subject: {subject}")
print(f"Public Key: {public_key}")
```
### **Verskil tussen OCSP en CRL Verspreidingspunte**

**OCSP** (**RFC 2560**) behels 'n kliënt en 'n responder wat saamwerk om te kontroleer of 'n digitale publieke sleutelsertifikaat herroep is, sonder om die volle **CRL** af te laai. Hierdie metode is meer doeltreffend as die tradisionele **CRL**, wat 'n lys van herroepte sertifikaatserienommers verskaf, maar vereis dat 'n potensieel groot lêer afgelaai word. CRL's kan tot 512 inskrywings insluit. Meer besonderhede is beskikbaar [hier](https://www.arubanetworks.com/techdocs/ArubaOS%206\_3\_1\_Web\_Help/Content/ArubaFrameStyles/CertRevocation/About\_OCSP\_and\_CRL.htm).

### **Wat is Sertifikaat Deursigtigheid**

Sertifikaat Deursigtigheid help om sertifikaatverwante bedreigings te bekamp deur te verseker dat die uitreiking en bestaan van SSL-sertifikate sigbaar is vir domeineienaars, CA's en gebruikers. Die doelwitte is:

* Om te voorkom dat CA's SSL-sertifikate vir 'n domein uitreik sonder die domeineienaar se kennis.
* Om 'n oop ouditstelsel te vestig vir die opsporing van per ongeluk of kwaadwillig uitgereikte sertifikate.
* Om gebruikers te beskerm teen bedrieglike sertifikate.

#### **Sertifikaat Logs**

Sertifikaat logs is publiek ouditbaar, byvoeging-alleen rekords van sertifikate, wat deur netwerkdienste onderhou word. Hierdie logs bied kriptografiese bewysstukke vir ouditdoeleindes. Beide uitreikingsowerhede en die publiek kan sertifikate aan hierdie logs indien of dit raadpleeg vir verifikasie. Terwyl die presiese aantal logbedieners nie vasgestel is nie, word verwag dat dit minder as 'n duisend wêreldwyd sal wees. Hierdie bedieners kan onafhanklik bestuur word deur CA's, ISP's, of enige belangstellende entiteit.

#### **Navraag**

Om Sertifikaat Deursigtigheid logs vir enige domein te verken, besoek [https://crt.sh/](https://crt.sh).

Verskillende formate bestaan vir die stoor van sertifikate, elk met sy eie gebruiksgevalle en kompatibiliteit. Hierdie opsomming dek die hoofformate en bied leiding oor die omskakeling tussen hulle.

## **Formate**

### **PEM Formaat**

* Meest gebruikte formaat vir sertifikate.
* Vereis aparte lêers vir sertifikate en private sleutels, gekodeer in Base64 ASCII.
* Algemene uitbreidings: .cer, .crt, .pem, .key.
* Primêr gebruik deur Apache en soortgelyke bedieners.

### **DER Formaat**

* 'n Binaire formaat van sertifikate.
* Ontbreek die "BEGIN/END CERTIFICATE" verklarings wat in PEM-lêers voorkom.
* Algemene uitbreidings: .cer, .der.
* Gereeld gebruik met Java platforms.

### **P7B/PKCS#7 Formaat**

* Gestoor in Base64 ASCII, met uitbreidings .p7b of .p7c.
* Bevat slegs sertifikate en kettingsertifikate, met uitsluiting van die private sleutel.
* Gesteun deur Microsoft Windows en Java Tomcat.

### **PFX/P12/PKCS#12 Formaat**

* 'n Binaire formaat wat bedienersertifikate, intermediêre sertifikate, en private sleutels in een lêer inkapsuleer.
* Uitbreidings: .pfx, .p12.
* Hoofsaaklik gebruik op Windows vir sertifikaat invoer en uitvoer.

### **Omskakeling van Formate**

**PEM omskakelings** is noodsaaklik vir kompatibiliteit:

* **x509 na PEM**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
* **PEM na DER**
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
* **DER na PEM**
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
* **PEM na P7B**
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
* **PKCS7 na PEM**
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**PFX omskakelings** is noodsaaklik vir die bestuur van sertifikate op Windows:

* **PFX na PEM**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
* **PFX na PKCS#8** behels twee stappe:
1. Skakel PFX na PEM om
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. Skakel PEM na PKCS8 om
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
* **P7B na PFX** vereis ook twee opdragte:
1. Skakel P7B na CER om
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. Skakel CER en Privaat Sleutel na PFX om
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
* **ASN.1 (DER/PEM) redigering** (werk met sertifikate of byna enige ander ASN.1 struktuur):
1. Kloneer [asn1template](https://github.com/wllm-rbnt/asn1template/)
```bash
git clone https://github.com/wllm-rbnt/asn1template.git
```
2. Skakel DER/PEM na OpenSSL se generasieformaat om
```bash
asn1template/asn1template.pl certificatename.der > certificatename.tpl
asn1template/asn1template.pl -p certificatename.pem > certificatename.tpl
```
3. Wysig certificatename.tpl volgens jou vereistes
```bash
vim certificatename.tpl
```
4. Bou die gewysigde sertifikaat weer op
```bash
openssl asn1parse -genconf certificatename.tpl -out certificatename_new.der
openssl asn1parse -genconf certificatename.tpl -outform PEM -out certificatename_new.pem
```
***

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=certificates) om maklik te bou en **werkvloei** te **automate** wat deur die wêreld se **mees gevorderde** gemeenskapstools aangedryf word.\
Kry Toegang Vandag:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=certificates" %}

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
