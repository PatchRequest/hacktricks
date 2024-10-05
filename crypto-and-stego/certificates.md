# Certificates

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

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=certificates) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=certificates" %}

## Šta je sertifikat

**Javni ključ sertifikat** je digitalni ID koji se koristi u kriptografiji da dokaže da neko poseduje javni ključ. Uključuje detalje o ključevi, identitet vlasnika (subjekt) i digitalni potpis od poverljive vlasti (izdavača). Ako softver veruje izdavaču i potpis je validan, moguća je sigurna komunikacija sa vlasnikom ključa.

Sertifikati se uglavnom izdaju od strane [sertifikacionih tela](https://en.wikipedia.org/wiki/Certificate\_authority) (CA) u okviru [infrastrukture javnog ključa](https://en.wikipedia.org/wiki/Public-key\_infrastructure) (PKI). Druga metoda je [mreža poverenja](https://en.wikipedia.org/wiki/Web\_of\_trust), gde korisnici direktno verifikuju ključeve jedni drugih. Uobičajeni format za sertifikate je [X.509](https://en.wikipedia.org/wiki/X.509), koji se može prilagoditi specifičnim potrebama kako je navedeno u RFC 5280.

## x509 Zajednička polja

### **Zajednička polja u x509 sertifikatima**

U x509 sertifikatima, nekoliko **polja** igra ključne uloge u osiguravanju validnosti i sigurnosti sertifikata. Evo pregleda ovih polja:

* **Broj verzije** označava verziju x509 formata.
* **Serijski broj** jedinstveno identifikuje sertifikat unutar sistema Sertifikacionog tela (CA), uglavnom za praćenje opoziva.
* Polje **Subjekt** predstavlja vlasnika sertifikata, što može biti mašina, pojedinac ili organizacija. Uključuje detaljnu identifikaciju kao što su:
* **Uobičajeno ime (CN)**: Domeni pokriveni sertifikatom.
* **Zemlja (C)**, **Lokacija (L)**, **Država ili provincija (ST, S, ili P)**, **Organizacija (O)** i **Organizaciona jedinica (OU)** pružaju geografske i organizacione detalje.
* **Istaknuto ime (DN)** obuhvata punu identifikaciju subjekta.
* **Izdavač** detaljno opisuje ko je verifikovao i potpisao sertifikat, uključujući slična podpolja kao Subjekt za CA.
* **Period važenja** označen je vremenskim oznakama **Ne pre** i **Ne posle**, osiguravajući da se sertifikat ne koristi pre ili posle određenog datuma.
* Sekcija **Javni ključ**, koja je ključna za sigurnost sertifikata, specificira algoritam, veličinu i druge tehničke detalje javnog ključa.
* **x509v3 ekstenzije** poboljšavaju funkcionalnost sertifikata, specificirajući **Korišćenje ključa**, **Prošireno korišćenje ključa**, **Alternativno ime subjekta** i druge osobine za fino podešavanje primene sertifikata.

#### **Korišćenje ključa i ekstenzije**

* **Korišćenje ključa** identifikuje kriptografske primene javnog ključa, kao što su digitalni potpis ili enkripcija ključa.
* **Prošireno korišćenje ključa** dodatno sužava slučajeve korišćenja sertifikata, npr. za TLS autentifikaciju servera.
* **Alternativno ime subjekta** i **Osnovna ograničenja** definišu dodatne nazive hostova pokrivene sertifikatom i da li je to CA ili sertifikat krajnjeg entiteta, redom.
* Identifikatori kao što su **Identifikator ključa subjekta** i **Identifikator ključa vlasti** osiguravaju jedinstvenost i praćenje ključeva.
* **Pristup informacijama o vlasti** i **Tačke distribucije CRL** pružaju puteve za verifikaciju izdavača CA i proveru statusa opoziva sertifikata.
* **CT Precertifikat SCTs** nude transparente dnevnike, što je ključno za javno poverenje u sertifikat.
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
### **Razlika između OCSP i CRL distribucionih tačaka**

**OCSP** (**RFC 2560**) uključuje klijenta i odgovarača koji rade zajedno kako bi proverili da li je digitalni javni ključ sertifikat opozvan, bez potrebe za preuzimanjem celog **CRL**. Ova metoda je efikasnija od tradicionalnog **CRL**, koji pruža listu opozvanih serijskih brojeva sertifikata, ali zahteva preuzimanje potencijalno velikog fajla. CRL-ovi mogu uključivati do 512 unosa. Više detalja je dostupno [ovde](https://www.arubanetworks.com/techdocs/ArubaOS%206\_3\_1\_Web\_Help/Content/ArubaFrameStyles/CertRevocation/About\_OCSP\_and\_CRL.htm).

### **Šta je transparentnost sertifikata**

Transparentnost sertifikata pomaže u borbi protiv pretnji vezanih za sertifikate osiguravajući da je izdavanje i postojanje SSL sertifikata vidljivo vlasnicima domena, CA-ima i korisnicima. Njeni ciljevi su:

* Sprečavanje CA-a da izdaju SSL sertifikate za domen bez znanja vlasnika domena.
* Uspostavljanje otvorenog sistema revizije za praćenje greškom ili zlonamerno izdatih sertifikata.
* Zaštita korisnika od prevarantskih sertifikata.

#### **Dnevnici sertifikata**

Dnevnici sertifikata su javno revizibilni, samo za dodavanje zapisi o sertifikatima, koje održavaju mrežne usluge. Ovi dnevnici pružaju kriptografske dokaze za svrhe revizije. Izdavaoci i javnost mogu podnositi sertifikate ovim dnevnicima ili ih pretraživati radi verifikacije. Dok tačan broj servera dnevnika nije fiksiran, očekuje se da će biti manje od hiljadu globalno. Ove servere mogu nezavisno upravljati CA, ISP ili bilo koja zainteresovana strana.

#### **Upit**

Da biste istražili dnevnike transparentnosti sertifikata za bilo koji domen, posetite [https://crt.sh/](https://crt.sh).

Postoje različiti formati za skladištenje sertifikata, svaki sa svojim slučajevima upotrebe i kompatibilnošću. Ovaj pregled pokriva glavne formate i pruža smernice za konvertovanje između njih.

## **Formati**

### **PEM format**

* Najšire korišćen format za sertifikate.
* Zahteva odvojene fajlove za sertifikate i privatne ključeve, kodirane u Base64 ASCII.
* Uobičajene ekstenzije: .cer, .crt, .pem, .key.
* Primarno koriste Apache i slični serveri.

### **DER format**

* Binarni format sertifikata.
* Nedostaju "BEGIN/END CERTIFICATE" izjave koje se nalaze u PEM fajlovima.
* Uobičajene ekstenzije: .cer, .der.
* Često se koristi sa Java platformama.

### **P7B/PKCS#7 format**

* Skladišti se u Base64 ASCII, sa ekstenzijama .p7b ili .p7c.
* Sadrži samo sertifikate i lance sertifikata, isključujući privatni ključ.
* Podržava Microsoft Windows i Java Tomcat.

### **PFX/P12/PKCS#12 format**

* Binarni format koji enkapsulira server sertifikate, međusertifikate i privatne ključeve u jednom fajlu.
* Ekstenzije: .pfx, .p12.
* Uglavnom se koristi na Windows-u za uvoz i izvoz sertifikata.

### **Konvertovanje formata**

**PEM konverzije** su neophodne za kompatibilnost:

* **x509 to PEM**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
* **PEM u DER**
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
* **DER u PEM**
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
* **PEM u P7B**
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
* **PKCS7 u PEM**
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**PFX konverzije** su ključne za upravljanje sertifikatima na Windows-u:

* **PFX u PEM**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
* **PFX to PKCS#8** uključuje dva koraka:
1. Konvertujte PFX u PEM
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. Konvertujte PEM u PKCS8
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
* **P7B to PFX** takođe zahteva dve komande:
1. Konvertujte P7B u CER
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. Konvertujte CER i privatni ključ u PFX
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
* **ASN.1 (DER/PEM) uređivanje** (radi sa sertifikatima ili gotovo bilo kojom drugom ASN.1 strukturom):
1. Klonirajte [asn1template](https://github.com/wllm-rbnt/asn1template/)
```bash
git clone https://github.com/wllm-rbnt/asn1template.git
```
2. Konvertujte DER/PEM u OpenSSL-ov format generacije
```bash
asn1template/asn1template.pl certificatename.der > certificatename.tpl
asn1template/asn1template.pl -p certificatename.pem > certificatename.tpl
```
3. Izmenite certificatename.tpl prema vašim zahtevima
```bash
vim certificatename.tpl
```
4. Ponovo izgradite izmenjeni sertifikat
```bash
openssl asn1parse -genconf certificatename.tpl -out certificatename_new.der
openssl asn1parse -genconf certificatename.tpl -outform PEM -out certificatename_new.pem
```
***

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=certificates) za lako kreiranje i **automatizaciju radnih tokova** pokretanih najnaprednijim **alatima** zajednice na svetu.\
Pribavite pristup danas:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=certificates" %}

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
