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

## What is a Certificate

**Cheti cha ufunguo wa umma** ni kitambulisho cha dijitali kinachotumika katika cryptography kuthibitisha kwamba mtu anamiliki ufunguo wa umma. Inajumuisha maelezo ya ufunguo, kitambulisho cha mmiliki (mada), na saini ya dijitali kutoka kwa mamlaka inayotegemewa (mtoaji). Ikiwa programu inategemea mtoaji na saini ni halali, mawasiliano salama na mmiliki wa ufunguo yanawezekana.

Vyeti kwa kawaida vinatolewa na [mamlaka ya vyeti](https://en.wikipedia.org/wiki/Certificate\_authority) (CAs) katika muundo wa [miundombinu ya ufunguo wa umma](https://en.wikipedia.org/wiki/Public-key\_infrastructure) (PKI). Njia nyingine ni [mtandao wa kuaminiana](https://en.wikipedia.org/wiki/Web\_of\_trust), ambapo watumiaji wanathibitisha ufunguo wa kila mmoja moja kwa moja. Muundo wa kawaida wa vyeti ni [X.509](https://en.wikipedia.org/wiki/X.509), ambayo inaweza kubadilishwa kwa mahitaji maalum kama ilivyoelezwa katika RFC 5280.

## x509 Common Fields

### **Sehemu za Kawaida katika Vyeti vya x509**

Katika vyeti vya x509, sehemu kadhaa **zinacheza** majukumu muhimu katika kuhakikisha halali na usalama wa cheti. Hapa kuna muhtasari wa sehemu hizi:

* **Nambari ya Toleo** inaashiria toleo la muundo wa x509.
* **Nambari ya Mfululizo** inatambulisha cheti ndani ya mfumo wa Mamlaka ya Cheti (CA), hasa kwa ajili ya kufuatilia kufutwa.
* Sehemu ya **Mada** inawakilisha mmiliki wa cheti, ambaye anaweza kuwa mashine, mtu binafsi, au shirika. Inajumuisha kitambulisho kilicho na maelezo kama:
* **Jina la Kawaida (CN)**: Majina ya maeneo yanayofunikwa na cheti.
* **Nchi (C)**, **Eneo (L)**, **Jimbo au Mkoa (ST, S, au P)**, **Shirika (O)**, na **Kitengo cha Shirika (OU)** vinatoa maelezo ya kijiografia na ya shirika.
* **Jina Lililoainishwa (DN)** linajumuisha kitambulisho kamili cha mada.
* **Mtoaji** inaelezea nani alithibitisha na kusaini cheti, ikiwa ni pamoja na sehemu zinazofanana kama za Mada kwa CA.
* **Muda wa Halali** umewekwa na alama za **Siyo Kabla** na **Siyo Baada**, kuhakikisha cheti hakitumiki kabla au baada ya tarehe fulani.
* Sehemu ya **Ufunguo wa Umma**, muhimu kwa usalama wa cheti, inaelezea algorithimu, ukubwa, na maelezo mengine ya kiufundi ya ufunguo wa umma.
* **x509v3 extensions** zinaboresha kazi ya cheti, zikielezea **Matumizi ya Ufunguo**, **Matumizi ya Ufunguo wa Kupanua**, **Jina Alternatif la Mada**, na mali nyingine za kuboresha matumizi ya cheti.

#### **Matumizi ya Ufunguo na Upanuzi**

* **Matumizi ya Ufunguo** yanatambulisha matumizi ya cryptographic ya ufunguo wa umma, kama saini ya dijitali au ufunguo wa kuandika.
* **Matumizi ya Ufunguo wa Kupanua** yanapunguza zaidi matumizi ya cheti, kwa mfano, kwa uthibitisho wa seva ya TLS.
* **Jina Alternatif la Mada** na **Kikomo cha Msingi** vin定义 maelezo ya ziada ya majina ya mwenyeji yanayofunikwa na cheti na ikiwa ni cheti cha CA au cheti cha mwisho, mtawalia.
* Vitambulisho kama **Kitambulisho cha Ufunguo wa Mada** na **Kitambulisho cha Ufunguo wa Mamlaka** vinahakikisha upekee na ufuatiliaji wa funguo.
* **Upatikanaji wa Taarifa za Mamlaka** na **Nukuu za Usambazaji wa CRL** vinatoa njia za kuthibitisha CA inayotoa na kuangalia hali ya kufutwa kwa cheti.
* **CT Precertificate SCTs** vinatoa kumbukumbu za uwazi, muhimu kwa kuaminika kwa umma katika cheti.
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
### **Tofauti kati ya OCSP na CRL Distribution Points**

**OCSP** (**RFC 2560**) inahusisha mteja na mrespondia wakifanya kazi pamoja ili kuangalia kama cheti cha dijitali cha funguo za umma kimeondolewa, bila kuhitaji kupakua **CRL** kamili. Njia hii ni bora zaidi kuliko **CRL** ya jadi, ambayo inatoa orodha ya nambari za serial za vyeti vilivyondolewa lakini inahitaji kupakua faili kubwa. CRLs zinaweza kujumuisha hadi ingizo 512. Maelezo zaidi yanapatikana [hapa](https://www.arubanetworks.com/techdocs/ArubaOS%206\_3\_1\_Web\_Help/Content/ArubaFrameStyles/CertRevocation/About\_OCSP\_and\_CRL.htm).

### **Nini maana ya Uwazi wa Cheti**

Uwazi wa Cheti husaidia kupambana na vitisho vinavyohusiana na vyeti kwa kuhakikisha utoaji na uwepo wa vyeti vya SSL unaonekana kwa wamiliki wa domain, CAs, na watumiaji. Malengo yake ni:

* Kuzuia CAs kutoa vyeti vya SSL kwa domain bila maarifa ya mmiliki wa domain.
* Kuanzisha mfumo wa ukaguzi wazi wa kufuatilia vyeti vilivyotolewa kwa makosa au kwa uovu.
* Kulinda watumiaji dhidi ya vyeti vya udanganyifu.

#### **Makaratasi ya Vyeti**

Makaratasi ya vyeti ni rekodi za vyeti zinazoweza kukaguliwa hadharani, zinazoongezwa tu, zinazoshughulikiwa na huduma za mtandao. Makaratasi haya yanatoa uthibitisho wa kihesabu kwa ajili ya ukaguzi. Mamlaka za utoaji na umma wanaweza kuwasilisha vyeti kwenye makaratasahaya au kuyatafuta kwa ajili ya uthibitisho. Ingawa idadi halisi ya seva za makaratasi si ya kudumu, inatarajiwa kuwa chini ya elfu moja duniani kote. Seva hizi zinaweza kusimamiwa kwa uhuru na CAs, ISPs, au shirika lolote linalovutiwa.

#### **Utafutaji**

Ili kuchunguza makaratasahaya ya Uwazi wa Cheti kwa domain yoyote, tembelea [https://crt.sh/](https://crt.sh).

Mifumo tofauti inapatikana kwa ajili ya kuhifadhi vyeti, kila moja ikiwa na matumizi yake na ulinganifu. Muhtasari huu unashughulikia mifumo kuu na unatoa mwongozo juu ya kubadilisha kati yao.

## **Mifumo**

### **PEM Format**

* Mfumo unaotumika zaidi kwa vyeti.
* Unahitaji faili tofauti kwa vyeti na funguo za faragha, zilizowekwa katika Base64 ASCII.
* Upanuzi wa kawaida: .cer, .crt, .pem, .key.
* Kimsingi hutumiwa na Apache na seva zinazofanana.

### **DER Format**

* Mfumo wa binary wa vyeti.
* Huna taarifa za "BEGIN/END CERTIFICATE" zinazopatikana katika faili za PEM.
* Upanuzi wa kawaida: .cer, .der.
* Mara nyingi hutumiwa na majukwaa ya Java.

### **P7B/PKCS#7 Format**

* Huhifadhiwa katika Base64 ASCII, ikiwa na upanuzi .p7b au .p7c.
* Inajumuisha vyeti tu na vyeti vya mnyororo, ikiondoa funguo za faragha.
* Inasaidiwa na Microsoft Windows na Java Tomcat.

### **PFX/P12/PKCS#12 Format**

* Mfumo wa binary unaojumuisha vyeti vya seva, vyeti vya kati, na funguo za faragha katika faili moja.
* Upanuzi: .pfx, .p12.
* Kimsingi hutumiwa kwenye Windows kwa ajili ya kuagiza na kuuza vyeti.

### **Kubadilisha Mifumo**

**Mabadiliko ya PEM** ni muhimu kwa ajili ya ulinganifu:

* **x509 hadi PEM**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
* **PEM hadi DER**
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
* **DER hadi PEM**
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
* **PEM hadi P7B**
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
* **PKCS7 hadi PEM**
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**PFX conversions** ni muhimu kwa usimamizi wa vyeti kwenye Windows:

* **PFX to PEM**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
* **PFX to PKCS#8** inahusisha hatua mbili:
1. Geuza PFX kuwa PEM
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. Geuza PEM kuwa PKCS8
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
* **P7B to PFX** pia inahitaji amri mbili:
1. Geuza P7B kuwa CER
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. Geuza CER na Funguo Binafsi kuwa PFX
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
* **ASN.1 (DER/PEM) editing** (inafanya kazi na vyeti au karibu muundo wowote wa ASN.1):
1. Clone [asn1template](https://github.com/wllm-rbnt/asn1template/)
```bash
git clone https://github.com/wllm-rbnt/asn1template.git
```
2. Geuza DER/PEM kuwa muundo wa uzalishaji wa OpenSSL
```bash
asn1template/asn1template.pl certificatename.der > certificatename.tpl
asn1template/asn1template.pl -p certificatename.pem > certificatename.tpl
```
3. Hariri certificatename.tpl kulingana na mahitaji yako
```bash
vim certificatename.tpl
```
4. Jenga upya cheti kilichobadilishwa
```bash
openssl asn1parse -genconf certificatename.tpl -out certificatename_new.der
openssl asn1parse -genconf certificatename.tpl -outform PEM -out certificatename_new.pem
```
***

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=certificates) kujenga na **kujiendesha** kwa urahisi kazi zinazotumiwa na zana za jamii **zilizoendelea zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=certificates" %}

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
