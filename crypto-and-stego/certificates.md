# Zertifikate

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Nutze [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=certificates), um einfach **Workflows** zu erstellen und zu **automatisieren**, die von den **fortschrittlichsten** Community-Tools der Welt unterstützt werden.\
Erhalte heute Zugang:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=certificates" %}

## Was ist ein Zertifikat

Ein **öffentliches Schlüsselzertifikat** ist eine digitale ID, die in der Kryptographie verwendet wird, um zu beweisen, dass jemand einen öffentlichen Schlüssel besitzt. Es enthält die Details des Schlüssels, die Identität des Eigentümers (das Subjekt) und eine digitale Signatur von einer vertrauenswürdigen Autorität (dem Aussteller). Wenn die Software dem Aussteller vertraut und die Signatur gültig ist, ist eine sichere Kommunikation mit dem Eigentümer des Schlüssels möglich.

Zertifikate werden hauptsächlich von [Zertifizierungsstellen](https://en.wikipedia.org/wiki/Certificate\_authority) (CAs) in einer [Public-Key-Infrastruktur](https://en.wikipedia.org/wiki/Public-key\_infrastructure) (PKI) ausgegeben. Eine andere Methode ist das [Web of Trust](https://en.wikipedia.org/wiki/Web\_of\_trust), bei dem Benutzer die Schlüssel einander direkt verifizieren. Das gängige Format für Zertifikate ist [X.509](https://en.wikipedia.org/wiki/X.509), das für spezifische Bedürfnisse gemäß RFC 5280 angepasst werden kann.

## x509 Gemeinsame Felder

### **Gemeinsame Felder in x509-Zertifikaten**

In x509-Zertifikaten spielen mehrere **Felder** eine entscheidende Rolle bei der Sicherstellung der Gültigkeit und Sicherheit des Zertifikats. Hier ist eine Übersicht über diese Felder:

* **Versionsnummer** bezeichnet die Version des x509-Formats.
* **Seriennummer** identifiziert das Zertifikat eindeutig innerhalb des Systems einer Zertifizierungsstelle (CA), hauptsächlich zur Rückverfolgung von Widerrufen.
* Das **Subjekt**-Feld repräsentiert den Eigentümer des Zertifikats, der eine Maschine, eine Einzelperson oder eine Organisation sein kann. Es enthält detaillierte Identifikationsinformationen wie:
* **Common Name (CN)**: Domains, die durch das Zertifikat abgedeckt sind.
* **Land (C)**, **Ort (L)**, **Bundesland oder Provinz (ST, S oder P)**, **Organisation (O)** und **Organisatorische Einheit (OU)** bieten geografische und organisatorische Details.
* **Distinguished Name (DN)** fasst die vollständige Subjektidentifikation zusammen.
* **Aussteller** gibt an, wer das Zertifikat verifiziert und signiert hat, einschließlich ähnlicher Unterfelder wie das Subjekt für die CA.
* **Gültigkeitszeitraum** wird durch die Zeitstempel **Not Before** und **Not After** markiert, um sicherzustellen, dass das Zertifikat nicht vor oder nach einem bestimmten Datum verwendet wird.
* Der Abschnitt **Öffentlicher Schlüssel**, der entscheidend für die Sicherheit des Zertifikats ist, spezifiziert den Algorithmus, die Größe und andere technische Details des öffentlichen Schlüssels.
* **x509v3-Erweiterungen** verbessern die Funktionalität des Zertifikats und spezifizieren **Key Usage**, **Extended Key Usage**, **Subject Alternative Name** und andere Eigenschaften, um die Anwendung des Zertifikats zu verfeinern.

#### **Schlüsselverwendung und Erweiterungen**

* **Key Usage** identifiziert kryptografische Anwendungen des öffentlichen Schlüssels, wie digitale Signatur oder Schlüsselausverschlüsselung.
* **Extended Key Usage** schränkt die Anwendungsfälle des Zertifikats weiter ein, z.B. für die TLS-Serverauthentifizierung.
* **Subject Alternative Name** und **Basic Constraint** definieren zusätzliche Hostnamen, die durch das Zertifikat abgedeckt sind, und ob es sich um ein CA- oder End-Entity-Zertifikat handelt.
* Identifikatoren wie **Subject Key Identifier** und **Authority Key Identifier** gewährleisten die Einzigartigkeit und Rückverfolgbarkeit von Schlüsseln.
* **Authority Information Access** und **CRL Distribution Points** bieten Wege zur Überprüfung der ausstellenden CA und zur Überprüfung des Widerrufsstatus des Zertifikats.
* **CT Precertificate SCTs** bieten Transparenzprotokolle, die entscheidend für das öffentliche Vertrauen in das Zertifikat sind.
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
### **Unterschied zwischen OCSP und CRL-Verteilungspunkten**

**OCSP** (**RFC 2560**) beinhaltet, dass ein Client und ein Responder zusammenarbeiten, um zu überprüfen, ob ein digitales Public-Key-Zertifikat widerrufen wurde, ohne die vollständige **CRL** herunterladen zu müssen. Diese Methode ist effizienter als die traditionelle **CRL**, die eine Liste von widerrufenen Zertifikat-Seriennummern bereitstellt, aber das Herunterladen einer potenziell großen Datei erfordert. CRLs können bis zu 512 Einträge enthalten. Weitere Details sind [hier](https://www.arubanetworks.com/techdocs/ArubaOS%206\_3\_1\_Web\_Help/Content/ArubaFrameStyles/CertRevocation/About\_OCSP\_and\_CRL.htm) verfügbar.

### **Was ist Zertifikatstransparenz**

Zertifikatstransparenz hilft, zertifikatsbezogene Bedrohungen zu bekämpfen, indem sichergestellt wird, dass die Ausstellung und Existenz von SSL-Zertifikaten für Domaininhaber, CAs und Benutzer sichtbar sind. Ihre Ziele sind:

* Verhindern, dass CAs SSL-Zertifikate für eine Domain ohne das Wissen des Domaininhabers ausstellen.
* Etablierung eines offenen Auditsystems zur Verfolgung fälschlicherweise oder böswillig ausgestellter Zertifikate.
* Schutz der Benutzer vor betrügerischen Zertifikaten.

#### **Zertifikatsprotokolle**

Zertifikatsprotokolle sind öffentlich prüfbare, nur anhängbare Aufzeichnungen von Zertifikaten, die von Netzwerkdiensten verwaltet werden. Diese Protokolle bieten kryptografische Nachweise für Prüfungszwecke. Sowohl Ausstellungseinrichtungen als auch die Öffentlichkeit können Zertifikate in diese Protokolle einreichen oder sie zur Verifizierung abfragen. Während die genaue Anzahl der Protokollserver nicht festgelegt ist, wird erwartet, dass sie weltweit weniger als tausend beträgt. Diese Server können unabhängig von CAs, ISPs oder jeder interessierten Entität verwaltet werden.

#### **Abfrage**

Um die Zertifikatstransparenzprotokolle für eine beliebige Domain zu durchsuchen, besuchen Sie [https://crt.sh/](https://crt.sh).

Es gibt verschiedene Formate zur Speicherung von Zertifikaten, jedes mit eigenen Anwendungsfällen und Kompatibilität. Diese Zusammenfassung behandelt die Hauptformate und bietet Anleitungen zur Konvertierung zwischen ihnen.

## **Formate**

### **PEM-Format**

* Am weitesten verbreitetes Format für Zertifikate.
* Erfordert separate Dateien für Zertifikate und private Schlüssel, kodiert in Base64 ASCII.
* Häufige Erweiterungen: .cer, .crt, .pem, .key.
* Hauptsächlich verwendet von Apache und ähnlichen Servern.

### **DER-Format**

* Ein binäres Format von Zertifikaten.
* Fehlen die "BEGIN/END CERTIFICATE"-Anweisungen, die in PEM-Dateien zu finden sind.
* Häufige Erweiterungen: .cer, .der.
* Oft verwendet mit Java-Plattformen.

### **P7B/PKCS#7-Format**

* In Base64 ASCII gespeichert, mit den Erweiterungen .p7b oder .p7c.
* Enthält nur Zertifikate und Kettenzertifikate, ohne den privaten Schlüssel.
* Unterstützt von Microsoft Windows und Java Tomcat.

### **PFX/P12/PKCS#12-Format**

* Ein binäres Format, das Serverzertifikate, Zwischenzertifikate und private Schlüssel in einer Datei kapselt.
* Erweiterungen: .pfx, .p12.
* Hauptsächlich auf Windows für den Import und Export von Zertifikaten verwendet.

### **Formate konvertieren**

**PEM-Konvertierungen** sind entscheidend für die Kompatibilität:

* **x509 zu PEM**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
* **PEM zu DER**
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
* **DER zu PEM**
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
* **PEM zu P7B**
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
* **PKCS7 zu PEM**
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**PFX-Konvertierungen** sind entscheidend für die Verwaltung von Zertifikaten unter Windows:

* **PFX zu PEM**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
* **PFX zu PKCS#8** umfasst zwei Schritte:
1. PFX in PEM konvertieren
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. Konvertiere PEM zu PKCS8
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
* **P7B zu PFX** erfordert ebenfalls zwei Befehle:
1. P7B in CER konvertieren
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. Konvertieren Sie CER und privaten Schlüssel in PFX
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
* **ASN.1 (DER/PEM) Bearbeitung** (funktioniert mit Zertifikaten oder fast jeder anderen ASN.1 Struktur):
1. Klone [asn1template](https://github.com/wllm-rbnt/asn1template/)
```bash
git clone https://github.com/wllm-rbnt/asn1template.git
```
2. Konvertieren von DER/PEM in das Generierungsformat von OpenSSL
```bash
asn1template/asn1template.pl certificatename.der > certificatename.tpl
asn1template/asn1template.pl -p certificatename.pem > certificatename.tpl
```
3. Bearbeiten Sie certificatename.tpl gemäß Ihren Anforderungen
```bash
vim certificatename.tpl
```
4. Stellen Sie das modifizierte Zertifikat wieder her
```bash
openssl asn1parse -genconf certificatename.tpl -out certificatename_new.der
openssl asn1parse -genconf certificatename.tpl -outform PEM -out certificatename_new.pem
```
***

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=certificates), um einfach **Workflows** zu erstellen und zu **automatisieren**, die von den **fortschrittlichsten** Community-Tools der Welt unterstützt werden.\
Zugang heute erhalten:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=certificates" %}

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}
