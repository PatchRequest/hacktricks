# Certyfikaty

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=certificates), aby łatwo budować i **automatyzować przepływy pracy** zasilane przez **najbardziej zaawansowane** narzędzia społecznościowe na świecie.\
Uzyskaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=certificates" %}

## Czym jest certyfikat

**Certyfikat klucza publicznego** to cyfrowy identyfikator używany w kryptografii do udowodnienia, że ktoś posiada klucz publiczny. Zawiera szczegóły klucza, tożsamość właściciela (temat) oraz podpis cyfrowy od zaufanej instytucji (wydawcy). Jeśli oprogramowanie ufa wydawcy, a podpis jest ważny, możliwa jest bezpieczna komunikacja z właścicielem klucza.

Certyfikaty są głównie wydawane przez [władze certyfikacyjne](https://en.wikipedia.org/wiki/Certificate\_authority) (CA) w ramach [infrastruktury klucza publicznego](https://en.wikipedia.org/wiki/Public-key\_infrastructure) (PKI). Inną metodą jest [sieć zaufania](https://en.wikipedia.org/wiki/Web\_of\_trust), w której użytkownicy bezpośrednio weryfikują klucze innych. Powszechnym formatem certyfikatów jest [X.509](https://en.wikipedia.org/wiki/X.509), który można dostosować do specyficznych potrzeb, jak opisano w RFC 5280.

## x509 Wspólne pola

### **Wspólne pola w certyfikatach x509**

W certyfikatach x509 kilka **pól** odgrywa kluczowe role w zapewnieniu ważności i bezpieczeństwa certyfikatu. Oto podział tych pól:

* **Numer wersji** oznacza wersję formatu x509.
* **Numer seryjny** unikalnie identyfikuje certyfikat w systemie Władzy Certyfikacyjnej (CA), głównie do śledzenia unieważnień.
* Pole **Temat** reprezentuje właściciela certyfikatu, którym może być maszyna, osoba lub organizacja. Zawiera szczegółową identyfikację, taką jak:
* **Nazwa wspólna (CN)**: Domeny objęte certyfikatem.
* **Kraj (C)**, **Lokalizacja (L)**, **Stan lub Prowincja (ST, S lub P)**, **Organizacja (O)** oraz **Jednostka organizacyjna (OU)** dostarczają szczegóły geograficzne i organizacyjne.
* **Nazwa wyróżniająca (DN)** obejmuje pełną identyfikację tematu.
* **Wydawca** podaje, kto zweryfikował i podpisał certyfikat, w tym podobne podpola jak w Temacie dla CA.
* **Okres ważności** oznaczony jest znacznikami **Nie wcześniej niż** i **Nie później niż**, zapewniając, że certyfikat nie jest używany przed lub po określonej dacie.
* Sekcja **Klucz publiczny**, kluczowa dla bezpieczeństwa certyfikatu, określa algorytm, rozmiar i inne szczegóły techniczne klucza publicznego.
* **Rozszerzenia x509v3** zwiększają funkcjonalność certyfikatu, określając **Zastosowanie klucza**, **Rozszerzone zastosowanie klucza**, **Alternatywną nazwę tematu** i inne właściwości, aby dostosować zastosowanie certyfikatu.

#### **Zastosowanie klucza i rozszerzenia**

* **Zastosowanie klucza** identyfikuje kryptograficzne zastosowania klucza publicznego, takie jak podpis cyfrowy lub szyfrowanie klucza.
* **Rozszerzone zastosowanie klucza** jeszcze bardziej zawęża przypadki użycia certyfikatu, np. do uwierzytelniania serwera TLS.
* **Alternatywna nazwa tematu** i **Podstawowe ograniczenie** definiują dodatkowe nazwy hostów objęte certyfikatem oraz czy jest to certyfikat CA czy certyfikat końcowy.
* Identyfikatory takie jak **Identyfikator klucza tematu** i **Identyfikator klucza autorytetu** zapewniają unikalność i możliwość śledzenia kluczy.
* **Dostęp do informacji o autorytecie** i **Punkty dystrybucji CRL** dostarczają ścieżek do weryfikacji wydającej CA i sprawdzenia statusu unieważnienia certyfikatu.
* **SCT certyfikatu CT** oferują dzienniki przejrzystości, kluczowe dla publicznego zaufania do certyfikatu.
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
### **Różnica między OCSP a punktami dystrybucji CRL**

**OCSP** (**RFC 2560**) polega na współpracy klienta i respondenta w celu sprawdzenia, czy cyfrowy certyfikat klucza publicznego został unieważniony, bez potrzeby pobierania pełnej **CRL**. Ta metoda jest bardziej efektywna niż tradycyjna **CRL**, która dostarcza listę unieważnionych numerów seryjnych certyfikatów, ale wymaga pobrania potencjalnie dużego pliku. CRL mogą zawierać do 512 wpisów. Więcej szczegółów można znaleźć [tutaj](https://www.arubanetworks.com/techdocs/ArubaOS%206\_3\_1\_Web\_Help/Content/ArubaFrameStyles/CertRevocation/About\_OCSP\_and\_CRL.htm).

### **Czym jest przejrzystość certyfikatów**

Przejrzystość certyfikatów pomaga w walce z zagrożeniami związanymi z certyfikatami, zapewniając, że wydanie i istnienie certyfikatów SSL są widoczne dla właścicieli domen, CAs i użytkowników. Jej cele to:

* Zapobieganie wydawaniu certyfikatów SSL dla domeny bez wiedzy właściciela domeny.
* Ustanowienie otwartego systemu audytowego do śledzenia błędnie lub złośliwie wydanych certyfikatów.
* Ochrona użytkowników przed fałszywymi certyfikatami.

#### **Logi certyfikatów**

Logi certyfikatów to publicznie audytowalne, tylko do dopisywania rejestry certyfikatów, prowadzone przez usługi sieciowe. Logi te dostarczają dowodów kryptograficznych do celów audytowych. Zarówno władze wydające, jak i publiczność mogą przesyłać certyfikaty do tych logów lub zapytywać je w celu weryfikacji. Chociaż dokładna liczba serwerów logów nie jest ustalona, oczekuje się, że będzie ich mniej niż tysiąc na całym świecie. Serwery te mogą być zarządzane niezależnie przez CAs, ISP lub jakąkolwiek zainteresowaną stronę.

#### **Zapytanie**

Aby zbadać logi przejrzystości certyfikatów dla dowolnej domeny, odwiedź [https://crt.sh/](https://crt.sh).

Istnieją różne formaty przechowywania certyfikatów, z których każdy ma swoje zastosowania i kompatybilność. To podsumowanie obejmuje główne formaty i dostarcza wskazówek dotyczących konwersji między nimi.

## **Formaty**

### **Format PEM**

* Najczęściej używany format dla certyfikatów.
* Wymaga oddzielnych plików dla certyfikatów i kluczy prywatnych, zakodowanych w Base64 ASCII.
* Powszechne rozszerzenia: .cer, .crt, .pem, .key.
* Głównie używany przez Apache i podobne serwery.

### **Format DER**

* Format binarny certyfikatów.
* Brak "BEGIN/END CERTIFICATE" znajdujących się w plikach PEM.
* Powszechne rozszerzenia: .cer, .der.
* Często używany z platformami Java.

### **Format P7B/PKCS#7**

* Przechowywany w Base64 ASCII, z rozszerzeniami .p7b lub .p7c.
* Zawiera tylko certyfikaty i certyfikaty łańcucha, wykluczając klucz prywatny.
* Obsługiwany przez Microsoft Windows i Java Tomcat.

### **Format PFX/P12/PKCS#12**

* Format binarny, który kapsułkuje certyfikaty serwera, certyfikaty pośrednie i klucze prywatne w jednym pliku.
* Rozszerzenia: .pfx, .p12.
* Głównie używany w systemie Windows do importu i eksportu certyfikatów.

### **Konwersja formatów**

**Konwersje PEM** są niezbędne dla kompatybilności:

* **x509 do PEM**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
* **PEM do DER**
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
* **DER do PEM**
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
* **PEM do P7B**
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
* **PKCS7 do PEM**
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**Konwersje PFX** są kluczowe dla zarządzania certyfikatami w systemie Windows:

* **PFX do PEM**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
* **PFX do PKCS#8** obejmuje dwa kroki:
1. Konwersja PFX do PEM
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. Konwertuj PEM na PKCS8
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
* **P7B do PFX** wymaga również dwóch poleceń:
1. Konwertuj P7B na CER
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. Konwertuj CER i klucz prywatny na PFX
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
* **Edycja ASN.1 (DER/PEM)** (działa z certyfikatami lub prawie każdą inną strukturą ASN.1):
1. Sklonuj [asn1template](https://github.com/wllm-rbnt/asn1template/)
```bash
git clone https://github.com/wllm-rbnt/asn1template.git
```
2. Konwertuj DER/PEM na format generacji OpenSSL
```bash
asn1template/asn1template.pl certificatename.der > certificatename.tpl
asn1template/asn1template.pl -p certificatename.pem > certificatename.tpl
```
3. Edytuj certificatename.tpl zgodnie z własnymi wymaganiami
```bash
vim certificatename.tpl
```
4. Odbuduj zmodyfikowany certyfikat
```bash
openssl asn1parse -genconf certificatename.tpl -out certificatename_new.der
openssl asn1parse -genconf certificatename.tpl -outform PEM -out certificatename_new.pem
```
***

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=certificates), aby łatwo budować i **automatyzować przepływy pracy** zasilane przez **najbardziej zaawansowane** narzędzia społecznościowe na świecie.\
Uzyskaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=certificates" %}

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
