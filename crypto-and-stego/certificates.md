# Certificati

{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository su github.

</details>
{% endhint %}

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=certificates) per costruire e **automatizzare flussi di lavoro** facilmente, alimentati dagli **strumenti** della comunità **più avanzati** al mondo.\
Accedi oggi:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=certificates" %}

## Cos'è un Certificato

Un **certificato a chiave pubblica** è un ID digitale utilizzato nella crittografia per dimostrare che qualcuno possiede una chiave pubblica. Include i dettagli della chiave, l'identità del proprietario (il soggetto) e una firma digitale da un'autorità fidata (l'emittente). Se il software si fida dell'emittente e la firma è valida, è possibile una comunicazione sicura con il proprietario della chiave.

I certificati sono principalmente emessi da [autorità di certificazione](https://en.wikipedia.org/wiki/Certificate\_authority) (CA) in un'architettura di [infrastruttura a chiave pubblica](https://en.wikipedia.org/wiki/Public-key\_infrastructure) (PKI). Un altro metodo è il [web of trust](https://en.wikipedia.org/wiki/Web\_of\_trust), dove gli utenti verificano direttamente le chiavi degli altri. Il formato comune per i certificati è [X.509](https://en.wikipedia.org/wiki/X.509), che può essere adattato per esigenze specifiche come delineato nell'RFC 5280.

## Campi Comuni x509

### **Campi Comuni nei Certificati x509**

Nei certificati x509, diversi **campi** svolgono ruoli critici nel garantire la validità e la sicurezza del certificato. Ecco una panoramica di questi campi:

* **Numero di Versione** indica la versione del formato x509.
* **Numero di Serie** identifica univocamente il certificato all'interno del sistema di un'Autorità di Certificazione (CA), principalmente per il tracciamento delle revoche.
* Il campo **Soggetto** rappresenta il proprietario del certificato, che potrebbe essere una macchina, un individuo o un'organizzazione. Include identificazione dettagliata come:
* **Nome Comune (CN)**: Domini coperti dal certificato.
* **Paese (C)**, **Località (L)**, **Stato o Provincia (ST, S, o P)**, **Organizzazione (O)** e **Unità Organizzativa (OU)** forniscono dettagli geografici e organizzativi.
* **Nome Distinto (DN)** racchiude l'intera identificazione del soggetto.
* **Emittente** dettaglia chi ha verificato e firmato il certificato, includendo sottocampi simili a quelli del Soggetto per la CA.
* Il **Periodo di Validità** è contrassegnato dai timestamp **Non Prima** e **Non Dopo**, assicurando che il certificato non venga utilizzato prima o dopo una certa data.
* La sezione **Chiave Pubblica**, cruciale per la sicurezza del certificato, specifica l'algoritmo, la dimensione e altri dettagli tecnici della chiave pubblica.
* Le **estensioni x509v3** migliorano la funzionalità del certificato, specificando **Utilizzo della Chiave**, **Utilizzo Esteso della Chiave**, **Nome Alternativo del Soggetto** e altre proprietà per affinare l'applicazione del certificato.

#### **Utilizzo della Chiave e Estensioni**

* **Utilizzo della Chiave** identifica le applicazioni crittografiche della chiave pubblica, come la firma digitale o la cifratura della chiave.
* **Utilizzo Esteso della Chiave** restringe ulteriormente i casi d'uso del certificato, ad esempio, per l'autenticazione del server TLS.
* **Nome Alternativo del Soggetto** e **Vincolo di Base** definiscono nomi host aggiuntivi coperti dal certificato e se si tratta di un certificato CA o di entità finale, rispettivamente.
* Identificatori come **Identificatore della Chiave del Soggetto** e **Identificatore della Chiave dell'Autorità** garantiscono l'unicità e la tracciabilità delle chiavi.
* **Accesso alle Informazioni dell'Autorità** e **Punti di Distribuzione CRL** forniscono percorsi per verificare la CA emittente e controllare lo stato di revoca del certificato.
* **SCTs Precertificate CT** offrono registri di trasparenza, cruciali per la fiducia pubblica nel certificato.
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
### **Differenza tra OCSP e Punti di Distribuzione CRL**

**OCSP** (**RFC 2560**) coinvolge un client e un risponditore che lavorano insieme per controllare se un certificato digitale a chiave pubblica è stato revocato, senza la necessità di scaricare l'intero **CRL**. Questo metodo è più efficiente rispetto al tradizionale **CRL**, che fornisce un elenco di numeri di serie di certificati revocati ma richiede il download di un file potenzialmente grande. I CRL possono includere fino a 512 voci. Maggiori dettagli sono disponibili [qui](https://www.arubanetworks.com/techdocs/ArubaOS%206\_3\_1\_Web\_Help/Content/ArubaFrameStyles/CertRevocation/About\_OCSP\_and\_CRL.htm).

### **Cos'è la Trasparenza dei Certificati**

La Trasparenza dei Certificati aiuta a combattere le minacce legate ai certificati garantendo che l'emissione e l'esistenza dei certificati SSL siano visibili ai proprietari di domini, CA e utenti. I suoi obiettivi sono:

* Prevenire che le CA emettano certificati SSL per un dominio senza la conoscenza del proprietario del dominio.
* Stabilire un sistema di auditing aperto per tracciare certificati emessi per errore o in modo malevolo.
* Proteggere gli utenti contro certificati fraudolenti.

#### **Log dei Certificati**

I log dei certificati sono registri pubblicamente auditabili, solo in append, di certificati, mantenuti dai servizi di rete. Questi log forniscono prove crittografiche per scopi di auditing. Sia le autorità di emissione che il pubblico possono inviare certificati a questi log o interrogarli per verifica. Sebbene il numero esatto di server di log non sia fisso, si prevede che sia inferiore a mille a livello globale. Questi server possono essere gestiti in modo indipendente da CA, ISP o qualsiasi entità interessata.

#### **Query**

Per esplorare i log della Trasparenza dei Certificati per qualsiasi dominio, visita [https://crt.sh/](https://crt.sh).

Esistono diversi formati per memorizzare i certificati, ognuno con i propri casi d'uso e compatibilità. Questo riepilogo copre i formati principali e fornisce indicazioni sulla conversione tra di essi.

## **Formati**

### **Formato PEM**

* Formato più ampiamente utilizzato per i certificati.
* Richiede file separati per certificati e chiavi private, codificati in Base64 ASCII.
* Estensioni comuni: .cer, .crt, .pem, .key.
* Utilizzato principalmente da Apache e server simili.

### **Formato DER**

* Un formato binario di certificati.
* Mancano le dichiarazioni "BEGIN/END CERTIFICATE" presenti nei file PEM.
* Estensioni comuni: .cer, .der.
* Spesso utilizzato con piattaforme Java.

### **Formato P7B/PKCS#7**

* Memorizzato in Base64 ASCII, con estensioni .p7b o .p7c.
* Contiene solo certificati e certificati di catena, escludendo la chiave privata.
* Supportato da Microsoft Windows e Java Tomcat.

### **Formato PFX/P12/PKCS#12**

* Un formato binario che racchiude certificati del server, certificati intermedi e chiavi private in un unico file.
* Estensioni: .pfx, .p12.
* Utilizzato principalmente su Windows per l'importazione e l'esportazione dei certificati.

### **Conversione dei Formati**

**Le conversioni PEM** sono essenziali per la compatibilità:

* **x509 a PEM**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
* **PEM a DER**
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
* **DER a PEM**
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
* **PEM a P7B**
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
* **PKCS7 a PEM**
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**Le conversioni PFX** sono cruciali per la gestione dei certificati su Windows:

* **PFX a PEM**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
* **PFX a PKCS#8** comporta due passaggi:
1. Convertire PFX in PEM
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. Convertire PEM in PKCS8
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
* **P7B a PFX** richiede anche due comandi:
1. Convertire P7B in CER
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. Convertire CER e chiave privata in PFX
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
* **Modifica ASN.1 (DER/PEM)** (funziona con certificati o quasi qualsiasi altra struttura ASN.1):
1. Clona [asn1template](https://github.com/wllm-rbnt/asn1template/)
```bash
git clone https://github.com/wllm-rbnt/asn1template.git
```
2. Convertire DER/PEM nel formato di generazione di OpenSSL
```bash
asn1template/asn1template.pl certificatename.der > certificatename.tpl
asn1template/asn1template.pl -p certificatename.pem > certificatename.tpl
```
3. Modifica certificatename.tpl secondo le tue esigenze
```bash
vim certificatename.tpl
```
4. Ricostruire il certificato modificato
```bash
openssl asn1parse -genconf certificatename.tpl -out certificatename_new.der
openssl asn1parse -genconf certificatename.tpl -outform PEM -out certificatename_new.pem
```
***

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Usa [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=certificates) per costruire e **automatizzare flussi di lavoro** facilmente, alimentati dagli **strumenti** della comunità **più avanzati** al mondo.\
Ottieni accesso oggi:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=certificates" %}

{% hint style="success" %}
Impara e pratica il hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica il hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}
