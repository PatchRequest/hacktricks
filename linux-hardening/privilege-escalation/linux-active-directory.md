# Linux Active Directory

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

{% embed url="https://websec.nl/" %}

Maszyna linuxowa może również znajdować się w środowisku Active Directory.

Maszyna linuxowa w AD może **przechowywać różne bilety CCACHE w plikach. Te bilety mogą być używane i nadużywane jak każdy inny bilet kerberosowy**. Aby odczytać te bilety, musisz być właścicielem biletu lub **rootem** na maszynie.

## Enumeracja

### Enumeracja AD z linuxa

Jeśli masz dostęp do AD w linuxie (lub bash w Windows), możesz spróbować [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn), aby enumerować AD.

Możesz również sprawdzić następującą stronę, aby dowiedzieć się o **innych sposobach enumeracji AD z linuxa**:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

### FreeIPA

FreeIPA to otwartoźródłowa **alternatywa** dla Microsoft Windows **Active Directory**, głównie dla środowisk **Unix**. Łączy kompletny **katalog LDAP** z MIT **Kerberos** Key Distribution Center do zarządzania podobnego do Active Directory. Wykorzystując system **certyfikatów Dogtag** do zarządzania certyfikatami CA i RA, wspiera **uwierzytelnianie wieloskładnikowe**, w tym karty inteligentne. SSSD jest zintegrowany z procesami uwierzytelniania Unix. Dowiedz się więcej o tym w:

{% content-ref url="../freeipa-pentesting.md" %}
[freeipa-pentesting.md](../freeipa-pentesting.md)
{% endcontent-ref %}

## Zabawa z biletami

### Pass The Ticket

Na tej stronie znajdziesz różne miejsca, w których możesz **znaleźć bilety kerberosowe w hoście linuxowym**, na następnej stronie możesz dowiedzieć się, jak przekształcić te formaty biletów CCache na Kirbi (format, którego musisz użyć w Windows) oraz jak przeprowadzić atak PTT:

{% content-ref url="../../windows-hardening/active-directory-methodology/pass-the-ticket.md" %}
[pass-the-ticket.md](../../windows-hardening/active-directory-methodology/pass-the-ticket.md)
{% endcontent-ref %}

### Ponowne użycie biletu CCACHE z /tmp

Pliki CCACHE to binarne formaty do **przechowywania poświadczeń Kerberos**, które zazwyczaj są przechowywane z uprawnieniami 600 w `/tmp`. Pliki te można zidentyfikować po ich **formacie nazwy, `krb5cc_%{uid}`,** odpowiadającym UID użytkownika. Aby zweryfikować bilet uwierzytelniający, **zmienna środowiskowa `KRB5CCNAME`** powinna być ustawiona na ścieżkę do pożądanego pliku biletu, co umożliwia jego ponowne użycie.

Wypisz aktualny bilet używany do uwierzytelniania za pomocą `env | grep KRB5CCNAME`. Format jest przenośny, a bilet może być **ponownie użyty, ustawiając zmienną środowiskową** za pomocą `export KRB5CCNAME=/tmp/ticket.ccache`. Format nazwy biletu Kerberos to `krb5cc_%{uid}`, gdzie uid to UID użytkownika.
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### CCACHE ticket reuse from keyring

**Bilety Kerberos przechowywane w pamięci procesu mogą być wyodrębnione**, szczególnie gdy ochrona ptrace maszyny jest wyłączona (`/proc/sys/kernel/yama/ptrace_scope`). Przydatnym narzędziem do tego celu jest dostępne pod adresem [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), które ułatwia wyodrębnianie poprzez wstrzykiwanie do sesji i zrzucanie biletów do `/tmp`.

Aby skonfigurować i użyć tego narzędzia, należy postępować zgodnie z poniższymi krokami:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Ta procedura spróbuje wstrzyknąć do różnych sesji, wskazując na sukces poprzez przechowywanie wyodrębnionych biletów w `/tmp` z konwencją nazewnictwa `__krb_UID.ccache`.

### Ponowne użycie biletu CCACHE z SSSD KCM

SSSD utrzymuje kopię bazy danych pod ścieżką `/var/lib/sss/secrets/secrets.ldb`. Odpowiedni klucz jest przechowywany jako ukryty plik pod ścieżką `/var/lib/sss/secrets/.secrets.mkey`. Domyślnie klucz jest czytelny tylko, jeśli masz uprawnienia **root**.

Wywołanie \*\*`SSSDKCMExtractor` \*\* z parametrami --database i --key zanalizuje bazę danych i **odszyfruje sekrety**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**Blob pamięci podręcznej poświadczeń Kerberos może być przekształcony w użyteczny plik CCache Kerberos**, który można przekazać do Mimikatz/Rubeus.

### Ponowne użycie biletu CCACHE z keytab
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### Wyciągnij konta z /etc/krb5.keytab

Klucze kont serwisowych, niezbędne dla usług działających z uprawnieniami roota, są bezpiecznie przechowywane w plikach **`/etc/krb5.keytab`**. Te klucze, podobnie jak hasła dla usług, wymagają ścisłej poufności.

Aby sprawdzić zawartość pliku keytab, można użyć **`klist`**. Narzędzie to jest zaprojektowane do wyświetlania szczegółów kluczy, w tym **NT Hash** do uwierzytelniania użytkowników, szczególnie gdy typ klucza jest identyfikowany jako 23.
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
Dla użytkowników Linuksa, **`KeyTabExtract`** oferuje funkcjonalność do ekstrakcji hasha RC4 HMAC, który można wykorzystać do ponownego użycia hasha NTLM.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Na macOS, **`bifrost`** służy jako narzędzie do analizy plików keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Wykorzystując wyodrębnione informacje o koncie i haszach, można nawiązać połączenia z serwerami za pomocą narzędzi takich jak **`crackmapexec`**.
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## Odniesienia

* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
