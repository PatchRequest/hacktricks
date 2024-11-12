# macOS Authorizations DB & Authd



{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## **Baza danych autoryzacji**

Baza danych znajdująca się w `/var/db/auth.db` jest używana do przechowywania uprawnień do wykonywania wrażliwych operacji. Operacje te są wykonywane całkowicie w **przestrzeni użytkownika** i zazwyczaj są używane przez **usługi XPC**, które muszą sprawdzić **czy wywołujący klient jest uprawniony** do wykonania określonej akcji, sprawdzając tę bazę danych.

Początkowo ta baza danych jest tworzona na podstawie zawartości `/System/Library/Security/authorization.plist`. Następnie niektóre usługi mogą dodać lub zmodyfikować tę bazę danych, aby dodać do niej inne uprawnienia.

Reguły są przechowywane w tabeli `rules` wewnątrz bazy danych i zawierają następujące kolumny:

* **id**: Unikalny identyfikator dla każdej reguły, automatycznie inkrementowany i służący jako klucz główny.
* **name**: Unikalna nazwa reguły używana do identyfikacji i odniesienia się do niej w systemie autoryzacji.
* **type**: Określa typ reguły, ograniczony do wartości 1 lub 2 w celu zdefiniowania jej logiki autoryzacji.
* **class**: Kategoruje regułę do określonej klasy, zapewniając, że jest to liczba całkowita dodatnia.
* "allow" dla zezwolenia, "deny" dla odmowy, "user" jeśli właściwość grupy wskazuje na grupę, której członkostwo umożliwia dostęp, "rule" wskazuje w tablicy regułę do spełnienia, "evaluate-mechanisms" po którym następuje tablica `mechanisms`, która jest albo wbudowana, albo nazwą pakietu w `/System/Library/CoreServices/SecurityAgentPlugins/` lub /Library/Security//SecurityAgentPlugins
* **group**: Wskazuje grupę użytkowników związaną z regułą dla autoryzacji opartej na grupach.
* **kofn**: Reprezentuje parametr "k-of-n", określający, ile subreguł musi być spełnionych z całkowitej liczby.
* **timeout**: Określa czas w sekundach, po którym autoryzacja przyznana przez regułę wygasa.
* **flags**: Zawiera różne flagi, które modyfikują zachowanie i cechy reguły.
* **tries**: Ogranicza liczbę dozwolonych prób autoryzacji w celu zwiększenia bezpieczeństwa.
* **version**: Śledzi wersję reguły dla kontroli wersji i aktualizacji.
* **created**: Rejestruje znacznik czasu, kiedy reguła została utworzona w celach audytowych.
* **modified**: Przechowuje znacznik czasu ostatniej modyfikacji dokonanej w regule.
* **hash**: Przechowuje wartość hasha reguły, aby zapewnić jej integralność i wykryć manipulacje.
* **identifier**: Dostarcza unikalny identyfikator w postaci ciągu, taki jak UUID, dla zewnętrznych odniesień do reguły.
* **requirement**: Zawiera zserializowane dane definiujące specyficzne wymagania autoryzacji i mechanizmy reguły.
* **comment**: Oferuje opis lub komentarz w formie czytelnej dla człowieka dotyczący reguły w celach dokumentacyjnych i jasności.

### Przykład
```bash
# List by name and comments
sudo sqlite3 /var/db/auth.db "select name, comment from rules"

# Get rules for com.apple.tcc.util.admin
security authorizationdb read com.apple.tcc.util.admin
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>rule</string>
<key>comment</key>
<string>For modification of TCC settings.</string>
<key>created</key>
<real>701369782.01043606</real>
<key>modified</key>
<real>701369782.01043606</real>
<key>rule</key>
<array>
<string>authenticate-admin-nonshared</string>
</array>
<key>version</key>
<integer>0</integer>
</dict>
</plist>
```
Ponadto w [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) można zobaczyć znaczenie `authenticate-admin-nonshared`:
```json
{
'allow-root' : 'false',
'authenticate-user' : 'true',
'class' : 'user',
'comment' : 'Authenticate as an administrator.',
'group' : 'admin',
'session-owner' : 'false',
'shared' : 'false',
'timeout' : '30',
'tries' : '10000',
'version' : '1'
}
```
## Authd

To demon, który odbiera żądania autoryzacji klientów do wykonywania wrażliwych działań. Działa jako usługa XPC zdefiniowana w folderze `XPCServices/` i używa do zapisywania swoich logów w `/var/log/authd.log`.

Ponadto, korzystając z narzędzia security, można testować wiele interfejsów API `Security.framework`. Na przykład `AuthorizationExecuteWithPrivileges` uruchamiając: `security execute-with-privileges /bin/ls`

To spowoduje fork i exec `/usr/libexec/security_authtrampoline /bin/ls` jako root, co poprosi o uprawnienia w oknie dialogowym, aby wykonać ls jako root:

<figure><img src="../../../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
