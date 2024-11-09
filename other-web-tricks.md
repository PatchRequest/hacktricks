# Inne sztuczki internetowe

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Uzyskaj perspektywę hakera na swoje aplikacje internetowe, sieć i chmurę**

**Znajdź i zgłoś krytyczne, wykorzystywalne luki w zabezpieczeniach, które mają rzeczywisty wpływ na biznes.** Użyj naszych 20+ niestandardowych narzędzi do mapowania powierzchni ataku, znajdowania problemów z bezpieczeństwem, które pozwalają na eskalację uprawnień, oraz użyj zautomatyzowanych exploitów do zbierania niezbędnych dowodów, przekształcając swoją ciężką pracę w przekonujące raporty.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

### Nagłówek hosta

Kilka razy backend ufa **nagłówkowi Host**, aby wykonać pewne działania. Na przykład, może użyć jego wartości jako **domeny do wysłania resetu hasła**. Gdy otrzymasz e-mail z linkiem do zresetowania hasła, używaną domeną jest ta, którą wpisałeś w nagłówku Host. Następnie możesz zażądać resetu hasła innych użytkowników i zmienić domenę na kontrolowaną przez siebie, aby ukraść ich kody resetowania hasła. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

{% hint style="warning" %}
Zauważ, że możliwe jest, że nie musisz nawet czekać, aż użytkownik kliknie link do resetowania hasła, aby uzyskać token, ponieważ nawet **filtry spamowe lub inne urządzenia/boty pośredniczące mogą kliknąć w niego, aby go przeanalizować**.
{% endhint %}

### Booleany sesji

Czasami, gdy poprawnie zakończysz weryfikację, backend **po prostu doda boolean z wartością "True" do atrybutu bezpieczeństwa twojej sesji**. Następnie inny punkt końcowy będzie wiedział, czy pomyślnie przeszedłeś tę kontrolę.\
Jednak jeśli **przejdziesz kontrolę** i twoja sesja otrzyma tę wartość "True" w atrybucie bezpieczeństwa, możesz spróbować **uzyskać dostęp do innych zasobów**, które **zależą od tego samego atrybutu**, ale do których **nie powinieneś mieć uprawnień** do dostępu. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Funkcjonalność rejestracji

Spróbuj zarejestrować się jako już istniejący użytkownik. Spróbuj także użyć równoważnych znaków (kropki, dużo spacji i Unicode).

### Przejęcie e-maili

Zarejestruj e-mail, przed potwierdzeniem zmień e-mail, a następnie, jeśli nowy e-mail potwierdzający zostanie wysłany na pierwszy zarejestrowany e-mail, możesz przejąć dowolny e-mail. Lub jeśli możesz włączyć drugi e-mail potwierdzający pierwszy, możesz również przejąć dowolne konto.

### Dostęp do wewnętrznego serwisu pomocy technicznej firm korzystających z Atlassian

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### Metoda TRACE

Programiści mogą zapomnieć wyłączyć różne opcje debugowania w środowisku produkcyjnym. Na przykład, metoda HTTP `TRACE` jest zaprojektowana do celów diagnostycznych. Jeśli jest włączona, serwer internetowy odpowie na żądania, które używają metody `TRACE`, echoując w odpowiedzi dokładne żądanie, które zostało odebrane. To zachowanie jest często nieszkodliwe, ale czasami prowadzi do ujawnienia informacji, takich jak nazwy wewnętrznych nagłówków uwierzytelniających, które mogą być dołączane do żądań przez odwrotne proxy.![Image for post](https://miro.medium.com/max/60/1\*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1\*wDFRADTOd9Tj63xucenvAA.png)


<figure><img src="/.gitbook/assets/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Uzyskaj perspektywę hakera na swoje aplikacje internetowe, sieć i chmurę**

**Znajdź i zgłoś krytyczne, wykorzystywalne luki w zabezpieczeniach, które mają rzeczywisty wpływ na biznes.** Użyj naszych 20+ niestandardowych narzędzi do mapowania powierzchni ataku, znajdowania problemów z bezpieczeństwem, które pozwalają na eskalację uprawnień, oraz użyj zautomatyzowanych exploitów do zbierania niezbędnych dowodów, przekształcając swoją ciężką pracę w przekonujące raporty.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
