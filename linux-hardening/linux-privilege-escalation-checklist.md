# Lista kontrolna - Eskalacja uprawnień w systemie Linux

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Dołącz do [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) serwera, aby komunikować się z doświadczonymi hackerami i łowcami bugów!

**Wgląd w hacking**\
Zaangażuj się w treści, które zagłębiają się w emocje i wyzwania związane z hackingiem

**Aktualności o hackingu w czasie rzeczywistym**\
Bądź na bieżąco z dynamicznym światem hackingu dzięki aktualnym wiadomościom i wglądom

**Najnowsze ogłoszenia**\
Bądź informowany o najnowszych programach bug bounty oraz istotnych aktualizacjach platformy

**Dołącz do nas na** [**Discord**](https://discord.com/invite/N3FrSbmwdy) i zacznij współpracować z najlepszymi hackerami już dziś!

### **Najlepsze narzędzie do wyszukiwania wektorów lokalnej eskalacji uprawnień w systemie Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informacje o systemie](privilege-escalation/#system-information)

* [ ] Uzyskaj **informacje o systemie operacyjnym**
* [ ] Sprawdź [**PATH**](privilege-escalation/#path), czy jest jakaś **zapisywalna folder**?
* [ ] Sprawdź [**zmienne środowiskowe**](privilege-escalation/#env-info), czy są jakieś wrażliwe dane?
* [ ] Szukaj [**eksploatacji jądra**](privilege-escalation/#kernel-exploits) **za pomocą skryptów** (DirtyCow?)
* [ ] **Sprawdź**, czy [**wersja sudo** jest podatna](privilege-escalation/#sudo-version)
* [ ] [**Weryfikacja podpisu Dmesg** nie powiodła się](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] Więcej informacji o systemie ([data, statystyki systemu, informacje o CPU, drukarki](privilege-escalation/#more-system-enumeration))
* [ ] [**Zenumeruj więcej zabezpieczeń**](privilege-escalation/#enumerate-possible-defenses)

### [Dyski](privilege-escalation/#drives)

* [ ] **Wypisz zamontowane** dyski
* [ ] **Czy jest jakiś niezmontowany dysk?**
* [ ] **Czy są jakieś dane uwierzytelniające w fstab?**

### [**Zainstalowane oprogramowanie**](privilege-escalation/#installed-software)

* [ ] **Sprawdź** [**przydatne oprogramowanie**](privilege-escalation/#useful-software) **zainstalowane**
* [ ] **Sprawdź** [**podatne oprogramowanie**](privilege-escalation/#vulnerable-software-installed) **zainstalowane**

### [Procesy](privilege-escalation/#processes)

* [ ] Czy jakieś **nieznane oprogramowanie działa**?
* [ ] Czy jakieś oprogramowanie działa z **większymi uprawnieniami niż powinno**?
* [ ] Szukaj **eksploatacji działających procesów** (szczególnie wersji działającej).
* [ ] Czy możesz **zmodyfikować binarny** plik jakiegoś działającego procesu?
* [ ] **Monitoruj procesy** i sprawdź, czy jakiś interesujący proces działa często.
* [ ] Czy możesz **odczytać** jakąś interesującą **pamięć procesu** (gdzie mogą być zapisane hasła)?

### [Zadania zaplanowane/Cron?](privilege-escalation/#scheduled-jobs)

* [ ] Czy [**PATH**](privilege-escalation/#cron-path) jest modyfikowany przez jakiś cron i możesz w nim **zapisać**?
* [ ] Czy w zadaniu cron jest jakiś [**znacznik**](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)?
* [ ] Czy jakiś [**modyfikowalny skrypt**](privilege-escalation/#cron-script-overwriting-and-symlink) jest **wykonywany** lub znajduje się w **modyfikowalnym folderze**?
* [ ] Czy wykryłeś, że jakiś **skrypt** może być lub jest [**wykonywany** bardzo **często**](privilege-escalation/#frequent-cron-jobs)? (co 1, 2 lub 5 minut)

### [Usługi](privilege-escalation/#services)

* [ ] Czy jest jakiś **zapisywalny plik .service**?
* [ ] Czy jest jakiś **zapisywalny plik binarny** wykonywany przez **usługę**?
* [ ] Czy jest jakiś **zapisywalny folder w systemd PATH**?

### [Timery](privilege-escalation/#timers)

* [ ] Czy jest jakiś **zapisywalny timer**?

### [Gniazda](privilege-escalation/#sockets)

* [ ] Czy jest jakiś **zapisywalny plik .socket**?
* [ ] Czy możesz **komunikować się z jakimś gniazdem**?
* [ ] **Gniazda HTTP** z interesującymi informacjami?

### [D-Bus](privilege-escalation/#d-bus)

* [ ] Czy możesz **komunikować się z jakimś D-Bus**?

### [Sieć](privilege-escalation/#network)

* [ ] Zenumeruj sieć, aby wiedzieć, gdzie jesteś
* [ ] **Otwarte porty, do których nie mogłeś uzyskać dostępu** przed uzyskaniem powłoki wewnątrz maszyny?
* [ ] Czy możesz **przechwytywać ruch** za pomocą `tcpdump`?

### [Użytkownicy](privilege-escalation/#users)

* [ ] Ogólna **enumeracja użytkowników/grup**
* [ ] Czy masz **bardzo duży UID**? Czy **maszyna** jest **podatna**?
* [ ] Czy możesz [**eskalować uprawnienia dzięki grupie**](privilege-escalation/interesting-groups-linux-pe/), do której należysz?
* [ ] **Dane z schowka**?
* [ ] Polityka haseł?
* [ ] Spróbuj **użyć** każdego **znanego hasła**, które wcześniej odkryłeś, aby zalogować się **z każdym** możliwym **użytkownikiem**. Spróbuj również zalogować się bez hasła.

### [Zapisywalny PATH](privilege-escalation/#writable-path-abuses)

* [ ] Jeśli masz **uprawnienia do zapisu w jakimś folderze w PATH**, możesz być w stanie eskalować uprawnienia

### [Polecenia SUDO i SUID](privilege-escalation/#sudo-and-suid)

* [ ] Czy możesz wykonać **jakiekolwiek polecenie z sudo**? Czy możesz użyć go do ODCZYTU, ZAPISU lub WYKONANIA czegokolwiek jako root? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Czy jest jakiś **eksploatowalny plik binarny SUID**? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Czy [**polecenia sudo** są **ograniczone** przez **ścieżkę**? czy możesz **obejść** te ograniczenia](privilege-escalation/#sudo-execution-bypassing-paths)?
* [ ] [**Sudo/SUID binarny bez wskazanej ścieżki**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
* [ ] [**SUID binarny z określoną ścieżką**](privilege-escalation/#suid-binary-with-command-path)? Obejście
* [ ] [**LD\_PRELOAD vuln**](privilege-escalation/#ld\_preload)
* [ ] [**Brak biblioteki .so w binarnym pliku SUID**](privilege-escalation/#suid-binary-so-injection) z zapisywalnego folderu?
* [ ] [**Dostępne tokeny SUDO**](privilege-escalation/#reusing-sudo-tokens)? [**Czy możesz stworzyć token SUDO**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
* [ ] Czy możesz [**czytać lub modyfikować pliki sudoers**](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
* [ ] Czy możesz [**zmodyfikować /etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d)?
* [ ] [**OpenBSD DOAS**](privilege-escalation/#doas) polecenie

### [Uprawnienia](privilege-escalation/#capabilities)

* [ ] Czy jakiś plik binarny ma jakąś **nieoczekiwaną zdolność**?

### [ACL](privilege-escalation/#acls)

* [ ] Czy jakiś plik ma jakąś **nieoczekiwaną ACL**?

### [Otwarte sesje powłoki](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL Przewidywalny PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**Interesujące wartości konfiguracyjne SSH**](privilege-escalation/#ssh-interesting-configuration-values)

### [Interesujące pliki](privilege-escalation/#interesting-files)

* [ ] **Pliki profilu** - Czytaj wrażliwe dane? Zapisz do privesc?
* [ ] **Pliki passwd/shadow** - Czytaj wrażliwe dane? Zapisz do privesc?
* [ ] **Sprawdź powszechnie interesujące foldery** pod kątem wrażliwych danych
* [ ] **Dziwne lokalizacje/Pliki własnościowe,** do których możesz mieć dostęp lub zmieniać pliki wykonywalne
* [ ] **Zmodyfikowane** w ostatnich minutach
* [ ] **Pliki bazy danych Sqlite**
* [ ] **Ukryte pliki**
* [ ] **Skrypty/Binary w PATH**
* [ ] **Pliki webowe** (hasła?)
* [ ] **Kopie zapasowe**?
* [ ] **Znane pliki, które zawierają hasła**: Użyj **Linpeas** i **LaZagne**
* [ ] **Ogólne wyszukiwanie**

### [**Zapisywalne pliki**](privilege-escalation/#writable-files)

* [ ] **Modyfikuj bibliotekę Pythona** w celu wykonania dowolnych poleceń?
* [ ] Czy możesz **modyfikować pliki dziennika**? **Logtotten** exploit
* [ ] Czy możesz **modyfikować /etc/sysconfig/network-scripts/**? Eksploit Centos/Redhat
* [ ] Czy możesz [**zapisać w plikach ini, int.d, systemd lub rc.d**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Inne sztuczki**](privilege-escalation/#other-tricks)

* [ ] Czy możesz [**wykorzystać NFS do eskalacji uprawnień**](privilege-escalation/#nfs-privilege-escalation)?
* [ ] Czy musisz [**uciec z restrykcyjnej powłoki**](privilege-escalation/#escaping-from-restricted-shells)?

<figure><img src="/.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Dołącz do [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) serwera, aby komunikować się z doświadczonymi hackerami i łowcami bugów!

**Wgląd w hacking**\
Zaangażuj się w treści, które zagłębiają się w emocje i wyzwania związane z hackingiem

**Aktualności o hackingu w czasie rzeczywistym**\
Bądź na bieżąco z dynamicznym światem hackingu dzięki aktualnym wiadomościom i wglądom

**Najnowsze ogłoszenia**\
Bądź informowany o najnowszych programach bug bounty oraz istotnych aktualizacjach platformy

**Dołącz do nas na** [**Discord**](https://discord.com/invite/N3FrSbmwdy) i zacznij współpracować z najlepszymi hackerami już dziś!

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>
{% endhint %}
