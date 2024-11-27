# macOS Security & Privilege Escalation

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Dołącz do [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) serwera, aby komunikować się z doświadczonymi hackerami i łowcami bugów!

**Wgląd w hacking**\
Zaangażuj się w treści, które zagłębiają się w emocje i wyzwania związane z hackingiem

**Aktualności o hackingu w czasie rzeczywistym**\
Bądź na bieżąco z dynamicznym światem hackingu dzięki aktualnym wiadomościom i spostrzeżeniom

**Najnowsze ogłoszenia**\
Bądź informowany o najnowszych nagrodach za błędy oraz istotnych aktualizacjach platformy

**Dołącz do nas na** [**Discord**](https://discord.com/invite/N3FrSbmwdy) i zacznij współpracować z najlepszymi hackerami już dziś!

## Podstawy MacOS

Jeśli nie znasz macOS, powinieneś zacząć od nauki podstaw macOS:

* Specjalne **pliki i uprawnienia** macOS:

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* Powszechni **użytkownicy** macOS

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* **Architektura** jądra

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* Powszechne **usługi i protokoły sieciowe** macOS

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **Oprogramowanie open source** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
* Aby pobrać `tar.gz`, zmień adres URL, na przykład [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) na [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

W firmach systemy **macOS** będą prawdopodobnie **zarządzane przez MDM**. Dlatego z perspektywy atakującego interesujące jest, **jak to działa**:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - Inspekcja, Debugowanie i Fuzzing

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## Ochrony bezpieczeństwa MacOS

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## Powierzchnia ataku

### Uprawnienia plików

Jeśli **proces działający jako root zapisuje** plik, który może być kontrolowany przez użytkownika, użytkownik może to wykorzystać do **eskalacji uprawnień**.\
Może to wystąpić w następujących sytuacjach:

* Użyty plik został już utworzony przez użytkownika (należy do użytkownika)
* Użyty plik jest zapisywalny przez użytkownika z powodu grupy
* Użyty plik znajduje się w katalogu należącym do użytkownika (użytkownik mógłby utworzyć plik)
* Użyty plik znajduje się w katalogu należącym do roota, ale użytkownik ma do niego dostęp do zapisu z powodu grupy (użytkownik mógłby utworzyć plik)

Możliwość **utworzenia pliku**, który będzie **używany przez roota**, pozwala użytkownikowi **wykorzystać jego zawartość** lub nawet utworzyć **symlinki/twarde linki**, aby wskazać go w inne miejsce.

W przypadku tego rodzaju luk nie zapomnij **sprawdzić podatnych instalatorów `.pkg`**:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}

### Obsługa rozszerzeń plików i schematów URL

Dziwne aplikacje zarejestrowane przez rozszerzenia plików mogą być nadużywane, a różne aplikacje mogą być zarejestrowane do otwierania określonych protokołów

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## macOS TCC / SIP Eskalacja Uprawnień

W macOS **aplikacje i pliki binarne mogą mieć uprawnienia** do dostępu do folderów lub ustawień, które czynią je bardziej uprzywilejowanymi niż inne.

Dlatego atakujący, który chce skutecznie skompromitować maszynę macOS, będzie musiał **eskalować swoje uprawnienia TCC** (lub nawet **obejść SIP**, w zależności od jego potrzeb).

Te uprawnienia są zazwyczaj przyznawane w formie **uprawnień**, z którymi aplikacja jest podpisana, lub aplikacja może poprosić o pewne dostępy, a po **zatwierdzeniu ich przez użytkownika** mogą być one znalezione w **bazach danych TCC**. Innym sposobem, w jaki proces może uzyskać te uprawnienia, jest bycie **dzieckiem procesu** z tymi **uprawnieniami**, ponieważ są one zazwyczaj **dziedziczone**.

Śledź te linki, aby znaleźć różne sposoby [**eskalacji uprawnień w TCC**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), aby [**obejść TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) i jak w przeszłości [**SIP został obejrzany**](macos-security-protections/macos-sip.md#sip-bypasses).

## macOS Tradycyjna Eskalacja Uprawnień

Oczywiście z perspektywy zespołu czerwonego powinieneś być również zainteresowany eskalacją do roota. Sprawdź następujący post, aby uzyskać kilka wskazówek:

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}

## Zgodność macOS

* [https://github.com/usnistgov/macos\_security](https://github.com/usnistgov/macos_security)

## Odniesienia

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Dołącz do [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) serwera, aby komunikować się z doświadczonymi hackerami i łowcami bugów!

**Wgląd w hacking**\
Zaangażuj się w treści, które zagłębiają się w emocje i wyzwania związane z hackingiem

**Aktualności o hackingu w czasie rzeczywistym**\
Bądź na bieżąco z dynamicznym światem hackingu dzięki aktualnym wiadomościom i spostrzeżeniom

**Najnowsze ogłoszenia**\
Bądź informowany o najnowszych nagrodach za błędy oraz istotnych aktualizacjach platformy

**Dołącz do nas na** [**Discord**](https://discord.com/invite/N3FrSbmwdy) i zacznij współpracować z najlepszymi hackerami już dziś!

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
