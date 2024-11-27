{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Zgłębiaj swoją wiedzę w **Bezpieczeństwie Mobilnym** z 8kSec Academy. Opanuj bezpieczeństwo iOS i Androida dzięki naszym kursom w trybie samodzielnym i zdobądź certyfikat:

{% embed url="https://academy.8ksec.io/" %}

**Manipulacja plikami audio i wideo** jest podstawą w **wyzwaniach forensycznych CTF**, wykorzystując **steganografię** i analizę metadanych do ukrywania lub ujawniania tajnych wiadomości. Narzędzia takie jak **[mediainfo](https://mediaarea.net/en/MediaInfo)** i **`exiftool`** są niezbędne do inspekcji metadanych plików i identyfikacji typów zawartości.

W przypadku wyzwań audio, **[Audacity](http://www.audacityteam.org/)** wyróżnia się jako premierowe narzędzie do przeglądania fal dźwiękowych i analizy spektrogramów, co jest niezbędne do odkrywania tekstu zakodowanego w audio. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** jest wysoko rekomendowane do szczegółowej analizy spektrogramów. **Audacity** umożliwia manipulację dźwiękiem, taką jak spowolnienie lub odwrócenie utworów w celu wykrycia ukrytych wiadomości. **[Sox](http://sox.sourceforge.net/)**, narzędzie wiersza poleceń, doskonale nadaje się do konwersji i edytowania plików audio.

Manipulacja **najmniej znaczącymi bitami (LSB)** jest powszechną techniką w steganografii audio i wideo, wykorzystującą stałe rozmiary fragmentów plików multimedialnych do dyskretnego osadzania danych. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** jest przydatne do dekodowania wiadomości ukrytych jako **tony DTMF** lub **kod Morse'a**.

Wyzwania wideo często obejmują formaty kontenerowe, które łączą strumienie audio i wideo. **[FFmpeg](http://ffmpeg.org/)** jest narzędziem do analizy i manipulacji tymi formatami, zdolnym do demultipleksowania i odtwarzania zawartości. Dla programistów, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** integruje możliwości FFmpeg z Pythonem dla zaawansowanych interakcji skryptowych.

Ta gama narzędzi podkreśla wszechstronność wymaganą w wyzwaniach CTF, gdzie uczestnicy muszą stosować szeroki wachlarz technik analizy i manipulacji, aby odkryć ukryte dane w plikach audio i wideo.

## Referencje
* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)


<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Zgłębiaj swoją wiedzę w **Bezpieczeństwie Mobilnym** z 8kSec Academy. Opanuj bezpieczeństwo iOS i Androida dzięki naszym kursom w trybie samodzielnym i zdobądź certyfikat:

{% embed url="https://academy.8ksec.io/" %}

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
