{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **nas pratite na** **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Produbite svoje znanje u **Mobilnoj Bezbednosti** sa 8kSec Akademijom. Savladajte iOS i Android bezbednost kroz naše kurseve po vašem tempu i dobijte sertifikat:

{% embed url="https://academy.8ksec.io/" %}

**Manipulacija audio i video fajlovima** je osnovna komponenta u **CTF forenzičkim izazovima**, koristeći **steganografiju** i analizu metapodataka za skrivanje ili otkrivanje tajnih poruka. Alati kao što su **[mediainfo](https://mediaarea.net/en/MediaInfo)** i **`exiftool`** su neophodni za inspekciju metapodataka fajlova i identifikaciju tipova sadržaja.

Za audio izazove, **[Audacity](http://www.audacityteam.org/)** se ističe kao vrhunski alat za pregled talasnih oblika i analizu spektrograma, što je ključno za otkrivanje teksta kodiranog u audio. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** se snažno preporučuje za detaljnu analizu spektrograma. **Audacity** omogućava manipulaciju audio sadržajem kao što su usporavanje ili preokretanje pesama kako bi se otkrile skrivene poruke. **[Sox](http://sox.sourceforge.net/)**, alat za komandnu liniju, odlično se snalazi u konvertovanju i uređivanju audio fajlova.

**Manipulacija najmanje značajnim bitovima (LSB)** je uobičajena tehnika u audio i video steganografiji, koristeći fiksne veličine delova medijskih fajlova za diskretno umetanje podataka. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** je koristan za dekodiranje poruka skrivenih kao **DTMF tonovi** ili **Morseova šifra**.

Video izazovi često uključuju kontejnerske formate koji kombinuju audio i video tokove. **[FFmpeg](http://ffmpeg.org/)** je alat koji se koristi za analizu i manipulaciju ovim formatima, sposoban za de-multiplexing i reprodukciju sadržaja. Za programere, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** integriše FFmpeg-ove mogućnosti u Python za napredne skriptabilne interakcije.

Ova paleta alata naglašava svestranost potrebnu u CTF izazovima, gde učesnici moraju koristiti širok spektar tehnika analize i manipulacije kako bi otkrili skrivene podatke unutar audio i video fajlova.

## Reference
* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)


<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Produbite svoje znanje u **Mobilnoj Bezbednosti** sa 8kSec Akademijom. Savladajte iOS i Android bezbednost kroz naše kurseve po vašem tempu i dobijte sertifikat:

{% embed url="https://academy.8ksec.io/" %}

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **nas pratite na** **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
