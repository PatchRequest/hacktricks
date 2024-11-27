{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Panua ujuzi wako katika **Usalama wa Simu** na 8kSec Academy. Master usalama wa iOS na Android kupitia kozi zetu za kujifunza kwa kasi yako na upate cheti:

{% embed url="https://academy.8ksec.io/" %}

**Ushughulikiaji wa faili za sauti na video** ni msingi katika **changamoto za forensics za CTF**, ikitumia **steganography** na uchambuzi wa metadata kuficha au kufichua ujumbe wa siri. Zana kama **[mediainfo](https://mediaarea.net/en/MediaInfo)** na **`exiftool`** ni muhimu kwa kukagua metadata ya faili na kubaini aina za maudhui.

Kwa changamoto za sauti, **[Audacity](http://www.audacityteam.org/)** inajitokeza kama zana bora ya kutazama mawimbi na kuchambua spectrograms, muhimu kwa kugundua maandiko yaliyoandikwa kwenye sauti. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** inapendekezwa sana kwa uchambuzi wa kina wa spectrogram. **Audacity** inaruhusu usindikaji wa sauti kama kupunguza kasi au kurudisha nyimbo ili kugundua ujumbe uliofichwa. **[Sox](http://sox.sourceforge.net/)**, zana ya amri, inajitahidi katika kubadilisha na kuhariri faili za sauti.

**Least Significant Bits (LSB)** usindikaji ni mbinu ya kawaida katika steganography ya sauti na video, ikitumia vipande vya saizi thabiti vya faili za media kuficha data kwa siri. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** ni muhimu kwa kufichua ujumbe uliofichwa kama **DTMF tones** au **Morse code**.

Changamoto za video mara nyingi zinahusisha muundo wa kontena unaounganisha mstream za sauti na video. **[FFmpeg](http://ffmpeg.org/)** ndiyo chaguo bora kwa kuchambua na kushughulikia muundo hizi, ikiwemo uwezo wa ku-demultiplex na kucheza maudhui. Kwa waendelezaji, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** inachanganya uwezo wa FFmpeg ndani ya Python kwa mwingiliano wa hali ya juu wa kuandikwa.

Mchanganyiko huu wa zana unasisitiza ufanisi unaohitajika katika changamoto za CTF, ambapo washiriki wanapaswa kutumia anuwai ya mbinu za uchambuzi na usindikaji ili kugundua data iliyofichwa ndani ya faili za sauti na video.

## Marejeo
* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)


<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Panua ujuzi wako katika **Usalama wa Simu** na 8kSec Academy. Master usalama wa iOS na Android kupitia kozi zetu za kujifunza kwa kasi yako na upate cheti:

{% embed url="https://academy.8ksec.io/" %}

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
