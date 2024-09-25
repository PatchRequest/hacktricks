# macOS Kernel & System Extensions

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

## XNU Kernel

**Msingi wa macOS ni XNU**, ambayo inasimama kwa "X is Not Unix". Kernel hii inaundwa kimsingi na **Mach microkernel** (itaongelewa baadaye), **na** vipengele kutoka Berkeley Software Distribution (**BSD**). XNU pia inatoa jukwaa kwa **madereva wa kernel kupitia mfumo unaoitwa I/O Kit**. Kernel ya XNU ni sehemu ya mradi wa wazi wa Darwin, ambayo inamaanisha **kanuni zake zinapatikana bure**.

Kutoka kwa mtazamo wa mtafiti wa usalama au mendelezo wa Unix, **macOS** inaweza kuonekana kuwa **kama** mfumo wa **FreeBSD** wenye GUI ya kuvutia na idadi ya programu maalum. Programu nyingi zilizotengenezwa kwa BSD zitakusanywa na kuendesha kwenye macOS bila kuhitaji marekebisho, kwani zana za amri zinazojulikana kwa watumiaji wa Unix zipo zote kwenye macOS. Hata hivyo, kwa sababu kernel ya XNU inajumuisha Mach, kuna tofauti kubwa kati ya mfumo wa jadi wa Unix na macOS, na tofauti hizi zinaweza kusababisha matatizo ya uwezekano au kutoa faida za kipekee.

Toleo la wazi la XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach ni **microkernel** iliyoundwa kuwa **UNIX-inayofaa**. Moja ya kanuni zake kuu za kubuni ilikuwa **kupunguza** kiasi cha **kanuni** zinazotumika katika **nafasi ya kernel** na badala yake kuruhusu kazi nyingi za kawaida za kernel, kama vile mfumo wa faili, mtandao, na I/O, ku **endesha kama kazi za ngazi ya mtumiaji**.

Katika XNU, Mach ni **responsible kwa shughuli nyingi muhimu za kiwango cha chini** ambazo kernel kawaida inashughulikia, kama vile kupanga ratiba ya processor, multitasking, na usimamizi wa kumbukumbu ya virtual.

### BSD

Kernel ya XNU pia **inaunganisha** kiasi kikubwa cha kanuni zinazotokana na mradi wa **FreeBSD**. Kanuni hii **inasimama kama sehemu ya kernel pamoja na Mach**, katika nafasi moja ya anwani. Hata hivyo, kanuni za FreeBSD ndani ya XNU zinaweza kutofautiana kwa kiasi kikubwa na kanuni za asili za FreeBSD kwa sababu marekebisho yalihitajika kuhakikisha ufanisi wake na Mach. FreeBSD inachangia katika shughuli nyingi za kernel ikiwa ni pamoja na:

* Usimamizi wa mchakato
* Kushughulikia ishara
* Mekanismu za msingi za usalama, ikiwa ni pamoja na usimamizi wa watumiaji na vikundi
* Miundombinu ya wito wa mfumo
* TCP/IP stack na soketi
* Firewall na kuchuja pakiti

Kuelewa mwingiliano kati ya BSD na Mach kunaweza kuwa ngumu, kutokana na mifumo yao tofauti ya dhana. Kwa mfano, BSD inatumia michakato kama kitengo chake cha msingi cha utekelezaji, wakati Mach inafanya kazi kwa msingi wa nyuzi. Tofauti hii inarekebishwa katika XNU kwa **kuunganisha kila mchakato wa BSD na kazi ya Mach** ambayo ina nyuzi moja ya Mach. Wakati wito wa mfumo wa fork() wa BSD unapotumika, kanuni za BSD ndani ya kernel zinatumia kazi za Mach kuunda kazi na muundo wa nyuzi.

Zaidi ya hayo, **Mach na BSD kila mmoja ina mifano tofauti ya usalama**: **mfano wa** usalama wa **Mach** unategemea **haki za bandari**, wakati mfano wa usalama wa BSD unafanya kazi kwa msingi wa **umiliki wa mchakato**. Tofauti kati ya mifano hii miwili mara nyingine imesababisha udhaifu wa kupanda kwa haki za ndani. Mbali na wito wa kawaida wa mfumo, pia kuna **Mach traps zinazoruhusu programu za nafasi ya mtumiaji kuingiliana na kernel**. Vipengele hivi tofauti pamoja vinaunda usanifu wa kipekee, wa mchanganyiko wa kernel ya macOS.

### I/O Kit - Madereva

I/O Kit ni mfumo wa wazi, wa mwelekeo wa kitu **wa madereva ya kifaa** katika kernel ya XNU, inashughulikia **madereva ya kifaa yanayopakiwa kwa nguvu**. Inaruhusu kanuni za moduli kuongezwa kwenye kernel mara moja, ikisaidia vifaa mbalimbali.

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - Mawasiliano kati ya Michakato

{% content-ref url="../macos-proces-abuse/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../macos-proces-abuse/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

## macOS Kernel Extensions

macOS ni **ya kukandamiza sana kupakia Kernel Extensions** (.kext) kwa sababu ya haki kubwa ambazo kanuni hiyo itatumika nazo. Kwa kweli, kwa kawaida haiwezekani (isipokuwa njia ya kupita ipatikane).

Katika ukurasa ufuatao unaweza pia kuona jinsi ya kurejesha `.kext` ambayo macOS inapakua ndani ya **kernelcache** yake:

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### macOS System Extensions

Badala ya kutumia Kernel Extensions, macOS iliumba System Extensions, ambayo inatoa APIs za ngazi ya mtumiaji kuingiliana na kernel. Kwa njia hii, waendelezaji wanaweza kuepuka kutumia kernel extensions.

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## Marejeleo

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

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
