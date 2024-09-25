# macOS Security Protections

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

## Gatekeeper

Gatekeeper kwa kawaida hutumiwa kurejelea mchanganyiko wa **Quarantine + Gatekeeper + XProtect**, moduli 3 za usalama za macOS ambazo zitajaribu **kuzuia watumiaji kutekeleza programu mbaya zinazoweza kupakuliwa**.

More information in:

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## Processes Limitants

### MACF



### SIP - System Integrity Protection

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Sandbox

MacOS Sandbox **inapunguza programu** zinazotembea ndani ya sandbox kwa **vitendo vilivyokubaliwa vilivyobainishwa katika profaili ya Sandbox** ambayo programu inatumia. Hii husaidia kuhakikisha kwamba **programu itakuwa ikipata rasilimali zinazotarajiwa tu**.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** ni mfumo wa usalama. Imeundwa ili **kusimamia ruhusa** za programu, hasa kwa kudhibiti ufikiaji wao kwa vipengele nyeti. Hii inajumuisha vipengele kama **huduma za eneo, mawasiliano, picha, kipaza sauti, kamera, upatikanaji, na ufikiaji wa diski nzima**. TCC inahakikisha kwamba programu zinaweza kufikia vipengele hivi tu baada ya kupata idhini wazi kutoka kwa mtumiaji, hivyo kuimarisha faragha na udhibiti juu ya data binafsi.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### Launch/Environment Constraints & Trust Cache

Vikwazo vya uzinduzi katika macOS ni kipengele cha usalama ili **kudhibiti uzinduzi wa mchakato** kwa kufafanua **nani anaweza kuzindua** mchakato, **vipi**, na **kutoka wapi**. Imeanzishwa katika macOS Ventura, inagawanya binaries za mfumo katika makundi ya vikwazo ndani ya **trust cache**. Kila binary inayoweza kutekelezwa ina **kanuni** zilizowekwa kwa **uzinduzi** wake, ikiwa ni pamoja na **mwenyewe**, **mzazi**, na **mwenye jukumu**. Imeongezwa kwa programu za wahusika wengine kama **Vikwazo vya Mazingira** katika macOS Sonoma, vipengele hivi husaidia kupunguza uwezekano wa matumizi mabaya ya mfumo kwa kudhibiti masharti ya uzinduzi wa mchakato.

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - Malware Removal Tool

Zana ya Kuondoa Malware (MRT) ni sehemu nyingine ya miundombinu ya usalama ya macOS. Kama jina linavyopendekeza, kazi kuu ya MRT ni **kuondoa malware inayojulikana kutoka kwa mifumo iliyoathirika**.

Mara tu malware inapogundulika kwenye Mac (ama na XProtect au kwa njia nyingine), MRT inaweza kutumika kuondoa **malware hiyo** kiotomatiki. MRT inafanya kazi kimya kimya nyuma ya pazia na kawaida inafanya kazi kila wakati mfumo unaposasishwa au wakati ufafanuzi mpya wa malware unapopakuliwa (inaonekana kama kanuni ambazo MRT inahitaji kugundua malware ziko ndani ya binary).

Ingawa XProtect na MRT ni sehemu ya hatua za usalama za macOS, zinafanya kazi tofauti:

* **XProtect** ni zana ya kuzuia. Inafanya **ukaguzi wa faili wakati zinapopakuliwa** (kupitia programu fulani), na ikiwa inagundua aina zozote za malware zinazojulikana, inazuia **faili kufunguliwa**, hivyo kuzuia malware kuathiri mfumo wako kwa mara ya kwanza.
* **MRT**, kwa upande mwingine, ni **zana ya kujibu**. Inafanya kazi baada ya malware kugundulika kwenye mfumo, kwa lengo la kuondoa programu inayosababisha tatizo ili kusafisha mfumo.

Programu ya MRT iko katika **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Background Tasks Management

**macOS** sasa **inaarifu** kila wakati zana inapotumia **mbinu inayojulikana ya kudumisha utekelezaji wa msimbo** (kama vile Vitu vya Kuingia, Daemons...), hivyo mtumiaji anajua vizuri **ni programu gani inayoendelea**.

<figure><img src="../../../.gitbook/assets/image (1183).png" alt=""><figcaption></figcaption></figure>

Hii inafanya kazi na **daemon** iliyoko katika `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` na **agent** katika `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`

Njia ambayo **`backgroundtaskmanagementd`** inajua kitu kimewekwa katika folda ya kudumu ni kwa **kupata FSEvents** na kuunda **wajibu** kwa ajili yao.

Zaidi ya hayo, kuna faili ya plist ambayo ina **programu zinazojulikana** ambazo mara kwa mara zinadumishwa na apple iliyoko katika: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### Enumeration

Inawezekana **kuorodhesha yote** yaliyowekwa kama vitu vya nyuma vinavyotumia zana ya Apple cli:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Zaidi ya hayo, inawezekana pia kuorodhesha habari hii kwa kutumia [**DumpBTM**](https://github.com/objective-see/DumpBTM).
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Hii habari inahifadhiwa katika **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** na Terminal inahitaji FDA.

### Kuingilia BTM

Wakati uvumbuzi mpya wa kudumu unapatikana, tukio la aina **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** linatokea. Hivyo, njia yoyote ya **kuzuia** tukio hili **kutumwa** au **wakala kuonya** mtumiaji itasaidia mshambuliaji _**kuepuka**_ BTM.

* **Kurekebisha hifadhidata**: Kukimbia amri ifuatayo kutarekebisha hifadhidata (inapaswa kujenga upya kutoka mwanzo), hata hivyo, kwa sababu fulani, baada ya kukimbia hii, **hakuna uvumbuzi mpya utakaonyeshwa hadi mfumo upya uzinduliwe**.
* **root** inahitajika.
```bash
# Reset the database
sfltool resettbtm
```
* **Stop the Agent**: Inawezekana kutuma ishara ya kusitisha kwa wakala ili **isiwe inamwonya mtumiaji** wakati kugundua mpya kunapatikana.
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
* **Bug**: Ikiwa **mchakato ulioanzisha kudumu upo haraka baada yake**, daemon itajaribu **kupata taarifa** kuhusu hiyo, **itashindwa**, na **haitaweza kutuma tukio** linaloashiria kwamba kitu kipya kinadumu.

Marejeo na **maelezo zaidi kuhusu BTM**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

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
