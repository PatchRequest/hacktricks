# PsExec/Winexec/ScExec

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

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## यह कैसे काम करता है

प्रक्रिया नीचे दिए गए चरणों में वर्णित है, जो दिखाती है कि सेवा बाइनरी को SMB के माध्यम से लक्षित मशीन पर दूरस्थ निष्पादन प्राप्त करने के लिए कैसे हेरफेर किया जाता है:

1. **ADMIN$ शेयर पर SMB के माध्यम से एक सेवा बाइनरी की कॉपी** की जाती है।
2. **दूरस्थ मशीन पर एक सेवा का निर्माण** बाइनरी की ओर इशारा करके किया जाता है।
3. सेवा **दूरस्थ रूप से शुरू की जाती है**।
4. बाहर निकलने पर, सेवा **रोक दी जाती है, और बाइनरी को हटा दिया जाता है**।

### **PsExec को मैन्युअल रूप से निष्पादित करने की प्रक्रिया**

मान लेते हैं कि एक निष्पादन योग्य पेलोड (जो msfvenom के साथ बनाया गया है और एंटीवायरस पहचान से बचने के लिए Veil का उपयोग करके छिपाया गया है), जिसका नाम 'met8888.exe' है, जो एक मीटरप्रीटर रिवर्स_http पेलोड का प्रतिनिधित्व करता है, निम्नलिखित चरण उठाए जाते हैं:

* **बाइनरी की कॉपी करना**: निष्पादन योग्य को एक कमांड प्रॉम्प्ट से ADMIN$ शेयर पर कॉपी किया जाता है, हालांकि इसे फ़ाइल सिस्टम पर कहीं भी रखा जा सकता है ताकि यह छिपा रहे।
* **एक सेवा बनाना**: Windows `sc` कमांड का उपयोग करते हुए, जो दूरस्थ रूप से Windows सेवाओं को क्वेरी, बनाने और हटाने की अनुमति देता है, "meterpreter" नामक एक सेवा बनाई जाती है जो अपलोड की गई बाइनरी की ओर इशारा करती है।
* **सेवा शुरू करना**: अंतिम चरण में सेवा को शुरू करना शामिल है, जो संभवतः "टाइम-आउट" त्रुटि का परिणाम देगा क्योंकि बाइनरी एक वास्तविक सेवा बाइनरी नहीं है और अपेक्षित प्रतिक्रिया कोड लौटाने में विफल रहती है। यह त्रुटि महत्वहीन है क्योंकि प्राथमिक लक्ष्य बाइनरी का निष्पादन है।

Metasploit श्रोता का अवलोकन करने पर पता चलेगा कि सत्र सफलतापूर्वक आरंभ किया गया है।

[Learn more about the `sc` command](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Find moe detailed steps in: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**आप Windows Sysinternals बाइनरी PsExec.exe का भी उपयोग कर सकते हैं:**

![](<../../.gitbook/assets/image (928).png>)

आप [**SharpLateral**](https://github.com/mertdas/SharpLateral) का भी उपयोग कर सकते हैं:

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
सीखें और AWS हैकिंग का अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
सीखें और GCP हैकिंग का अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) देखें!
* **हमारे** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**telegram समूह**](https://t.me/peass) में शामिल हों या **हमारा अनुसरण करें** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **हैकिंग ट्रिक्स साझा करें और** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में PR सबमिट करें।

</details>
{% endhint %}
