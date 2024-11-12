# macOS Authorizations DB & Authd



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

## **Autoriserings DB**

Die databasis geleë in `/var/db/auth.db` is 'n databasis wat gebruik word om toestemmings te stoor om sensitiewe operasies uit te voer. Hierdie operasies word heeltemal in **gebruikerspas** uitgevoer en word gewoonlik deur **XPC-dienste** gebruik wat moet nagaan **of die oproepende kliënt gemagtig is** om sekere aksies uit te voer deur hierdie databasis te kontroleer.

Aanvanklik word hierdie databasis geskep uit die inhoud van `/System/Library/Security/authorization.plist`. Dan kan sommige dienste hierdie databasis bywerk of wysig om ander toestemmings by te voeg.

Die reëls word in die `rules` tabel binne die databasis gestoor en bevat die volgende kolomme:

* **id**: 'n Unieke identifiseerder vir elke reël, outomaties verhoog en dien as die primêre sleutel.
* **name**: Die unieke naam van die reël wat gebruik word om dit binne die autorisasiesisteem te identifiseer en te verwys.
* **type**: Gee die tipe van die reël aan, beperk tot waardes 1 of 2 om sy autorisasielogika te definieer.
* **class**: Kategoriseer die reël in 'n spesifieke klas, wat verseker dat dit 'n positiewe heelgetal is.
* "allow" vir toelaat, "deny" vir weier, "user" as die groep eienskap 'n groep aandui waarvan lidmaatskap toegang toelaat, "rule" dui in 'n array 'n reël aan wat nagekom moet word, "evaluate-mechanisms" gevolg deur 'n `mechanisms` array wat of ingeboude funksies of 'n naam van 'n bundel binne `/System/Library/CoreServices/SecurityAgentPlugins/` of /Library/Security//SecurityAgentPlugins is.
* **group**: Dui die gebruikersgroep aan wat met die reël geassosieer word vir groep-gebaseerde autorisasie.
* **kofn**: Verteenwoordig die "k-of-n" parameter, wat bepaal hoeveel subreëls uit 'n totale aantal bevredig moet word.
* **timeout**: Definieer die duur in sekondes voordat die autorisasie wat deur die reël toegestaan word, verval.
* **flags**: Bevat verskeie vlae wat die gedrag en eienskappe van die reël wysig.
* **tries**: Beperk die aantal toegelate autorisasiepogings om sekuriteit te verbeter.
* **version**: Hou die weergawe van die reël dop vir weergawebeheer en opdaterings.
* **created**: Registreer die tydstempel wanneer die reël geskep is vir ouditdoeleindes.
* **modified**: Stoor die tydstempel van die laaste wysiging aan die reël.
* **hash**: Hou 'n hash-waarde van die reël om sy integriteit te verseker en om te detecteer of daar gemanipuleer is.
* **identifier**: Verskaf 'n unieke string identifiseerder, soos 'n UUID, vir eksterne verwysings na die reël.
* **requirement**: Bevat geserialiseerde data wat die spesifieke autorisasievereistes en meganismes van die reël definieer.
* **comment**: Bied 'n menslike leesbare beskrywing of opmerking oor die reël vir dokumentasie en duidelikheid.

### Voorbeeld
```bash
# List by name and comments
sudo sqlite3 /var/db/auth.db "select name, comment from rules"

# Get rules for com.apple.tcc.util.admin
security authorizationdb read com.apple.tcc.util.admin
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>rule</string>
<key>comment</key>
<string>For modification of TCC settings.</string>
<key>created</key>
<real>701369782.01043606</real>
<key>modified</key>
<real>701369782.01043606</real>
<key>rule</key>
<array>
<string>authenticate-admin-nonshared</string>
</array>
<key>version</key>
<integer>0</integer>
</dict>
</plist>
```
Boonop in [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) is dit moontlik om die betekenis van `authenticate-admin-nonshared` te sien:
```json
{
'allow-root' : 'false',
'authenticate-user' : 'true',
'class' : 'user',
'comment' : 'Authenticate as an administrator.',
'group' : 'admin',
'session-owner' : 'false',
'shared' : 'false',
'timeout' : '30',
'tries' : '10000',
'version' : '1'
}
```
## Authd

Dit is 'n daemon wat versoeke sal ontvang om kliënte te autoriseer om sensitiewe aksies uit te voer. Dit werk as 'n XPC-diens wat binne die `XPCServices/`-map gedefinieer is en gebruik om sy logs in `/var/log/authd.log` te skryf.

Boonop is dit moontlik om baie `Security.framework` API's te toets met die sekuriteitstoepassing. Byvoorbeeld, die `AuthorizationExecuteWithPrivileges` wat loop: `security execute-with-privileges /bin/ls`

Dit sal `/usr/libexec/security_authtrampoline /bin/ls` as root fork en exec, wat toestemming sal vra in 'n prompt om ls as root uit te voer:

<figure><img src="../../../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

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
