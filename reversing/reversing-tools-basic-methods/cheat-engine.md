# Cheat Engine

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is 'n nuttige program om te vind waar belangrike waardes in die geheue van 'n lopende speletjie gestoor word en om hulle te verander.\
Wanneer jy dit aflaai en uitvoer, word jy **aanbied** met 'n **tutorial** oor hoe om die hulpmiddel te gebruik. As jy wil leer hoe om die hulpmiddel te gebruik, word dit sterk aanbeveel om dit te voltooi.

## Wat soek jy?

![](<../../.gitbook/assets/image (762).png>)

Hierdie hulpmiddel is baie nuttig om te vind **waar 'n waarde** (gewoonlik 'n nommer) **in die geheue** van 'n program gestoor word.\
**Gewoonlik word nommers** in **4bytes** vorm gestoor, maar jy kan hulle ook in **double** of **float** formate vind, of jy mag dalk iets **anders as 'n nommer** wil soek. Om hierdie rede moet jy seker wees dat jy **kies** wat jy wil **soek**:

![](<../../.gitbook/assets/image (324).png>)

Jy kan ook **verskillende** tipes **soeke** aandui:

![](<../../.gitbook/assets/image (311).png>)

Jy kan ook die boks merk om **die speletjie te stop terwyl jy die geheue skandeer**:

![](<../../.gitbook/assets/image (1052).png>)

### Hotkeys

In _**Edit --> Settings --> Hotkeys**_ kan jy verskillende **hotkeys** vir verskillende doeleindes stel, soos **om die** **speletjie** te **stop** (wat baie nuttig is as jy op 'n stadium die geheue wil skandeer). Ander opsies is beskikbaar:

![](<../../.gitbook/assets/image (864).png>)

## Waarde verander

Sodra jy **gevind** het waar die **waarde** is wat jy **soek** (meer oor hierdie in die volgende stappe) kan jy dit **verander** deur dit dubbel te klik, en dan dubbel te klik op sy waarde:

![](<../../.gitbook/assets/image (563).png>)

En uiteindelik **merk die vink** om die verandering in die geheue te laat plaasvind:

![](<../../.gitbook/assets/image (385).png>)

Die **verandering** aan die **geheue** sal onmiddellik **toegepas** word (let daarop dat totdat die speletjie hierdie waarde weer gebruik, die waarde **nie in die speletjie opgedateer sal word**).

## Waarde soek

So, ons gaan veronderstel dat daar 'n belangrike waarde is (soos die lewe van jou gebruiker) wat jy wil verbeter, en jy soek hierdie waarde in die geheue)

### Deur 'n bekende verandering

Veronderstel jy soek die waarde 100, jy **voer 'n skandering uit** wat daardie waarde soek en jy vind baie ooreenkomste:

![](<../../.gitbook/assets/image (108).png>)

Dan, jy doen iets sodat **die waarde verander**, en jy **stop** die speletjie en **voer** 'n **volgende skandering** uit:

![](<../../.gitbook/assets/image (684).png>)

Cheat Engine sal soek na die **waardes** wat **van 100 na die nuwe waarde gegaan het**. Geluk, jy **het gevind** die **adres** van die waarde waarna jy gesoek het, jy kan dit nou verander.\
_**As jy steeds verskeie waardes het, doen iets om daardie waarde weer te verander, en voer nog 'n "volgende skandering" uit om die adresse te filter.**_

### Onbekende Waarde, bekende verandering

In die scenario waar jy **nie die waarde weet nie** maar jy weet **hoe om dit te laat verander** (en selfs die waarde van die verandering) kan jy jou nommer soek.

So, begin deur 'n skandering van die tipe "**Onbekende aanvanklike waarde**" uit te voer:

![](<../../.gitbook/assets/image (890).png>)

Dan, laat die waarde verander, dui **hoe** die **waarde** **verander** het (in my geval is dit met 1 verminder) en voer 'n **volgende skandering** uit:

![](<../../.gitbook/assets/image (371).png>)

Jy sal **alle waardes wat op die geselekteerde manier gewysig is** voorgestel word:

![](<../../.gitbook/assets/image (569).png>)

Sodra jy jou waarde gevind het, kan jy dit verander.

Let daarop dat daar 'n **groot aantal moontlike veranderinge** is en jy kan hierdie **stappe soveel keer as wat jy wil** doen om die resultate te filter:

![](<../../.gitbook/assets/image (574).png>)

### Willekeurige Geheueadres - Vind die kode

Tot nou toe het ons geleer hoe om 'n adres te vind wat 'n waarde stoor, maar dit is hoogs waarskynlik dat in **verskillende uitvoerings van die speletjie daardie adres in verskillende plekke van die geheue is**. So kom ons vind uit hoe om daardie adres altyd te vind.

Gebruik sommige van die genoem truuks, vind die adres waar jou huidige speletjie die belangrike waarde stoor. Dan (stop die speletjie as jy wil) doen 'n **regsklik** op die gevonde **adres** en kies "**Vind uit wat hierdie adres benader**" of "**Vind uit wat na hierdie adres skryf**":

![](<../../.gitbook/assets/image (1067).png>)

Die **eerste opsie** is nuttig om te weet watter **dele** van die **kode** hierdie **adres** **gebruik** (wat nuttig is vir meer dinge soos **om te weet waar jy die kode** van die speletjie kan verander).\
Die **tweede opsie** is meer **spesifiek**, en sal meer nuttig wees in hierdie geval aangesien ons belangstel om te weet **van waar hierdie waarde geskryf word**.

Sodra jy een van daardie opsies gekies het, sal die **debugger** aan die program **gekoppel** word en 'n nuwe **leë venster** sal verskyn. Nou, **speel** die **speletjie** en **verander** daardie **waarde** (sonder om die speletjie te herbegin). Die **venster** moet **gevul** wees met die **adresse** wat die **waarde** **verander**:

![](<../../.gitbook/assets/image (91).png>)

Nou dat jy die adres gevind het wat die waarde verander, kan jy die **kode na jou goeddunke verander** (Cheat Engine laat jou toe om dit vinnig vir NOPs te verander):

![](<../../.gitbook/assets/image (1057).png>)

So, jy kan dit nou verander sodat die kode nie jou nommer beïnvloed nie, of altyd op 'n positiewe manier beïnvloed.

### Willekeurige Geheueadres - Vind die pointer

Volg die vorige stappe, vind waar die waarde wat jy belangstel in is. Dan, gebruik "**Vind uit wat na hierdie adres skryf**" om uit te vind watter adres hierdie waarde skryf en dubbelklik daarop om die disassembly weergave te kry:

![](<../../.gitbook/assets/image (1039).png>)

Dan, voer 'n nuwe skandering uit **soek na die hex waarde tussen "\[]"** (die waarde van $edx in hierdie geval):

![](<../../.gitbook/assets/image (994).png>)

(_As verskeie verskyn, het jy gewoonlik die kleinste adres een nodig_)\
Nou, het ons **die pointer gevind wat die waarde wat ons belangstel in sal verander**.

Klik op "**Voeg adres handmatig by**":

![](<../../.gitbook/assets/image (990).png>)

Nou, klik op die "Pointer" vink en voeg die gevonde adres in die teksvak (in hierdie scenario was die gevonde adres in die vorige beeld "Tutorial-i386.exe"+2426B0):

![](<../../.gitbook/assets/image (392).png>)

(Noteer hoe die eerste "Adres" outomaties ingevul word vanaf die pointer adres wat jy invoer)

Klik OK en 'n nuwe pointer sal geskep word:

![](<../../.gitbook/assets/image (308).png>)

Nou, elke keer as jy daardie waarde verander, **verander jy die belangrike waarde selfs al is die geheueadres waar die waarde is anders.**

### Kode-inspuiting

Kode-inspuiting is 'n tegniek waar jy 'n stuk kode in die teikenproses inspuit, en dan die uitvoering van kode herlei om deur jou eie geskryf kode te gaan (soos om jou punte te gee in plaas van om hulle af te trek).

So, verbeel jou jy het die adres gevind wat 1 van die lewe van jou speler aftrek:

![](<../../.gitbook/assets/image (203).png>)

Klik op Wys disassembler om die **disassemble kode** te kry.\
Dan, klik **CTRL+a** om die Auto assemble venster aan te roep en kies _**Template --> Kode-inspuiting**_

![](<../../.gitbook/assets/image (902).png>)

Vul die **adres van die instruksie wat jy wil verander** (dit word gewoonlik outomaties ingevul):

![](<../../.gitbook/assets/image (744).png>)

'n Sjabloon sal gegenereer word:

![](<../../.gitbook/assets/image (944).png>)

So, voeg jou nuwe assembly kode in die "**newmem**" afdeling in en verwyder die oorspronklike kode uit die "**originalcode**" as jy nie wil hê dit moet uitgevoer word\*\*.\*\* In hierdie voorbeeld sal die ingespuite kode 2 punte byvoeg in plaas van om 1 af te trek:

![](<../../.gitbook/assets/image (521).png>)

**Klik op voer uit en so aan en jou kode behoort in die program ingespuit te wees wat die gedrag van die funksionaliteit verander!**

## **Verwysings**

* **Cheat Engine tutorial, voltooi dit om te leer hoe om met Cheat Engine te begin**
