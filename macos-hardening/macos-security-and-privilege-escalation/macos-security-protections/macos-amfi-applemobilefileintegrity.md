# macOS - AMFI - AppleMobileFileIntegrity

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



## AppleMobileFileIntegrity.kext and amfid

Inalenga katika kutekeleza uadilifu wa msimbo unaotumika kwenye mfumo ikitoa mantiki nyuma ya uthibitishaji wa saini ya msimbo wa XNU. Pia ina uwezo wa kuangalia haki na kushughulikia kazi nyeti nyingine kama vile kuruhusu ufuatiliaji au kupata bandari za kazi.

Zaidi ya hayo, kwa baadhi ya operesheni, kext inapendelea kuwasiliana na nafasi ya mtumiaji inayotumia daemon `/usr/libexec/amfid`. Uhusiano huu wa kuaminiana umekataliwa katika jailbreak nyingi.

AMFI inatumia sera za **MACF** na inasajili vidokezo vyake mara tu inapoanzishwa. Pia, kuzuia upakiaji au upakuaji wake kunaweza kusababisha paniki ya kernel. Hata hivyo, kuna baadhi ya hoja za kuanzisha ambazo zinaruhusu kudhoofisha AMFI:

* `amfi_unrestricted_task_for_pid`: Ruhusu task\_for\_pid kuruhusiwa bila haki zinazohitajika
* `amfi_allow_any_signature`: Ruhusu saini yoyote ya msimbo
* `cs_enforcement_disable`: Hoja ya mfumo mzima inayotumika kuzima utekelezaji wa saini ya msimbo
* `amfi_prevent_old_entitled_platform_binaries`: Batilisha binaries za jukwaa zenye haki
* `amfi_get_out_of_my_way`: Inazima amfi kabisa

Hizi ni baadhi ya sera za MACF ambazo inasajili:

* **`cred_check_label_update_execve:`** Sasisho la lebo litafanywa na kurudisha 1
* **`cred_label_associate`**: Sasisha slot ya lebo ya mac ya AMFI
* **`cred_label_destroy`**: Ondoa slot ya lebo ya mac ya AMFI
* **`cred_label_init`**: Hamisha 0 katika slot ya lebo ya mac ya AMFI
* **`cred_label_update_execve`:** Inakagua haki za mchakato kuona kama inapaswa kuruhusiwa kubadilisha lebo.
* **`file_check_mmap`:** Inakagua ikiwa mmap inapata kumbukumbu na kuipatia kama inayoweza kutekelezwa. Katika kesi hiyo inakagua ikiwa uthibitishaji wa maktaba unahitajika na ikiwa ndivyo, inaita kazi ya uthibitishaji wa maktaba.
* **`file_check_library_validation`**: Inaita kazi ya uthibitishaji wa maktaba ambayo inakagua miongoni mwa mambo mengine ikiwa binary ya jukwaa inapakua binary nyingine ya jukwaa au ikiwa mchakato na faili mpya iliyopakuliwa zina TeamID sawa. Haki fulani pia zitaruhusu kupakua maktaba yoyote.
* **`policy_initbsd`**: Inaanzisha Funguo za NVRAM zinazotambulika
* **`policy_syscall`**: Inakagua sera za DYLD kama binary ina sehemu zisizo na kikomo, ikiwa inapaswa kuruhusu env vars... hii pia inaitwa wakati mchakato unapoanzishwa kupitia `amfi_check_dyld_policy_self()`.
* **`proc_check_inherit_ipc_ports`**: Inakagua ikiwa wakati mchakato unatekeleza binary mpya mchakato mingine yenye haki za SEND juu ya bandari ya kazi ya mchakato inapaswa kuendelea kuwa nazo au la. Binaries za jukwaa zinaruhusiwa, haki ya `get-task-allow` inaruhusu, haki za `task_for_pid-allow` zinaruhusiwa na binaries zenye TeamID sawa.
* **`proc_check_expose_task`**: inatekeleza haki
* **`amfi_exc_action_check_exception_send`**: Ujumbe wa kipekee unatumwa kwa debugger
* **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Mzunguko wa lebo wakati wa kushughulikia kipekee (ufuatiliaji)
* **`proc_check_get_task`**: Inakagua haki kama `get-task-allow` ambayo inaruhusu mchakato mwingine kupata bandari za kazi na `task_for_pid-allow`, ambayo inaruhusu mchakato kupata bandari za kazi za mchakato mingine. Ikiwa hakuna hata moja ya hizo, inaita `amfid permitunrestricteddebugging` kuangalia ikiwa inaruhusiwa.
* **`proc_check_mprotect`**: Kanusha ikiwa `mprotect` inaitwa na bendera `VM_PROT_TRUSTED` ambayo inaashiria kwamba eneo linapaswa kutendewa kana kwamba lina saini halali ya msimbo.
* **`vnode_check_exec`**: Inaitwa wakati faili zinazoweza kutekelezwa zinapopakuliwa kwenye kumbukumbu na kuweka `cs_hard | cs_kill` ambayo itaua mchakato ikiwa mojawapo ya kurasa inakuwa batili
* **`vnode_check_getextattr`**: MacOS: Angalia `com.apple.root.installed` na `isVnodeQuarantined()`
* **`vnode_check_setextattr`**: Kama pata + com.apple.private.allow-bless na haki sawa na mfunguo wa ndani
* &#x20;**`vnode_check_signature`**: Msimbo unaoitwa XNU kuangalia saini ya msimbo kwa kutumia haki, cache ya kuaminika na `amfid`
* &#x20;**`proc_check_run_cs_invalid`**: Inakabili `ptrace()` calls (`PT_ATTACH` na `PT_TRACE_ME`). Inakagua haki zozote za `get-task-allow`, `run-invalid-allow` na `run-unsigned-code` na ikiwa hakuna, inakagua ikiwa ufuatiliaji unaruhusiwa.
* **`proc_check_map_anon`**: Ikiwa mmap inaitwa na bendera **`MAP_JIT`**, AMFI itakagua haki ya `dynamic-codesigning`.

`AMFI.kext` pia inatoa API kwa nyongeza nyingine za kernel, na inawezekana kupata utegemezi wake kwa:
```bash
kextstat | grep " 19 " | cut -c2-5,50- | cut -d '(' -f1
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
8   com.apple.kec.corecrypto
19   com.apple.driver.AppleMobileFileIntegrity
22   com.apple.security.sandbox
24   com.apple.AppleSystemPolicy
67   com.apple.iokit.IOUSBHostFamily
70   com.apple.driver.AppleUSBTDM
71   com.apple.driver.AppleSEPKeyStore
74   com.apple.iokit.EndpointSecurity
81   com.apple.iokit.IOUserEthernet
101   com.apple.iokit.IO80211Family
102   com.apple.driver.AppleBCMWLANCore
118   com.apple.driver.AppleEmbeddedUSBHost
134   com.apple.iokit.IOGPUFamily
135   com.apple.AGXG13X
137   com.apple.iokit.IOMobileGraphicsFamily
138   com.apple.iokit.IOMobileGraphicsFamily-DCP
162   com.apple.iokit.IONVMeFamily
```
## amfid

Hii ni huduma ya mtumiaji inayotumia daemon ambayo `AMFI.kext` itatumia kuangalia saini za msimbo katika hali ya mtumiaji.\
Ili `AMFI.kext` iweze kuwasiliana na daemon inatumia ujumbe wa mach kupitia bandari `HOST_AMFID_PORT` ambayo ni bandari maalum `18`.

Kumbuka kwamba katika macOS si tena inawezekana kwa michakato ya root kuchukua bandari maalum kwani zimekingwa na `SIP` na ni launchd pekee anayeweza kuzipata. Katika iOS inakaguliwa kwamba mchakato unaotuma jibu nyuma una CDHash iliyowekwa kwa `amfid`.

Inawezekana kuona wakati `amfid` inapoombwa kuangalia binary na jibu lake kwa ku-debug na kuweka breakpoint katika `mach_msg`.

Mara ujumbe unapopokelewa kupitia bandari maalum **MIG** inatumika kutuma kila kazi kwa kazi inayoita. Kazi kuu zilirejeshwa na kufafanuliwa ndani ya kitabu.

## Provisioning Profiles

Profaili ya usambazaji inaweza kutumika kusaini msimbo. Kuna profaili za **Developer** ambazo zinaweza kutumika kusaini msimbo na kuujaribu, na profaili za **Enterprise** ambazo zinaweza kutumika katika vifaa vyote.

Baada ya App kuwasilishwa kwa Duka la Apple, ikiwa imeidhinishwa, inasainiwa na Apple na profaili ya usambazaji haitahitajika tena.

Profaili kwa kawaida hutumia kiambishi `.mobileprovision` au `.provisionprofile` na inaweza kutolewa kwa:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Ingawa wakati mwingine inaitwa kama iliyothibitishwa, hizi profiles za usambazaji zina zaidi ya cheti:

* **AppIDName:** Kitambulisho cha Programu
* **AppleInternalProfile**: Inatambulisha hii kama profaili ya Ndani ya Apple
* **ApplicationIdentifierPrefix**: Imewekwa kabla ya AppIDName (sawa na TeamIdentifier)
* **CreationDate**: Tarehe katika muundo wa `YYYY-MM-DDTHH:mm:ssZ`
* **DeveloperCertificates**: Mfululizo wa (kwa kawaida mmoja) cheti, kilichowekwa kama data ya Base64
* **Entitlements**: Haki zinazoruhusiwa na haki za profaili hii
* **ExpirationDate**: Tarehe ya kumalizika katika muundo wa `YYYY-MM-DDTHH:mm:ssZ`
* **Name**: Jina la Programu, sawa na AppIDName
* **ProvisionedDevices**: Mfululizo (kwa cheti za waendelezaji) wa UDIDs ambazo profaili hii ni halali
* **ProvisionsAllDevices**: Boolean (kweli kwa cheti za biashara)
* **TeamIdentifier**: Mfululizo wa (kwa kawaida mmoja) nyuzi za alfanumeriki zinazotumika kutambulisha mendelezi kwa madhumuni ya mwingiliano kati ya programu
* **TeamName**: Jina linaloweza kusomeka na binadamu linalotumika kutambulisha mendelezi
* **TimeToLive**: Uhalali (katika siku) wa cheti
* **UUID**: Kitambulisho cha Kipekee Duniani kwa profaili hii
* **Version**: Kwa sasa imewekwa kuwa 1

Kumbuka kwamba kipengele cha haki kitakuwa na seti iliyozuiliwa ya haki na profaili ya usambazaji itakuwa na uwezo wa kutoa haki hizo maalum ili kuzuia kutoa haki za kibinafsi za Apple.

Kumbuka kwamba profaili kwa kawaida ziko katika `/var/MobileDeviceProvisioningProfiles` na inawezekana kuziangalia kwa **`security cms -D -i /path/to/profile`**

## **libmis.dyld**

Hii ni maktaba ya nje ambayo `amfid` inaita ili kuuliza ikiwa inapaswa kuruhusu kitu au la. Hii imekuwa ikitumiwa kiholela katika jailbreaking kwa kukimbia toleo lililokuwa na backdoor ambalo lingeweza kuruhusu kila kitu.

Katika macOS hii iko ndani ya `MobileDevice.framework`.

## AMFI Trust Caches

iOS AMFI inashikilia orodha ya hash zinazojulikana ambazo zimesainiwa ad-hoc, zinazoitwa **Trust Cache** na kupatikana katika sehemu ya kext's `__TEXT.__const`. Kumbuka kwamba katika operesheni maalum na nyeti inawezekana kupanua Trust Cache hii kwa faili ya nje.

## References

* [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

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