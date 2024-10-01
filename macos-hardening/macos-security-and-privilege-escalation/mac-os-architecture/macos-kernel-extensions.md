# macOS Kernel Extensions & Debugging

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

## Basic Information

As extensões do kernel (Kexts) são **pacotes** com uma extensão **`.kext`** que são **carregados diretamente no espaço do kernel do macOS**, fornecendo funcionalidade adicional ao sistema operacional principal.

### Requirements

Obviamente, isso é tão poderoso que é **complicado carregar uma extensão do kernel**. Estes são os **requisitos** que uma extensão do kernel deve atender para ser carregada:

* Ao **entrar no modo de recuperação**, as **extensões do kernel devem ser permitidas** para serem carregadas:

<figure><img src="../../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

* A extensão do kernel deve ser **assinada com um certificado de assinatura de código do kernel**, que só pode ser **concedido pela Apple**. Quem irá revisar em detalhes a empresa e as razões pelas quais é necessário.
* A extensão do kernel também deve ser **notarizada**, a Apple poderá verificá-la em busca de malware.
* Então, o usuário **root** é quem pode **carregar a extensão do kernel** e os arquivos dentro do pacote devem **pertencer ao root**.
* Durante o processo de upload, o pacote deve ser preparado em um **local protegido não-root**: `/Library/StagedExtensions` (requer a concessão `com.apple.rootless.storage.KernelExtensionManagement`).
* Finalmente, ao tentar carregá-la, o usuário [**receberá um pedido de confirmação**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) e, se aceito, o computador deve ser **reiniciado** para carregá-la.

### Loading process

No Catalina era assim: É interessante notar que o processo de **verificação** ocorre no **userland**. No entanto, apenas aplicativos com a concessão **`com.apple.private.security.kext-management`** podem **solicitar ao kernel que carregue uma extensão**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **inicia** o processo de **verificação** para carregar uma extensão
* Ele se comunicará com **`kextd`** enviando usando um **serviço Mach**.
2. **`kextd`** verificará várias coisas, como a **assinatura**
* Ele se comunicará com **`syspolicyd`** para **verificar** se a extensão pode ser **carregada**.
3. **`syspolicyd`** **pedirá** ao **usuário** se a extensão não foi carregada anteriormente.
* **`syspolicyd`** relatará o resultado para **`kextd`**
4. **`kextd`** finalmente poderá **dizer ao kernel para carregar** a extensão

Se **`kextd`** não estiver disponível, **`kextutil`** pode realizar as mesmas verificações.

### Enumeration (loaded kexts)
```bash
# Get loaded kernel extensions
kextstat

# Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
## Kernelcache

{% hint style="danger" %}
Embora as extensões do kernel sejam esperadas em `/System/Library/Extensions/`, se você for para esta pasta você **não encontrará nenhum binário**. Isso se deve ao **kernelcache** e, para reverter um `.kext`, você precisa encontrar uma maneira de obtê-lo.
{% endhint %}

O **kernelcache** é uma **versão pré-compilada e pré-vinculada do kernel XNU**, juntamente com **drivers** e **extensões do kernel** essenciais. Ele é armazenado em um formato **compactado** e é descompactado na memória durante o processo de inicialização. O kernelcache facilita um **tempo de inicialização mais rápido** ao ter uma versão pronta para execução do kernel e drivers cruciais disponíveis, reduzindo o tempo e os recursos que seriam gastos carregando e vinculando dinamicamente esses componentes no momento da inicialização.

### Kernelcache Local

No iOS, está localizado em **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** no macOS você pode encontrá-lo com: **`find / -name "kernelcache" 2>/dev/null`** \
No meu caso no macOS, eu o encontrei em:

* `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

O formato de arquivo IMG4 é um formato de contêiner usado pela Apple em seus dispositivos iOS e macOS para **armazenar e verificar com segurança** componentes de firmware (como **kernelcache**). O formato IMG4 inclui um cabeçalho e várias tags que encapsulam diferentes partes de dados, incluindo a carga útil real (como um kernel ou bootloader), uma assinatura e um conjunto de propriedades de manifesto. O formato suporta verificação criptográfica, permitindo que o dispositivo confirme a autenticidade e integridade do componente de firmware antes de executá-lo.

Ele é geralmente composto pelos seguintes componentes:

* **Carga útil (IM4P)**:
* Frequentemente compactada (LZFSE4, LZSS, …)
* Opcionalmente criptografada
* **Manifesto (IM4M)**:
* Contém Assinatura
* Dicionário adicional de Chave/Valor
* **Informações de Restauração (IM4R)**:
* Também conhecido como APNonce
* Impede a repetição de algumas atualizações
* OPCIONAL: Geralmente isso não é encontrado

Descompacte o Kernelcache:
```bash
# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Download&#x20;

* [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

No [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) é possível encontrar todos os kits de depuração do kernel. Você pode baixá-lo, montá-lo, abri-lo com a ferramenta [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html), acessar a pasta **`.kext`** e **extrair**.

Verifique os símbolos com:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
* [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Às vezes, a Apple libera **kernelcache** com **símbolos**. Você pode baixar alguns firmwares com símbolos seguindo os links nessas páginas. Os firmwares conterão o **kernelcache** entre outros arquivos.

Para **extrair** os arquivos, comece mudando a extensão de `.ipsw` para `.zip` e **descompacte**.

Após extrair o firmware, você obterá um arquivo como: **`kernelcache.release.iphone14`**. Está no formato **IMG4**, você pode extrair as informações interessantes com:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**

{% code overflow="wrap" %}
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
{% endcode %}

[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Inspecionando kernelcache

Verifique se o kernelcache possui símbolos com
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
Com isso, agora podemos **extrair todas as extensões** ou a **que você está interessado em:**
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## Depuração



## Referências

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

{% hint style="success" %}
Aprenda e pratique AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
