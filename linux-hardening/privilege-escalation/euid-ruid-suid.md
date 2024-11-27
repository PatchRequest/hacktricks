# euid, ruid, suid

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

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Aprofunde sua experiência em **Segurança Móvel** com a 8kSec Academy. Domine a segurança de iOS e Android através de nossos cursos autônomos e obtenha certificação:

{% embed url="https://academy.8ksec.io/" %}


### Variáveis de Identificação do Usuário

- **`ruid`**: O **ID do usuário real** denota o usuário que iniciou o processo.
- **`euid`**: Conhecido como o **ID do usuário efetivo**, representa a identidade do usuário utilizada pelo sistema para determinar privilégios de processo. Geralmente, `euid` reflete `ruid`, exceto em casos como a execução de um binário SetUID, onde `euid` assume a identidade do proprietário do arquivo, concedendo assim permissões operacionais específicas.
- **`suid`**: Este **ID do usuário salvo** é fundamental quando um processo de alto privilégio (normalmente executando como root) precisa temporariamente renunciar a seus privilégios para realizar certas tarefas, apenas para depois recuperar seu status elevado inicial.

#### Nota Importante
Um processo que não opera sob root pode apenas modificar seu `euid` para corresponder ao `ruid`, `euid` ou `suid` atuais.

### Compreendendo as Funções set*uid

- **`setuid`**: Ao contrário das suposições iniciais, `setuid` modifica principalmente `euid` em vez de `ruid`. Especificamente, para processos privilegiados, alinha `ruid`, `euid` e `suid` com o usuário especificado, frequentemente root, solidificando efetivamente esses IDs devido ao `suid` que sobrepõe. Informações detalhadas podem ser encontradas na [página do manual setuid](https://man7.org/linux/man-pages/man2/setuid.2.html).
- **`setreuid`** e **`setresuid`**: Essas funções permitem o ajuste sutil de `ruid`, `euid` e `suid`. No entanto, suas capacidades dependem do nível de privilégio do processo. Para processos não-root, as modificações são restritas aos valores atuais de `ruid`, `euid` e `suid`. Em contraste, processos root ou aqueles com a capacidade `CAP_SETUID` podem atribuir valores arbitrários a esses IDs. Mais informações podem ser obtidas na [página do manual setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html) e na [página do manual setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html).

Essas funcionalidades não são projetadas como um mecanismo de segurança, mas para facilitar o fluxo operacional pretendido, como quando um programa adota a identidade de outro usuário alterando seu ID de usuário efetivo.

Notavelmente, enquanto `setuid` pode ser uma escolha comum para elevação de privilégios para root (já que alinha todos os IDs a root), diferenciar entre essas funções é crucial para entender e manipular comportamentos de ID de usuário em diferentes cenários.

### Mecanismos de Execução de Programas no Linux

#### **Chamada de Sistema `execve`**
- **Funcionalidade**: `execve` inicia um programa, determinado pelo primeiro argumento. Ele aceita dois argumentos de array, `argv` para argumentos e `envp` para o ambiente.
- **Comportamento**: Retém o espaço de memória do chamador, mas atualiza a pilha, heap e segmentos de dados. O código do programa é substituído pelo novo programa.
- **Preservação do ID do Usuário**:
- `ruid`, `euid` e IDs de grupo suplementares permanecem inalterados.
- `euid` pode ter mudanças sutis se o novo programa tiver o bit SetUID definido.
- `suid` é atualizado a partir de `euid` após a execução.
- **Documentação**: Informações detalhadas podem ser encontradas na [página do manual `execve`](https://man7.org/linux/man-pages/man2/execve.2.html).

#### **Função `system`**
- **Funcionalidade**: Ao contrário de `execve`, `system` cria um processo filho usando `fork` e executa um comando dentro desse processo filho usando `execl`.
- **Execução de Comando**: Executa o comando via `sh` com `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **Comportamento**: Como `execl` é uma forma de `execve`, opera de maneira semelhante, mas no contexto de um novo processo filho.
- **Documentação**: Mais informações podem ser obtidas na [página do manual `system`](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Comportamento de `bash` e `sh` com SUID**
- **`bash`**:
- Possui uma opção `-p` que influencia como `euid` e `ruid` são tratados.
- Sem `-p`, `bash` define `euid` para `ruid` se eles inicialmente diferirem.
- Com `-p`, o `euid` inicial é preservado.
- Mais detalhes podem ser encontrados na [página do manual `bash`](https://linux.die.net/man/1/bash).
- **`sh`**:
- Não possui um mecanismo semelhante ao `-p` em `bash`.
- O comportamento em relação aos IDs de usuário não é explicitamente mencionado, exceto sob a opção `-i`, enfatizando a preservação da igualdade entre `euid` e `ruid`.
- Informações adicionais estão disponíveis na [página do manual `sh`](https://man7.org/linux/man-pages/man1/sh.1p.html).

Esses mecanismos, distintos em sua operação, oferecem uma gama versátil de opções para executar e transitar entre programas, com nuances específicas em como os IDs de usuário são gerenciados e preservados.

### Testando Comportamentos de ID de Usuário em Execuções

Exemplos retirados de https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, confira para mais informações

#### Caso 1: Usando `setuid` com `system`

**Objetivo**: Compreender o efeito de `setuid` em combinação com `system` e `bash` como `sh`.

**Código C**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
system("id");
return 0;
}
```
**Compilação e Permissões:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Análise:**

* `ruid` e `euid` começam como 99 (ninguém) e 1000 (frank), respectivamente.
* `setuid` alinha ambos para 1000.
* `system` executa `/bin/bash -c id` devido ao symlink de sh para bash.
* `bash`, sem `-p`, ajusta `euid` para corresponder a `ruid`, resultando em ambos sendo 99 (ninguém).

#### Caso 2: Usando setreuid com system

**Código C**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setreuid(1000, 1000);
system("id");
return 0;
}
```
**Compilação e Permissões:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Execução e Resultado:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Análise:**

* `setreuid` define tanto ruid quanto euid para 1000.
* `system` invoca bash, que mantém os IDs de usuário devido à sua igualdade, operando efetivamente como frank.

#### Caso 3: Usando setuid com execve
Objetivo: Explorar a interação entre setuid e execve.
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/usr/bin/id", NULL, NULL);
return 0;
}
```
**Execução e Resultado:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Análise:**

* `ruid` permanece 99, mas euid é definido como 1000, de acordo com o efeito do setuid.

**Exemplo de Código C 2 (Chamando Bash):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/bin/bash", NULL, NULL);
return 0;
}
```
**Execução e Resultado:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Análise:**

* Embora `euid` esteja definido como 1000 por `setuid`, `bash` redefine euid para `ruid` (99) devido à ausência de `-p`.

**Exemplo de Código C 3 (Usando bash -p):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
setuid(1000);
execve(paramList[0], paramList, NULL);
return 0;
}
```
**Execução e Resultado:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## Referências
* [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Aprofunde sua experiência em **Segurança Móvel** com a 8kSec Academy. Domine a segurança de iOS e Android através de nossos cursos autoguiados e obtenha certificação:

{% embed url="https://academy.8ksec.io/" %}


{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}
