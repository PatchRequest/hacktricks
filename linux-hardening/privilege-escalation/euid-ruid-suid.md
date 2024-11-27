# euid, ruid, suid

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

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Deepen your expertise in **Mobile Security** with 8kSec Academy. Master iOS and Android security through our self-paced courses and get certified:

{% embed url="https://academy.8ksec.io/" %}


### ユーザー識別変数

- **`ruid`**: **実ユーザーID**は、プロセスを開始したユーザーを示します。
- **`euid`**: **有効ユーザーID**として知られ、システムがプロセスの特権を確認するために使用するユーザーの識別を表します。一般的に、`euid`は`ruid`と同じですが、SetUIDバイナリの実行のような場合には、`euid`がファイル所有者の識別を引き受け、特定の操作権限を付与します。
- **`suid`**: この**保存されたユーザーID**は、高特権プロセス（通常はrootとして実行される）が特定のタスクを実行するために一時的に特権を放棄し、後に元の昇格した状態を取り戻す必要があるときに重要です。

#### 重要な注意
rootでないプロセスは、`euid`を現在の`ruid`、`euid`、または`suid`に一致させることしかできません。

### set*uid関数の理解

- **`setuid`**: 初期の仮定とは異なり、`setuid`は主に`ruid`ではなく`euid`を変更します。具体的には、特権プロセスの場合、指定されたユーザー（通常はroot）に`ruid`、`euid`、および`suid`を合わせ、これらのIDを強化します。詳細な情報は[setuidマニュアルページ](https://man7.org/linux/man-pages/man2/setuid.2.html)で確認できます。
- **`setreuid`**および**`setresuid`**: これらの関数は、`ruid`、`euid`、および`suid`の微妙な調整を可能にします。ただし、その機能はプロセスの特権レベルに依存します。非rootプロセスの場合、変更は`ruid`、`euid`、および`suid`の現在の値に制限されます。一方、rootプロセスまたは`CAP_SETUID`権限を持つプロセスは、これらのIDに任意の値を割り当てることができます。詳細は[setresuidマニュアルページ](https://man7.org/linux/man-pages/man2/setresuid.2.html)および[setreuidマニュアルページ](https://man7.org/linux/man-pages/man2/setreuid.2.html)で確認できます。

これらの機能は、セキュリティメカニズムとしてではなく、プログラムが他のユーザーの識別を採用するために有効ユーザーIDを変更する際の意図された操作フローを促進するために設計されています。

特に、`setuid`はrootへの特権昇格の一般的な手段であるかもしれませんが（すべてのIDをrootに合わせるため）、これらの関数の違いを理解し、さまざまなシナリオでユーザーIDの動作を操作することが重要です。

### Linuxにおけるプログラム実行メカニズム

#### **`execve`システムコール**
- **機能**: `execve`は、最初の引数によって決定されるプログラムを開始します。引数用の2つの配列引数`argv`と環境用の`envp`を取ります。
- **動作**: 呼び出し元のメモリ空間を保持しますが、スタック、ヒープ、およびデータセグメントを更新します。プログラムのコードは新しいプログラムによって置き換えられます。
- **ユーザーIDの保持**:
- `ruid`、`euid`、および追加のグループIDは変更されません。
- 新しいプログラムにSetUIDビットが設定されている場合、`euid`に微妙な変更があるかもしれません。
- 実行後に`suid`は`euid`から更新されます。
- **文書**: 詳細な情報は[`execve`マニュアルページ](https://man7.org/linux/man-pages/man2/execve.2.html)で確認できます。

#### **`system`関数**
- **機能**: `execve`とは異なり、`system`は`fork`を使用して子プロセスを作成し、その子プロセス内でコマンドを`execl`を使用して実行します。
- **コマンド実行**: `sh`を介してコマンドを実行します。`execl("/bin/sh", "sh", "-c", command, (char *) NULL);`。
- **動作**: `execl`は`execve`の一形態であり、同様に動作しますが、新しい子プロセスの文脈で実行されます。
- **文書**: さらなる洞察は[`system`マニュアルページ](https://man7.org/linux/man-pages/man3/system.3.html)から得られます。

#### **SUIDを持つ`bash`と`sh`の動作**
- **`bash`**:
- `euid`と`ruid`の扱いに影響を与える`-p`オプションがあります。
- `-p`なしでは、`bash`は`euid`を`ruid`に設定します（最初に異なる場合）。
- `-p`がある場合、最初の`euid`が保持されます。
- 詳細は[`bash`マニュアルページ](https://linux.die.net/man/1/bash)で確認できます。
- **`sh`**:
- `bash`の`-p`に類似したメカニズムはありません。
- ユーザーIDに関する動作は明示的に記載されておらず、`-i`オプションの下で`euid`と`ruid`の等価性の保持が強調されています。
- 追加情報は[`sh`マニュアルページ](https://man7.org/linux/man-pages/man1/sh.1p.html)で確認できます。

これらのメカニズムは、それぞれ異なる動作を持ち、プログラムの実行と遷移のための多様なオプションを提供し、ユーザーIDの管理と保持における特定のニュアンスを持っています。

### 実行におけるユーザーIDの動作のテスト

例はhttps://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jailから取得したもので、さらなる情報はそちらで確認してください。

#### ケース1: `system`と`setuid`の使用

**目的**: `system`と`bash`を`sh`として組み合わせた場合の`setuid`の効果を理解すること。

**Cコード**:
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
**コンパイルと権限:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**分析:**

* `ruid` と `euid` はそれぞれ 99 (nobody) と 1000 (frank) から始まります。
* `setuid` は両方を 1000 に揃えます。
* `system` は sh から bash へのシンボリックリンクのために `/bin/bash -c id` を実行します。
* `bash` は `-p` なしで `euid` を `ruid` に合わせるため、両方が 99 (nobody) になります。

#### ケース 2: system で setreuid を使用する

**C コード**:
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
**コンパイルと権限:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**実行と結果:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**分析:**

* `setreuid` は ruid と euid の両方を 1000 に設定します。
* `system` は bash を呼び出し、ユーザー ID の等価性によりそれらを維持し、実質的に frank として動作します。

#### ケース 3: execve とともに setuid を使用する
目的: setuid と execve の相互作用を探る。
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
**実行と結果:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**分析:**

* `ruid` は 99 のままですが、euid は setuid の効果に従って 1000 に設定されています。

**C コード例 2 (Bash を呼び出す):**
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
**実行と結果:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**分析:**

* `euid`は`setuid`によって1000に設定されていますが、`bash`は`-p`がないため`ruid`（99）に`euid`をリセットします。

**Cコード例 3（bash -pを使用）:**
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
**実行と結果:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## 参考文献
* [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

**モバイルセキュリティ**の専門知識を深めるために、8kSecアカデミーで学びましょう。自己ペースのコースを通じてiOSとAndroidのセキュリティをマスターし、認定を取得しましょう：

{% embed url="https://academy.8ksec.io/" %}


{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングトリックを共有してください。**

</details>
{% endhint %}
