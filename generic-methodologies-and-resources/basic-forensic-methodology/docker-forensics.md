# Docker Forensics

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

## コンテナの改変

いくつかのdockerコンテナが侵害された疑いがあります:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
このコンテナに対して行われた**イメージに関する変更を簡単に見つけることができます**:
```bash
docker diff wordpress
C /var
C /var/lib
C /var/lib/mysql
A /var/lib/mysql/ib_logfile0
A /var/lib/mysql/ib_logfile1
A /var/lib/mysql/ibdata1
A /var/lib/mysql/mysql
A /var/lib/mysql/mysql/time_zone_leap_second.MYI
A /var/lib/mysql/mysql/general_log.CSV
...
```
前のコマンドで **C** は **Changed** を意味し、**A** は **Added** を意味します。\
もし `/etc/shadow` のような興味深いファイルが変更されていることがわかった場合、悪意のある活動を確認するために、次のコマンドでコンテナからダウンロードできます：
```bash
docker cp wordpress:/etc/shadow.
```
あなたは新しいコンテナを実行し、その中からファイルを抽出することで、**元のものと比較することもできます**:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
もし**疑わしいファイルが追加された**ことがわかった場合は、コンテナにアクセスして確認できます：
```bash
docker exec -it wordpress bash
```
## Images modifications

エクスポートされたdockerイメージ（おそらく`.tar`形式）を受け取った場合、[**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases)を使用して**変更の要約を抽出**できます：
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
次に、イメージを**解凍**し、**ブロブにアクセス**して、変更履歴で見つけた疑わしいファイルを検索できます：
```bash
tar -xf image.tar
```
### 基本分析

イメージから**基本情報**を取得するには、次のコマンドを実行します:
```bash
docker inspect <image>
```
変更履歴の要約を取得することもできます:
```bash
docker history --no-trunc <image>
```
あなたは次のコマンドを使用して、**イメージからdockerfileを生成**することもできます:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Dockerイメージ内の追加または変更されたファイルを見つけるために、[**dive**](https://github.com/wagoodman/dive)（[**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)からダウンロード）ユーティリティを使用することもできます：
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
これにより、**dockerイメージの異なるblobをナビゲート**し、どのファイルが変更/追加されたかを確認できます。**赤**は追加されたことを意味し、**黄色**は変更されたことを意味します。**tab**を使用して他のビューに移動し、**space**を使用してフォルダーを折りたたむ/開くことができます。

dieを使用すると、イメージの異なるステージの内容にアクセスすることはできません。そうするには、**各レイヤーを解凍してアクセスする必要があります**。\
イメージが解凍されたディレクトリから、次のコマンドを実行してすべてのレイヤーを解凍できます：
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## メモリからの資格情報

ホスト内でdockerコンテナを実行するとき、**ホストからコンテナ上で実行されているプロセスを見ることができます**。単に`ps -ef`を実行するだけです。

したがって（rootとして）、**ホストからプロセスのメモリをダンプし**、**資格情報**を検索することができます。これは[**次の例のように**](../../linux-hardening/privilege-escalation/#process-memory)行います。

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

8kSec Academyで**モバイルセキュリティ**の専門知識を深めましょう。自己ペースのコースを通じてiOSとAndroidのセキュリティをマスターし、認定を取得しましょう：

{% embed url="https://academy.8ksec.io/" %}

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}
