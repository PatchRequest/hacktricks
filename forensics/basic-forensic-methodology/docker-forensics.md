# Docker 取证

{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

通过 8kSec 学院深化您在 **移动安全** 方面的专业知识。通过我们的自学课程掌握 iOS 和 Android 安全并获得认证：

{% embed url="https://academy.8ksec.io/" %}

## 容器修改

有怀疑某些 docker 容器被入侵：
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
您可以轻松地**找到与镜像相关的对该容器所做的修改**：
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
在之前的命令中，**C** 代表 **Changed**，而 **A** 代表 **Added**。\
如果你发现某个有趣的文件，比如 `/etc/shadow` 被修改了，你可以从容器中下载它以检查恶意活动，使用：
```bash
docker cp wordpress:/etc/shadow.
```
您还可以**将其与原始文件进行比较**，通过运行一个新容器并从中提取文件：
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
如果您发现**添加了一些可疑文件**，您可以访问容器并检查它：
```bash
docker exec -it wordpress bash
```
## Images modifications

当你获得一个导出的 docker 镜像（可能是 `.tar` 格式）时，你可以使用 [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) 来 **提取修改的摘要**：
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
然后，您可以**解压缩**映像并**访问 blobs**以搜索您可能在更改历史中发现的可疑文件：
```bash
tar -xf image.tar
```
### 基本分析

您可以通过运行以下命令获取**基本信息**：
```bash
docker inspect <image>
```
您还可以通过以下方式获取**更改历史**的摘要：
```bash
docker history --no-trunc <image>
```
您还可以使用以下命令从镜像生成 **dockerfile**：
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

为了在docker镜像中查找添加/修改的文件，您还可以使用[**dive**](https://github.com/wagoodman/dive)（从[**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)下载）：
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
这允许您**浏览不同的docker镜像的blob**并检查哪些文件被修改/添加。**红色**表示添加，**黄色**表示修改。使用**tab**键移动到其他视图，使用**space**键折叠/打开文件夹。

使用die，您将无法访问镜像不同阶段的内容。要做到这一点，您需要**解压每一层并访问它**。\
您可以通过在解压镜像的目录中执行以下命令来解压镜像的所有层：
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## 从内存中获取凭证

请注意，当您在主机内运行 docker 容器时，**您可以通过运行 `ps -ef` 查看容器中运行的进程**。

因此（作为 root），您可以**从主机转储进程的内存**并搜索**凭证**，就像[**以下示例**](../../linux-hardening/privilege-escalation/#process-memory)中所示。

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

通过 8kSec Academy 深入了解 **移动安全**。通过我们的自学课程掌握 iOS 和 Android 安全并获得认证：

{% embed url="https://academy.8ksec.io/" %}

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **在 Twitter 上关注** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
