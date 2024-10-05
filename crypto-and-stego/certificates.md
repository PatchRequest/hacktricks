# 证书

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=certificates) 轻松构建和 **自动化工作流**，由世界上 **最先进** 的社区工具提供支持。\
今天就获取访问权限：

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=certificates" %}

## 什么是证书

**公钥证书** 是一种数字身份，用于加密技术中证明某人拥有公钥。它包括密钥的详细信息、所有者的身份（主题）以及来自受信任机构（颁发者）的数字签名。如果软件信任颁发者并且签名有效，则可以与密钥所有者进行安全通信。

证书主要由 [证书颁发机构](https://en.wikipedia.org/wiki/Certificate\_authority) (CAs) 在 [公钥基础设施](https://en.wikipedia.org/wiki/Public-key\_infrastructure) (PKI) 设置中颁发。另一种方法是 [信任网络](https://en.wikipedia.org/wiki/Web\_of\_trust)，用户直接验证彼此的密钥。证书的常见格式是 [X.509](https://en.wikipedia.org/wiki/X.509)，可以根据 RFC 5280 中概述的特定需求进行调整。

## x509 常见字段

### **x509 证书中的常见字段**

在 x509 证书中，几个 **字段** 在确保证书的有效性和安全性方面发挥着关键作用。以下是这些字段的详细说明：

* **版本号** 表示 x509 格式的版本。
* **序列号** 在证书颁发机构 (CA) 系统中唯一标识证书，主要用于撤销跟踪。
* **主题** 字段表示证书的所有者，可以是机器、个人或组织。它包括详细的身份识别，例如：
* **通用名称 (CN)**：证书覆盖的域。
* **国家 (C)**、**地方 (L)**、**州或省 (ST, S, 或 P)**、**组织 (O)** 和 **组织单位 (OU)** 提供地理和组织详细信息。
* **区分名称 (DN)** 概括了完整的主题识别。
* **颁发者** 详细说明了谁验证并签署了证书，包括与主题类似的子字段。
* **有效期** 由 **生效时间** 和 **失效时间** 时间戳标记，确保证书在某个日期之前或之后不被使用。
* **公钥** 部分对证书的安全性至关重要，指定公钥的算法、大小和其他技术细节。
* **x509v3 扩展** 增强了证书的功能，指定 **密钥使用**、**扩展密钥使用**、**主题备用名称** 和其他属性，以微调证书的应用。

#### **密钥使用和扩展**

* **密钥使用** 确定公钥的加密应用，例如数字签名或密钥加密。
* **扩展密钥使用** 进一步缩小证书的使用案例，例如用于 TLS 服务器身份验证。
* **主题备用名称** 和 **基本约束** 定义证书覆盖的其他主机名，以及它是否为 CA 或最终实体证书。
* 标识符如 **主题密钥标识符** 和 **颁发者密钥标识符** 确保密钥的唯一性和可追溯性。
* **颁发者信息访问** 和 **CRL 分发点** 提供验证颁发 CA 和检查证书撤销状态的路径。
* **CT 预证书 SCTs** 提供透明日志，对于公众信任证书至关重要。
```python
# Example of accessing and using x509 certificate fields programmatically:
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Load an x509 certificate (assuming cert.pem is a certificate file)
with open("cert.pem", "rb") as file:
cert_data = file.read()
certificate = x509.load_pem_x509_certificate(cert_data, default_backend())

# Accessing fields
serial_number = certificate.serial_number
issuer = certificate.issuer
subject = certificate.subject
public_key = certificate.public_key()

print(f"Serial Number: {serial_number}")
print(f"Issuer: {issuer}")
print(f"Subject: {subject}")
print(f"Public Key: {public_key}")
```
### **OCSP与CRL分发点的区别**

**OCSP**（**RFC 2560**）涉及客户端和响应者共同检查数字公钥证书是否已被撤销，而无需下载完整的**CRL**。这种方法比传统的**CRL**更高效，后者提供被撤销证书序列号的列表，但需要下载一个可能很大的文件。CRL可以包含多达512个条目。更多细节可在[这里](https://www.arubanetworks.com/techdocs/ArubaOS%206\_3\_1\_Web\_Help/Content/ArubaFrameStyles/CertRevocation/About\_OCSP\_and\_CRL.htm)找到。

### **什么是证书透明性**

证书透明性通过确保SSL证书的发行和存在对域名所有者、CA和用户可见，帮助抵御与证书相关的威胁。其目标包括：

* 防止CA在未通知域名所有者的情况下为域名发行SSL证书。
* 建立一个开放的审计系统，以跟踪错误或恶意发行的证书。
* 保护用户免受欺诈证书的影响。

#### **证书日志**

证书日志是公开可审计的、仅附加的证书记录，由网络服务维护。这些日志提供加密证明以供审计使用。发行机构和公众都可以向这些日志提交证书或查询以进行验证。虽然日志服务器的确切数量并不固定，但预计全球不会超过一千个。这些服务器可以由CA、ISP或任何感兴趣的实体独立管理。

#### **查询**

要探索任何域的证书透明性日志，请访问[https://crt.sh/](https://crt.sh)。

存储证书的不同格式各有其使用案例和兼容性。此摘要涵盖主要格式并提供转换指导。

## **格式**

### **PEM格式**

* 最广泛使用的证书格式。
* 需要为证书和私钥分别创建文件，采用Base64 ASCII编码。
* 常见扩展名：.cer, .crt, .pem, .key。
* 主要用于Apache及类似服务器。

### **DER格式**

* 证书的二进制格式。
* 缺少PEM文件中的“BEGIN/END CERTIFICATE”语句。
* 常见扩展名：.cer, .der。
* 通常与Java平台一起使用。

### **P7B/PKCS#7格式**

* 以Base64 ASCII存储，扩展名为.p7b或.p7c。
* 仅包含证书和链证书，不包括私钥。
* 受Microsoft Windows和Java Tomcat支持。

### **PFX/P12/PKCS#12格式**

* 一种二进制格式，将服务器证书、中间证书和私钥封装在一个文件中。
* 扩展名：.pfx, .p12。
* 主要用于Windows进行证书的导入和导出。

### **格式转换**

**PEM转换**对于兼容性至关重要：

* **x509到PEM**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
* **PEM 转 DER**
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
* **DER 转 PEM**
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
* **PEM 转 P7B**
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
* **PKCS7 转 PEM**
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**PFX 转换** 对于在 Windows 上管理证书至关重要：

* **PFX 到 PEM**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
* **PFX 转 PKCS#8** 涉及两个步骤：
1. 将 PFX 转换为 PEM
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. 将PEM转换为PKCS8
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
* **P7B 转 PFX** 还需要两个命令：
1. 将 P7B 转换为 CER
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. 将 CER 和私钥转换为 PFX
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
* **ASN.1 (DER/PEM) 编辑** (适用于证书或几乎任何其他 ASN.1 结构):
1. 克隆 [asn1template](https://github.com/wllm-rbnt/asn1template/)
```bash
git clone https://github.com/wllm-rbnt/asn1template.git
```
2. 将 DER/PEM 转换为 OpenSSL 的生成格式
```bash
asn1template/asn1template.pl certificatename.der > certificatename.tpl
asn1template/asn1template.pl -p certificatename.pem > certificatename.tpl
```
3. 根据您的要求编辑 certificatename.tpl
```bash
vim certificatename.tpl
```
4. 重建修改后的证书
```bash
openssl asn1parse -genconf certificatename.tpl -out certificatename_new.der
openssl asn1parse -genconf certificatename.tpl -outform PEM -out certificatename_new.pem
```
***

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=certificates) 轻松构建和 **自动化工作流程**，由世界上 **最先进** 的社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=certificates" %}

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **在** **Twitter** 🐦 **上关注我们** [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
