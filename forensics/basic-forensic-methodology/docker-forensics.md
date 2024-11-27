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

## Container modification

Kuna shaka kwamba baadhi ya kontena za docker zilipatikana zimevunjwa:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Unaweza kwa urahisi **kupata marekebisho yaliyofanywa kwa kontena hili kuhusiana na picha** kwa kutumia:
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
Katika amri iliyopita, **C** inamaanisha **Ilibadilishwa** na **A,** **Iliyoongezwa**.\
Ikiwa utagundua kuwa faili ya kuvutia kama `/etc/shadow` ilibadilishwa, unaweza kuipakua kutoka kwenye kontena ili kuangalia shughuli za uhalifu kwa:
```bash
docker cp wordpress:/etc/shadow.
```
Unaweza pia **kuilinganisha na ile ya asili** kwa kuendesha kontena mpya na kutoa faili kutoka kwake:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Ikiwa unapata kwamba **faili fulani ya kushuku iliongezwa** unaweza kufikia kontena na kuangalia:
```bash
docker exec -it wordpress bash
```
## Images modifications

Wakati unapata picha ya docker iliyosafirishwa (labda katika muundo wa `.tar`) unaweza kutumia [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) ili **kutoa muhtasari wa mabadiliko**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Kisha, unaweza **kufungua** picha na **kufikia blobs** kutafuta faili za kushangaza ambazo huenda umepata katika historia ya mabadiliko:
```bash
tar -xf image.tar
```
### Basic Analysis

Unaweza kupata **taarifa za msingi** kutoka kwa picha ukikimbia:
```bash
docker inspect <image>
```
Unaweza pia kupata muhtasari wa **historia ya mabadiliko** kwa kutumia:
```bash
docker history --no-trunc <image>
```
Unaweza pia kuunda **dockerfile kutoka kwa picha** kwa:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

Ili kupata faili zilizoongezwa/zilizobadilishwa katika picha za docker unaweza pia kutumia [**dive**](https://github.com/wagoodman/dive) (pakua kutoka [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)) chombo:
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Hii inakuwezesha **kuvinjari kupitia blobs tofauti za picha za docker** na kuangalia faili zipi zilirekebishwa/kuongezwa. **Nyekundu** inamaanisha kuongezwa na **njano** inamaanisha kurekebishwa. Tumia **tab** kuhamia kwenye mtazamo mwingine na **space** kufunga/kufungua folda.

Kwa die huwezi kufikia maudhui ya hatua tofauti za picha. Ili kufanya hivyo, utahitaji **kufungua kila safu na kuifikia**.\
Unaweza kufungua safu zote kutoka kwa picha kutoka kwenye saraka ambapo picha ilifunguliwa kwa kutekeleza:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Credentials kutoka kwa kumbukumbu

Kumbuka kwamba unapokimbia kontena la docker ndani ya mwenyeji **unaweza kuona michakato inayokimbia kwenye kontena kutoka kwa mwenyeji** kwa kukimbia tu `ps -ef`

Hivyo (kama root) unaweza **kuchota kumbukumbu ya michakato** kutoka kwa mwenyeji na kutafuta **credentials** kama [**ilivyo katika mfano ufuatao**](../../linux-hardening/privilege-escalation/#process-memory).

<figure><img src="/.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Deepen your expertise in **Mobile Security** with 8kSec Academy. Master iOS and Android security through our self-paced courses and get certified:

{% embed url="https://academy.8ksec.io/" %}

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
