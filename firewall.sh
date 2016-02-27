#!/bin/bash
### BEGIN INIT INFO
# Provides:          firewall
# Required-Start:    $local_fs $remote_fs $network $syslog
# Required-Stop:     $local_fs $remote_fs $network $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# X-Interactive:     true
# Short-Description: Start/stop firewall script from hell
### END INIT INFO
 
 
# Description: Simple firewall script
# Author: Ivan Bachvarov a.k.a SlaSerX
# Version: 0.04
# Usage:
#    ./firewall.sh 
 
 
#---------#
# History #
#---------#
 
# 0.01 .... Initial release, based on http://iptables-tutorial.frozentux.net/iptables-tutorial.html
# 0.02 .... Added more security by reading http://www.brandonhutchinson.com/iptables_fw.html
# 0.03 .... Added even more shit thanks to http://danieldegraaf.afraid.org/info/iptables/examples
# 0.04 .... Using ULOGD now for traffic accounting (inspired by http://tumbleweed.org.za/2008/04/02/bandwidth-accounting-ulogd)
# 0.05 .... Loading modules through modprobe
 
#---------------#
# Configuration #
#---------------#
 
IPTABLES=/sbin/iptables
SYSCTL=/sbin/sysctl
MODPROBE=/sbin/modprobe
 
#----------------#
# Initialization #
#----------------#
 
echo 
echo "    #---------------------------#"
echo "    #       Firewall Script     #"
echo "    #---------------------------#"
echo "                 by Ivan Bachvarov"
echo
 
#
# Module loading
#
echo "Preload IP-Tables modules..."
$MODPROBE ip_tables
$MODPROBE iptable_nat
$MODPROBE iptable_mangle
$MODPROBE iptable_filter
$MODPROBE ipt_REJECT
$MODPROBE ipt_ULOG
$MODPROBE nf_nat
$MODPROBE nf_conntrack
$MODPROBE nf_conntrack_ipv4
$MODPROBE nf_conntrack_ftp
 
#
# Drop ICMP echo-request messages sent to broadcast or multicast addresses
#
echo "Enable network security settings..."
echo 1 &gt; /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
echo 1 &gt; /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses
 
#
# Drop source routed packets
#
echo 0 &gt; /proc/sys/net/ipv4/conf/all/accept_source_route
 
#
# Enable TCP SYN cookie protection from SYN floods
#
echo 1 &gt; /proc/sys/net/ipv4/tcp_syncookies
 
#
# Don't accept ICMP redirect messages
#
echo 0 &gt; /proc/sys/net/ipv4/conf/all/accept_redirects
 
#
# Don't send ICMP redirect messages
#
echo 0 &gt; /proc/sys/net/ipv4/conf/all/send_redirects
 
#
# Enable source address spoofing protection
#
echo 1 &gt; /proc/sys/net/ipv4/conf/all/rp_filter
 
#
# Log packets with impossible source addresses
#
echo 1 &gt; /proc/sys/net/ipv4/conf/all/log_martians
 
#
# Disable some ICMP settings that can be insecure
# Some of these were already disabled by the above echo statements
#
echo "Disable some ICMP settings..."
$SYSCTL -q -w net.ipv4.icmp_ignore_bogus_error_responses=1
$SYSCTL -q -w net.ipv4.icmp_echo_ignore_all=0
$SYSCTL -q -w net.ipv4.icmp_echo_ignore_broadcasts=1
$SYSCTL -q -w net.ipv4.icmp_ratelimit=1000
 
echo "Enable some extra network security..."
$SYSCTL -q -w net.ipv4.conf.all.accept_redirects=0
$SYSCTL -q -w net.ipv4.conf.all.accept_source_route=0
$SYSCTL -q -w net.ipv4.conf.all.rp_filter=1
$SYSCTL -q -w net.ipv4.conf.all.log_martians=1
$SYSCTL -q -w net.netfilter.nf_conntrack_acct=1
 
#
# Prevent SYN flood
#
$SYSCTL -q -w net.ipv4.tcp_syncookies=1
 
#
# Don't accept TCP connections unless we were here for their establishment
#
if [ -e /proc/sys/net/netfilter/ ]; then
        $SYSCTL -q -w net.netfilter.nf_conntrack_tcp_loose=1
else
        $SYSCTL -q -w net.ipv4.ip_conntrack_tcp_loose=1
fi
 
#
# Create policies and flush chains, then delete rules
#
echo "Creating default policies..."
$IPTABLES -P INPUT ACCEPT  
$IPTABLES -P OUTPUT ACCEPT
$IPTABLES -P FORWARD DROP  
 
echo "Flushing and deleting chains..."
for type in filter mangle nat; do
        echo "- Flushing, deleting and zeroing chains for $type"
        $IPTABLES -t $type -F
        $IPTABLES -t $type -X
        $IPTABLES -t $type -Z
done
 
# 
# Accounting stuff
#
echo "Creating accounting chains"
$IPTABLES -t mangle -N incoming
$IPTABLES -t mangle -N outgoing
$IPTABLES -t mangle -F incoming
$IPTABLES -t mangle -F outgoing
 
#$IPTABLES -t mangle -A incoming -p tcp --dport 80  -m comment --comment  "Incoming http TCP connections"
#$IPTABLES -t mangle -A incoming -p tcp --dport 443 -m comment --comment  "Incoming http/ssl TCP connections"
#$IPTABLES -t mangle -A incoming -p tcp --dport 22  -m comment --comment  "Incoming ssh TCP connections"
#$IPTABLES -t mangle -A incoming -p tcp --dport 21  -m comment --comment  "Incoming ftp TCP connections"
#$IPTABLES -t mangle -A incoming -p tcp --dport 25  -m comment --comment  "Incoming smtp TCP connections"
$IPTABLES -t mangle -A incoming -p tcp -m comment --comment  "Incoming TCP connections"
 
$IPTABLES -t mangle -A incoming -p udp -m comment --comment  "Incoming UDP connections"
$IPTABLES -t mangle -A incoming -p icmp -m comment --comment "Incoming ICMP connections"
 
$IPTABLES -t mangle -A outgoing -p tcp -m comment --comment  "Outgoing TCP connections"
$IPTABLES -t mangle -A outgoing -p udp -m comment --comment  "Outgoing UDP connections"
$IPTABLES -t mangle -A outgoing -p icmp -m comment --comment "Outgoing ICMP connections"
 
echo "Adding accounting to PRE- and POSTROUTING"
$IPTABLES -t mangle -A PREROUTING -i eth0 -j incoming
$IPTABLES -t mangle -A POSTROUTING -o eth0 -j outgoing
 
#
# Create a LOGDROP chain to log and drop packets
#
echo "Creating LOGDROP chain..."
$IPTABLES -N LOGDROP
$IPTABLES -F LOGDROP
#$IPTABLES -A LOGDROP -j LOG --log-prefix "firewall dropped packet: " --log-tcp-options --log-ip-options --log-uid -m limit --limit 2/sec
$IPTABLES -A LOGDROP -j ULOG --ulog-prefix "FIREWALL DROPPED" --ulog-nlgroup 1
$IPTABLES -A LOGDROP -p tcp -j REJECT --reject-with tcp-reset -m comment --comment "Reject TCP connections with tcp-reset"
$IPTABLES -A LOGDROP -p udp -j REJECT --reject-with icmp-port-unreachable -m comment --comment "Reject UDP connections with icmp-port-unreachable"
$IPTABLES -A LOGDROP -j DROP
 
#
# Create TCP_CHAIN chain
#
for CHAIN in TCP_CHAIN BAD_TCP TCP_SLOWLORIS ICMP_CHAIN UDP_CHAIN ; do
        echo "Creating chain $CHAIN..."
        $IPTABLES -N $CHAIN
        $IPTABLES -F $CHAIN
done
 
#----------------#
# Firewall rules #
#----------------#
#
 
#
# allow localhost services
#
echo "Accept localhost connections..."
$IPTABLES -A INPUT -i lo -s 0/0 -d 0/0 -j ACCEPT
$IPTABLES -A OUTPUT -o lo -s 0/0 -d 0/0 -j ACCEPT
 
#
#
# Allow network connections which have already been established (started by host) and related to your connection.
# FTP requires this as it may use various ports in support of the file transfer.)
#
echo "Set up established state..."
$IPTABLES -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT -m comment --comment "Allow established incoming connections"
$IPTABLES -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT -m comment --comment "Allow established outgoing connections"
 
#
# Block Fragments
#
echo "Drop Fragments on INPUT"
$IPTABLES -A INPUT -f -j LOGDROP -m comment --comment "Fragments Packets"
 
#
# Block bad TCP stuff
#
echo "Drop bad TCP packets (portscans, spoofing, ...)"
$IPTABLES -A BAD_TCP -p tcp ! --syn -m state --state NEW -j LOGDROP -m comment  --comment "Drop Sync"
$IPTABLES -A BAD_TCP -p tcp --tcp-flags ALL ALL -j LOGDROP -m comment           --comment "XMAS Scan"
$IPTABLES -A BAD_TCP -p tcp --tcp-flags ALL NONE -j LOGDROP  -m comment         --comment  "NULL Scan"
$IPTABLES -A BAD_TCP -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j LOGDROP -m comment --comment "Merry XMAS Scan"
$IPTABLES -A BAD_TCP -p tcp --tcp-flags ALL FIN,URG,PSH -j LOGDROP -m comment   --comment "NMAP XMAS Scan"
$IPTABLES -A BAD_TCP -p tcp --tcp-flags ALL PSH,ACK -m state --state RELATED -j LOGDROP -m comment --comment "Drop ALL PSH,ACK state RELATED"
$IPTABLES -A BAD_TCP -p tcp --tcp-flags ALL SYN,ACK,PSH -j LOGDROP -m comment   --comment "Drop ALL SYN,ACK,PSH"
$IPTABLES -A BAD_TCP -p tcp --tcp-flags ALL SYN,PSH -j LOGDROP -m comment       --comment "Drop ALL SYN,PSH"
$IPTABLES -A BAD_TCP -p tcp --tcp-flags SYN,RST SYN,RST -j LOGDROP -m comment   --comment "SYN/RST Scan"
$IPTABLES -A BAD_TCP -p tcp --tcp-flags RST,FIN RST,FIN -j LOGDROP -m comment   --comment "RST/FIN Scan"
$IPTABLES -A BAD_TCP -p tcp --tcp-flags SYN,URG SYN,URG -j LOGDROP -m comment   --comment "SYN/URG Scan"
$IPTABLES -A BAD_TCP -p tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j REJECT --reject-with tcp-reset -m comment --comment "SYN/ACK Attack"
$IPTABLES -A BAD_TCP -p tcp --tcp-flags SYN,FIN SYN,FIN -j LOGDROP  -m comment  --comment  "SYN/FIN Scan"
$IPTABLES -A BAD_TCP -p tcp --tcp-flags SYN,ACK NONE -j LOGDROP -m comment      --comment "Drop SYN,ACK NONE"
$IPTABLES -A BAD_TCP -p tcp --tcp-flags ACK,FIN FIN -j LOGDROP -m comment       --comment "Drop ACK,FIN FIN"
$IPTABLES -A BAD_TCP -p tcp --tcp-flags ACK,PSH PSH -j LOGDROP -m comment       --comment "Drop ACK,PSH PSH"
$IPTABLES -A BAD_TCP -p tcp --tcp-flags ACK,URG URG -j LOGDROP -m comment       --comment "Drop ACK,URG URG"
$IPTABLES -A BAD_TCP -p tcp --tcp-flags FIN,ACK FIN -j LOGDROP  -m comment      --comment  "Fin Packets Scan"
$IPTABLES -A BAD_TCP -p tcp --tcp-flags FIN,RST FIN,RST -j LOGDROP -m comment   --comment "Drop FIN,RST FIN,RST"
 
#
# Add BAD_TCP chain as 1st rule to TCP_CHAIN
# 
$IPTABLES -A TCP_CHAIN -j BAD_TCP
 
# ICMP rules
# Allow ping and traceroute
#
echo "Allow ping and traceroute..."
$IPTABLES -A ICMP_CHAIN -p icmp -s 0/0 --icmp-type 8 -j ACCEPT -m comment --comment "Allow ICMP ping"
$IPTABLES -A ICMP_CHAIN -p icmp -s 0/0 --icmp-type 11 -j ACCEPT -m comment --comment "Allow ICMP traceroute"
 
 
##
## Disable port-scans (part 1)
## 
#echo "Disable portscans..."
#$IPTABLES -A INPUT -m recent --update --hitcount 16 --name portscanblock --seconds 3600 -j LOGDROP
#$IPTABLES -A INPUT -m recent --name portscanblock --set -m tcp -p tcp --tcp-flags ! SYN,RST,ACK,FIN SYN -j LOGDROP
 
#
# Prevents more than 2 SSH connections per minute, to slow down SSH scans
# Allow connections to SSH server, but only allow 2 connections from one IP
#
echo "Allow only 2 SSH connections /minute and not more than 4 connections in total..."
$IPTABLES -A TCP_CHAIN -p tcp -m tcp --dport 22 -m recent --update --hitcount 2 --seconds 60 --name sshsin -j LOGDROP -m comment --comment "Drop SSH connection if more than 2 in 60 secs"
$IPTABLES -A TCP_CHAIN -p tcp --syn --dport 22 -m connlimit --connlimit-mask 32 --connlimit-above 4 -j LOGDROP -m comment --comment "Don't allow more than 4 connections"
$IPTABLES -A TCP_CHAIN -p tcp -m tcp --syn --dport 22 -m recent --set --name sshsin -j ACCEPT -m comment --comment "Allow TCP connections to ssh"
 
#
# Allow traffic to webserver
#
echo "Allow web traffic..."
# Small defense against slowloris
$IPTABLES -A TCP_CHAIN -p tcp --dport 80 -m connlimit --connlimit-above 20 --connlimit-mask 32 -j LOGDROP -m comment --comment "Allow only 20 connections per IP to port 80"
# This chain will be provisioned from /root/bin/block_slowloris_attacks.sh
$IPTABLES -A TCP_CHAIN -p tcp --dport 80 -j TCP_SLOWLORIS
 
$IPTABLES -A TCP_CHAIN -p tcp --dport 80 -j ACCEPT -m comment --comment "Allow TCP connections to http"
$IPTABLES -A TCP_CHAIN -p tcp --dport 443 -j ACCEPT -m comment --comment "Allow TCP connections to https"
 
#$IPTABLES -A TCP_CHAIN -p tcp --dport 6000 -j ACCEPT -m comment --comment "Allow TCP connections to X11"
#$IPTABLES -A TCP_CHAIN -p udp --dport 6000 -j ACCEPT -m comment --comment "Allow UDP connections to X11"
 
#
# Allow traffic to mail platform
#
echo "Allow mail traffic..."
$IPTABLES -A TCP_CHAIN -p tcp --dport  25 -j ACCEPT -m comment --comment "Allow TCP connections to smtp"
$IPTABLES -A TCP_CHAIN -p tcp --dport 110 -j ACCEPT -m comment --comment "Allow TCP connections to pop3"
$IPTABLES -A TCP_CHAIN -p tcp --dport 143 -j ACCEPT -m comment --comment "Allow TCP connections to imap"
$IPTABLES -A TCP_CHAIN -p tcp --dport 465 -j ACCEPT -m comment --comment "Allow TCP connections to smtps"
$IPTABLES -A TCP_CHAIN -p tcp --dport 993 -j ACCEPT -m comment --comment "Allow TCP connections to imaps"
$IPTABLES -A TCP_CHAIN -p tcp --dport 995 -j ACCEPT -m comment --comment "Allow TCP connections to pop3s"
 
#
# Allow traffic to FTP server
#
echo "Allow FTP traffic..."
$IPTABLES -A TCP_CHAIN -p tcp --dport 20 -j ACCEPT -m comment --comment "Allow TCP connections to ftp-data"
$IPTABLES -A TCP_CHAIN -p tcp --dport 21 -j ACCEPT -m comment --comment "Allow TCP connections to ftp"
$IPTABLES -A TCP_CHAIN -p tcp --dport 989 -j ACCEPT -m comment --comment "Allow TCP connections to ftps-data"
$IPTABLES -A TCP_CHAIN -p tcp --dport 990 -j ACCEPT -m comment --comment "Allow TCP connections to ftps"
$IPTABLES -A TCP_CHAIN -p tcp --dport 115 -j ACCEPT -m comment --comment "Allow TCP connections to sftp"
$IPTABLES -A INPUT -m helper --helper ftp -j ACCEPT
 
 
#
# Allow traffic to DNS server
#
echo "Allow FTP traffic..."
$IPTABLES -A TCP_CHAIN -p tcp --dport 53 -j ACCEPT -m comment --comment "Allow TCP connections to dns"
$IPTABLES -A UDP_CHAIN -p udp --dport 53 -j ACCEPT -m comment --comment "Allow UDP connections to dns"
 
#
# Allow traffic to database server (needed for replication)
#
echo "Allow MYSQL traffic..."
$IPTABLES -A TCP_CHAIN -p tcp --dport 3306 -s 88.198.65.228 -j ACCEPT -m comment --comment "Allow TCP connections to mysql"
$IPTABLES -A UDP_CHAIN -p udp --dport 3306 -s 88.198.65.228 -j ACCEPT -m comment --comment "Allow UDP connections to mysql"
 
#
# Allow traffic to NTP server
#
echo "Allow NTP traffic..."
$IPTABLES -A TCP_CHAIN -p tcp --dport 123 -j ACCEPT -m comment --comment "Allow TCP connections to ntp"
$IPTABLES -A UDP_CHAIN -p udp --dport 123 -j ACCEPT -m comment --comment "Allow UDP connections to ntp"
 
#
# Allow traffic to torrent
#
echo "Allow torrent traffic..."
$IPTABLES -A TCP_CHAIN -p tcp --dport 6959 -j ACCEPT -m comment --comment "Allow TCP connections to torrent"
$IPTABLES -A UDP_CHAIN -p udp --dport 6959 -j ACCEPT -m comment --comment "Allow UDP connections to torrent"
 
#
# Allow traffic to DCC
#
echo "Allow DCC traffic..."
$IPTABLES -A UDP_CHAIN -p udp --dport 6277 -j ACCEPT -m comment --comment "Allow UDP connections to DCC"
 
#
# Needed for portscan block (part 2)
#
#$IPTABLES -A INPUT -m recent --set --name portscanblock
 
#
# Allow the ICMP_CHAIN, TCP_CHAIN and UDP_CHAIN chains on INPUT
# 
echo "Add ICMP_, TCP_ and UDP_CHAIN to INPUT..."
$IPTABLES -A INPUT -p icmp -j ICMP_CHAIN
$IPTABLES -A INPUT -p tcp  -j TCP_CHAIN
$IPTABLES -A INPUT -p udp  -j UDP_CHAIN
 
#
# debugging and logging
#
echo "Log and drop everything else..."
$IPTABLES -p ALL -A INPUT -j LOGDROP -m comment --comment "Drop all packets"
firewall.shОтваряне
Настройки за споделянето
