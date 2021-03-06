/testing/guestbin/swan-prep --x509
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.254/32 -j LOGDROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm with a ping
ping -c 4 -n -I 192.0.3.254 192.0.2.254
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add northnet-eastnet-nat
echo "initdone"
