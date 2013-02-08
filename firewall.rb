#!/usr/bin/ruby
#
# Name:     firewall.rb
# Author:   Thomas VIAL
#
      
IPTABLES   = "/sbin/iptables"
IP6TABLES  = "/sbin/ip6tables"
IFACE_NAME = "eth0"
IFACE_IP   = "192.168.1.200"
NETWORK    = "192.168.1.0/24"

puts "------------------------------------------------------"
puts ""
puts "                  FIREWALL IPTABLES"
puts ""
puts "------------------------------------------------------"
puts ""


print "> Enabling proc                                "
proc_files = [
  "/proc/sys/net/ipv4/tcp_syncookies",
  "/proc/sys/net/ipv4/ip_forward"
]
proc_files.each do |f|
  if File.exists?(f)
    p = File.open(f, "w")
    p.write("1")
    p.close   
  end
end
puts "[ OK ]"

print "> Flush existing chains                        "
ipt_flush   = ['INPUT', 'OUTPUT', 'FORWARD']
ipt_flush.each do |f|
  exec("#{IPTABLES} -F #{f}")
end
puts "[ OK ]"

print "> Setting DROP policy                          "
ipt_policy   = ['INPUT', 'FORWARD']
ipt_policy.each do |f|
  exec("#{IPTABLES} -P #{f} DROP")
end
puts "[ OK ]"

print "> Setting Up NAT                               "
exec("#{IPTABLES} -F -t nat")
exec("#{IPTABLES} -P FORWARD DROP")
exec("#{IPTABLES} -A FORWARD -i #{IFACE_NAME} -j ACCEPT")
exec("#{IPTABLES} -A INPUT -i #{IFACE_NAME} -j ACCEPT")
exec("#{IPTABLES} -A OUTPUT -o #{IFACE_NAME} -j ACCEPT")
puts "[ OK ]"

print "> Allow ICMP & loopback packets                "
exec("#{IPTABLES} -A INPUT -p icmp -j ACCEPT")
exec("#{IPTABLES} -A INPUT -i lo -j ACCEPT")
exec("#{IPTABLES} -A OUTPUT -o lo -j ACCEPT")
puts "[ OK ]"


print "> Opening ports via TCP                        "
ipt_input_ports_tcp = [22, 25, 53, 80, 113, 143, 953, 1723, 6667]
ipt_input_ports_tcp.each do |f|
  exec("#{IPTABLES} -A INPUT -p tcp --dport #{f} -j ACCEPT")
end
puts "[ OK ]"

print "> Opening ports via UDP                        "
ipt_input_ports_udp = [53, 113, 953]
ipt_input_ports_udp.each do |f|
  exec("#{IPTABLES} -A INPUT -p udp --dport #{f} -j ACCEPT")
end
puts "[ OK ]"

print "> Opening ports via Protocols ID               "
ipt_input_ports_protocol = [47]
ipt_input_ports_protocol.each do |f|
  exec("#{IPTABLES} -A INPUT -p #{f} -d #{NETWORK} -j ACCEPT")
end
puts "[ OK ]"

dest  = "192.168.1.201"
print "> Setting up port forwarding to #{dest}  "
ipt_forward_port = { 201 => 22, 8080 => 80 }
ipt_forward_port.each_pair do |f,t|
  exec("#{IPTABLES} -A INPUT -p #{f} -d #{NETWORK} -j ACCEPT")
  exec("#{IPTABLES} -A INPUT -p tcp --dport #{f} -j ACCEPT")
  exec("#{IPTABLES} -A FORWARD -p tcp --dport #{f} -j ACCEPT")
  exec("#{IPTABLES} -t nat -A PREROUTING -i #{IFACE_NAME} -p tcp --dport #{f} -j DNAT --to #{dest}:#{t}")
  exec("#{IPTABLES} -t nat -A POSTROUTING -p tcp --dport #{t} -j SNAT --to #{IFACE_IP}")
end
puts "[ OK ]"



puts ""
puts "------------------------------------------------------"
