#!/usr/bin/ruby
#
# Name:     firewall.rb
# Author:   Thomas VIAL
# Usage:    ./firewall-iptables.rb (test|apply)
#           => 'test' will only print the rules
#           => 'apply' will execute iptables and apply the rules


# Configuration      
IPTABLES   = "/sbin/iptables"
IFACE_NAME = "eth0"
IFACE_IP   = "192.168.1.200"
NETWORK    = "192.168.1.0/24"

# Firewall settings
ipt_input_ports_tcp       = [22, 25, 53, 80, 113, 143, 6667]
ipt_input_ports_udp       = [53, 113]
ipt_input_ports_protocol  = [47]
ipt_forward_port          = {
                              "192.168.1.201" => { 201 => 22, 8080 => 80 }
                            }
ipt_blacklist             = [
                              "84.54.110.165",
                              "82.160.245.29",
                              "14.97.89.98",
                              "115.118.75.252",
                              "1.173.245.133",
                              "122.172.6.74",
                              "115.119.137.180",
                              "37.8.194.163"
]

#
#
# /!\ # Don't touch the next part
#
#

def arg
  ARGV[0].to_s
end

def notify_and_exit
  puts "----------------------------------------------------------------"
  puts "Error : Wrong or Missing parameter"
  puts "Use './firewall-iptables.rb test' to check rules before apply" 
  puts "Use './firewall-iptables.rb apply' to apply rules set" 
  puts "----------------------------------------------------------------"
  exit
end

if arg.empty?
  notify_and_exit
elsif not ["test", "apply"].include?(arg)
  notify_and_exit  
end

def label(label_text)
  if arg.eql? "test"
    puts(label_text)
  elsif arg.eql? "apply"
    print(label_text)
  end
end

def cmd(cmd_options)
  if arg.eql? "test"
    puts(cmd_options)
  elsif arg.eql? "apply"
    system(cmd_options)
  end
end

def confirm(confirm_text)
    if arg.eql? "test"
    puts ""
  elsif arg.eql? "apply"
    puts(confirm_text)
  end
end

puts "----------------------------------------------------------------"
puts ""
puts "                      FIREWALL IPTABLES"
puts ""
puts "----------------------------------------------------------------"
puts ""

label("> Enabling proc                                          ")
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
confirm("[ OK ]")

label("> Flush existing chains                                 ")
ipt_flush   = ['INPUT', 'OUTPUT', 'FORWARD']
ipt_flush.each do |f|
  cmd("sudo #{IPTABLES} -F #{f}")
end
confirm("[ OK ]")

label("> Setting DROP policy                                   ")
ipt_policy   = ['INPUT', 'FORWARD']
ipt_policy.each do |f|
  cmd("sudo #{IPTABLES} -P #{f} DROP")
end
confirm("[ OK ]")

label("> Setting Up NAT                                        ")
cmd("sudo #{IPTABLES} -F -t nat")
cmd("sudo #{IPTABLES} -P FORWARD DROP")
cmd("sudo #{IPTABLES} -A FORWARD -i #{IFACE_NAME} -j ACCEPT")
cmd("sudo #{IPTABLES} -A INPUT -i #{IFACE_NAME} -j ACCEPT")
cmd("sudo #{IPTABLES} -A OUTPUT -o #{IFACE_NAME} -j ACCEPT")
confirm("[ OK ]")

label("> Allow ICMP & loopback packets                          ")
cmd("sudo #{IPTABLES} -A INPUT -p icmp -j ACCEPT")
cmd("sudo #{IPTABLES} -A INPUT -i lo -j ACCEPT")
cmd("sudo #{IPTABLES} -A OUTPUT -o lo -j ACCEPT")
confirm("[ OK ]")


label("> Opening ports via TCP                                  ")
ipt_input_ports_tcp.each do |f|
  cmd("sudo #{IPTABLES} -A INPUT -p tcp --dport #{f} -j ACCEPT")
end
confirm("[ OK ]")

label("> Opening ports via UDP                                 ")
ipt_input_ports_udp.each do |f|
  cmd("sudo #{IPTABLES} -A INPUT -p udp --dport #{f} -j ACCEPT")
end
confirm("[ OK ]")

label("> Opening ports via Protocols ID                         ")
ipt_input_ports_protocol.each do |f|
  cmd("sudo #{IPTABLES} -A INPUT -p #{f} -d #{NETWORK} -j ACCEPT")
end
confirm("[ OK ]")

ipt_forward_port.each do |ip,arr|
  label("> Setting up port forwarding to #{ip}  ")
  arr.each do |from,to|
    cmd("sudo #{IPTABLES} -A FORWARD -p tcp --dport #{from} -j ACCEPT")
    cmd("sudo #{IPTABLES} -t nat -A PREROUTING -i #{IFACE_NAME} -p tcp --dport #{from} -j DNAT --to #{ip}:#{to}")
    cmd("sudo #{IPTABLES} -t nat -A POSTROUTING -p tcp --dport #{to} -j SNAT --to #{IFACE_IP}") 
  end
end
confirm("[ OK ]")

label("> Blacklist some ips                                     ")
ipt_blacklist.each do |ip|
  cmd("sudo #{IPTABLES}  -A INPUT -s #{ip} -j DROP") 
end
confirm("[ OK ]")

puts ""
puts "----------------------------------------------------------------"
