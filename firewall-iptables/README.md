# Firewall iptables

Ruby script to manage a linux firewall based on `iptables`

Some defaults :
- Incoming & Forwarded trafic is dropped
- Outgoing trafic is accepted

Don't forget to adapt this script to your needs before you apply the rules.

## Setup

Path to iptables

    IPTABLES   = "/sbin/iptables"

Interface identifier

    IFACE_NAME = "eth0"

Current server interface IP

    IFACE_IP   = "192.168.1.200"

Current server network

    NETWORK    = "192.168.1.0/24"

## Firewall rules

TCP ports to open

    ipt_input_ports_tcp       = [22, 25, 53, 80, 113, 143, 6667]

UDP ports to open

    ipt_input_ports_udp       = [53, 113]

Protocols ID to open

    ipt_input_ports_protocol  = [47]

Port forwarding 

    ipt_forward_port          = {
                                  # remote_ip => { local_port => remote_port }
                                  "192.168.1.201" => { 201 => 22, 8080 => 80 }
                                }

## Usage

Test the rules (nothing will be applied)

    ./firewall-iptables.rb test

Apply the rules

    ./firewall-iptables.rb apply