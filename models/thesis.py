from mergexp import *

n_servers = 1
n_clients = 12
n_attackers = 8
n_sinks = 1
n_routers = 5
bottleneck_capacity = 1000
bottleneck_latency = 1
core_latency = 10
os_image="2004"

# Create a netwok topology object.
net = Network('ansible', routing==static, addressing==ipv4)

servers = [net.node('s{}'.format(i), image==os_image, proc.cores==5, memory.capacity>=gb(16), metal==False) for i in range(n_servers)]
for n in servers:
    n.properties['group'] = ['server']
clients = [net.node('c{}'.format(i), image==os_image, metal==False) for i in range(n_clients)]
for n in clients:
    n.properties['group'] = ['client']
attackers = [net.node('a{}'.format(i), image==os_image, metal==False) for i in range(n_attackers)]
for n in attackers:
    n.properties['group'] = ['attacker']
sinks = [net.node('sink{}'.format(i), image==os_image, proc.cores==5, memory.capacity>=gb(16), metal==False) for i in range(n_sinks)]
for n in sinks:
    n.properties['group'] = ['sink']
routers = [net.node('r{}'.format(i), image==os_image, proc.cores==5, memory.capacity>=gb(16), metal==False) for i in range(n_routers)]
for n in routers:
    n.properties['group'] = ['router']

routers[0].properties['group'].append('firewall')
routers[1].properties['group'].append('edge_router')
routers[2].properties['group'].append('edge_router')
routers[3].properties['group'].append('edge_router')
routers[4].properties['group'].append('core_router')

server_subnet = net.connect([routers[0]] + servers)
server_subnet.properties["tags"] = ("server_subnet", "ss")
server_lan = net.connect(clients[0:3] + servers)
server_lan.properties["tags"] = ("server_lan", "slan")
client_subnet_a = net.connect([routers[1]] + clients[3:6] + sinks)
client_subnet_a.properties["tags"] = ("client_subnet_a", "csa")
client_subnet_b = net.connect([routers[2]] + attackers[4:8] + clients[6:9])
client_subnet_b.properties["tags"] = ("client_subnet_b", "csb")
attacker_subnet = net.connect([routers[3]] + attackers[0:4] + clients[9:12])
attacker_subnet.properties["tags"] = ("attacker_subnet", "as")
server_link = net.connect([routers[0], routers[4]], capacity == mbps(bottleneck_capacity), latency == ms(bottleneck_latency))
server_link.properties["tags"] = ("server_link", "sl", "bottleneck")
client_link_a = net.connect([routers[1], routers[4]])
client_link_a.properties["tags"] = ("client_link_a", "cla")
client_link_b = net.connect([routers[2], routers[0]])
client_link_b.properties["tags"] = ("client_link_b", "clb")
attacker_link = net.connect([routers[3], routers[4]])
attacker_link.properties["tags"] = ("attacker_link", "al")

experiment(net)
