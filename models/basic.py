from mergexp import *

n_servers = 1
n_clients = 1
n_attackers = 1
n_sinks = 1
n_routers = 1
bottleneck_capacity = 1000
bottleneck_latency = 1
os_image="2004"

# Create a netwok topology object.
net = Network('ansible', routing==static, addressing==ipv4)

servers = [net.node('s{}'.format(i), image==os_image, metal==False) for i in range(n_servers)]
for n in servers:
    n.properties['group'] = ['server']

clients = [net.node('c{}'.format(i), image==os_image, metal==False) for i in range(n_clients)]
for n in clients:
    n.properties['group'] = ['client']

attackers = [net.node('a{}'.format(i), image==os_image, metal==False) for i in range(n_attackers)]
for n in attackers:
    n.properties['group'] = ['attacker']

sinks = [net.node('sink{}'.format(i), image==os_image, metal==False) for i in range(n_sinks)]
for n in sinks:
    n.properties['group'] = ['sink']

routers = [net.node('r{}'.format(i), image==os_image, metal==False) for i in range(n_routers)]
for n in routers:
    n.properties['group'] = ['router']
routers[0].properties['group'].append('firewall')

main_lan = net.connect([routers[0]] + clients + attackers + sinks)
server_link = net.connect([routers[0], servers[0]], capacity == mbps(bottleneck_capacity), latency == ms(bottleneck_latency))
server_link.properties["tags"] = ("bottleneck")

experiment(net)
