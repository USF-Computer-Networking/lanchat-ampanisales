import ipaddress
from subprocess import Popen, PIPE
from __future__ import print_function
from future.utils import python_2_unicode_compatible
from builtins import input
import sys, socket, select, future, builtins
from sys import argv

net4 = ipaddress.ip_network('10.10.12.0/24')
for x in net4.hosts():
	x = str(x)
	hostup = Popen(["ping", "-c1", x], stdout=PIPE)
	output = hostup.communicate()[0]
	val1 = hostup.returncode
	if val1 == 0:
		print(x, "is pinging")
	else:
		print(x, "is not responding")