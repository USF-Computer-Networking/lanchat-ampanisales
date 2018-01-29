from __future__ import print_function
from future.utils import python_2_unicode_compatible
from builtins import input
import sys, socket, select
from sys import argv
from scapy import *
import future
import builtins

def isIpRange(range):
	rangeParts = range.split("/")
	if rangeParts[0] == "0" and rangeParts[1] == "24":
		return True
	else:
		return False

def isIpAddress(address):
	if address.count(".") != 3:
		return False
	nums = address.split(".")
	thisIsRange = False
	if nums[3].count("/") == 1:
		if not isIpRange(nums[3]):
			return False
		else:
			thisIsRange = True
	for n in nums:
		if n == nums[3] and thisIsRange:
			break
		if len(n) > 3:
			return False
		try:
			test = int(n)
		except ValueError:
			return False
		if test > 255 or test < 0:
			return False
	return True

def getMessage():
	messages,x,y = select.select([sys.stdin],[],[],0.0001)
	for m in messages:
		if m == sys.stdin:
			message = sys.stdin.readline()
			return message
	return None

# LAN ARP Scanner		
def lanScan():
	print("\n-------------------------------")
	print("\n\tLAN Scanner")
	print("\n-------------------------------")
	try:
		interface = input("\nEnter interface: ")
		assert isinstance(interface, str)
		while (True):
			ipRange = input("\nEnter IP Address Range:  ")
			assert isinstance(ipRange, str)
			if isIpAddress(ipRange):
				break
			print ("\nInvalid IP Range")
	except KeyboardInterrupt:
		print("\nLAN Scanner shutting down...")
		sys.exit();

	print("\nNow Scanning...")

	conf.verb = 0
	ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = ipRange), timeout = 2, 
		iface = interface, inter = 0.1)

	print("\n MAC Address \t IP Address")

	for send, recv in ans:
		print(recv.sprintf(r"%Ether.src% - %ARP.psrc%"))

	print("End of scan")

# UDP Chat
def udpChat():
	print("\n-------------------------------")
	print("\n\tUDP Chat")
	print("\n-----------------------------")

	print("\nIf (optional), press ENTER to skip")

	try:
		while (True):
			sendHost = input("Enter recipient IP Address: ")
			assert isinstance(sendHost, str)
			if isIpAddress(sendHost):
				break
			print("\nInvalid IP Address/Range")

		portString = input("Enter PORT (optional): ")
		assert isinstance(portString, str)

		if portString == '': # Default port value is 1027
			port = int("1027", 16) # Hex value is base 16
		else:
			try:
				port = int(portString, 16)
				if port < 1000:
					print("Invalid port number. Default port will be used")
					port = int("1027", 16)
			except ValueError:
				print("Invalid port number. Default port will be used")
				port = int("1027", 16)
	except KeyboardInterrupt:
		print("\nUDP Chat shutting down...")
		sys.exit();

	# Sets the address to send messages to
	sendAddress = (sendHost, port)

	# Creates datagram socket for UDP
	skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	# Allows socket to receive incoming broadcasts
	skt.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) 

	# Makes the socket reusable    
	skt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

	# Set socket to be non-blocking
	skt.setblocking(False) 

	# Port is able to accept connections
	skt.bind(('', port))

	print("\nPress 'ctrl + C' to exit chat")
	print("Accepting connections on port", hex(port))
	print("You can start typing now\n")

	try:
		while 1:
			try:
				# Buffer size is 8000
				message, address = skt.recvfrom(8000)
				if message:
					print(address, "-> ", message)
			except:
				pass
		 
			message = getMessage();
			if message != None:
				skt.sendto(message, sendAddress)
	except KeyboardInterrupt:
		print ("\nLeaving UDP Chat...")

# Checks for help on command line
def help():
	for a in argv:
		if a == "-h" or a == "--help":
			print("\n-------------------------------")
			print("\n\tHelp")
			print("\n-------------------------------")
			print("The LAN Scanner requires the user to input an network interface and an IP address range. " +
				"Valid IP address ranges have '0/24' as the last byte of the IP address " +
				"(i.e. 100.222.3.0/24). The UDP Chat supports unicast and broadcast packet " + 
				"transmission. For unicast, enter IP and Port. For broadcast mode set the last " +
				"byte of IP address to 255 (i.e. 121.16.0.255).\n")

help()
lanScan()
udpChat()
