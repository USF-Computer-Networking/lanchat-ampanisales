from __future__ import print_function
from future.utils import python_2_unicode_compatible
from builtins import input
import sys, socket, select
from sys import argv
from scapy.all import *
import future
import builtins

# Code for LAN Scanner was inspired by this
# source: https://null-byte.wonderhowto.com/how-to/build-arp-scanner-using-scapy-and-python-0162731/

# Code for UDP Chat was inspired by this
# source: https://thecodeninja.net/2014/12/udp-chat-in-python/

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
		if len(n) > 1 and n[0] == "0":
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
	
	while (True):
		try:
			print("Press 'q' to quit scanner")	
			interface = input("Enter network interface: ")
			assert isinstance(interface, str)
			if interface == "q":
				print("\nLAN Scanner shutting down...")
				return
			while (True):
				ipRange = input("\nEnter IP Address Range:  ")
				assert isinstance(ipRange, str)
				if ipRange == "q":
					print("\nLAN Scanner shutting down...")
					return
				if isIpAddress(ipRange):
					break
				print ("Invalid IP Range")
			print("\nNow Scanning...")
			conf.verb = 0
			ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = ipRange), timeout = 2, 
				iface = interface, inter = 0.1)
			
			print("\n      MAC Address - IP Address")
			for send, recv in ans:
				print(recv.sprintf(r"%Ether.src% - %ARP.psrc%"))
			break
		except IOError:
			print("\nInvalid Interface\n")
			continue
		except KeyboardInterrupt:
			print("\n\nLAN Scanner shutting down...")
			print("Program shutting down...")
			sys.exit();
	print("End of scan")

# UDP Chat
def udpChat():
	print("\n-------------------------------")
	print("\n\tUDP Chat")
	print("\n-------------------------------")
	
	try:	
		while (True):
			print("Press 'q' to quit chat")
			chat = input("Broadcast (press 'b') or Unicast (press 'u'): ").lower()
			assert isinstance(chat, str)
			if chat == "q":
				print("\nUDP Chat shutting down...")
				return
			elif chat == "b" or chat == "u":
				break
			print("Invalid Input\n")
		if chat == "u":
			print("\nIf (optional), press ENTER to skip")
			while (True):
				sendHost = input("Enter recipient IP Address: ")
				assert isinstance(sendHost, str)
				if sendHost == "q":
					print("\nUDP Chat shutting down...")
					return
				if isIpAddress(sendHost):
					break
				print("Invalid IP Address\n")
			portString = input("Enter PORT (optional): ")
			assert isinstance(portString, str)
			if portString == "q":
				print("\nUDP Chat shutting down...")
				return
			if portString == '': # Default port value is 1027
				port = int("1027", 16) # Hex value is base 16
			else:
				try:
					port = int(portString, 16)
				except ValueError:
					print("Invalid port number. Default port will be used")
					port = int("1027", 16)
			sendAddress = (sendHost, port)
		elif chat == "b":
			port = int("1027", 16)
			sendAddress = ('<broadcast>', port)
	except KeyboardInterrupt:
		print("\n\nUDP Chat shutting down...")
		print("Program shutting down...")
		sys.exit();
	
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
			print("The LAN Scanner requires the user to enter a network interface and an IP address range. " +
				"Valid IP address ranges have '0/24' as the last byte of the IP address " +
				"(e.g. 100.222.3.0/24). The UDP Chat supports unicast and broadcast packet " + 
				"transmission. For unicast, the user is required to enter the recipient IP Address and " +
				"optionally, the PORT.\n")

def main():
	help()
	decision = ""
	while True:
		try:
			print("\nPress 'q' to quit program")
			decision = input("LAN Scan (press 's') or UDP Chat (press 'c'): ").lower()
			assert isinstance(decision, str)
			if decision == "s":
				lanScan()
			elif decision == "c":
				udpChat()
			elif decision == "q":
				break
			else:
				print("Invalid input")
		except KeyboardInterrupt:
			break
	print("\nProgram shutting down...")
	print("Have a nice day!")
	
main()
