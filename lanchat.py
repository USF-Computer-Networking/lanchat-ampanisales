""" lanchat.py

Author: Anthony Panisales

- discovers other computers on the same LAN
    - provides a user friendly display of information about each discovered peer

 - supports sending text messages carried in UDF packets
    - supports either unicast or broadcast packet transmission
    - provides a default port but allows the selection of a different port 
      for the unicast chat
    - allows the selection of a specific recipient IP address for the unicast chat

- Code for LAN Scanner was inspired by this source: 
	https://null-byte.wonderhowto.com/how-to/build-arp-scanner-using-scapy-and-python-0162731/

- Code for UDP Chat was inspired by this source: 
	https://thecodeninja.net/2014/12/udp-chat-in-python/

"""

from __future__ import print_function
from future.utils import python_2_unicode_compatible
from builtins import input
import sys, socket, select
from sys import argv
from scapy.all import *
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
			interface = input("Enter network interface: ").strip()
			assert isinstance(interface, str)
			if interface == "q":
				print("\nLAN Scanner shutting down...")
				return
			while (True):
				ipRange = input("\nEnter IP Address Range:  ").strip()
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

	# Creates datagram socket for UDP
	skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	# Allows socket to receive incoming broadcasts
	skt.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) 

	# Makes the socket reusable    
	skt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

	# Set socket to be non-blocking
	skt.setblocking(False) 
	
	try:	
		while (True):
			print("Press 'q' to quit chat")
			chat = input("Broadcast (press 'b') or Unicast (press 'u'): ").lower().strip()
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
				sendHost = input("Enter recipient IP Address: ").strip()
				assert isinstance(sendHost, str)
				if sendHost == "q":
					print("\nUDP Chat shutting down...")
					return
				if isIpAddress(sendHost):
					break
				print("Invalid IP Address\n")
			portString = input("Enter PORT (optional): ").strip()
			assert isinstance(portString, str)
			if portString == "q":
				print("\nUDP Chat shutting down...")
				return
			if portString == '': # Default port value is 1027
				port = 1027
			else:
				try:
					port = int(portString)
					if port < 1 or port > 65535:
						raise ValueError
				except ValueError:
					print("Invalid port number. Default port will be used")
					port = 1027
			sendAddress = (sendHost, port)
		elif chat == "b":
			port = 1027
			sendAddress = ('<broadcast>', port)
	except KeyboardInterrupt:
		print("\n\nUDP Chat shutting down...")
		print("Program shutting down...")
		sys.exit();

	# Port is able to accept connections
	skt.bind(('', port)) 

	print("\nPress 'ctrl + C' to exit chat")
	print("Accepting connections on port", port)
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
		skt.close()
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
				"optionally, the PORT (Range of available PORT numbers: 1-65535).\n")

def main():
	help()
	decision = ""
	while True:
		try:
			print("\nPress 'q' to quit program")
			decision = input("LAN Scan (press 's') or UDP Chat (press 'c'): ").lower().strip()
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

if __name__ == '__main__':
	main()
