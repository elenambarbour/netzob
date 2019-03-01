from netzob.all import *
import os

#messages_1 = PCAPImporter.readFile("./DataFiles/target_src_v1_session1.pcap").values()
#messages_2 = PCAPImporter.readFile("./DataFiles/target_src_v1_session2.pcap").values()

combMessage = PCAPImporter.readFile("./DataFiles/HMI_00000_20140928210831.pcap").values()#messages_1 + messages_2

print('Raw for of PCAP using xxd')
os.system("xxd ./DataFiles/1_100_filtered_udp_00000_20171210163416.pcap")#target_src_v1_session2.pcap")

print('Can show raw for of PCAP using xxd to display binary')
#os.system("xxd -b ./DataFiles/1_1000_filtered_udp.pcap")

print('Messages combined in python reader')
for mes in combMessage:
	print(mes)
#observe the data printed all has the character # in it. Lets create fields based of the seperation of text by the # char.

symbolDelim = Symbol(messages=combMessage)
symbolStatic = Symbol(messages=combMessage)
symbolAlign = Symbol(messages=combMessage)
print('===================Raw symbol==========')
print (symbolStatic)

print('===============Split with Static Field #=========================================')

#Format.split
#call in class field split static
Format.splitStatic(symbolStatic)
#run the execute definition on the symboll data we have from pcap messages
#fs.execute(symbolStatic)
print("[+] Symbol Structure:")
print(symbolStatic._str_debug())
print('partitioned Messages: ')
print(symbolStatic)

print('===============Split with Delimiter #=========================================')
Format.splitDelimiter(symbolDelim,ASCII('#'))

print("[+] Symbol Structure:")
print(symbolDelim._str_debug())

print('partitioned Messages: ')
print(symbolDelim)

#organized the data into fields seperated by the # char.

print('===============Split with ALigned #=========================================')
Format.splitAligned(symbolAlign)

print("[+] Symbol Structure:")
print(symbolAlign._str_debug())

print('partitioned Messages: ')
print(symbolAlign)
