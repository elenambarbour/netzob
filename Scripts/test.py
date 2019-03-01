from netzob.all import *
import os

messages_1 = PCAPImporter.readFile("./DataFiles/1_1000_filtered_udp_stripped.pcap", importLayer=2).values()
messages_2 = PCAPImporter.readFile("./DataFiles/target_src_v1_session2.pcap").values()

print(repr(messages_1[0].data))
