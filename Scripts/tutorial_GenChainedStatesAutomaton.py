from netzob.all import *
messages_1 = PCAPImporter.readFile("./DataFiles/target_src_v1_session1.pcap").values()
messages_2 = PCAPImporter.readFile("./DataFiles/target_src_v1_session2.pcap").values()

combMessage = messages_1 + messages_2
for mes in messages_1:
	print(mes)
print("\n")
for mes in messages_2:
	print(mes)
print("\n")
for mes in combMessage:
	print(mes)
#observe the data printed all has the character # in it. Lets create fields based of the seperation of text by the # char.

symbol = Symbol(messages=combMessage)


Format.splitDelimiter(symbol,ASCII('#'))

print("[+] Symbol Structure:")
print(symbol._str_debug())

print('partitioned Messages: ')
print(symbol)

#organized the data into fields seperated by the # char.

#Create a cluster based of filed 1 type

symbols = Format.clusterByKeyField(symbol,symbol.fields[0])

print("Number of symbols after clustering: {0}".format(len(symbols)))
print("Symbols list: ")
for keyFieldName, s in symbols.items():
	print (" *{0}".format(keyFieldName))
#print((symbols.items()))

#Align static and dynamic subfields.
for sym in symbols.values():
	Format.splitAligned(sym.fields[2], doInternalSlick=True)
	print("\nPartitionned messages: ") 
	print(sym)

# Find field relations in each message.
for sym in symbols.values():
	rels = RelationFinder.findOnSymbol(sym)
	print("Relations found:")
	for rel in rels:
		print("1.  " + rel["relation_type"]+ ", between '"+ rel['x_attribute'] + "' of :")
		print("2.    "+ str('-'.join([f.name for f in rel["x_fields"]])))
		p= [v.getValues()[:] for v in rel["x_fields"]]
		print("3.     "+str(p))
		print("4.     and '"+ rel["y_attribute"] + "' of :" )
		print("5.\t" + str('-'.join([f.name for f in rel["y_fields"]])))
		p = [v.getValues()[:] for v in rel["y_fields"]]		
		print("6.\t"+ str(p))
# Create a session of messages
session = Session(messages_1)

#Abstract this session according to the inferred symbols
abstractSession = session.abstract(list(symbols.values()))

# Generate an automata according to the observed sequence of messages/symbols
automata = Automata.generateChainedStatesAutomata(abstractSession,list(symbols.values()))

# Prints out the dot representation of the automata
dotcode = automata.generateDotCode()
print(dotcode)
