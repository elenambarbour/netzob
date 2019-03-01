    def __decodeLayer2(self, header, payload):
        """Internal method that parses the specified header and extracts
        layer2 related proprieties."""

        def formatMacAddress(arrayMac):
            return ":".join("{0:0>2}".format(hex(b)[2:])
                            for b in arrayMac.tolist())

        if self.datalink == pcapy.DLT_EN10MB:
            l2Decoder = Decoders.EthDecoder()
            l2Proto = "Ethernet"
            layer2 = l2Decoder.decode(payload)
            l2SrcAddr = formatMacAddress(layer2.get_ether_shost())
            l2DstAddr = formatMacAddress(layer2.get_ether_dhost())
            l2Payload = payload[layer2.get_header_size():]
            etherType = layer2.get_ether_type()
        elif self.datalink == pcapy.DLT_LINUX_SLL:
            l2Decoder = Decoders.LinuxSLLDecoder()
            l2Proto = "Linux SLL"
            layer2 = l2Decoder.decode(payload)
            l2SrcAddr = layer2.get_addr()
            l2DstAddr = None
            l2Payload = payload[layer2.get_header_size():]
            etherType = layer2.get_ether_type()
        elif self.datalink == PCAPImporter.PROTOCOL201:
            l2Proto = "Protocol 201"
            hdr = payload.encode('hex')[0:8]
            if hdr[6:] == "01":
                l2SrcAddr = "Received"
            else:
                l2SrcAddr = "Sent"
            l2DstAddr = None
            l2Payload = payload[8:]
            etherType = payload[4:6]

        return (l2Proto, l2SrcAddr, l2DstAddr, l2Payload, etherType)
