## BCACTF 5.0 - Foren, Rev, Web

Pretty fun challenges I did last weekend. Here's some writeups for some of them.

### forensics/flagserver

Description: It looks like Ircus have been using a fully exposed application to access their flags! Look at this traffic I captured. I can't seem to get it to work, though... can you help me get the flag for this very challenge?

We are given a flagserver.pcapng PCAP file. Inspect the network traffic in Wireshark. 
Server: 192.168.1.178, host: 10.0.2.15.

This challenge has to do with Java object serialization. Right away, we can see the magic number 0xaced, which is the constant for ObjectStreamConstants.STREAM_MAGIC defined in JDK.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/5dfe759e-126b-40fe-a83b-846d1365995f)

I used a tool called SerializationDumper to automate the analysis of serialization streams. First, we can follow the TCP stream in Wireshark.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/4798af01-36ad-48e8-865d-20c0528bbbfe)

Red = client, blue = server.

Copy as raw data and feed it as an argument to the SerializationDumper jar file.

Extraction of client stream:

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/53943aae-aa3c-4491-8cfd-6bbca140e715)

