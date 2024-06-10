## BCACTF 5.0 - Foren, Rev, Web

Pretty fun challenges I did last weekend. Here's some writeups for some of them.

### forensics/flagserver

Description: It looks like Ircus have been using a fully exposed application to access their flags! Look at this traffic I captured. I can't seem to get it to work, though... can you help me get the flag for this very challenge?

We are given a flagserver.pcapng PCAP file. Inspect the network traffic in Wireshark. 
Server: 192.168.1.178, host: 10.0.2.15.

This challenge has to do with Java object serialization. Right away, we can see the magic number `0xaced`, which is the constant for `ObjectStreamConstants.STREAM_MAGIC` defined in JDK.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/5dfe759e-126b-40fe-a83b-846d1365995f)

I used a tool called SerializationDumper to automate the analysis of serialization streams. First, we can follow the TCP stream in Wireshark.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/4798af01-36ad-48e8-865d-20c0528bbbfe)

Red = client, blue = server.

Copy as raw data and feed it as an argument to the SerializationDumper jar file.

Extraction of client stream:

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/53943aae-aa3c-4491-8cfd-6bbca140e715)

The class being serialized is `flagserver.MessageCtoS_Request`, with a version identifier of `0xbd164155d760d5a3`. It also implements a the `Serializable` interface. 

Only 1 field is serialized within this class, `chall` which if of type ` Ljava/lang/String;`, and it has the value `fakechall`

Extraction of server stream:

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/6b931d4b-3213-4905-ab58-c7e11f9c7074)

When the client sent the object, the server responded with a serialized object as well, containing a fake flag. The trick is that the server is hosting 2 flags, and we can craft the serialized object ourselves and send it to the server but changing the value of `chall` to `flagserver` to access the actual flag.

In Java, I made a class ` MessageCtoS_Request` which implements the Serializable class, with attributes `serialVersionUID`and `chall`. 

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/8cc71ddf-7c7b-4d93-bae9-4dfeffc92054)

And also a main class which initializes the object and sends the serialized data to the server. 

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/602f92f7-a434-4877-a6a7-613abb1ca763)

I didn’t really parse the server’s output, I just dumped it.

`bcactf{thankS_5OCK3ts_and_tHreADInG_clA5s_2f6fb44c998fd8}`

### forensics/magic

Description: I found this piece of paper on the floor. I was going to throw it away, but it somehow screamed at me while I was holding it?!

We are given a PDF file, so I tried opening it Microsoft Edge:

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/68effdef-d397-462b-96a7-9e34874085df)

Looks like a flag checker.

I opened it up in PDF Stream Dumper to analyze any streams. These streams are usually images, compressed data, fonts, etc. but they can contain embedded files like JavaScript as well, which seems to be the case here. 

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/87fc17a9-ed8a-4823-830a-006d46c4e753)

I found the Flag checker script, but it looks obfuscated. Instead of manually de-obfuscating it, we can plug it into [deobfuscate.io](https://obf-io.deobfuscate.io/), which happened to be the tool used for obfuscating the original code. 

