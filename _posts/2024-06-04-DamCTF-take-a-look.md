## DamCTF take-a-look

This challenge is kind of like a mix of rev and forensics, and I spent at least 10 hours looking at the Bee movie script. Kudos to the challenge writer.

The challenge folder consisted of these files:

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/93098037-ab64-4bf6-b03d-f11e321b3ee5)

The contents of `chal` looks like it's base64 encoded. 

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/1c3a518a-f466-46d3-8be7-a6a57c9380c5)

Decoding it gives us an PowerShell script, where variable names are o's of different length.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/a9c2dc8e-ad66-494c-a21a-df98eb8c4877)

My attempt at deobfuscation:

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/05e3dc78-3f8b-4b88-bdce-a0b1eeee4e32)

`$lookup` is a string that contains a custom set of characters. Few of the variables are initialized using specific positions within the `$lookup` string.

`Get-Command g????o????T*` resolves to `Get-Content`, and `$var8` uses this to read the contents of `.\book\0.txt`, the result is stored in `$book_txt_contents`. 

`$password` is not used I just ignored that.

`Get-Command g????????m` resolve to `Get-Random`, `$var5 = -join ((65..90)+(97..122) | &(Get-Command g????????m) -Count 4 | % {[char]$_}) * 8` generates 4 random letters (uppercase/lowercase), concatenated to itself 7 more times, and the gets stored in `$var5`. This is the encryption key.

`$IV = [system.Text.Encoding]::$utf8.$GetByTeS(-join ((65..80) |  % {[char]$_}))` The IV in this case is just the first 16 letters of the alphabet (A to P).

The rest of the script is just encrypting the contents of `.\book\0.txt` with AES, set up using the key and IV, then outputting it to a file, but in this case, 21 fragmented files.

Since the IV is known, to break the encryption we just have to brute force for 4 letters. I wrote a script to brute force and check whether the attempted decryption output is printable. And ran it on the file `0.enc`.

```python
import itertools
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# The Base64-encoded encrypted content
with open('0.enc', 'rb') as file:
    content = file.read()
    content = content.replace(b'\x00', b'')  # Remove null bytes
    encrypted_content = base64.b64decode(content)  # Base64 decode

# AES IV is known
iv = b'ABCDEFGHIJKLMNOP'

# Function to attempt decryption with a given key
def decrypt_aes(encrypted_data, key, iv):
    try:
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        return decrypted
    except:
        return None

# Generator for all combinations of 4 letters
letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
combinations = itertools.product(letters, repeat=4)

# Attempt to brute force the key
for combo in combinations:
    key_fragment = ''.join(combo)
    key = key_fragment * 8  # Repeat the fragment 8 times to form the key
    # print(key)
    decrypted_content = decrypt_aes(encrypted_content, key, iv)
    if decrypted_content:
        # Assuming the decrypted content is printable, check for readability
        if all(c < 128 for c in decrypted_content):
            print(f"Decryption successful with key: {key}")
            print(f"Decrypted content: {decrypted_content.decode('utf-8')}")
            exit()
```

Key found: jwCUjwCUjwCUjwCUjwCUjwCUjwCUjwCU

And we are presented with the first part of Bee movie script.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/7d6b24df-833e-4dec-99b8-f5941176c215)

Decrypting `cipher_no_ciphering` gives us what looks like a list of indices:
`8 2 29 12 673 19 6 124 464 2 14 211 13 19 20 87 90 1 19 20 27 110 20 7 6 211 126`

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/a78f42d2-a5e8-4e8b-8730-35b738a30610)

This is where I got stuck, and spent hours trying out different strategies and looking at the movie script for hours.

After the event ended, apparently it was a book cipher: https://en.wikipedia.org/wiki/Book_cipher, and `17.enc` contained the flag.
Each element of the key is used to point to a position within the file (8 = 8th character, 2 = 2nd character because we count from 0), but we are ignoring spaces and newline characters in the file.

This is the official solver script for the final stage (modified to print l):

```python
cipher = [8, 2, 29, 12, 673, 19, 6, 124, 464, 2, 14, 211, 13, 19, 20, 87, 90, 1, 19, 20, 27, 110, 20, 7, 6, 211, 126]
        
l = list()
with open('17_decrypted','r') as file:
    data = file.read()
    print(file.name)
    
for y in data:
    if y != " " and y != "" and y != '\n':
        l.append(y)

print(l)
for z in cipher:
    print(l[z], end ="")
print('\n')
```

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/f032a306-885d-4e3b-be6d-dc8246cbcd81)

And we can use the list of indices to point to each character of the flag and concatenate them together.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/97cafc6b-9616-4a8a-990b-4f28129bff87)
