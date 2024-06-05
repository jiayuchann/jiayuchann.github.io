## DamCTF-take-a-look

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

Since the IV is known, to break the encryption we just have to brute force for 4 letters. I wrote a script for this:

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

Here I am assuming that the decrypted contents are printable.

