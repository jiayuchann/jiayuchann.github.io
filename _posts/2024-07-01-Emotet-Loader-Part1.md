## Emotet Loader Part 1

SHA256: 47dba610a04ef1d7f18a795108cf9e62d2d6e9e22f0fba51143462f4d569a70d

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/407ffbf4-d416-42f8-803e-4129d091f529)

In part 1, I will be focusing on how the Dynamic Import Resolution works and also how to decrypt strings in the Emotet Loader. 

As you can see, the IAT is pretty much empty, and Emotet loads the required libraries and functions during runtime.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/e5162640-1c15-4dd2-b52e-ce417b47f39b)

In `start`, there are 2 function calls I labeled as `resolve_ntdll_apis` and `resolve_kerneldll_apis`, they both call the same functions pretty much.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/439453ec-2d9e-4967-8f25-ddbdf7e3cdc7)

In `resolve_ntdll_apis`, there are a bunch of `ntdll.dll` function hashes, and two function calls, one to get the base address of the `ntdll.dll` module, and another to do the actual API resolution.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/57d9b5b0-baf4-4238-bf01-67518ba7ce14)

The `get_dllbase_from_PEB` function takes in a hash, which in this case corresponds to the name `ntdll.dll` (recognized by HashDB), and walks the Process Environment Block to get the DLL names of each loaded modules in memory. For each name, it does a SDBM hash and compare it with the target hash. If it matches, return the base address of the DLL.  

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/b3263433-db07-4365-bd31-77549555aad3)

Hashing routine:

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/ae3704e0-6145-4dc2-94f2-4b1c25460e3f)

Back in `resolve_ntdll_apis` after getting the base address of `ntdll.dll`, it calls a wrapper function for an API resolving routine, passing in the module's base address, the array of `ntdll` hashes, number of functions to resolve, an XOR key, and a global buffer for storing the function addresses. `API_resolve_wrapper` just calls `API_resolve`.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/247d5a0b-3446-4b88-a982-9951ee5b3b20)

In `API_resolve`, it parses the PE header of the module. A quick overview:

`v6` points to the `IMAGE_EXPORT_DIRECTORY` via the first entry of `DataDirectory` in the `OptionalHeader`. This directory contains information about exported functions.

`address_of_functions` points to the array containing RVA of exported functions.

`address_of_names` points to the array containing RVA of function names.

`address_name_ordinals`points to the array of ordinals associated with names.

The loop runs through all the names specified in the export directory of the module, each name’s address is accessed and used to compute a hashed value using the same SDBM routine seen before, which is then XORed with a provided key. 

For each of the results it is checked against the list of hashes, and if a match is found, it gets stored in the `function_address_store` at offsets pointed to by `v10`.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/d18c9e06-fb6e-4919-8783-73258a5ed9ea)

We can create a struct for the `ntdll_APIs` global with size 209 * 4 (209 hashes, each resolved address is 4 bytes).

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/ada99ef1-ce9e-4bab-bdfe-e9ae50e3ec8a)

In x32dbg, break on the call after `API_resolve_wrapper` and inspect the global array.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/25f89b1d-46dd-488c-89fe-f596ace82d8b)

There isn’t a lot of addresses that got resolved, but here, at offset 5 `0x77D28D0` is `ntdll.memcpy` and at offset 8 `0x77CDFF50` is `ntdll.RtlGetVersion`. 

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/d28b6229-9c64-442f-8126-2ddf7ad5ed40)

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/3d5af8ee-cf1f-4ab5-8cea-3a5ecc96cf81)

In IDA, we can just rename the struct variables to the function names.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/553e854f-5377-40b9-b13a-cb0fb566e45e)

Repeat the same steps for `kernel32.dll` and other DLLs (but their DLL names are still encrypted for now). There’s quite a lot of functions, and I feel like there is a better way to do this through scripting. Anyways, for `kernel32.dll` after making the struct and applying it on the global `kernel32_APIs`:

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/65287cb2-0291-431f-a68d-14b27996c732)

Obviously, this is really tedious as you would have to repeat this for every loaded module. Pretty sure it can be scripted but I'll just move on for now.

Looking at the string decryption routine in the function `decryption`:

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/ecc70476-c24b-4bbc-8331-e29c4bb8356d)

It takes in 2 parameters, a pointer to a block to decrypt, and a key. Looks like it allocates some memory and `v5` points to the beginning of it, and then XORing each DWORD with the key and storing them accordingly in `v5`. This can be pretty easily replicated in Python and just hardcoding the data and key used.

```python
def decrypt(to_decrypt, key):
    # Convert the hex string to bytes
    data = bytes.fromhex(to_decrypt)

    # XOR the first 4 bytes with the key and adjust the result to a 4-byte boundary
    v3 = int.from_bytes(data[0:4], 'little') ^ key
    if v3 & 3:
        v4 = (v3 & ~3) + 4
    else:
        v4 = v3 + 4

    decrypted = bytearray(2 * v4)

    # Actual decryption
    idx = 4
    end_idx = 4 * (v4 // 4) + 4
    output_idx = 0
    while idx < end_idx:
        # Read 4 bytes, XOR with key, and split into 2 bytes each
        block = int.from_bytes(data[idx:idx+4], 'little')
        xored = key ^ block
        decrypted[output_idx] = xored & 0xFF
        decrypted[output_idx + 1] = (xored >> 8) & 0xFF
        decrypted[output_idx + 2] = (xored >> 16) & 0xFF
        decrypted[output_idx + 3] = (xored >> 24) & 0xFF
        idx += 4
        output_idx += 4

    # Null terminate
    decrypted[2 * v3] = 0

    return decrypted

# Inputs
to_decrypt = " 67F99F144ED4BA6C4259000106BBA3843232F76172BEE0F80000000000000000"
key = 0x149FF963

result = decrypt(to_decrypt, key)
print(result.decode('utf-8', errors='ignore'))
```

Attempting to decrypt the block at `0x410930` with the key `0x149FF963`, we get a format string specifier:

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/80812f46-5a80-4287-ba43-d43b972acf35)

There's quite a few string decryption calls:

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/1ed8ef2a-f2ef-497b-b998-bda61e15002a)

And additional DLL names were also decrypted before calling LoadLibraryW on it, and later performing the API resolutions like we've seen in the beginning.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/400b1c9b-1426-4f2f-90b8-75fbece7a34c)

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/b8d24e01-8c49-4870-b4e0-c5d1e2a224fb)

Anyways, just a quick guide (not the best) on how to deobfuscate Emotet. Will try to analyze its functionality in part 2!
