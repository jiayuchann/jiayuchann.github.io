## Emotet Deobfuscation

##### [Dynamic Imports](#dynamicimports-1)
##### [String Decryption](#stringdecryption-1)

SHA256: 47dba610a04ef1d7f18a795108cf9e62d2d6e9e22f0fba51143462f4d569a70d

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/407ffbf4-d416-42f8-803e-4129d091f529)

In this walkthrough, I will be focusing on how the Dynamic Import Resolution works and also how to decrypt strings in Emotet's main binary. 

## Dynamic Imports

As you can see, the Import Address Table is pretty much empty, and Emotet loads the required libraries and functions during runtime.

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

In x32dbg, break on the call after `API_resolve_wrapper` and inspect the global array.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/25f89b1d-46dd-488c-89fe-f596ace82d8b)

There isn’t a lot of addresses that got resolved, but here, at offset 5 `0x77D28D0` is `ntdll.memcpy` and at offset 8 `0x77CDFF50` is `ntdll.RtlGetVersion`. 

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/d28b6229-9c64-442f-8126-2ddf7ad5ed40)

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/cbadfc78-bbe9-4168-a135-9a86451695fe)

In IDA, We can create a struct for the `ntdll_APIs` global with size 209 * 4 (209 hashes, each resolved address is 4 bytes), and just rename the struct variables to the function names.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/553e854f-5377-40b9-b13a-cb0fb566e45e)

Repeat the same steps for `kernel32.dll` and other DLLs (but their DLL names are still encrypted for now). There’s quite a lot of functions, and I feel like there is a better way to do this through scripting. Anyways, for `kernel32.dll` after making the struct and applying it on the global `kernel32_APIs`:

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/65287cb2-0291-431f-a68d-14b27996c732)

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/df743b49-14b2-434c-8d5a-035c085163f5)

Obviously, this is really tedious, that you would have to repeat for every loaded module. But here’s how you can script it by hardcoding the XOR key and list of hashes (for ntdll.dll and kernel32.dll), with a [symbol file](https://raw.githubusercontent.com/deepinstinct/DeMotet/master/scripts/symbols.json) containing modules and function names:

```python
import json
import ctypes

data = None
with open('symbols.json', 'r') as file:
    data = json.load(file)

def sdbm_hash(s):
    """Calculate the SDBM hash value of a string."""
    hash = 0
    for char in s:
        hash = ord(char) + (hash << 6) + (hash << 16) - hash
    return hash & 0xffffffff  # Ensure the hash is within a 32-bit range

def process_json(key, known_hashes, dll):
    """Process the JSON file containing DLL names, apply hashing and XOR, then check against known hashes."""

    if dll in data:
        for function_name in data[dll]:
            hashed = sdbm_hash(function_name)
            xor_result = hashed ^ key

            if xor_result in known_hashes:
                index = known_hashes.index(xor_result)
                print(f"Match found: DLL = {dll}, Function = {function_name}, Hash = {hex(xor_result)}, Index = {hex(index*4)}")


# ntdll.dll
key = 0x4FD42B7F  # XOR key
hashes = [
    458489477, 0x35C735ED, 0x34684578, 0x7DA1DFAC, 1163895892, 0x7269F408, 0x2B6BABA0, 0xFCE877DB,
    1803210675, 993707440, -593074225, 944033120, 1873418899, 898596668, 1790873785, 1241943052,
    -786788150, 1934451275, 139009560, 1921783316, 1941476231, 389460348, 2081827473, 1027588416,
    -2011641112, -762108311, 75052870, -1537178410, -1684757762, 1913576543, -155672362, -1527522083,
    -447674786, -1946366817, -221653972, 2068741451, 961292448, -4861339, 39206258, 949513565,
    -1062575075, 2048943609, 1787468201, 1325010961, -574847448, 1022006994, -1795782622, 1548688093,
    -616717281, 1596678118, 1324618422, -188944261, -300135197, -692641690, -1942041556, 104211129,
    -677453388, 1603862743, -356758590, -1571226152, -1797777833, -2077087117, 1461523490, 869603369,
    1916163927, 45360603, -1800265013, -196032636, 712548902, -1085424892, -988740347, 2121955801,
    -1096198797, 1076998864, -293946160, -670389840, -566004961, 1029901497, -1138429882, -402719228,
    1297651674, 574382285, -874215270, -224305404, 1655589545, 190527887, 525270342, -860059551,
    1280403880, -1198403921, 848504654, -1169784806, -1026325238, 1946702984, -1240192928, -25894259,
    -1632988480, -1204714927, -640758677, -798286251, 2083685474, 213475553, 904616159, -1349966897,
    -1078707987, 308563850, 459140934, -717946675, 1619156657, 709962950, -2146886994, -1655157861,
    -522543157, 4504621, -99046203, 1454382011, -645399901, -1065878448, -1304906487, 1082674442,
    -933140710, -123691996, 1254341366, -2123652626, -168654795, 74772201, -15482076, -336826374,
    -1697156487, 1495830867, -129593425, -1482377084, -1173659197, -1435707616, 1754403974, 250320125,
    1469514288, -326035173, -1302319047, 1150885128, -1445702829, 1558562885, 1823698117, 74977144,
    -708268193, -548397131, -834877463, -321382476, 2135108446, 28474496, -1902781170, -1822540244,
    10010634, -704277623, -505815852, -609882758, -1378829494, 880818231, 633153409, 172490674,
    1656714030, -1560428849, -1312921605, -1968658949, 274850675, 188881594, 759348899, -1989054534,
    -508506694, -1404262227, 1840812108, 337530532, 361770297, -1972876442, 120568504, -2088072207,
    1484345686, 432001881, 131817917, 1618840602, -359127879, -691740334, -744720743, -215518776,
    -2059493069, 1863218994, -1519893002, 2117609735, 1210091598, 517009352, 1977455091, 2059624229,
    149786144, 931073839, -2053312798, 937357216, -354917298, -1790589380, 413790586, 2085566943,
    1165984169, 633181884, -19820312, 1482770548, 547145341, -160016180, -2075771673, 1643547958,
    -1736884622
]
unsigned_hashes = [ctypes.c_uint32(h).value for h in hashes]
process_json(key, unsigned_hashes, 'ntdll.dll')

# kernel32.dll
key = 0x3562DF8D
hashes = [
    0xB3073C82, 0x15C0F2, 0xC4F5CE02, 0xEDC6CA9A, 0x9B94B105, 0x71573028, 0xBEA036C8, 0x88D03EB,
    -29010397, -364289137, -420483516, 124959503, -1505462222, -1266433923, -68548242, 0x75DC0E79,
    0xE27F0276, 0xF4E440A6, 1774699001, -1117215267, 1932679075, 123795536, 1072794820, 81415418,
    -1395728827, 1243461475, -1492421158, -1951791990, 774216589, 301695247, -597111705, -1406054306,
    1703969051, 1375101692, 1592478549, 213088711, -2083142604, 588201373, 1786267235, -892986380,
    870581806, -2029504228, 1535017249, 1043780337, -1713546018, -315428384, 687409771, -1249134075,
    -528858165, -1192067796, -19823306, -1245079561, -1985206487, -2059241092, 795855510, 1278798761,
    472345565, 348878358, -1218920893, -1147330414, -1116569894, -1332532571, 1682507272, 530313423,
    -649511837, -266374314, -482487056, -1438698612, 1781262823, 1476388404, 2102354388, 1321071965,
    -1677962005, 1889951344, -1309323691, -1201075304, -1207316101, 1661683130, 1468781954, -776790354,
    1624661178, 1938357960, 1169393150, 1883435517, -1861513596, 1327229355, 1539397874, 709498602,
    1056631197, -703290799, -1281939863, -892434421, -1609230917, -812646182, 253426083, -1034264384,
    -1198089582, 1403251467, 240719490, -660472492, 1464291085, 1773013141, 774981822, 1174088725,
    376564632, 1473290953, 2056162740, 1069193765, -364288927, 129656762, 794052039, -1099996369,
    1675071102, 429380634, -560121759, 709498588, -893101231, 1970728242, 1529842321, -1607556850,
    -1112383429, -940306690, -839549738, 1203532377, 1903619376, -526917114, -255505400, 1380550582,
    -505282938
]
unsigned_hashes = [ctypes.c_uint32(h).value for h in hashes]
process_json(key, unsigned_hashes, 'kernel32.dll')
```

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/6a133ece-6125-49f9-b9e4-28d34245895d)

## String Decryption

Moving on to the string decryption routine in the function `decryption`:

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

Little whacky update to the decryptor because I didn’t wanna figure out how to use IDAPython:

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

data = [
    {
        "to_decrypt": "1108392E267B03746C665C004A6C5C4077615F47667AADD7FA8D375CAB4719A3CEE6ABB45E8B9CD50789D4DE9E33158B96E15F66000000000000000000000000",
        "key": 0x2E390803,
        "address": 0x410000
    },
    {
        "to_decrypt": "46F4D13312BB82676CD15854E7A438BCEAA00708000000000000000000000000",
        "key": 0x33D1F442,
        "address": 0x410040
    },
    {
        "to_decrypt": "D1B5671A89DC0949AAD457469AD0017BABD913BEC3BC33A93CCA86F7E9A05EBB0B2A67B32212B8550000000000000000",
        "key": 0x1A67B5DE,
        "address": 0x410060
    },
    {
        "to_decrypt": "CCF88006C79CE176DC8DAC76DD89AC72C38DAC75C395E175DBD5F36FC79CAC65DC9DE5659F91E567DF8DE82AD198EC6ADC96EE2AD098E22ADC9DE2659F9BE162D49CAC62DE98AC76C09CE32AD096EF6DDA9CF32ADA89EC6D9F9DE570DA9AE5759F9CEE67D195E52ADE8CEC729F89F269C5D5F663C194EF68C7D5E172C78BE9649F8AE36ED694E12ADA98E22AD091F568D8D5F073D195E975DBD5F074D689AC75C18FE32AC09CF3759F8BE968D490EE2ADD8AE9769F8AF473D18AAC6FDE9EAC67D79DAC7EDA98EE2AD990F42AD58BE5639F89E4609F95EF67D798EE2AD28BE97CDC97E12AC795E22AD596F265D69DAC74D68AF56AC78AAC75CA94E269DF8AAC74D689EF74C7D5E773DA9DF32AC798F36DD198F22AD091E96AD7D5E369DD9CAC61DF90F465DBD5E568C78BE963C0D5E263C78EE563DDD5E26BDFD5F575D19AE36FD7D5F37FDED5E568D29BEC63D7D5ED63C19EE52AC490EE62DC8EAC75D08BE976C78AAC74D28AF463C1D5E165C28CE974D6D5EA75DC97AC74C794AC71D295EB2AD198EE61A79A3DEE9309BA28233A8B375DBAF6F19F664D5D0F3546C100000000",
        "key": 0x680F9B3,
        "address": 0x410090
    },
    {
        "to_decrypt": "E3F98006E19CE663C19CF23C9391F472C3C3AF29968AAF23C0F48A45DC97F463DD8DAD52CA89E53C9398F076DF90E367C790EF689C81AD71C48EAD60DC8BED2BC68BEC63DD9AEF62D69D8D0CF7B7D43C93C88D0CDFAE77F4DD681B65DCD0F825083D79CEF8D205782BD1523999956C3DCAC57075000000000000000000000000",
        "key": 0x680F9B3,
        "address": 0x410260
    },
    {
        "to_decrypt": "B8F98006968CAE23C6D7A5739DDCF540919D5775A416EF0555CE5AF02B6D286DB1BB69F5000000000000000000000000",
        "key": 0x680F9B3,
        "address": 0x410230
    },
    {
        "to_decrypt": "6FF99F14029DE9751390AC264D9DF3786655397C1448A64C0000000000000000",
        "key": 0x149FF963,
        "address": 0x4107B0
    },
    {
        "to_decrypt": "68F99F141091FA780FCAAD3A0795F31039DD45A7793CAB82ED66B552605461F6AF26EE19D4C0670F3D92BF7C9FF8347120773F28D4E75B203C491B4ACC464C42D38786D4000000000000000000000000",
        "key": 0x149FF963,
        "address": 0x4102E0
    },
    {
        "to_decrypt": "68F99F14008BE66417CAAD3A0795F3B4EDE7F9245417E79FE5EC0A9B111F94AE",
        "key": 0x149FF963,
        "address": 0x410790
    },
    {
        "to_decrypt": "69F99F14168BF3790C97B1700F95CE66640349BEC010AE3C1DC175E3E5A75D214298FF7C30171505DD4102DD6D0B4931",
        "key": 0x149FF963,
        "address": 0x410900
    },
    {
        "to_decrypt": "68F99F14168AFA660697E93A0795F3C16A9AC3BF8BCECC506AA3C7C7EE8F7948B8DEF37AD7E610FFCBA454D3447980B39DB56ECC0EB412E896EAA0A500000000",
        "key": 0x149FF963,
        "address": 0x410350
    },
    {
        "to_decrypt": "68F99F141490F17D0D9CEB3A0795F3EAB53FC334391844CC56243BF900000000",
        "key": 0x149FF963,
        "address": 0x4108E0
    },
    {
        "to_decrypt": "6FF99F14148DEC751390AC264D9DF3789EA51C47702CD417319A15CD72E2B410B724F0524029417B",
        "key": 0x149FF963,
        "address": 0x410810
    },
    {
        "to_decrypt": "69F99F142495F0760295C35D46A1D1F51B93038BAF8D065186B4C614D25DD5B3DA74B1495D2E3AD1BE71D35600000000",
        "key": 0x149FF963,
        "address": 0x4108B0
    },
    {
        "to_decrypt": "69F99F142495F0760295C35946A12C035F2C1998E68C336EEFC4295B11CD1C44",
        "key": 0x149FF963,
        "address": 0x410330
    },
    {
        "to_decrypt": "69F99F142495F0760295C35146A126333C42E80C89D17D6A0D43E92FAE7B020CCFBA05A165F301F1316F0BCA8C5AB1C7BAFB1530FF42035E0000000000000000",
        "key": 0x149FF963,
        "address": 0x4107D0
    },
    {
        "to_decrypt": "67F99F144ED4BA6C4259000106BBA3843232F76172BEE0F80000000000000000",
        "key": 0x149FF963,
        "address": 0x410930
    },
    {
        "to_decrypt": "FCE6773FDC952B1A8A14AC5562696E56A8BAE87787F2AD6DEF0CF85A00FC5F212E42EBB972B84DB429B69FF5BF38719BD596785AB32B1D68637CDCEEF8A77F692B6E3E01000000000000000000000000",
        "key": 0x3F77E6F9,
        "address": 0x410D50
    },
    {
        "to_decrypt": "FCE6773FDC952B1A8A14AC5562696E56A8BAE87787F2AD6DEF0CF85A00FC5F212E42EBB972B84DB429B69FF5BF38719BD596785AB32B1D68637CDCEEF8A77F692B6E3E01000000000000000000000000",
        "key": 0x3F77E6F9,
        "address": 0x410D50
    },
    {
        "to_decrypt": "8FE7773F8D830552D5911E4B91CA0750958A124DD58F195B9087195ED5951F5E9D8305138A921E139D8A104CD58B124B9C94125BD587044F8D8A15139A89195298885B4F95871E51D5911F5695835B5C898A5B5C8B870457D592125E898903139D8301569A835B5E9D871A139B87034B9C940E138D94184A9B8A12139A871457908810139187195BD58E1B59D58E124D96CA04529ACA055A988216519DCA144F95955B519C9200508B8D5B5A97811913948B141395851B1389821F139A8A00138F8F044B98CA14539083194BD59616568B955B598A8F5B529C821E4A94CA075B9C8003139288184897CA055A98851F138F83054BD58418508A925B4C97825B598E8D5B5D8C8F1B5B9C945B5698845B528A851A4CD595044FD585165D95835B5A8D915B5E97811B5AD589055B9C94125BD595145E958705138A8919588ACA144B97925B4C9C94015A8BCA14579088124C9CCA1A5A9D8F16139C8813569FCA044A89965B4C9C9203579CCA1A568A855B5B9087104D988B5B4A8B821D22225571DF65F6D3844314065F6CBD0D153A29D83C34A9A6B96200D6E93CCBB0D4132A9C0A",
        "key": 0x3F77E6F9,
        "address": 0x410BB0
    },
    {
        "to_decrypt": "F0E6773FDC952B1A8AC812479C212E712D0F56BEC61D932FACD9BE95B0DEB828EA8AE265000000000000000000000000",
        "key": 0x3F77E6F9,
        "address": 0x410B30
    },
    {
        "to_decrypt": "8AE7773F958719588ACA154A9F80124DD593045A8BCA044F96891B5A8BCA03539BCA155E9A8D5B4D8C955B5D8B89004C9C945B508B815B5995815B4F8A8314139A9F1651D583054DD5851F5E89965B5B948F5B55968F19138A92164D8D8313139A8703138B83045A8DCA13528B855B4C9A8719139B871958D5941E4F898A12138987105AD58F1D4F97CA145E9B8F195A8DCA135E8A8B055CD58B1052D584185B80CA045B9D8A5B53909503509FCA0E508B8D5B529684044697855B529682124D97CA1356988A1858D5901653D58F125395CA05508E95124BD58E124798CA12519E8A1E4C91CA144D908B045097CA00508ECA0346898315139B94184897CA115396915B4F989403519C945B4F9085034A8B835B4C909C12139694135A8B8313139A8E0251928305138A8E18508D8305139088015092835B56978F03139B930413898A16138A8701139096044F8ACA135D948A5B5D8C8F1B5B9C945B4C9283035C91CA144A9B835B4C8C965B539687135ED5841E519D83055B107D13597DDE5FCFDE12F8D88D1DD15929A3700500000000",
        "key": 0x3F77E6F9,
        "address": 0x410970
    },
    {
        "to_decrypt": "FCE6773FDC952B1A8A14AC5562696E56A8BAE87787F2AD6DEF0CF85A00FC5F212E42EBB972B84DB429B69FF5BF38719BD596785AB32B1D68637CDCEEF8A77F692B6E3E01000000000000000000000000",
        "key": 0x3F77E6F9,
        "address": 0x410D50
    },
    {
        "to_decrypt": "F0E6773FDC952B1A8AC812479C212E712D0F56BEC61D932FACD9BE95B0DEB828EA8AE265000000000000000000000000",
        "key": 0x3F77E6F9,
        "address": 0x410B30
    },
    {
        "to_decrypt": "FDE6773FDBC3041DA633A102A2123376008DFF8EB3EB552751A97DBE00000000",
        "key": 0x3F77E6F9,
        "address": 0x410950
    },
    {
        "to_decrypt": "D4E6773FAAA9316BAEA7257AA5AB1E5C8B8904509F922B68908813508E952B7C8C94055A9792215A8B951E5097BA254A978B15A3614A057CDCC6554A684D91EFC0FA2D890FAC0D696557635B00000000",
        "key": 0x3F77E6F9,
        "address": 0x410B60
    },
    {
        "to_decrypt": "58A2ED707E879E52035EF85619683824C0C3FBAFD3A0AB0D248B4BEC7AAE784D",
        "key": 0x70EDA25C,
        "address": 0x410DD0
    },
]

for entry in data:
    result = decrypt(entry['to_decrypt'], entry['key'])
    print(f"Address {entry['address']:08X}: {result.decode('utf-8', errors='ignore')}")
```

Decrypted strings:

```
C:\Users\lulwt\Downloads>python emotet_stringdecrypt.py
Address 00410000: %s:Zone.Identifier
Address 00410040: POST.%g
Address 00410060: WinSta0\Default
Address 00410090: teapot,pnp,tpt,splash,site,codec,health,balloon,cab,odbc,badge,dma,psec,cookies,iplk,devices,enable,mult,prov,vermont,attrib,schema,iab,chunk,publish,prep,srvc,sess,ringin,nsip,stubs,img,add,xian,jit,free,pdf,loadan,arizona,tlb,forced,results,symbols,report,guids,taskbar,child,cone,glitch,entries,between,bml,usbccid,sym,enabled,merge,window,scripts,raster,acquire,json,rtm,walk,bang                                                                                                                                                                                                                                                                                                                                                            
Address 00410260: Referer: http://%s/%s
Content-Type: application/x-www-form-urlencoded
DNT: 1
lW
Address 00410230: %u.%u.%u.%uF
Address 004107B0: advapi32.dll♣h
Address 004102E0: shell32.dll♦
Address 00410790: crypt32.dll
Address 00410900: urlmon.dllQr
Address 00410350: userenv.dll
Address 004108E0: wininet.dll
Address 00410810: wtsapi32.dll\S
Address 004108B0: Global\I%XN
Address 00410330: Global\M%X↨
Address 004107D0: Global\E%X'
Address 00410930: --%x!§
Address 00410D50: %s\%sj
Address 00410D50: %s\%sj
Address 00410BB0: term,with,poller,indiana,shader,sti,dlgs,metered,asptlb,conman,plain,while,cpl,crash,teapot,device,adam,battery,trouble,caching,hand,hlf,hero,smc,readand,cpls,network,engn,mmc,lcl,pdh,clw,vista,client,pairs,fsi,medium,pdeft,known,reach,vert,boost,snd,fwk,builder,iab,mscms,ssp,cable,etw,angle,ordered,scalar,songs,ctnt,server,chinese,media,endif,supp,setthe,misc,diagram,urdj↔                                                                                                                                                                                                                                                                                                                                                                    
Address 00410B30: %s\%s.exeYN
Address 00410970: langs,buffer,user,spooler,tlb,back,rus,browser,org,flg,psec,cyan,err,chapp,dmi,join,started,cat,reset,dmrc,scan,bang,ripple,page,ijpn,cabinet,dasmrc,mgm,body,sddl,listof,york,mobsync,modern,dialog,val,iell,rowset,hexa,english,crimson,wow,typeb,brown,flow,partner,picture,size,ordered,chunker,shooter,invoke,init,bus,pla,sav,ipsps,dbml,builder,sketch,cube,sup,loada,binderd                                                                                                                                                                                                                                                                                                                                                                        
Address 00410D50: %s\%sj
Address 00410B30: %s\%s.exeYN
Address 00410950: "%s"_=
Address 00410B60: SOFTWARE\Microsoft\Windows\CurrentVersion\Runmb
Address 00410DD0: "%s"_§&
```

And we can see a list of additional DLLs that will be loaded: advapi32.dll, shell32.dll, crypt32.dll, urlmon.dll, userenv.dll, wininet.dll, wtsapi32.dll. HTTP header stuff and registry keys. Some interesting wordlists where strings at `0x00410BB0` are used for file name generation (unique per machine based on the lpVolumeSerialNumber value) and strings at `0x410090` are used for C2 URI path generation. 

In my case, the Emotet binary was copied into the %APPDATA% directory into `knownpoller/knownpoller.exe` and executed. 

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/992b0369-72de-4f4b-a838-5b32995c77fb)

And an example of contacting the C2 server looking at the arguments to `sub_40140A`, one of the server has an IP `187.188.166.192` and the host used a path `site/ringin/attrib`.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/6ea48834-7c85-4115-8e07-45afd4944449)

Anyways, just a quick guide on how to deobfuscate Emotet. Here's a [link](https://www.virusbulletin.com/uploads/pdf/magazine/2019/VB2019-Nagy.pdf) to an article for more in depth analysis on this specific variant! 
