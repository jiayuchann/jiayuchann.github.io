## Stealc Overview

##### [String Decryption](#string-decryption-1)
##### [Dynamic Import Resolution](#dynamic-import-resolution-1)
##### [Event Creation](#event-creation-1)
##### [Pseudorandom Name Generation](#pseudorandom-name-generation-1)
##### [C2 Communication and Data Exfiltration](#c2-communication-and-data-exfiltration-1)
##### [Cleanup](#cleanup-1)
##### [Bypass C2 blockage](#bypass-c2-blockage)
##### [Anti VM and Second Domain](#anti-vm-and-second-domain)

Another info stealer 🤔. Let’s see what’s up.

![image](https://github.com/user-attachments/assets/8498aabc-0f43-44aa-9782-f3e489f0e3ca)

MalwareBazaar categorizes this sample as Vidar, but it's more accurately Stealc, which derives from Vidar Stealer. This version appears either poorly written or potentially a low-effort modification of an older version, having some hardcoded configuration strings and easily extractable C2 IP addresses.

![image](https://github.com/user-attachments/assets/65827169-b8af-4809-9a10-94c6377143ee)

The sample was packed with UPX, so we can easily unpack it with UPX itself and open the unpacked file in IDA.

## String Decryption

String decryption is a simple XOR decrypt by calling the function I named `decrypt` and passing in as arguments: the encrypted blob, an XOR key, and the length of the key. 

![image](https://github.com/user-attachments/assets/4650d7a4-2611-4d60-9c63-d925031b8a7c)

I developed an IDAPython script to automate the decryption of data chunks, adding decrypted content directly into IDA's disassembly and pseudocode views for ease of analysis. The script identifies calls to the decrypt function, extracts arguments, and replaces them with their decrypted counterparts.

```python
import idaapi
import idautils
import idc

def set_hexrays_comment(address,text):
    # breakpoint()
    print("Setting hex rays comment")
    # breakpoint()
    cfunc = idaapi.decompile(address + 8)
    tl = idaapi.treeloc_t()
    tl.ea = address + 8
    tl.itp = idaapi.ITP_SEMI

    if cfunc:
      cfunc.set_user_cmt(tl, text)
      cfunc.save_user_cmts()
    else:
      print("Decompile failed: {:#x}".format(address))

def decrypt(addr, xor_key, length):
    decrypted = []
    xor_key_bytes = bytes(xor_key, 'utf-8')  # Convert xor_key to bytes
    for i in range(length):
        decrypted_byte = idc.get_wide_byte(addr + i) ^ xor_key_bytes[i % len(xor_key_bytes)]
        decrypted.append(decrypted_byte)
    return bytes(decrypted).decode('utf-8', errors='ignore')

# Get all references to decrypt() and extract arguments
def find_decrypt_calls(decrypt_func_ea):
    calls = []
    for ref in idautils.CodeRefsTo(decrypt_func_ea, 0):
        # Go back to the previous instructions to find the arguments pushed onto the stack
        address_insn = idc.prev_head(ref)
        xor_key_insn = idc.prev_head(address_insn)
        length_insn = idc.prev_head(xor_key_insn)
        
        addr = idc.get_operand_value(address_insn, 0)
        xor_key_addr = idc.get_operand_value(xor_key_insn, 0)
        length = idc.get_operand_value(length_insn, 0)
        
        xor_key_str = idc.get_strlit_contents(xor_key_addr, -1, idc.STRTYPE_C).decode('utf-8')
        if addr and xor_key_str and length:
            calls.append((addr, xor_key_str, length, ref))
    return calls

# Find address of the decrypt function
decrypt_func_name = 'decrypt'
decrypt_func_ea = idc.get_name_ea_simple(decrypt_func_name)

if decrypt_func_ea != idc.BADADDR:
    calls = find_decrypt_calls(decrypt_func_ea)
    for addr, xor_key_str, length, call_ea in calls:
        # print(addr, xor_key_str, length)
        decrypted = decrypt(addr, xor_key_str, length)
        print(f"Address: {hex(addr)}, XOR Key: {xor_key_str}, Length: {length}")
        print(f"Decrypted Data: {decrypted}")
        
        idc.set_cmt(call_ea, decrypted, 1)
        set_hexrays_comment(call_ea, decrypted)
```

Here’s what it looks like after running the script:

![image](https://github.com/user-attachments/assets/c56576a4-e8d2-4256-a436-a19e8eb78764)

## Dynamic Import Resolution

After retrieving the base address of kernel32.dll by walking the PEB, it does some API resolution.

![image](https://github.com/user-attachments/assets/b1a4b5a6-9e70-473a-972c-33ebde2c78f0)

Then it loads additional libraries and resolves APIs for them as well.

![image](https://github.com/user-attachments/assets/06d7a57c-3ecc-4c5b-b49f-4bc1af2acf98)

## Event Creation

Stealc queries for the username of the currently running thread, prepends the name with `JohnDoe_`, and creates an event using the concatenated name. 

![image](https://github.com/user-attachments/assets/d0974b0c-6d17-4267-b403-6b6a40bc3eb8)

## Pseudorandom Name Generation

Based on the current system time, it generates random letters/numbers and uses them to create unique directories and file names.

![image](https://github.com/user-attachments/assets/19a8aff7-640c-46ac-afe1-071a008b6693)

## C2 Communication and Data Exfiltration

The C2 IP address is grabbed and parsed from the username of a Steam profile. The current username reflects the most recent IP.

![image](https://github.com/user-attachments/assets/00cd8f14-4bda-42dd-a2f6-08f34508d6ed)

![image](https://github.com/user-attachments/assets/7fc05eba-604e-4f9a-8f85-fc8eeecb409b)

C2 beaconing: HTTP Headers when sending a POST request to `hxxp://65[.]109[.]241[.]221` contains the `hwid` which is the concatenation of the system’s VolumeSerialNumber and hardware profile GUID. Alongside a `build_id` value to represent the malware build identifier.

![image](https://github.com/user-attachments/assets/e4465d67-5fb8-4d5c-956a-223fcb81a5cc)

Example of the initial C2 response, which includes a token to be used for all communications. 

![image](https://github.com/user-attachments/assets/623196c6-444b-40c1-94c5-4c21b6124c3c)

The first field of the response is also checked against the word “block”, if it matches, the process exits immediately.

![image](https://github.com/user-attachments/assets/b4bb2aad-9d9e-4391-85db-2d5dd165afe5)

It then attempts to retrieve the configuration for targeting files that match a specific pattern. Depending on the `mode` value set in the form of the request, the C2 responds with base64-encoded configurations targeting specific data. When `mode` is 1, the C2 responds with a base64-encoded configuration for browsers:

![image](https://github.com/user-attachments/assets/d02faa54-dc8a-4506-9d09-9ee684e50d74)

![image](https://github.com/user-attachments/assets/6c73c475-b74f-4a18-8d63-fa256a762aed)

![image](https://github.com/user-attachments/assets/d240c856-4a37-41a4-b9dc-f53b193b20ca)

For `mode` 2 and 21, the C2 responds with a base64-encoded configuration for browser extensions (mostly Crypto wallets):

![image](https://github.com/user-attachments/assets/a464ad68-5c81-47b9-94fd-2c394e7e28ce)

Some legitimate DLLs are also downloaded and dropped into `C:\ProgramData\`, used to extract different data formats conveniently. First, `sqlite3.dll` (named sqlt.dll on the C2 endpoint: hxxp://65[.]109[.]241[.]221/sqlt.dll) is downloaded, then `freebl3.dll`, `mozglue.dll`, `msvcp140.dll`, `softokn3.dll`, `vcruntime140.dll`, and `nss3.dll`.

![image](https://github.com/user-attachments/assets/331e5559-b0bb-47d9-9ad8-5e3babc46f98)

Stealc also fingerprints the system by sending to the C2 server: 

  •	HWID, GUID, MachineID
  •	Path of the executable
  •	Windows version
  •	Computer name
  •	Username
  •	Antivirus products installed
  •	Display resolution
  •	Keyboard languages
  •	Timezone
  •	Hardware info (Processor information, Available cores, threads, and RAM)
  •	Running processes
  •	Installed software and their versions.

![image](https://github.com/user-attachments/assets/3294c1b6-6de5-4a53-aa9c-31a07c5e347e)

Some artifacts are stored in `C:\ProgramData\<random_string>\` before being read and sent to the C2 server as base64 encoded data. For example, here my Chrome data is stored in a sqlite3 format:

![image](https://github.com/user-attachments/assets/52106460-e944-48ab-8906-f97065b46cca)

While other file data were being sent directly through a POST request after contents were read, with a few forms:

  •	token (for session tracking)
  •	build_id (malware build)
  •	file_name (base64-encoded relative path to stolen file)
  •	file_data (base64-encoded file content)

In this case, the file name is `Cookies\Google Chrome\Default.txt`:

![image](https://github.com/user-attachments/assets/8665e94b-2b9e-4658-b55f-7cc86a7ec3e8)

## Cleanup

In many other Stealc variants, it cleans up the `C:\ProgramData\` directory by removing any downloaded DLLs and temporary data files such as SQLite3 files. 

![image](https://github.com/user-attachments/assets/b330adc6-195b-47c7-9c32-307cf3fa2c8f)

However, this code was never invoked in my sample. This Stealc instance did not clean up after itself, leaving behind artifacts and downloaded DLLs in `C:\ProgramData\`. The malware terminates abruptly post-data exfiltration, driven by specific C2 commands. However, this behavior can be manipulated by patching some instructions to bypass the termination process.

![image](https://github.com/user-attachments/assets/03a7d453-4a28-4967-945c-48fc82df6686)

## Bypass C2 blockage

To bypass the `ExitProcess` and continue with the rest of the program, we can patch `jnz short loc_4057B3` to `jmp short loc_4057B3` in `sub_404E03`.

![image](https://github.com/user-attachments/assets/2d8fab51-688c-45ce-8eb5-2c46db46d3af)

![image](https://github.com/user-attachments/assets/4693c0b9-96bf-460c-9538-1a23187901d8)

## Anti VM and Second Domain

There are 2 calls to an anti-VM check using `cpuid` with `eax` set to 1 before calling it. The call returns a 31-byte response, and the last byte would be 0 if running on a physical machine, otherwise, 1 if running on a VM.

![image](https://github.com/user-attachments/assets/57f5b68b-624a-4ff9-8e39-1d893518dcbd)

To bypass this check, we can just flip the return value from the call `sub_40101E`.

If the malware was not executed in a VM, a PKZIP file (with base64 encoded name `_DEBUG.zip`) consisting of exfiltrated files will be sent to a secondary domain `hxxp://tea[.]arpdabl[.].org`. 

![image](https://github.com/user-attachments/assets/d7158b34-7214-4704-a337-65361e34c184)

In my run, for example, it consisted of the following files:

  •	Autofill/Google Chrome_Default.txt
  •	Autofill/Mozilla Firefox_tz3k441j.default-release.txt
  •	Cookies/Google Chrome_Default.txt
  •	Cookies/Microsoft Edge_Default.txt
  •	Cookies/Mozilla Firefox_tz3k441j.default-release.txt
  •	Downloads/Google Chrome_Default.txt
  •	History/Microsoft Edge_Default.txt
  •	History/Mozilla Firefox_ tz3k441j.default-release.txt
  •	Soft/Steam/steam_tokens.txt
  •	Information.txt (System fingerprint)

Also depending on the config, Discord, Telegram, Outlook, Tox, or other data may be exfiltrated.
