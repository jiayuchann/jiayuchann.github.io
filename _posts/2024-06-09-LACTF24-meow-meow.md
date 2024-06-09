## LACTF 2024 meow meow

Reverse engineering! yay

I did this challenge a few months back but thought to just document it.

Description: When I was running my cyber lab, I asked if anyone doesn't like cats, and no one raised their hard, so it is FINAL, CATS >> DOGS!!!!! As a test, you need to find the cat in the sea of dogs in order to get the flag.

There are 7 data files and an ELF binary. I just opened up the binary in IDA.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/11b0f4ce-3f2b-4700-9403-495bea50f3ca)

In main, it first prompts us for an input, and then checks whether our input length is a multiple of 5, exit otherwise.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/70062db9-dcbd-4006-b609-91b704c54b01)

Once we pass the check, each byte of our input is passed into `sub_1225`.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/d0e166b4-2c53-42e6-bea8-79bc6b2dc57b)

Looking at `sub_1225`, it first checks if the character is a lowercase, if not, convert it from uppercase to lowercase. It also maps the ‘_’, ‘{’, and ‘}’ symbols to 0x1A, 0x1B and 0x1C respectively.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/34e8cd98-6a3e-405b-99bc-d89ff55423bf)

Here, `__ctype_b_loc()` contains character classification data used by the `ctype.h` functions. The array contains integers, each corresponding to a different character of the unsigned char type. Each integer's bits represent different character properties. `(*__ctype_b_loc())` dereferences this pointer to give us the actual array. `[a1]`then accesses the array at the position `a1`, which is our character. This returns the classification data (an integer) for the character.
The & 0x200 operation is related to the character classification function `islower`. A table for the flag to function mapping is shown below.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/b9684b61-af5a-4360-83a0-37a104f2d83c)

Here, we have a loop which pretty much just checks whether all files `data0` to `data7` are present and accessible. If they are the program then runs several threads on a function I renamed as `interesting_function`, with our input in index form as the argument `v34`, where I created a struct for it.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/22536133-04f5-428c-afb7-10067ec3d9b5)

Here's what the struct looks like:

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/42caeb0f-a7ca-4f16-9d4b-11712770f6b4)

In the main section of `interesting_function`, there is a do while loop, which loops through all 7 data files. 

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/a9f8398c-87c1-41a1-a70d-9f85490b1a03)

For each data file, the thread first seeks to the beginning of the file `0x74 * v15`(v15 is 0 before the loop), and reads 0x74 bytes from that location, storing it in `buf`. `v12` is calculated through `v12 = input->input_index[5 * file_counter + i];`, and then used as an index within `buf` to get the value of `v15` for the next loop. Remember that `v15`is used for the offset within the file. This continues 5 times in total, then the final value of `v15` is checked against `\x00tac`(cat in reverse because little-endian).  If it matches, we get the first 5 characters of the flag. Because the inner for loop runs 5 times and counter `i` is used for indexing our transformed user input (user input translated into index within the defined charset in `sub_1225`).

The outer do-while loop continues looping through the other data files sequentially. 

We can pretty much reconstruct the logic here in a solver script, and brute force for the flag 5 characters at a time for each data file, with the winning condition being we reached the offset containing `\x00tac` at the end, and then concatenate them to form the full flag.

Below is my solver script:

```python
import itertools
import os
import struct

charset = 'abcdefghijklmnopqrstuvwxyz{}_'

# Target value to check against "\x00tac"
final_target = 0x63617400

def get_offset_for_combination(fd, combo):
    offset = 0
    for character in combo:
        input_index = (ord(character) - 0x61)*4
        os.lseek(fd, offset * 0x74, 0)
        buf = os.read(fd, 0x74)
        offset = struct.unpack('<I', buf[input_index:input_index+4])[0]
    ret = struct.unpack('<I', buf[input_index:input_index+4])[0]
    return ret

num = 1
while(1):
    file_path = 'data' + str(num)
    fd = os.open(file_path, os.O_RDONLY)
    num += 1
    for combo in itertools.product(charset, repeat=5):
        target = get_offset_for_combination(fd, combo)
        if target == final_target:
            print("Matching combination found:", ''.join(combo))
            break

os.close(fd)
```

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/32f05f79-ac2b-4b51-8bf7-bf0d65c2aea7)

Well, seems like the flag order is not based on file numbering, but we can still construct it nonetheless.

`lactf{meow_you_found_me_epcsihnxos}`
