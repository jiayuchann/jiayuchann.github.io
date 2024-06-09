##HTB Cyber Apocalypse CTF 2024 – Metagaming (Z3 tutorial)

This is a hard VM challenge, but instead of manually reversing the math operations, I used Z3, a really powerful theorem prover by Microsoft for symbolic execution!

main.cpp was provided, and in `main`, we see a `program_t` template instantiated with `flag` being the first parameter (that we have to figure out 40 bytes for) and a bunch of `insn_t` type instances following. 

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/8dc5637f-af9f-4308-8733-829dfd5d92e6)

We can confirm that the `insn_t` type represents an instruction, and takes 3 integers as parameters, an opcode and 2 operands.

```
struct insn_t {
    uint32_t opcode = 0;
    uint32_t op0 = 0;
    uint32_t op1 = 0;
};
```

Under the `program_t` struct, this is where the operations are defined:

```
template<insn_t Insn>
static constexpr void execute_one(R &regs) {
    if constexpr (Insn.opcode == 0) {
        regs[Insn.op0] = Flag.at(Insn.op1);
    } else if constexpr (Insn.opcode == 1) {
        regs[Insn.op0] = Insn.op1;
    } else if constexpr (Insn.opcode == 2) {
        regs[Insn.op0] ^= Insn.op1;
    } else if constexpr (Insn.opcode == 3) {
        regs[Insn.op0] ^= regs[Insn.op1];
    } else if constexpr (Insn.opcode == 4) {
        regs[Insn.op0] |= Insn.op1;
    } else if constexpr (Insn.opcode == 5) {
        regs[Insn.op0] |= regs[Insn.op1];
    } else if constexpr (Insn.opcode == 6) {
        regs[Insn.op0] &= Insn.op1;
    } else if constexpr (Insn.opcode == 7) {
        regs[Insn.op0] &= regs[Insn.op1];
    } else if constexpr (Insn.opcode == 8) {
        regs[Insn.op0] += Insn.op1;
    } else if constexpr (Insn.opcode == 9) {
        regs[Insn.op0] += regs[Insn.op1];
    } else if constexpr (Insn.opcode == 10) {
        regs[Insn.op0] -= Insn.op1;
    } else if constexpr (Insn.opcode == 11) {
        regs[Insn.op0] -= regs[Insn.op1];
    } else if constexpr (Insn.opcode == 12) {
        regs[Insn.op0] *= Insn.op1;
    } else if constexpr (Insn.opcode == 13) {
        regs[Insn.op0] *= regs[Insn.op1];
    } else if constexpr (Insn.opcode == 14) {
        __noop;
    } else if constexpr (Insn.opcode == 15) {
        __noop;
        __noop;
    } else if constexpr (Insn.opcode == 16) {
        regs[Insn.op0] = rotr(regs[Insn.op0], Insn.op1);
    } else if constexpr (Insn.opcode == 17) {
        regs[Insn.op0] = rotr(regs[Insn.op0], regs[Insn.op1]);
    } else if constexpr (Insn.opcode == 18) {
        regs[Insn.op0] = rotl(regs[Insn.op0], Insn.op1);
    } else if constexpr (Insn.opcode == 19) {
        regs[Insn.op0] = rotl(regs[Insn.op0], regs[Insn.op1]);
    } else if constexpr (Insn.opcode == 20) {
        regs[Insn.op0] = regs[Insn.op1];
    } else if constexpr (Insn.opcode == 21) {
        regs[Insn.op0] = 0;
    } else if constexpr (Insn.opcode == 22) {
        regs[Insn.op0] >>= Insn.op1;
    } else if constexpr (Insn.opcode == 23) {
        regs[Insn.op0] >>= regs[Insn.op1];
    } else if constexpr (Insn.opcode == 24) {
        regs[Insn.op0] <<= Insn.op1;
    } else if constexpr (Insn.opcode == 25) {
        regs[Insn.op0] <<= regs[Insn.op1];
    } else {
        static_assert(always_false_insn_v<Insn>);
    }
}
```

There are 15 registers in total. Towards the end of the main function, there is a check on each registers’ state such that when `program` finishes running with the correct flag, all registers should reflect those values. In other words, if all registers reflect those values given our input, our input must be the flag.

```
static_assert(program::registers[0] == 0x3ee88722 && program::registers[1] == 0xecbdbe2 && program::registers[2] == 0x60b843c4 && program::registers[3] == 0x5da67c7 && program::registers[4] == 0x171ef1e9 && program::registers[5] == 0x52d5b3f7 && program::registers[6] == 0x3ae718c0 && program::registers[7] == 0x8b4aacc2 && program::registers[8] == 0xe5cf78dd && program::registers[9] == 0x4a848edf && program::registers[10] == 0x8f && program::registers[11] == 0x4180000 && program::registers[12] == 0x0 && program::registers[13] == 0xd && program::registers[14] == 0x0, "Ah! Your flag is invalid.");
```

Technically we can work backwards from the last instruction and the final register states, but this might only work for reversible operations like XOR, ADD, ROTL, etc. and not lossy operations like AND, OR. To reverse XOR, we can do another XOR. To reverse ADD, the inverse is subtracting. To reverse ROTL, we can do ROTR. 

But, if you’re using symbolic execution tools, you don’t have to worry about this. 

```
from z3 import *

s = Solver()

Flag = [BitVec(f'Flag_{i}', 8) for i in range(40)]

regs = [BitVec(f'regs_{i}', 32) for i in range(15)]

def rotr(x, n, width=32):
    return (x >> n) | (x << (width - n))

def rotl(x, n, width=32):
    return (x << n) | (x >> (width - n))

def apply_instruction(opcode, op0, op1):
    if opcode == 0:
        regs[op0] = ZeroExt(24, Flag[op1])
    elif opcode == 1:
        regs[op0] = BitVecVal(op1, 32)
    elif opcode == 2:
        regs[op0] ^= BitVecVal(op1, 32)
    elif opcode == 3:
        regs[op0] ^= regs[op1]
    elif opcode == 4:
        regs[op0] |= BitVecVal(op1, 32)
    elif opcode == 5:
        regs[op0] |= regs[op1]
    elif opcode == 6:
        regs[op0] &= BitVecVal(op1, 32)
    elif opcode == 7:
        regs[op0] &= regs[op1]
    elif opcode == 8:
        regs[op0] += BitVecVal(op1, 32)
    elif opcode == 9:
        regs[op0] += regs[op1]
    elif opcode == 10:
        regs[op0] -= BitVecVal(op1, 32)
    elif opcode == 11:
        regs[op0] -= regs[op1]
    elif opcode == 12:
        regs[op0] *= BitVecVal(op1, 32)
    elif opcode == 13:
        regs[op0] *= regs[op1]
    elif opcode == 14 or opcode == 15:
        # __noop; Do nothing
        pass
    elif opcode == 16:
        regs[op0] = rotr(regs[op0], op1)
    elif opcode == 17:
        regs[op0] = rotr(regs[op0], regs[op1])
    elif opcode == 18:
        regs[op0] = rotl(regs[op0], op1)
    elif opcode == 19:
        regs[op0] = rotl(regs[op0], regs[op1])
    elif opcode == 20:
        regs[op0] = regs[op1]
    elif opcode == 21:
        regs[op0] = BitVecVal(0, 32)
    elif opcode == 22:
        regs[op0] >>= BitVecVal(op1, 32)
    elif opcode == 23:
        regs[op0] >>= regs[op1]
    elif opcode == 24:
        regs[op0] <<= BitVecVal(op1, 32)
    elif opcode == 25:
        regs[op0] <<= regs[op1]

# List of instructions
instructions = [
    (12, 13, 10), (21, 0, 0), (0, 13, 13), (0, 14, 0), (15, 11, 12), (24, 14, 0), (5, 0, 14), (0, 14, 1), (7, 11, 11), (24, 14, 8), (5, 0, 14), (0, 14, 2), (2, 10, 11), (24, 14, 16), (18, 12, 11), (5, 0, 14), (0, 14, 3), (0, 11, 11), (24, 14, 24), (13, 10, 10), (5, 0, 14), (2, 11, 13), (21, 1, 0), (0, 14, 4), (24, 14, 0), (5, 1, 14), (6, 11, 12), (0, 14, 5), (8, 10, 10), (24, 14, 8), (11, 12, 11), (5, 1, 14), (0, 14, 6), (0, 12, 10), (24, 14, 16), (9, 10, 13), (5, 1, 14), (0, 14, 7), (13, 12, 12), (24, 14, 24), (15, 10, 12), (5, 1, 14), (21, 2, 0), (20, 13, 13), (0, 14, 8), (24, 14, 0), (19, 10, 11), (5, 2, 14), (6, 12, 10), (0, 14, 9), (8, 11, 11), (24, 14, 8), (5, 2, 14), (0, 14, 10), (4, 11, 12), (24, 14, 16), (5, 2, 14), (0, 14, 11), (24, 14, 24), (4, 13, 12), (5, 2, 14), (21, 3, 0), (14, 10, 12), (0, 14, 12), (13, 10, 11), (24, 14, 0), (16, 10, 10), (5, 3, 14), (5, 11, 12), (0, 14, 13), (12, 10, 13), (24, 14, 8), (2, 10, 13), (5, 3, 14), (20, 11, 11), (0, 14, 14), (24, 14, 16), (18, 13, 11), (5, 3, 14), (6, 11, 13), (0, 14, 15), (24, 14, 24), (4, 11, 10), (5, 3, 14), (21, 4, 0), (15, 13, 11), (0, 14, 16), (6, 10, 10), (24, 14, 0), (14, 10, 12), (5, 4, 14), (0, 14, 17), (12, 13, 13), (24, 14, 8), (19, 11, 10), (5, 4, 14), (0, 14, 18), (17, 13, 12), (24, 14, 16), (5, 4, 14), (0, 14, 19), (24, 14, 24), (21, 12, 10), (5, 4, 14), (13, 13, 10), (21, 5, 0), (0, 14, 20), (19, 10, 13), (24, 14, 0), (5, 5, 14), (0, 14, 21), (24, 14, 8), (8, 13, 13), (5, 5, 14), (0, 14, 22), (16, 13, 11), (24, 14, 16), (10, 10, 13), (5, 5, 14), (7, 10, 12), (0, 14, 23), (19, 13, 10), (24, 14, 24), (5, 5, 14), (17, 12, 10), (21, 6, 0), (16, 11, 10), (0, 14, 24), (24, 14, 0), (10, 11, 10), (5, 6, 14), (0, 14, 25), (24, 14, 8), (7, 10, 12), (5, 6, 14), (0, 14, 26), (16, 12, 11), (24, 14, 16), (3, 11, 10), (5, 6, 14), (15, 11, 13), (0, 14, 27), (4, 12, 13), (24, 14, 24), (5, 6, 14), (14, 11, 13), (21, 7, 0), (0, 14, 28), (21, 13, 11), (24, 14, 0), (7, 12, 11), (5, 7, 14), (17, 11, 10), (0, 14, 29), (24, 14, 8), (5, 7, 14), (0, 14, 30), (12, 10, 10), (24, 14, 16), (5, 7, 14), (0, 14, 31), (20, 10, 10), (24, 14, 24), (5, 7, 14), (21, 8, 0), (18, 10, 12), (0, 14, 32), (9, 11, 11), (24, 14, 0), (21, 12, 11), (5, 8, 14), (0, 14, 33), (24, 14, 8), (19, 10, 13), (5, 8, 14), (8, 12, 13), (0, 14, 34), (24, 14, 16), (5, 8, 14), (8, 10, 10), (0, 14, 35), (24, 14, 24), (21, 13, 10), (5, 8, 14), (0, 12, 10), (21, 9, 0), (0, 14, 36), (24, 14, 0), (5, 9, 14), (17, 11, 11), (0, 14, 37), (14, 10, 13), (24, 14, 8), (5, 9, 14), (4, 10, 11), (0, 14, 38), (13, 11, 13), (24, 14, 16), (5, 9, 14), (0, 14, 39), (10, 11, 10), (24, 14, 24), (20, 13, 13), (5, 9, 14), (6, 12, 11), (21, 14, 0), (8, 0, 2769503260), (10, 0, 997841014), (19, 12, 11), (2, 0, 4065997671), (5, 13, 11), (8, 0, 690011675), (15, 11, 11), (8, 0, 540576667), (2, 0, 1618285201), (8, 0, 1123989331), (8, 0, 1914950564), (8, 0, 4213669998), (21, 13, 11), (8, 0, 1529621790), (10, 0, 865446746), (2, 10, 11), (8, 0, 449019059), (16, 13, 11), (8, 0, 906976959), (6, 10, 10), (8, 0, 892028723), (10, 0, 1040131328), (2, 0, 3854135066), (2, 0, 4133925041), (2, 0, 1738396966), (2, 12, 12), (8, 0, 550277338), (10, 0, 1043160697), (2, 1, 1176768057), (10, 1, 2368952475), (8, 12, 11), (2, 1, 2826144967), (8, 1, 1275301297), (10, 1, 2955899422), (2, 1, 2241699318), (12, 11, 10), (8, 1, 537794314), (11, 13, 10), (8, 1, 473021534), (17, 12, 13), (8, 1, 2381227371), (10, 1, 3973380876), (10, 1, 1728990628), (6, 11, 13), (8, 1, 2974252696), (0, 11, 11), (8, 1, 1912236055), (2, 1, 3620744853), (3, 10, 13), (2, 1, 2628426447), (11, 13, 12), (10, 1, 486914414), (16, 11, 12), (10, 1, 1187047173), (14, 12, 11), (2, 2, 3103274804), (13, 10, 10), (8, 2, 3320200805), (8, 2, 3846589389), (1, 13, 13), (2, 2, 2724573159), (10, 2, 1483327425), (2, 2, 1957985324), (14, 13, 12), (10, 2, 1467602691), (8, 2, 3142557962), (2, 13, 12), (2, 2, 2525769395), (8, 2, 3681119483), (8, 12, 11), (10, 2, 1041439413), (10, 2, 1042206298), (2, 2, 527001246), (20, 10, 13), (10, 2, 855860613), (8, 10, 10), (8, 2, 1865979270), (1, 13, 10), (8, 2, 2752636085), (2, 2, 1389650363), (10, 2, 2721642985), (18, 10, 11), (8, 2, 3276518041), (15, 10, 10), (2, 2, 1965130376), (2, 3, 3557111558), (2, 3, 3031574352), (16, 12, 10), (10, 3, 4226755821), (8, 3, 2624879637), (8, 3, 1381275708), (2, 3, 3310620882), (2, 3, 2475591380), (8, 3, 405408383), (2, 3, 2291319543), (0, 12, 12), (8, 3, 4144538489), (2, 3, 3878256896), (6, 11, 10), (10, 3, 2243529248), (10, 3, 561931268), (11, 11, 12), (10, 3, 3076955709), (18, 12, 13), (8, 3, 2019584073), (10, 13, 12), (8, 3, 1712479912), (18, 11, 11), (2, 3, 2804447380), (17, 10, 10), (10, 3, 2957126100), (18, 13, 13), (8, 3, 1368187437), (17, 10, 12), (8, 3, 3586129298), (10, 4, 1229526732), (19, 11, 11), (10, 4, 2759768797), (1, 10, 13), (2, 4, 2112449396), (10, 4, 1212917601), (2, 4, 1524771736), (8, 4, 3146530277), (2, 4, 2997906889), (16, 12, 10), (8, 4, 4135691751), (8, 4, 1960868242), (6, 12, 12), (10, 4, 2775657353), (16, 10, 13), (8, 4, 1451259226), (8, 4, 607382171), (13, 13, 13), (10, 4, 357643050), (2, 4, 2020402776), (8, 5, 2408165152), (13, 12, 10), (2, 5, 806913563), (10, 5, 772591592), (20, 13, 11), (2, 5, 2211018781), (10, 5, 2523354879), (8, 5, 2549720391), (2, 5, 3908178996), (2, 5, 1299171929), (8, 5, 512513885), (10, 5, 2617924552), (1, 12, 13), (8, 5, 390960442), (12, 11, 13), (8, 5, 1248271133), (8, 5, 2114382155), (1, 10, 13), (10, 5, 2078863299), (20, 12, 12), (8, 5, 2857504053), (10, 5, 4271947727), (2, 6, 2238126367), (2, 6, 1544827193), (8, 6, 4094800187), (2, 6, 3461906189), (10, 6, 1812592759), (2, 6, 1506702473), (8, 6, 536175198), (2, 6, 1303821297), (8, 6, 715409343), (2, 6, 4094566992), (14, 10, 11), (2, 6, 1890141105), (0, 13, 13), (2, 6, 3143319360), (10, 7, 696930856), (2, 7, 926450200), (8, 7, 352056373), (20, 13, 11), (10, 7, 3857703071), (8, 7, 3212660135), (5, 12, 10), (10, 7, 3854876250), (21, 12, 11), (8, 7, 3648688720), (2, 7, 2732629817), (4, 10, 12), (10, 7, 2285138643), (18, 10, 13), (2, 7, 2255852466), (2, 7, 2537336944), (3, 10, 13), (2, 7, 4257606405), (10, 8, 3703184638), (7, 11, 10), (10, 8, 2165056562), (8, 8, 2217220568), (19, 10, 12), (8, 8, 2088084496), (15, 13, 10), (8, 8, 443074220), (16, 13, 12), (10, 8, 1298336973), (2, 13, 11), (8, 8, 822378456), (19, 11, 12), (8, 8, 2154711985), (0, 11, 12), (10, 8, 430757325), (2, 12, 10), (2, 8, 2521672196), (10, 9, 532704100), (10, 9, 2519542932), (2, 9, 2451309277), (2, 9, 3957445476), (5, 10, 10), (8, 9, 2583554449), (10, 9, 1149665327), (12, 13, 12), (8, 9, 3053959226), (0, 10, 10), (8, 9, 3693780276), (15, 11, 10), (2, 9, 609918789), (2, 9, 2778221635), (16, 13, 10), (8, 9, 3133754553), (8, 11, 13), (8, 9, 3961507338), (2, 9, 1829237263), (16, 11, 13), (2, 9, 2472519933), (6, 12, 12), (8, 9, 4061630846), (10, 9, 1181684786), (13, 10, 11), (10, 9, 390349075), (8, 9, 2883917626), (10, 9, 3733394420), (10, 12, 12), (2, 9, 3895283827), (20, 10, 11), (2, 9, 2257053750), (10, 9, 2770821931), (18, 10, 13), (2, 9, 477834410), (19, 13, 12), (3, 0, 1), (12, 12, 12), (3, 1, 2), (11, 13, 11), (3, 2, 3), (3, 3, 4), (3, 4, 5), (1, 13, 13), (3, 5, 6), (7, 11, 11), (3, 6, 7), (4, 10, 12), (3, 7, 8), (18, 12, 12), (3, 8, 9), (21, 12, 10), (3, 9, 10)
]

for opcode, op0, op1 in instructions:
    apply_instruction(opcode, op0, op1)

# constraints for the final state of the registers
s.add(regs[0] == 0x3ee88722, regs[1] == 0xecbdbe2, regs[2] == 0x60b843c4, regs[3] ==0x5da67c7, regs[4] == 0x171ef1e9, regs[5] == 0x52d5b3f7, regs[6] == 0x3ae718c0, regs[7] == 0x8b4aacc2, regs[8] == 0xe5cf78dd, regs[9] == 0x4a848edf, regs[10] == 0x8f, regs[11] == 0x4180000, regs[12] == 0x0, regs[13] == 0xd, regs[14] == 0x0)

# Solve the constraints
if s.check() == sat:
    m = s.model()
    flag_solution = [m.eval(Flag[i]).as_long() for i in range(40)]
    # Convert flag_solution to a string
    flag_str = ''.join(chr(b) for b in flag_solution if b is not None)
    print("Solution found:", flag_str)
else:
    print("No solution exists")
```

I initialized a `Flag` array of 40 8-bit bit-vectors, a `regs` array of 15 32-bit bit-vectors, an `apply_instruction` function, which is a direct translation of the defined operations based on opcodes. 

For execution of instructions, they are just tuples, each representing a single operation, copied over from the source file. 

After applying all the instructions, I added constraints to the solver for the expected final values of the registers. Z3 is then asked to solve these constraints, attempting to find values for the `Flag` array. If a solution satisfies all constraints, we can then extract the input value that gave us the solution.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/7cfffa89-5e8f-4391-aa23-a972955728bd)

`HTB{m4n_1_l0v4_cXX_TeMpl4t35_9fb60c17b0}`
