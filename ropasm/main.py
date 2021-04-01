from collections import namedtuple
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
        self._relocations = []
        self._from_overflow = from_overflow

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
        self._labels[lbl] = len(self._data)

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
        self._stack = struct.pack('>B', val) + self._stack

    def push16(self, val: int):
        self._stack = struct.pack('>H', val) + self._stack

    def push32(self, val: int):
        self._stack = struct.pack('>I', val) + self._stack

    def push64(self, val: int):
        self._stack = struct.pack('>Q', val) + self._stack

    def push_lbl(self, val: str):
        """
        push an address of a label
        """
        self._relocations.append(Relocation(len(self._stack), val))
        self.push16(0x00)

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

    def set_lr(self):
        """
        Sets the LR and LCSR registers so we can use gadgets that require 
        the link register

        TODO: automatic

        overwrites ER12
        """

        # we don't have the link setup yet, we need to set
        # it nicely

        # Set ER12 to the next address
        # 14A7A                 POP     ER12
        # 14A7C                 POP     PC
        self.push_addr(0x14a7a)

        # we need to use a trampoline, and this is perfect 
        # to be used as a trampoline, only need the address
        # since `BL ERn` works on the same CSR
        self.push16(0x11D92 & 0xFFFF)

        # Jump to it with the link register being set
        # 11D90                 BL      ER12
        # 11D92                 POP     PC
        self.push_addr(0x11D90)

        self._has_link = True

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
        )
    }

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
        """

        # For this gadget to work we need
        # this to be zero
        asm.set_reg('R1', 0)

        # 8ac4                 CMP R1, R0
        # 8ac6                 SUBC R0, R0
        # 8ac8                 NEG R0
        # 8aca                 RT 
        asm.push_addr(0x8ac4)

    def _st_relative_er2(self, offset):
        """
        Set a value relative to the SP of after this instruction

        overwrites ER0
        """
        # We are going to get the current stack position so we 
        # can modify it to point to the 
        # 4588                 MOV ER0, SP
        # 458a                 RT 
        self.push_addr(0x4588)

        # Load R4 to have the value we want to add to R0
        # 15EE0                 POP     R4
        # 15EE2                 POP     PC
        self.push_addr(0x15EE0)
        self.push8(13 + offset)

        # now we need to add to ER0 the offset so the value after 
        # the store is the address that will be poped, we need to 
        # add 13 (POP R4 (4) + addition value (1) + ADD address (4) + ST address (4) + offset)
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

        # 4E4C                 POP     ER14
        # 4E4E                 POP     PC
        self.push_addr(0x4E4C)
        self.push16(0x0000)

        # 4E4A                 MOV     SP, ER14
        # 4E4C                 POP     ER14
        # 4E4E                 POP     PC
        self.push_addr(0x4E4A)
        self.push16(0x0000)
        
    def goto(self, lbl: str):
        """
        Allows to jump to a label in the code

        TODO: we can probably better optimize this, making so the next label we going to jump
              to will already have the address we want making so for the next gadgets we only 
              need a single gadget
        """
        # 4E4C                 POP     ER14
        # 4E4E                 POP     PC
        self.push_addr(0x4E4C)
        self.push_lbl(lbl)

        # 4E4A                 MOV     SP, ER14
        # 4E4C                 POP     ER14
        # 4E4E                 POP     PC
        self.push_addr(0x4E4A)
        self.push16(0x0)

    def deref_er0_to_r2(self):
        """
        Deref the address in er0 into r2
        """
        # 276a                 ST R2, [ER0]
        # 276c                 POP PC
        self.push_addr(0x276a) # 0x2b4a 
    
    def load_word_from_er2(self, table):
        """
        This will index into ER2 with the value in ER0 treating
        ER2 as an array of words

        overwrites R2
        """
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

    def relocate(self, initial_sp):
        """
        Relocate the labels, we need to know the stack position so
        we can calculate the addresses to set the stack to
        """
        pass


if __name__ == '__main__':

    asm = Assembler(True)
    
    asm.set_lr()
    asm.set_reg('ER2', 0xBABE)
    asm.goto_indirect_er2()

    asm.brk()

    full = asm._data =  asm._stack

    s = ''
    for byt in asm._stack:
        s += hex(byt)[2:].zfill(2)
    print(len(s) // 2)
    print(s)
