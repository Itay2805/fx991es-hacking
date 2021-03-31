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
        self._data = bytes()
        self._labels = {}
        self._relocations = []
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
        self._data = struct.pack('>B', val) + self._data

    def push16(self, val: int):
        self._data = struct.pack('>H', val) + self._data

    def push32(self, val: int):
        self._data = struct.pack('>I', val) + self._data

    def push64(self, val: int):
        self._data = struct.pack('>Q', val) + self._data

    def push_addr(self, val: int or str):
        """
        Push addr pushes a full address nicely, 
        """
        if isinstance(val, str):
            # This is a label, create relocation, place 0 for now 
            self._relocations.append(Relocation(len(self._data), val))
            self.push32(0x00)
        else:
            # Fix the address and push it 
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

    def link_call(self, next: int):
        """
        Call a gadget that returns with RT, to do so we are going 
        to call a BL gadget once
        """

        if not self._has_link:
            # we don't have the link setup yet, we need to set
            # it nicely

            # Set ER12 to the next address
            # 14A7A                 POP     ER12
            # 14A7C                 POP     PC
            self.push_addr(0x14a7a)

            # `BL ERn` can only jump to the same segment
            if next >= 0x10000:
                # we can do a direct jump
                self.push16(next & 0xFFFF)
            else:
                # we need to use a trampoline
                self.push16(0x11D92 & 0xFFFF)

            # Jump to it with the link register being set
            # 11D90                 BL      ER12
            # 11D92                 POP     PC
            self.push_addr(0x11D90)

            if next < 0x10000:
                # we need to push the address for the trampoline
                self.push_addr(next)

            self._has_link = True

        else:
            # We already have the link register set, just push 
            # the address
            self.push_addr(next)

    # These are gadgets to set different registers
    # We also keep gadgets that set a register to a certain value
    # which can be helpful to make the code smaller, all of these 
    # are assumed to be non-link
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

    def call(self, addr: int):
        """
        Call a normal function
        """
        self.push_addr(addr)

    def _r0_as_bool(self):
        """
        Truncates R0 to a "bool"
        * if it has value set it to 1
        * if it has no value set it to 0
        """

        # For this gadget to work we need
        # this to be zero
        asm.set_reg('R1', 0)

        # 0x8ac4 CMP R1, R0
        # 0x8ac6 SUBC R0, R0
        # 0x8ac8 NEG R0
        # 0x8aca RT 
        asm.link_call(0x8ac4)
        

    def brk(self):
        """
        Just break
        """
        self.push_addr(0xffc2)


if __name__ == '__main__':

    asm = Assembler(True)

    # Set R0 to the value we want to check
    asm.set_reg('R0', 0x01)




    asm.brk()

    s = ''
    for byt in asm._data:
        s += hex(byt)[2:].zfill(2)
    print(len(s) // 2)
    print(s)
