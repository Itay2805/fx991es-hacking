from ida_bytes import *
from ida_diskio import *
from ida_enum import *
from ida_ua import *
from ida_idp import *
from ida_auto import *
from ida_nalt import *
import ida_frame
from ida_funcs import *
from ida_lines import *
from ida_problems import *
from ida_offset import *
from ida_segment import *
from ida_name import *
from ida_netnode import *
import ida_ida

import struct
import re

SPECVAL_NONE = 0
SPECVAL_INC_EA = 1
SPECVAL_BIT = 2

INSTRUCTIONS = [
    # Special: DSR Prefix Instructions
    ('11100011iiiiiiii', 'DSR<-', ['#{i}'], 0),
    ('10010000dddd1111', 'DSR<-', ['R{d}'], 0),
    ('1111111010011111', 'DSR<-', ['DSR'], 0),

    # Arithmetic instructions
    ('1000nnnnmmmm0001', 'ADD', ['R{n}', 'R{m}'], 0),
    ('0001nnnniiiiiiii', 'ADD', ['R{n}', '#{i}'], 0),
    ('1111nnn0mmm00110', 'ADD', ['ER{n*2}', 'ER{m*2}'], 0),
    ('1110nnn01iiiiiii', 'ADD', ['ER{n*2}', '#{i << 25 >> 25}'], 0),
    ('1000nnnnmmmm0110', 'ADDC', ['R{n}', 'R{m}'], 0),
    ('0110nnnniiiiiiii', 'ADDC', ['R{n}', '#{i}'], 0),
    ('1000nnnnmmmm0010', 'AND', ['R{n}', 'R{m}'], 0),
    ('0010nnnniiiiiiii', 'AND', ['R{n}', '#{i}'], 0),
    ('1000nnnnmmmm0111', 'CMP', ['R{n}', 'R{m}'], 0),
    ('0111nnnniiiiiiii', 'CMP', ['R{n}', '#{i}'], 0),
    ('1000nnnnmmmm0101', 'CMPC', ['R{n}', 'R{m}'], 0),
    ('0101nnnniiiiiiii', 'CMPC', ['R{n}', '#{i}'], 0),
    ('1111nnn0mmm00101', 'MOV', ['ER{n*2}', 'ER{m*2}'], 0),
    ('1110nnn00iiiiiii', 'MOV', ['ER{n*2}', '#{i}'], 0),
    ('1000nnnnmmmm0000', 'MOV', ['R{n}', 'R{m}'], 0),
    ('0000nnnniiiiiiii', 'MOV', ['R{n}', '#{i}'], 0),
    ('1000nnnnmmmm0011', 'OR', ['R{n}', 'R{m}'], 0),
    ('0011nnnniiiiiiii', 'OR', ['R{n}', '#{i}'], 0),
    ('1000nnnnmmmm0100', 'XOR', ['R{n}', 'R{m}'], 0),
    ('0100nnnniiiiiiii', 'XOR', ['R{n}', '#{i}'], 0),
    ('1111nnn0mmm00111', 'CMP', ['ER{n*2}', 'ER{m*2}'], 0),
    ('1000nnnnmmmm1000', 'SUB', ['R{n}', 'R{m}'], 0),
    ('1000nnnnmmmm1001', 'SUBC', ['R{n}', 'R{m}'], 0),

    # Shift Instructions
    ('1000nnnnmmmm1010', 'SLL', ['R{n}', 'R{m}'], 0),
    ('1001nnnn0www1010', 'SLL', ['R{n}', '#{w}'], 0),
    ('1000nnnnmmmm1011', 'SLLC', ['R{n}', 'R{m}'], 0),
    ('1001nnnn0www1011', 'SLLC', ['R{n}', '#{w}'], 0),
    ('1000nnnnmmmm1110', 'SRA', ['R{n}', 'R{m}'], 0),
    ('1001nnnn0www1110', 'SRA', ['R{n}', '#{w}'], 0),
    ('1000nnnnmmmm1100', 'SRL', ['R{n}', 'R{m}'], 0),
    ('1001nnnn0www1100', 'SRL', ['R{n}', '#{w}'], 0),
    ('1000nnnnmmmm1101', 'SRLC', ['R{n}', 'R{m}'], 0),
    ('1001nnnn0www1101', 'SRLC', ['R{n}', '#{w}'], 0),

    # Load/Store Instructions
    ('1001nnn000110010', 'L', ['ER{n*2}', '[EA]'], 0),
    ('1001nnn001010010', 'L', ['ER{n*2}', '[EA+]'], 0),
    ('1001nnn0mmm00010', 'L', ['ER{n*2}', '[ER{m*2}]'], 0),
    ('1011nnn000DDDDDD', 'L', ['ER{n*2}', '{signedtohex(D, 6)}h[ER12]'], 0),
    ('1011nnn001DDDDDD', 'L', ['ER{n*2}', '{signedtohex(D, 6)}h[ER14]'], 0),
    ('1001nnnn00110000', 'L', ['R{n}', '[EA]'], 0),
    ('1001nnnn01010000', 'L', ['R{n}', '[EA+]'], 0),
    ('1001nnnnmmm00000', 'L', ['R{n}', '[ER{m*2}]'], 0),
    ('1101nnnn00DDDDDD', 'L', ['R{n}', '{signedtohex(D, 6)}h[ER12]'], 0),
    ('1101nnnn01DDDDDD', 'L', ['R{n}', '{signedtohex(D, 6)}h[ER14]'], 0),
    ('1001nn0000110100', 'L', ['XR{n*4}', '[EA]'], 0),
    ('1001nn0001010100', 'L', ['XR{n*4}', '[EA+]'], 0),
    ('1001n00000110110', 'L', ['QR{n*8}', '[EA]'], 0),
    ('1001n00001010110', 'L', ['QR{n*8}', '[EA+]'], 0),
    ('1001nnn000110011', 'ST', ['ER{n*2}', '[EA]'], 0),
    ('1001nnn001010011', 'ST', ['ER{n*2}', '[EA+]'], 0),
    ('1001nnn0mmm00011', 'ST', ['ER{n*2}', '[ER{m*2}]'], 0),
    ('1011nnn010DDDDDD', 'ST', ['ER{n*2}', '{signedtohex(D, 6)}h[ER12]'], 0),
    ('1011nnn011DDDDDD', 'ST', ['ER{n*2}', '{signedtohex(D, 6)}h[ER14]'], 0),
    ('1001nnnn00110001', 'ST', ['R{n}', '[EA]'], 0),
    ('1001nnnn01010001', 'ST', ['R{n}', '[EA+]'], 0),
    ('1001nnnnmmm00001', 'ST', ['R{n}', '[ER{m*2}]'], 0),
    ('1101nnnn10DDDDDD', 'ST', ['R{n}', '{signedtohex(D, 6)}h[ER12]'], 0),
    ('1101nnnn11DDDDDD', 'ST', ['R{n}', '{signedtohex(D, 6)}h[ER14]'], 0),
    ('1001nn0000110101', 'ST', ['XR{n*4}', '[EA]'], 0),
    ('1001nn0001010101', 'ST', ['XR{n*4}', '[EA+]'], 0),
    ('1001n00000110111', 'ST', ['QR{n*8}', '[EA]'], 0),
    ('1001n00001010111', 'ST', ['QR{n*8}', '[EA+]'], 0),
    ('11100001iiiiiiii', 'ADD', ['SP', '#{signedtohex(i, 8)}'], 0),
    ('10100000mmmm1111', 'MOV', ['ECSR', 'R{m}'], 0),
    ('1010mmm000001101', 'MOV', ['ELR', 'ER{m*2}'], 0),
    ('10100000mmmm1100', 'MOV', ['EPSW', 'R{m}'], 0),
    ('1010nnn000000101', 'MOV', ['ER{n*2}', 'ELR'], 0),
    ('1010nnn000011010', 'MOV', ['ER{n*2}', 'SP'], 0),
    ('10100000mmmm1011', 'MOV', ['PSW', 'R{m}'], 0),
    ('11101001iiiiiiii', 'MOV', ['PSW', '#{i}'], 0),
    ('1010nnnn00000111', 'MOV', ['R{n}', 'ECSR'], 0),
    ('1010nnnn00000100', 'MOV', ['R{n}', 'EPSW'], 0),
    ('1010nnnn00000011', 'MOV', ['R{n}', 'PSW'], 0),
    ('10100001mmm01010', 'MOV', ['SP', 'ER{m*2}'], 0),

    # PUSH/POP Instructions
    ('1111nnn001011110', 'PUSH', ['ER{n*2}'], 0),
    ('1111n00001111110', 'PUSH', ['QR{n*8}'], 0),
    ('1111nnnn01001110', 'PUSH', ['R{n}'], 0),
    ('1111nn0001101110', 'PUSH', ['XR{n*4}'], 0),
    ('1111lep111001110', 'PUSH', ['{"LR, " if l==1 else ""}{"EPSW, " if e==1 else ""}{"ELR, " if p==1 else ""}EA'], 0),
    ('1111le1011001110', 'PUSH', ['{"LR, " if l==1 else ""}{"EPSW, " if e==1 else ""}ELR'], 0),
    ('1111l10011001110', 'PUSH', ['{"LR, " if l==1 else ""}EPSW'], 0),
    ('1111100011001110', 'PUSH', ['LR'], 0),
    ('1111nnn000011110', 'POP', ['ER{n*2}'], 0),
    ('1111n00000111110', 'POP', ['QR{n*8}'], 0),
    ('1111nnnn00001110', 'POP', ['R{n}'], 0),
    ('1111nn0000101110', 'POP', ['XR{n*4}'], 0),
    ('1111lep110001110', 'POP', ['{"LR, " if l==1 else ""}{"PSW, " if e==1 else ""}{"PC, " if p==1 else ""}EA'], 0),
    ('1111le1010001110', 'POP', ['{"LR, " if l==1 else ""}{"PSW, " if e==1 else ""}PC'], 0),
    ('1111l10010001110', 'POP', ['{"LR, " if l==1 else ""}PSW'], 0),
    ('1111100010001110', 'POP', ['LR'], 0),

    # Coprocessor Data Transfer Instructions
    ('1010nnnnmmmm1110', 'MOV', ['CR{n}', 'R{m}'], 0),
    ('1111nnn000101101', 'MOV', ['CER{n*2}', '[EA]'], 0),
    ('1111nnn000111101', 'MOV', ['CER{n*2}', '[EA+]'], 0),
    ('1111nnnn00001101', 'MOV', ['CR{n}', '[EA]'], 0),
    ('1111nnnn00011101', 'MOV', ['CR{n}', '[EA+]'], 0),
    ('1111nn0001001101', 'MOV', ['CXR{n*4}', '[EA]'], 0),
    ('1111nn0001011101', 'MOV', ['CXR{n*4}', '[EA+]'], 0),
    ('1111n00001101101', 'MOV', ['CQR{n*8}', '[EA]'], 0),
    ('1111n00001111101', 'MOV', ['CQR{n*8}', '[EA+]'], 0),
    ('1010nnnnmmmm0110', 'MOV', ['R{n}', 'CR{m}'], 0),
    ('1111mmm010101101', 'MOV', ['[EA]', 'CER{m*2}'], 0),
    ('1111mmm010111101', 'MOV', ['[EA+]', 'CER{m*2}'], 0),
    ('1111mmmm10001101', 'MOV', ['[EA]', 'CR{m}'], 0),
    ('1111mmmm10011101', 'MOV', ['[EA+]', 'CR{m}'], 0),
    ('1111mm0011001101', 'MOV', ['[EA]', 'CXR{m*4}'], 0),
    ('1111mm0011011101', 'MOV', ['[EA+]', 'CXR{m*4}'], 0),
    ('1111m00011101101', 'MOV', ['[EA]', 'CQR{m*8}'], 0),
    ('1111m00011111101', 'MOV', ['[EA+]', 'CQR{m*8}'], 0),

    # EA Register Data Transfer Instructions
    ('11110000mmm01010', 'LEA', ['[ER{m*2}]'], 0),

    # ALU Instructions
    ('1000nnnn00011111', 'DAA', ['R{n}'], 0),
    ('1000nnnn00111111', 'DAS', ['R{n}'], 0),
    ('1000nnnn01011111', 'NEG', ['R{n}'], 0),

    # Bit Access Instructions
    ('1010nnnn0bbb0000', 'SB', ['R{n}.{b}'], 0),
    ('1010nnnn0bbb0010', 'RB', ['R{n}.{b}'], 0),
    ('1010nnnn0bbb0001', 'TB', ['R{n}.{b}'], 0),

    # PSW Access Instructions
    ('1110110100001000', 'EI', [], 0),
    ('1110101111110111', 'DI', [], 0),
    ('1110110110000000', 'SC', [], 0),
    ('1110101101111111', 'RC', [], 0),
    ('1111111011001111', 'CPLC', [], 0),

    # Conditional Relative Branch Instructions
    ('11000000rrrrrrrr', 'BGE', ['{tohex(2 + pc + (signed(r) << 1), 4+1)}h'], CF_JUMP),
    ('11000001rrrrrrrr', 'BLT', ['{tohex(2 + pc + (signed(r) << 1), 4+1)}h'], CF_JUMP),
    ('11000010rrrrrrrr', 'BGT', ['{tohex(2 + pc + (signed(r) << 1), 4+1)}h'], CF_JUMP),
    ('11000011rrrrrrrr', 'BLE', ['{tohex(2 + pc + (signed(r) << 1), 4+1)}h'], CF_JUMP),
    ('11000100rrrrrrrr', 'BGES', ['{tohex(2 + pc + (signed(r) << 1), 4+1)}h'], CF_JUMP),
    ('11000101rrrrrrrr', 'BLTS', ['{tohex(2 + pc + (signed(r) << 1), 4+1)}h'], CF_JUMP),
    ('11000110rrrrrrrr', 'BGTS', ['{tohex(2 + pc + (signed(r) << 1), 4+1)}h'], CF_JUMP),
    ('11000111rrrrrrrr', 'BLES', ['{tohex(2 + pc + (signed(r) << 1), 4+1)}h'], CF_JUMP),
    ('11001000rrrrrrrr', 'BNE', ['{tohex(2 + pc + (signed(r) << 1), 4+1)}h'], CF_JUMP),
    ('11001001rrrrrrrr', 'BEQ', ['{tohex(2 + pc + (signed(r) << 1), 4+1)}h'], CF_JUMP),
    ('11001010rrrrrrrr', 'BNV', ['{tohex(2 + pc + (signed(r) << 1), 4+1)}h'], CF_JUMP),
    ('11001011rrrrrrrr', 'BOV', ['{tohex(2 + pc + (signed(r) << 1), 4+1)}h'], CF_JUMP),
    ('11001100rrrrrrrr', 'BPS', ['{tohex(2 + pc + (signed(r) << 1), 4+1)}h'], CF_JUMP),
    ('11001101rrrrrrrr', 'BNS', ['{tohex(2 + pc + (signed(r) << 1), 4+1)}h'], CF_JUMP),
    ('11001110rrrrrrrr', 'BAL', ['{tohex(2 + pc + (signed(r) << 1), 4+1)}h'], CF_JUMP|CF_STOP),

    # Sign Extension Instruction
    ('1000mmm1nnn01111', 'EXTBW', ['ER{n*2}'], 0),

    # Software Interrupt Instructions
    ('1110010100iiiiii', 'SWI', ['#{i}'], 0),
    ('1111111111111111', 'BRK', [], CF_STOP),

    #  Branch Instructions
    ('11110000nnn00010', 'B', ['ER{n*2}'], CF_JUMP|CF_STOP),
    ('11110000nnn00011', 'BL', ['ER{n*2}'], CF_JUMP|CF_CALL),

    # Multiplication and Division Instructions
    ('1111nnn0mmmm0100', 'MUL', ['ER{n*2}', 'R{m}'], 0),
    ('1111nnn0mmmm1001', 'DIV', ['ER{n*2}', 'R{m}'], 0),

    # Miscellaneous
    ('1111111000101111', 'INC', ['[EA]'], 0),
    ('1111111000111111', 'DEC', ['[EA]'], 0),
    ('1111111000011111', 'RT', [], CF_STOP),
    ('1111111000001111', 'RTI', [], CF_STOP),
    ('1111111010001111', 'NOP', [], 0),

    # Load/Store Instructions
    ('EEEEEEEEDDDDDDDD1010nnn0mmm01000', 'L', ['ER{n*2}', '{tohex(E*256+D, 16)}h[ER{m*2}]'], 0),
    ('EEEEEEEEDDDDDDDD1001nnn000010010', 'L', ['ER{n*2}', '0{tohex(E*256+D, 4)}h'], 0),
    ('EEEEEEEEDDDDDDDD1001nnnnmmm01000', 'L', ['R{n}', '{tohex(E*256+D, 16)}h[ER{m*2}]'], 0),
    ('EEEEEEEEDDDDDDDD1001nnnn00010000', 'L', ['R{n}', '0{tohex(E*256+D, 4)}h'], 0),
    ('EEEEEEEEDDDDDDDD1010nnn0mmm01001', 'ST', ['ER{n*2}', '{tohex(E*256+D, 16)}h[ER{m*2}]'], 0),
    ('EEEEEEEEDDDDDDDD1001nnn000010011', 'ST', ['ER{n*2}', '0{tohex(E*256+D, 4)}h'], 0),
    ('EEEEEEEEDDDDDDDD1001nnnnmmm01001', 'ST', ['R{n}', '{tohex(E*256+D, 16)}h[ER{m*2}]'], 0),
    ('EEEEEEEEDDDDDDDD1001nnnn00010001', 'ST', ['R{n}', '0{tohex(E*256+D, 4)}h'], 0),

    # EA Register Data Transfer Instructions
    ('EEEEEEEEDDDDDDDD11110000mmm01011', 'LEA', ['{tohex(E*256+D, 16)}h[ER{m*2}]'], 0),
    ('EEEEEEEEDDDDDDDD1111000000001100', 'LEA', ['0{tohex(E*256+D, 4)}h'], 0),

    # Bit Access Instructions
    ('EEEEEEEEDDDDDDDD101000001bbb0000', 'SB', ['0{tohex(E*256+D, 4)}h.{b}'], 0),
    ('EEEEEEEEDDDDDDDD101000001bbb0010', 'RB', ['0{tohex(E*256+D, 4)}h.{b}'], 0),
    ('EEEEEEEEDDDDDDDD101000001bbb0001', 'TB', ['0{tohex(E*256+D, 4)}h.{b}'], 0),

    # Branch Instructions
    ('DDDDDDDDCCCCCCCC1111gggg00000000', 'B', ['0{tohex(g, 1)}h:0{tohex(D*256+C, 4)}h'], CF_JUMP|CF_STOP),
    ('DDDDDDDDCCCCCCCC1111gggg00000001', 'BL', ['0{tohex(g, 1)}h:0{tohex(D*256+C, 4)}h'], CF_JUMP|CF_CALL),
]


class NXU8100Processor(processor_t):
    id = 0x8000 + 0xbabe

    # TODO: PR_ASSEMBLE
    # TODO: PR_TYPEINFO
    flag = 0
    flag2 = 0

    # 8 bits per byte
    cnbits = 8
    dnbits = 8

    reg_names = [
        # Code Segment Register
        'CSR',

        'DSR',

        # Program Counter
        'PC',

        # General registers
        'R0', 'R1', 'R2', 'R3',
        'R4', 'R5', 'R6', 'R7',
        'R8', 'R9', 'R10', 'R11',
        'R12', 'R13', 'R14', 'R15',

        'ER0', 'ER2', 'ER4', 'ER6',
        'ER8', 'ER10', 'ER12', 'ER14',

        'XR0', 'XR4', 'XR8', 'XR12',

        'QR0', 'QR8',

        # Coprocessor General registers
        'CR0', 'CR1', 'CR2', 'CR3',
        'CR4', 'CR5', 'CR6', 'CR7',
        'CR8', 'CR9', 'CR10', 'CR11',
        'CR12', 'CR13', 'CR14', 'CR15',

        'CER0', 'CER2', 'CER4', 'CER6',
        'CER8', 'CER10', 'CER12', 'CER14',

        'CXR0', 'CXR4', 'CXR8', 'CXR12',

        'CQR0', 'CQR8',

        # Link registers
        'LR',
        'ELR',

        # CSR backup registers
        'LCSR',
        'ECSR',

        # Program status word
        'PSW',

        # PSW backup registers
        'EPSW',

        # EA register
        'EA',

        # Address register
        'AR',

        # Stack pointer
        'SP'
    ]

    psnames = ['nxu8100']
    plnames = ['NX-U8/100']

    # only one assembler is supported
    assembler = {
        'flag': ASH_HEXF3 | AS_UNEQU | AS_COLON | ASB_BINF4 | AS_N2CHR,
        'uflag': 0,
        'name': "My processor module bytecode assembler",
        'header': ["Line1", "Line2"],
        'origin': "org",
        'end': "end",
        'cmnt': ";",
        'ascsep': "\"",
        'accsep': "'",
        'esccodes': "\"'",
        'a_ascii': "db",
        'a_byte': "db",
        'a_word': "dw",
        'a_dword': "dd",
        'a_qword': "dq",
        'a_oword': "xmmword",
        'a_yword': "ymmword",
        'a_float': "dd",
        'a_double': "dq",
        'a_tbyte': "dt",
        'a_packreal': "",
        'a_dups': "#d dup(#v)",
        'a_bss': "%s dup ?",
        'a_equ': ".equ",
        'a_seg': "seg",
        'a_curip': "$",
        'a_public': "public",
        'a_weak': "weak",
        'a_extrn': "extrn",
        'a_comdef': "",
        'a_align': "align",
        'lbrace': "(",
        'rbrace': ")",
        'a_mod': "%",
        'a_band': "&",
        'a_bor': "|",
        'a_xor': "^",
        'a_bnot': "~",
        'a_shl': "<<",
        'a_shr': ">>",
        'a_sizeof_fmt': "size %s",
        'flag2': 0,
        'cmnt2': "",
        'low8': "",
        'high8': "",
        'low16': "",
        'high16': "",
        'a_include_fmt': "include %s",
        'a_vstruc_fmt': "",
        'a_rva': "rva"
    }

    reg_first_sreg = 0
    reg_last_sreg = 1
    sreg_size = 8
    segreg_size = 0

    reg_code_sreg = 0
    reg_data_sreg = 1

    instruc_start = 0
    instruc = [{'name': inst[1], 'feature': inst[3]} for inst in INSTRUCTIONS]
    instruc_end = len(instruc) + 1

    def __init__(self):
        processor_t.__init__(self)

        # Find the return opcode itype
        for i in range(len(self.instruc)):
            if self.instruc[i]['name'] == 'RT':
                self.icode_return = i

    def _reg_dtype(self, reg):
        """
        Returns the size of the register
        """
        if reg.startswith('ER') or reg.startswith('CER') or reg in ['PC', 'SP', 'AR', 'LR', 'ELR', 'EA']:
            return dt_word
        elif reg.startswith('XR') or reg.startswith('CXR'):
            return dt_dword
        elif reg.startswith('QR') or reg.startswith('CQR'):
            return dt_qword
        elif reg.startswith('R') or reg.startswith('CR') or reg in ['EPSW', 'PSW', 'LCSR']:
            return dt_byte
        else:
            assert False, reg

    def _parse_operand(self, opr, out):
        """
        Parse the operand nicely
        """
        if opr in self.reg_names:
            # This is a register
            out.type = o_reg
            out.reg = self.reg_names.index(opr)
            out.dtype = self._reg_dtype(opr)

        elif opr.startswith('#'):
            # Immediate
            out.type = o_imm
            out.dtype = dt_byte
            out.value = int(opr[1:], 16)

        elif ':' in opr or opr.endswith('h'):
            # A direct address
            out.type = o_mem
            # TODO: we can't decide the size
            #  without the other end

            if ':' in opr:
                addr = opr.split(':')
                out.addr = int(addr[0][:-1], 16) << 16 | int(addr[1][:-1], 16)
            else:
                out.addr = int(opr[:-1], 16)

        elif opr[0] == '[':
            # Indirect, no disp
            out.type = o_phrase

            opr = opr[1:-1]
            if opr == 'EA+':
                out.phrase = self.reg_names.index('EA')
                out.dtype = self._reg_dtype('EA')
                out.specval |= SPECVAL_INC_EA
            elif opr in self.reg_names:
                out.phrase = self.reg_names.index(opr)
                out.dtype = self._reg_dtype(opr)
            else:
                assert False, opr

        elif '[' in opr:
            # Indirect with disp
            out.type = o_displ

            # Parse it
            disp, reg = opr.split('[')
            reg = reg[:-1]
            disp = int(disp[:-1], 16)

            if reg == 'EA+':
                out.phrase = self.reg_names.index('EA')
                out.dtype = self._reg_dtype('EA')
                out.addr = disp
                out.specval |= SPECVAL_INC_EA
            elif reg in self.reg_names:
                out.phrase = self.reg_names.index(reg)
                out.dtype = self._reg_dtype(reg)
                out.addr = disp
            else:
                assert False, opr

        elif '.' in opr:
            a, bit = opr.split('.')
            self._parse_operand(a, out)
            out.specval |= SPECVAL_BIT
            out.specval |= int(bit) << 16

        elif ',' in opr:
            # This is a special case of push/pop
            return [x.strip() for x in opr.split(',')]
        else:
            assert False, opr

    def _match_pattern(self, inst, ptrn):
        inst = bin(inst)[2:].zfill(len(ptrn))
        args = {}

        # Go over the pattern
        for i in range(len(ptrn)):
            if ptrn[i] in '10':
                # Check if the constant is the same
                if ptrn[i] != inst[i]:
                    return None
            else:
                # Parse the variable
                if ptrn[i] not in args:
                    args[ptrn[i]] = ''
                args[ptrn[i]] += inst[i]

        # Parse the args to integers
        for arg in args:
            args[arg] = int(args[arg], 2)

        return args

    def notify_ana(self, insn):
        """
        Decodes an instruction into insn
        Returns: insn.size (=the size of the decoded instruction) or zero
        """

        opcode = insn.get_next_word()
        read_more = False

        for itype in range(len(INSTRUCTIONS)):
            ptrn, mnemonic, fmts, _ = INSTRUCTIONS[itype]

            # Check if we need more
            if not read_more and len(ptrn) > 16:
                opcode = insn.get_next_word() << 16 | opcode
                read_more = True

            # Try to parse
            args = self._match_pattern(opcode, ptrn)
            if args is None:
                continue

            # Parsed!
            insn.itype = itype

            def signedtohex(n, bitlen):
                bitlen -= 1
                is_pos = (n >> bitlen) == 0
                if not is_pos:
                    n = (2 << bitlen) - n
                retval = ''
                for x in range(bitlen):
                    retval = '0123456789abcdef'[n & 0xF] + retval
                    n >>= 4
                return retval if is_pos else '-' + retval

            # resolve args
            args['signed'] = lambda x: struct.unpack('<b', struct.pack('<B', x))[0]
            args['tohex'] = lambda x, y: hex(x)[2:].zfill(y)
            args['signedtohex'] = signedtohex
            args['pc'] = insn.ea
            for i in range(len(fmts)):
                # Resolve it
                opr = re.sub('{(.*?)}', lambda m: str(eval(m.group(1), args)), fmts[i])
                opr = opr.replace('Lh', 'h')
                more_oprs = self._parse_operand(opr, getattr(insn, 'Op{}'.format(i+1)))
                if more_oprs is not None:
                    # Special case of push/pop
                    i = 0
                    for opr in more_oprs:
                        assert self._parse_operand(opr, getattr(insn, 'Op{}'.format(i+1))) is None
                        i += 1

            # We done here
            return insn.size

    def notify_emu(self, insn):
        """
        Emulate instruction, create cross-references, plan to analyze
        subsequent instructions, modify flags etc. Upon entrance to this function
        all information about the instruction is in 'insn' structure.
        If zero is returned, the kernel will delete the instruction.
        """
        feature = insn.get_canon_feature()
        flow = (feature & CF_STOP) == 0
        _, name, _, _ = INSTRUCTIONS[insn.itype]

        # Check for branches
        if feature & CF_JUMP:
            remember_problem(PR_JUMP, insn.ea)

            if insn.Op1.type == o_mem:
                if name == 'BL' or name == 'B':
                    add_cref(insn.ea, insn.Op1.addr, fl_CN)
                else:
                    add_cref(insn.ea, insn.Op1.addr, fl_JN)

        # Other than unconditional branches which are already handled in the CF_STOP, we also
        # have special case for `POP PC`, which is also a stopper
        if name == 'POP' and insn.Op1.type == o_reg and self.reg_names[insn.Op1.reg] == 'PC':
            flow = False

        # The next instruction is valid
        if flow:
            add_cref(insn.ea, insn.ea + insn.size, fl_F)

        return 1

    # ----------------------------------------------------------------------
    # Output to screen functions
    #

    def notify_out_operand(self, ctx, op):
        """
        Generate text representation of an instructon operand.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        The output text is placed in the output buffer initialized with init_output_buffer()
        This function uses out_...() functions from ua.hpp to generate the operand text
        Returns: 1-ok, 0-operand is hidden.
        """
        optype = op.type

        if optype == o_reg:
            # From the ABI:
            #   ER12 - Base Pointer
            #   ER14 - Frame Pointer
            if op.reg == 'ER14':
                ctx.out_register('FP')
            elif op.reg == 'ER12':
                ctx.out_register('BP')
            else:
                ctx.out_register(self.reg_names[op.reg])

            if op.specval & 0xFF == SPECVAL_BIT:
                ctx.out_symbol('.')
                ctx.out_btoa(op.specval >> 16, 10)

        elif optype == o_imm:
            ctx.out_symbol('#')
            ctx.out_value(op, OOFW_IMM | OOFW_8)

        elif optype == o_phrase:
            ctx.out_symbol('[')
            ctx.out_register(self.reg_names[op.phrase])
            if op.specval & 0xFF == SPECVAL_INC_EA:
                ctx.out_symbol('+')
            ctx.out_symbol(']')

        elif optype == o_displ:
            ctx.out_value(op, OOF_ADDR | OOFW_16)
            ctx.out_symbol('h')
            ctx.out_symbol('[')
            ctx.out_register(self.reg_names[op.phrase])
            if op.specval & 0xFF == SPECVAL_INC_EA:
                ctx.out_symbol('+')
            ctx.out_symbol(']')

        elif optype == o_mem:
            r = ctx.out_name_expr(op, op.addr, BADADDR)
            if not r:
                ctx.out_tagon(COLOR_ERROR)
                ctx.out_btoa(op.addr, 16)
                ctx.out_tagoff(COLOR_ERROR)
                ctx.out_symbol('h')

            if op.specval & 0xFF == SPECVAL_BIT:
                ctx.out_symbol('.')
                ctx.out_btoa(op.specval & 0xFF, 10)

        else:
            assert False, op

        return True

    def notify_out_insn(self, ctx):
        """
        Generate text representation of an instruction in 'ctx.insn' structure.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        Returns: nothing
        """
        ctx.out_mnemonic()
        if ctx.insn.Op1.type != o_void:
            ctx.out_one_operand(0)
        for i in xrange(1, 4):
            if ctx.insn[i].type == o_void:
                break
            ctx.out_symbol(',')
            ctx.out_char(' ')
            ctx.out_one_operand(i)
        ctx.set_gen_cmt()
        ctx.flush_outbuf()

    def notify_str2reg(self, regname):
        """
        Convert a register name to a register number
          args: regname
          Returns: register number or -1 if not avail
          The register number is the register index in the reg_names array
          Most processor modules do not need to implement this callback
          It is useful only if ph.reg_names[reg] does not provide
          the correct register names
        """
        # r = regname2index(regname)
        try:
            r = self.reg_names.index(regname)
        except ValueError:
            r = -1
        if r < 0:
            return -1
        else:
            return r


def PROCESSOR_ENTRY():
    return NXU8100Processor()
