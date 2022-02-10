import ida_ua
import ida_idp
import ida_nalt
import ida_lines
import ida_segregs

from patching.util.ida import *
import patching.keystone as keystone

TEST_KS_RESOLVER = False

class KeystoneAssembler(object):
    """
    An abstraction of a CPU-specific fixup layer to wrap Keystone.
    """

    # the mnemonic for an unconditional jump
    UNCONDITIONAL_JUMP = NotImplementedError

    # the list of known conditional jump mnemonics
    CONDITIONAL_JUMPS = []

    # a list of mnemonics that we KNOW are currently unsupported
    UNSUPPORTED_MNEMONICS = []

    # the number of instruction bytes to show in the patch preview pane
    MAX_PREVIEW_BYTES = 4

    #
    # NOTE: for now, we explicitly try to print operands using 'blank' type
    # info because it can produce simpler output for the assembler engine
    #
    # we initialize just one instance of this blank printop for performance
    # reasons, so we do not have to initialize a new one for *every* print.
    #
    # it is particularly useful when using the assemble_all(...) DEV / test
    # function to round-trip assemble an entire IDB
    #

    _NO_OP_TYPE = ida_nalt.printop_t()

    def __init__(self, arch, mode):

        # a super low-effort TODO assert to ensure we're not using incomplete code
        assert self.UNCONDITIONAL_JUMP != NotImplementedError, "Incomplete Assembler Implementation"

        # initialize a backing keystone assembler
        self._arch = arch
        self._mode = mode | (keystone.KS_OPT_SYM_RESOLVER if TEST_KS_RESOLVER else 0)
        self._ks = keystone.Ks(arch, mode)

        # TODO/XXX: the keystone sym resolver callback is only for DEV / testing
        if TEST_KS_RESOLVER:
            self._ks.sym_resolver = self._ks_sym_resolver

    def _ks_sym_resolver(self, symbol, value):
        """
        TODO: the keystone symbol resolver can be a bit goofy, so we opt not
        to use it (keypatch doesn't, either!) for now. it has been left here
        for future testing or further bugfixing of keystone

        NOTE: this *CAN* be beneficial to use for MULTI INSTRUCTION assembly,
        such as assembling a block of instructions (eg. shellcode, or a
        more complex patch) which makes use of labels within said block.
        """
        symbol = symbol.decode('utf-8')

        #
        # some symbols in IDA names / chars cannot pass cleanly through
        # keystone. for that reason, we try to replace some 'problematic'
        # characters that may appear in IDA symbols (and then disas text)
        #
        # when they pop back up here, in keystone's symbol resolver, we
        # try to subsitute the 'problematic' characters back in so that
        # we can look up the original symbol value in IDA
        #

        if 'AT_SPECIAL_AT' in symbol:
            symbol = symbol.replace('AT_SPECIAL_AT', '@')
        if 'QU_SPECIAL_QU' in symbol:
            symbol = symbol.replace('QU_SPECIAL_QU', '?')

        #
        # XXX: pretty messy, sorry. no way to resolve 'symbol collisions'
        # that could technically manifest from IDA
        #

        for sym_value, sym_real_name in resolve_symbol(self._ks_address, symbol):
            value[0] = sym_value
            return True

        # symbol resolution failed
        return False

    def rewrite_symbols(self, assembly, ea):
        """
        Rewrite the symbols in the given assembly text to their concrete values.
        """

        #
        # TODO: is there a reason i'm not using parse_disassembly_components()
        # here? I forget, this code probably predates that.
        #

        mnem, sep, ops = assembly.partition(' ')

        # 'mnem' appears to be an instruction prefix actually, so keep parsing
        if mnem in KNOWN_PREFIXES:
            real_mnem, sep, ops = ops.partition(' ')
            mnem += ' ' + real_mnem

        #
        # scrape symbols from *just* the operands text, as that's the only
        # place we would expect to see them in assembly code anyway!
        #

        symbols = scrape_symbols(ops)

        #
        # if the symbol count is too high, it might take 'too long' to try
        # and resolve them all in a big database. At 10+ symbols, it is
        # probably just an invalid input to the assembler as is (at least,
        # for a single instruction ...)
        #
        # TODO: really, we should be throwing a set of more descriptive
        # errors from the assembler that the dialog can render rather
        # than trying to catch issues in preview.py (UI land)
        #

        if len(symbols) > 10:
            print("Aborting symbol re-writing, too (%u) many potential symbols..." % (len(symbols)))
            return assembly

        #
        # with a list of believed symbols and their text location, we will
        # try to resolve a value for each text symbol and swap a raw hex
        # number in to replace the symbol text
        #
        #   eg. 'mov    eax, [foo]' --> 'mov    eax, [0x410800]'
        #
        # where 'foo' was a symbol name entered by the user, but we can
        # query IDA to try and resolve (func address, data address, etc)
        #

        prev_index = 0
        new_ops = ''

        for name, location in symbols:
            sym_start, sym_end = location

            for sym_value, sym_real_name in resolve_symbol(ea, name):
                sym_value_text = '0x%X' % sym_value

                #
                # we are carefully carving around the original symbol text
                # to build out a new 'string' for the full operand text
                #

                new_ops += ops[prev_index:sym_start] + sym_value_text
                prev_index = sym_end

                #
                # TODO: the case where resolve_symbol can return 'multiple'
                # results (eg, a symbol 'collision') is currently unhandled
                # but could happen in very rare cases
                #
                # by always breaking on the first iteration of this loop,
                # we're effectively always selecting the first symbol value
                # without any consideration of others (TODO how?)
                #
                # lol, this symbol resolution / rewriting is ugly enough as
                # is. it will probably have to get re-written an simplified
                # at a later time, if possible :S
                #

                break

            else:
                #print("%08X: Failed to resolve possible symbol '%s'" % (ea, name))
                continue

        new_ops += ops[prev_index:]
        raw_assembly = mnem + sep + new_ops

        #
        # return assembly text that has (ideally) had possible symbols
        # replaced with unambiguous values that are easy for the assembler
        # to consume
        #

        return raw_assembly

    def asm(self, assembly, ea=0, resolve=True):
        """
        Assemble the given instruction with an optional base address.

        TODO/v0.2.0: support 'simple' one-line but multi-instruction assembly?
        """
        unaliased_assembly = self.unalias(assembly)

        if TEST_KS_RESOLVER:
            raw_assembly = unaliased_assembly
            raw_assembly = raw_assembly.replace('@', 'AT_SPECIAL_AT')
            raw_assembly = raw_assembly.replace('?', 'QU_SPECIAL_QU')
            self._ks_address = ea
        elif resolve:
            raw_assembly = self.rewrite_symbols(unaliased_assembly, ea)
        else:
            raw_assembly = unaliased_assembly

        #print(" Assembling: '%s' @ ea 0x%08X" % (raw_assembly, ea))

        #
        # TODO: this whole function is kind of gross, and it would be good if
        # we could surface at least 'some' of the error information that
        # keystone can produce of failures
        #

        # try assemble
        try:
            asm_bytes, count = self._ks.asm(raw_assembly, ea, True)
            if asm_bytes == None:
                return bytes()
        except Exception as e:
            #print("FAIL", e)
            return bytes()

        # return the generatied instruction bytes if keystone succeeded
        return asm_bytes

    def is_conditional_jump(self, mnem):
        """
        Return True if the given mnemonic is a conditional jump.

        TODO: 'technically' I think IDA might actually have some CPU
        agnostic API's to tell if an instruction is a conditional jump.

        so maybe the need to manually define CONDITIONAL_JUMPS mnemonics
        for CPU's can be removed in a future version of this plugin...
        """
        return bool(mnem.upper() in self.CONDITIONAL_JUMPS)

    def nop_buffer(self, start_ea, end_ea):
        """
        Generate a NOP buffer for the given address range.
        """
        range_size = end_ea - start_ea
        if range_size < 0:
            return bytes()

        # fetch the bytes for a NOP instruction (and its size)
        nop_data = self.asm('nop', start_ea)
        nop_size = len(nop_data)

        # generate a buffer of NOP's equal to the range we are filling in
        nop_buffer = nop_data * (range_size // nop_size)

        return nop_buffer

    #--------------------------------------------------------------------------
    # Assembly Normalization
    #--------------------------------------------------------------------------

    def format_prefix(self, insn, prefix):
        """
        Return an assembler compatible version of the given prefix.
        """
        return prefix

    def format_mnemonic(self, insn, mnemonic):
        """
        Return an assembler compatible version of the given mnemonic.
        """
        return mnemonic

    def format_memory_op(self, insn, n):
        """
        Return an assembler compatible version of the given memory op.
        """
        op_text = ida_ua.print_operand(insn.ea, n, 0, self._NO_OP_TYPE)
        return op_text

    def format_imm_op(self, insn, n):
        """
        Return an assembler compatible version of the given imm val op.
        """
        return ida_ua.print_operand(insn.ea, n)

    def format_assembly(self, ea):
        """
        Return assembler compatible disassembly for the given address.

        This function sort re-implements the general instruction printing
        pipeline of the loaded processor module, but just way more shady.
        """
        prefix, mnem, _ = get_disassembly_components(ea)

        #
        # TODO: this 'used' to be used to handle a failure from the above
        # function, but I don't think it is needed anymore. as the above func
        # has been dramatically simplified to parse 'dumber' than it used to
        #
        # it had to do with something with trying to parse/format addresses
        # that would return stuff like 'align 10h' (not real instructions)
        #

        if mnem is None:
            return ''

        #
        # decode the instruction just once so the CPU-specific layers can
        # read and use it to apply specific fixups when needed
        #

        insn = ida_ua.insn_t()
        ida_ua.decode_insn(insn, ea)

        # this will accumulate the final fixed up text for all ops
        ops = []

        # this will hold the fixed up operand text for the current op
        op_text = ''

        #
        # generate the operand text for each op, with callbacks into the
        # processor specific fixups as necessary for each op type
        #

        for op in insn.ops:

            #
            # NOTE/PERF: these if/elif statements have been arranged based on
            # frequency (at least in x86/x64) for performance reasons
            #
            # be careful re-ordering them, as it may make assemble_all(...)
            # run twice as slow!!
            #

            if op.type in [ida_ua.o_reg, ida_ua.o_far, ida_ua.o_near]:
                op_text = ida_ua.print_operand(ea, op.n)

            # reached final operand in this instruction
            elif op.type == ida_ua.o_void:
                break

            #
            # TODO: ideally we should allow users to toggle between 'pretty'
            # and 'raw' displacement / phrase ops, but I think there's keystone /
            # LLVM weirdness that is causing some bad assembly to be generated?
            #
            #       IDA: 'mov     [esp+6Ch+dest], esi'
            #       RAW: 'mov     [esp+6Ch+0xFFFFFF94], esi'
            #  WHICH IS: 'mov     [esp], esi'
            #
            # but this is what keystone 'evaluates' and generates 'bad' asm for
            #
            #       IDA: 'mov     [esp], esi'             -- 89 34 24
            #  keystone: 'mov     [esp+0x100000000], esi' -- 89 74 24 (? invalid asm)
            #
            # this will have to be investigated later. so for now we generate asm
            # without IDA's special offsetting...
            #

            elif op.type in [ida_ua.o_displ, ida_ua.o_phrase]:
                op_text = ida_ua.print_operand(ea, op.n, 0, self._NO_OP_TYPE)

            elif op.type == ida_ua.o_imm:
                op_text = self.format_imm_op(insn, op.n)

            elif op.type == ida_ua.o_mem:
                op_text = self.format_memory_op(insn, op.n)

            else:
                op_text = ida_ua.print_operand(ea, op.n)

            #
            # the operand is marked as invisible according to IDA,
            # so we shouldn't be showing / generating text for it anyway
            # (eg. Op4 for UMULH in ARM64)
            #

            if not(op.flags & ida_ua.OF_SHOW):
                continue

            ops.append(op_text)

        ops = list(map(ida_lines.tag_remove, filter(None, ops)))
        prefix = self.format_prefix(insn, prefix)
        mnem = self.format_mnemonic(insn, mnem)

        if prefix:
            mnem = prefix + ' ' + mnem

        # generate the fully disassembled instruction / text
        text = '%s %s' % (mnem.ljust(7, ' '), ', '.join(ops))

        # TODO/XXX: ehh this should probably be cleaned up / moved in v0.2.0
        for banned in ['[offset ', '(offset ', ' offset ', ' short ', ' near ptr ', ' far ptr ', ' large ']:
            text = text.replace(banned, banned[0])

        return text.strip()

    def unalias(self, assembly):
        """
        Translate an instruction alias / shorthand to its full version.
        """
        return assembly

#------------------------------------------------------------------------------
# x86 / x86_64
#------------------------------------------------------------------------------

class AsmX86(KeystoneAssembler):
    """
    Intel x86 & x64 specific wrapper for Keystone.
    """

    UNCONDITIONAL_JUMP = 'JMP'
    CONDITIONAL_JUMPS = \
    [
        'JZ', 'JE', 'JNZ', 'JNE', 'JC', 'JNC',
        'JO', 'JNO', 'JS', 'JNS', 'JP', 'JPE',
        'JNP', 'JPO', 'JCXZ', 'JECXZ', 'JRCXZ',
        'JG', 'JNLE', 'JGE', 'JNL', 'JL', 'JNGE',
        'JLE', 'JNG', 'JA', 'JNBE', 'JAE', 'JNB',
        'JB', 'JNAE', 'JBE', 'JNA'
    ]

    UNSUPPORTED_MNEMONICS = \
    [
        # intel CET
        'ENDBR32', 'ENDBR64',
        'RDSSPD', 'RDSSPQ',
        'INCSSPD', 'INCSSPQ',
        'SAVEPREVSSP', 'RSTORSSP',
        'WRSSD', 'WRSSQ', 'WRUSSD', 'WRUSSQ',
        'SETSSBSY', 'CLRSSBSY',

        # misc
        'MONITOR', 'MWAIT', 'MONITORX', 'MWAITX',
        'INVPCID',

        # bugged?
        'REPE CMPSW',
    ]

    def __init__(self, inf):
        arch = keystone.KS_ARCH_X86

        if inf.is_64bit():
            mode = keystone.KS_MODE_64
            self.MAX_PREVIEW_BYTES = 7
        elif inf.is_32bit():
            mode = keystone.KS_MODE_32
            self.MAX_PREVIEW_BYTES = 6
        else:
            mode = keystone.KS_MODE_16

        # initialize keystone-based assembler
        super(AsmX86, self).__init__(arch, mode)

    #--------------------------------------------------------------------------
    # Intel Assembly Formatting / Fixups
    #--------------------------------------------------------------------------

    def format_mnemonic(self, insn, mnemonic):
        original = mnemonic.strip()

        # normalize the mnemonic case for fixup checking
        mnemonic = original.upper()

        if mnemonic == 'RETN':
            return 'ret'
        if mnemonic == 'XLAT':
            return 'xlatb'

        # no mnemonic fixups, return the original
        return original

    def format_memory_op(self, insn, n):

        #
        # because IDA generates some 'non-standard' syntax in favor of human
        # readability, we have to fixup / re-print most memory operands to
        # reconcile them with what the assembler expects.
        #
        # (i'll go through later and document examples of each 'case' below)
        #

        op_text = super(AsmX86, self).format_memory_op(insn, n)
        op_text = ida_lines.tag_remove(op_text)

        #
        # since this is a memory operation, we expect there to be a '[...]'
        # present in the operand text. if there isn't we should try to wrap
        # the appropriate parts of operand with square brackets
        #

        if '[' not in op_text:

            #
            # this case is to wrap segment:offset kind of prints:
            #
            # eg.
            #  - .text:00000001400AD89A 65 48 8B 04 25 58 00+        mov     rax, gs:58h
            #
            # NOTE: the secondary remaining[0] != ':' check is to avoid 'cpp'
            # cases, basically ensuring we are not modifying a '::'
            #
            # eg.
            #  - .text:000000014000A4F2 48 8D 05 EF 14 25 00         lea     rax, const QT::QSplitter::'vftable'
            #

            start, sep, remaining = op_text.partition(':')
            if sep and remaining[0] != ':':
                op_text = start + sep + '[' + remaining + ']'

            #
            # eg.
            #  - .text:08049F52 F6 05 A4 40 0F 08 02         test    byte ptr dword_80F40A4, 2
            #

            elif ' ptr ' in op_text:
                start, sep, remaining = op_text.partition(' ptr ')
                op_text = start + sep + '[' + remaining + ']'

            #
            # eg.
            #  - .text:000000014002F0C6 48 8D 0D 53 B9 E2 00         lea     rcx, unk_140E5AA20
            #

            else:
                op_text = '[' + op_text + ']'

        if ' ptr ' in op_text and self._mode is keystone.KS_MODE_32:
            return op_text

        #
        # TODO: document these cases
        #

        op = insn.ops[n]
        seg_reg = (op.specval & 0xFFFF0000) >> 16

        if seg_reg:
            #print("SEG REG: 0x%X 0x%X" % (op.specval & 0xFFFF, ((op.specval & 0xFFFF0000) >> 16)))
            seg_reg_name = ida_idp.ph.regnames[seg_reg]
            if seg_reg_name == 'cs':
                op_text = op_text.replace('cs:', '')
            elif seg_reg_name not in op_text:
                op_text = '%s:%s' % (seg_reg_name, op_text)

        if ' ptr ' in op_text:
            return op_text

        t_name = get_dtype_name(op.dtype, ida_ua.get_dtype_size(op.dtype))
        op_text = '%s ptr %s' % (t_name, op_text)

        return op_text

    def format_imm_op(self, insn, n):
        op_text = super(AsmX86, self).format_imm_op(insn, n)
        if '$+' in op_text:
            op_text = ida_ua.print_operand(insn.ea, n, 0, self._NO_OP_TYPE)
        return op_text

    def unalias(self, assembly):

        # normalize spacing / capitalization
        parts = list(filter(None, assembly.lower().split(' ')))
        full = ' '.join(parts)
        if not full:
            return assembly

        #
        # IDA64 likes to print 'int 3' for 'CC', but keystone assembles this
        # to 'CD 03'... so we alias 'int 3' to 'int3' here instead which will
        # emit the preferred form 'CC'
        #

        if full == 'int 3':
            return 'int3'

        #
        # TODO/XXX: keystone doesn't know about 'movsd' ? so we correct it
        # here for now ... this will handle 'movsd' / 'rep* movsd'
        #

        if parts[-1] == 'movsd':

            if self._mode & keystone.KS_MODE_64:
                regs = ('rdi', 'rsi')
            else:
                 regs = ('edi', 'esi')

            # preserves prefix ... if there was one
            return assembly + ' dword ptr [%s], dword ptr [%s]' % regs

        # no special aliasing / fixups
        return assembly

#------------------------------------------------------------------------------
# ARM / ARM64
#------------------------------------------------------------------------------

class AsmARM(KeystoneAssembler):
    """
    ARM specific wrapper for Keystone.
    """

    UNCONDITIONAL_JUMP = 'B'
    CONDITIONAL_JUMPS = \
    [
        # ARM
        'BEQ', 'BNE', 'BCC', 'BCS', 'BVC', 'BVS',
        'BMI', 'BPL', 'BHS', 'BLO', 'BHI', 'BLS',
        'BGE', 'BLT', 'BGT', 'BLE'

        # ARM64
        'B.EQ', 'B.NE', 'B.CS', 'B.CC', 'B.MI', 'B.PL',
        'B.VS', 'B.VC', 'B.HI', 'B.LS', 'B.GE', 'B.LT',
        'B.GT', 'B.LE', 'CBNZ', 'CBZ', 'TBZ', 'TBNZ'
    ]

    UNSUPPORTED_MNEMONICS = \
    [
        'ADR', 'ADRL',

        # Pointer Authentication
        'AUTDA', 'AUTDZA', 'AUTDB', 'AUTDZB',
        'AUTIA', 'AUTIA1716', 'AUTIASP', 'AUTIAZ', 'AUTIZA',
        'AUTIB', 'AUTIB1716', 'AUTIBSP', 'AUTIBZ', 'AUTIZB',

        'BLRAA', 'BLRAAZ', 'BLRAB', 'BLRABZ',
        'BRAA',  'BRAAZ', 'BRAB', 'BRABZ',

        'PACDA', 'PACDZA', 'PACDB', 'PACDZB', 'PACGA',
        'PACIA', 'PACIA1716', 'PACIASP', 'PACIAZ', 'PACIZA',
        'PACIB', 'PACIB1716', 'PACIBSP', 'PACIBZ', 'PACIZB',
        'RETAA', 'RETAB',

        'XPACD', 'XPACI', 'XPACLRI'

        # TODO: MRS and MOV (32/64 bit) are semi-supported too
    ]

    def __init__(self, inf):

        # ARM64
        if inf.is_64bit():
            arch = keystone.KS_ARCH_ARM64

            if inf.is_be():
                mode = keystone.KS_MODE_BIG_ENDIAN
            else:
                mode = keystone.KS_MODE_LITTLE_ENDIAN

            # AArch64 does not use THUMB
            self._ks_thumb = None

        # ARM
        else:
            arch = keystone.KS_ARCH_ARM

            if inf.is_be():
                mode = keystone.KS_MODE_ARM | keystone.KS_MODE_BIG_ENDIAN
                self._ks_thumb = keystone.Ks(arch, keystone.KS_MODE_THUMB | keystone.KS_MODE_BIG_ENDIAN)
            else:
                mode = keystone.KS_MODE_ARM | keystone.KS_MODE_LITTLE_ENDIAN
                self._ks_thumb = keystone.Ks(arch, keystone.KS_MODE_THUMB | keystone.KS_MODE_LITTLE_ENDIAN)

        # initialize keystone-based assembler
        super(AsmARM, self).__init__(arch, mode)

        # pre-assemble for later, repeated use
        self.__ARM_NOP_4, _ = self._ks.asm('NOP', as_bytes=True)
        if self._ks_thumb:
            self.__THUMB_NOP_2, _ = self._ks_thumb.asm('NOP', as_bytes=True)
            self.__THUMB_NOP_4, _ = self._ks_thumb.asm('NOP.W', as_bytes=True)

    def asm(self, assembly, ea=0, resolve=True):

        # swap engines when trying to assemble to a THUMB region
        if self.is_thumb(ea):
            ks = self._ks
            self._ks = self._ks_thumb
            data = super(AsmARM, self).asm(assembly, ea, resolve)
            self._ks = ks
            return data

        # assemble as ARM
        return super(AsmARM, self).asm(assembly, ea, resolve)

    @staticmethod
    def is_thumb(ea):
        """
        Return True if the given address is marked as THUMB.
        """
        return bool(ida_segregs.get_sreg(ea, ida_idp.str2reg('T')) == 1)

    def nop_buffer(self, start_ea, end_ea):
        """
        Generate a NOP buffer for the given address range.
        """
        range_size = end_ea - start_ea
        if range_size < 0:
            return bytes()

        #
        # TODO/XXX: how should we handle 'mis-aligned' NOP actions? or
        # truncated range? (eg, not enough bytes to fill as complete NOPs...
        #
        # Should we just reject them here? or attempt to NOP some? Need to
        # ensure UI fails gracefully, etc.
        #

        # the crafted buffer on NOP instructions to return
        nop_list = []

        #
        # with ARM, it is imperative we attempt to retain the size of the
        # instruction being NOP'd. this is to help account for cases such as
        # the ITTT blocks in THUMB:
        #
        # __text:000021A2 1E BF               ITTT NE
        # __text:000021A4 D4 F8 C4 30         LDRNE.W         R3, [R4,#0xC4]
        # __text:000021A8 43 F0 04 03         ORRNE.W         R3, R3, #4
        # __text:000021AC C4 F8 C4 30         STRNE.W         R3, [R4,#0xC4]
        # __text:000021B0 94 F8 58 30         LDRB.W          R3, [R4,#0x58]
        #
        # replacing these 4-byte THUMB instructions with 2-byte THUMB NOP's
        # breaks the intrinsics of the conditional block. therefore, we
        # will attempt to replace THUMB instructions with a NOP of the same
        # size as the original instruction
        #

        cur_ea = ida_bytes.get_item_head(start_ea)
        while cur_ea < end_ea:
            item_size = ida_bytes.get_item_size(cur_ea)

            # special handling to pick THUMB 2 / 4 byte NOP as applicable
            if self.is_thumb(cur_ea):
                if item_size == 2:
                    nop_list.append(self.__THUMB_NOP_2)
                else:
                    nop_list.append(self.__THUMB_NOP_4)

            # NOP'ing a normal 4-byte ARM instruction
            else:
                nop_list.append(self.__ARM_NOP_4)

            # continue to next instruction
            cur_ea += item_size

        # return a buffer of (NOP) instruction bytes
        return b''.join(nop_list)

    #--------------------------------------------------------------------------
    # ARM Assembly Formatting / Fixups
    #--------------------------------------------------------------------------

    def format_memory_op(self, insn, n):
        op = insn.ops[n]

        # ARM / ARM64
        if ida_idp.ph.regnames[op.reg] == 'PC':
            offset = (op.addr - insn.ea) - 8
            op_text = '[PC, #%s0x%X]' % ('-' if offset < 0 else '', abs(offset))
            return op_text

        #
        # TODO: THUMB-ish... note this is kind of groess and should
        # probably be cleaned up / documented better. I don't think it's a
        # fair assumption that all THUMB memory references are PC rel? but
        # maybe that's true. (I'm not an ARM expert)
        #

        elif self.is_thumb(insn.ea):
            offset = (op.addr - insn.ea) - 4 + (insn.ea % 4)
            op_text = '[PC, #%s0x%X]' % ('-' if offset < 0 else '', abs(offset))
            return op_text

        op_text = ida_lines.tag_remove(super(AsmARM, self).format_memory_op(insn, n))

        if op_text[0] == '=':
            op_text = '#0x%X' % op.addr

        return op_text

    def format_imm_op(self, insn, n):
        """
        TODO: this is temporary, until we do work on formatting IDA's
        ARM memory ref 'symbols' (which are often imms on ARM)
        """
        op_text = ida_ua.print_operand(insn.ea, n, 0, self._NO_OP_TYPE)
        return op_text

    def unalias(self, assembly):
        prefix, mnemonic, ops = parse_disassembly_components(assembly)

        # IDA seems to prefer showing 'STMFA', but keystone expects 'STMIB'
        if mnemonic.upper() == 'STMFA':
            return ' '.join([prefix, 'STMIB', ops])

        return assembly

#------------------------------------------------------------------------------
# PPC / PPC64 TODO
#------------------------------------------------------------------------------

class AsmPPC(KeystoneAssembler):

    def __init__(self, inf):
        arch = keystone.KS_ARCH_PPC

        if inf.is_64bit():
            mode = keystone.KS_MODE_PPC64
        else:
            mode = keystone.KS_MODE_PPC32

        # TODO: keystone does not support Little Endian mode for PPC?
        #if arch_name == 'ppc':
        #    mode += keystone.KS_MODE_BIG_ENDIAN

        # initialize keystone-based assembler
        super(AsmPPC, self).__init__(arch, mode)

#------------------------------------------------------------------------------
# MIPS / MIPS64 TODO
#------------------------------------------------------------------------------

class AsmMIPS(KeystoneAssembler):

    def __init__(self, inf):
        arch = keystone.KS_ARCH_MIPS

        if inf.is_64bit():
            mode = keystone.KS_MODE_MIPS64
        else:
            mode = keystone.KS_MODE_MIPS32

        if inf.is_be():
            mode |= keystone.KS_MODE_BIG_ENDIAN
        else:
            mode |= keystone.KS_MODE_LITTLE_ENDIAN

        # initialize keystone-based assembler
        super(AsmMIPS, self).__init__(arch, mode)

#------------------------------------------------------------------------------
# SPARC TODO
#------------------------------------------------------------------------------

class AsmSPARC(KeystoneAssembler):

    def __init__(self, inf):
        arch = keystone.KS_ARCH_SPARC

        if inf.is_64bit():
            mode = keystone.KS_MODE_SPARC64
        else:
            mode = keystone.KS_MODE_SPARC32

        if inf.is_be():
            mode |= keystone.KS_MODE_BIG_ENDIAN
        else:
            mode |= keystone.KS_MODE_LITTLE_ENDIAN

        # initialize keystone-based assembler
        super(AsmSPARC, self).__init__(arch, mode)

#------------------------------------------------------------------------------
# System-Z
#------------------------------------------------------------------------------

class AsmSystemZ(KeystoneAssembler):

    def __init__(self, inf):
        super(AsmSystemZ, self).__init__(keystone.KS_ARCH_SYSTEMZ, keystone.KS_MODE_BIG_ENDIAN)
