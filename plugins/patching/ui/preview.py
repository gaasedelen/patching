import ida_nalt
import ida_name
import ida_bytes
import ida_lines
import ida_idaapi
import ida_kernwin

from patching.util.qt import QT_AVAILABLE
from patching.util.ida import parse_disassembly_components, scrape_symbols
from patching.util.python import hexdump

if QT_AVAILABLE:
    from patching.ui.preview_ui import PatchingDockable

LAST_LINE_IDX = -1

class PatchingController(object):
    """
    The backing logic & model (data) for the patch editing UI.
    """
    WINDOW_TITLE = "Patching"

    def __init__(self, core, ea=ida_idaapi.BADADDR):
        self.core = core
        self.view = None

        #
        # if no context (an address to patch at) was provided, use IDA's
        # current cursor position instead as the origin for the dialog
        #

        if ea == ida_idaapi.BADADDR:
            ea = ida_kernwin.get_screen_ea()

        self._address_origin = ida_bytes.get_item_head(ea)

        # public properties
        self.address = self._address_origin
        self.address_idx = LAST_LINE_IDX
        self.assembly_text = ''
        self.assembly_bytes = b''

        # for error text or other dynamic information to convey to the user
        self.status_message = ''

        # do an initial 'refresh' to populate data for the patching dialog
        self.refresh()

        # connect signals from the plugin core to the patching dialog
        self.core.patches_changed(self.refresh)

        # only create the UI for the patching dialog as needed
        if QT_AVAILABLE:
            self.view = PatchingDockable(self)
            self.view.Show()

    #-------------------------------------------------------------------------
    # Actions
    #-------------------------------------------------------------------------

    def select_address(self, ea, idx=LAST_LINE_IDX):
        """
        Select the given address.
        """
        insn, lineno = self.get_insn_lineno(ea)

        # if the target instruction does not exist
        if insn.address != ea:
            idx = LAST_LINE_IDX

        #
        # clear all clobber highlights if the cursor is moving to a new line
        #
        # TODO/NOTE: this feels a bit dirty / out of place. there is probably
        # a place for it that is more appropriate
        #

        if insn.address != self.address or self.address_idx != idx:
            for insn_cur in self.instructions:
                insn_cur.clobbered = False

        self.address = insn.address
        self.address_idx = idx

        self._update_assembly_text(self.core.assembler.format_assembly(insn.address))

        if self.view:
            self.view.refresh_fields()
            self.view.refresh_cursor()

    def edit_assembly(self, assembly_text):
        """
        Edit the assembly text.
        """
        self._update_assembly_text(assembly_text)

        # refresh visible fields, as the assembled bytes may have changed
        if self.view:
            self.view.refresh_fields()

        # fetch the displayed instruction that the user is 'editing'
        current_insn = self.get_insn(self.address)

        #
        # if the newly assembled instruction is smaller than the existing
        # instruction, there is no need to highlight clobbers
        #

        edit_index = self.instructions.index(current_insn)
        clobber_end = self.address + len(self.assembly_bytes)
        will_clobber = clobber_end > (current_insn.address + current_insn.size)

        # loop through the next N instructions
        for next_insn in self.instructions[edit_index+1:]:
            next_insn.clobbered = (next_insn.address < clobber_end) and will_clobber

        # done marking clobbered instructions, nothing else to do
        if self.view:
            self.view.refresh_code()

    def commit_assembly(self):
        """
        Commit the current assembly.
        """
        if not self.assembly_bytes:
            return

        # patch the instruction at the current address
        self.core.patch(self.address, self.assembly_bytes)

        # refresh lines
        self._refresh_lines()

    def _update_assembly_text(self, assembly_text):
        """
        Update the assembly text (and attempt to assemble it).
        """
        self.assembly_text = assembly_text
        self.assembly_bytes = bytes()
        self.status_message = ''

        #
        # before trying to assemble the user input, we'll try to check for a
        # few problematic and unsupported cases before even attempting to
        # assemble the given text
        #
        # TODO/NOTE: we should probably move this into the 'assembler'
        # class and expose an error reason message/text for failures
        #

        _, mnemonic, operands = parse_disassembly_components(assembly_text)

        #
        # if it looks like the user is trying to assemble an instruction that
        # we KNOW Keystone does not support for whatever reason, we should
        # give them a heads up instead of an 'unspecified error' (...)
        #

        if mnemonic.upper() in self.core.assembler.UNSUPPORTED_MNEMONICS:
            self.status_message = "Keystone does not support this instruction (%s)" % mnemonic
            return

        #
        # in the odd event that a user pastes a massive blob of random text
        # into the the assembly field by accident, the plugin could 'hang'
        # IDA in an attempt to resolve a bunch of words as 'symbols' while
        # assembling the 'text' -- which is not what wen want
        #

        if len(scrape_symbols(operands)) > 10:
            self.status_message = "Too many potential symbols in the assembly text"
            return

        #
        # TODO/XXX/KEYSTONE: 11th hour hack, but Keystone will HANG if the
        # user tries to assemble the following inputs:
        #
        #       .string '
        #       .string "
        #
        # so we're just going to try and block those until we can fix it
        # in Keystone proper :-X
        #

        assembly_normalized = assembly_text.strip().lower()

        if assembly_normalized.startswith('.string'):
            self.status_message = "Unsupported declaration (.string can hang Keystone)"
            return

        #
        # TODO: in v0.2.0 we should try to to re-enable multi-instruction
        # inputs. the only reason it is 'disabled' for now is that I need more
        # time to better define its behavior in the context of the plugin
        #
        # NOTE: Keystone supports 'xor eax, eax; ret;' just fine, it's purely
        # ensuring the rest of this plugin / wrapping layers are going to
        # handle it okay
        #

        if ';' in assembly_normalized:
            self.status_message = "Multi-instruction input not yet supported (';' not allowed)"
            return

        #
        # we didn't catch any 'early' issues with the user input, go ahead
        # and try to assemble it to see what happens
        #

        self.assembly_bytes = self.core.assemble(self.assembly_text, self.address)
        if not self.assembly_bytes:
            self.status_message = '...' # error assembling

    #-------------------------------------------------------------------------
    # Misc
    #-------------------------------------------------------------------------

    def refresh(self):
        """
        Refresh the controller state based on the current IDA state.
        """
        self._refresh_lines()
        self.select_address(self.address)

    def _refresh_lines(self):
        """
        Refresh the disassembly for the dialog based on the current IDA state.
        """
        instructions, current_address = [], self._address_origin

        IMAGEBASE = ida_nalt.get_imagebase()
        PREV_INSTRUCTIONS = 50
        NEXT_INSTRUCTIONS = 50
        MAX_PREVIEW_BYTES = self.core.assembler.MAX_PREVIEW_BYTES

        # rewind a little bit from the target address to create a buffer
        for i in range(PREV_INSTRUCTIONS):
            current_address -= ida_bytes.get_item_size(current_address)

        # generate lines for the region of instructions around the target address
        for i in range(PREV_INSTRUCTIONS + NEXT_INSTRUCTIONS):
            try:
                line = InstructionLine(current_address, MAX_PREVIEW_BYTES)
            except ValueError:
                current_address += 1
                continue
            current_address += line.size
            instructions.append(line)

        self.instructions = instructions

        if self.view:
            self.view.refresh_code()

    def get_insn(self, ea):
        """
        Return the instruction text object for the given address.
        """
        insn, _ = self.get_insn_lineno(ea)
        return insn

    def get_insn_lineno(self, ea):
        """
        Return the instruction text object and its line number for the given address.
        """
        lineno = 0
        for insn in self.instructions:
            if insn.address <= ea < insn.address + insn.size:
                return (insn, lineno)
            lineno += insn.num_lines
        return (None, 0)

#-----------------------------------------------------------------------------
#
#-----------------------------------------------------------------------------

COLORED_SEP = ida_lines.COLSTR('|', ida_lines.SCOLOR_SYMBOL)

class InstructionLine(object):
    """
    A helper for drawing an instruction in a simple IDA viewer.
    """
    def __init__(self, ea, max_preview=4):

        #
        # NOTE/XXX: this kind of needs to be called first, otherwise
        # 'get_item_size(ea)' may fetch a stale size for the instruction
        # if it was *just* patched
        #

        self.colored_instruction = ida_lines.generate_disasm_line(ea)
        if not self.colored_instruction:
            raise ValueError("Bad address... 0x%08X" % ea)

        # a label / jump target if this instruction has one
        self.name = ida_name.get_short_name(ea)

        # the number of lines this instruction object will render as
        self.num_lines = 1 + (2 if self.name else 0)

        # info about the instruction
        self.size = ida_bytes.get_item_size(ea)
        self.bytes = ida_bytes.get_bytes(ea, self.size)
        self.address = ea

        # flag to tell code view to highlight line as clobbered
        self.clobbered = False

        # how many instruction bytes to show before eliding
        self._max_preview = max_preview

    @property
    def colored_address(self):
        """
        Return an IDA-colored string for the instruction address.
        """
        pretty_address = ida_lines.COLSTR('%08X' % self.address, ida_lines.SCOLOR_PREFIX)
        return pretty_address

    @property
    def colored_bytes(self):
        """
        Return an IDA-colored string for the instruction bytes.
        """
        MAX_BYTES = self._max_preview

        if self.size > MAX_BYTES:
            text_bytes = hexdump(self.bytes[:MAX_BYTES-1]).ljust(3*MAX_BYTES-1, '.')
        else:
            text_bytes = hexdump(self.bytes).ljust(3*MAX_BYTES-1, ' ')

        pretty_bytes = ida_lines.COLSTR(text_bytes, ida_lines.SCOLOR_BINPREF)
        return pretty_bytes

    @property
    def line_blank(self):
        """
        Return an IDA-colored string for a blank line at this address.
        """
        byte_padding = ' ' * ((self._max_preview*3) - 1)
        self._line_blank = ' '.join(['', self.colored_address, COLORED_SEP, byte_padding , COLORED_SEP])
        return self._line_blank

    @property
    def line_name(self):
        """
        Return an IDA-colored string for the name text line (if a named address).
        """
        if not self.name:
            return None

        pretty_name = ida_lines.COLSTR(self.name, ida_lines.SCOLOR_CNAME) + ':'
        byte_padding = ' ' * ((self._max_preview*3) - 1)

        self._line_name = ' '.join(['', self.colored_address, COLORED_SEP, byte_padding , COLORED_SEP, pretty_name])
        return self._line_name

    @property
    def line_instruction(self):
        """
        Return an IDA-colored string for the instruction text line.
        """
        self._line_text = ' '.join(['', self.colored_address, COLORED_SEP, self.colored_bytes, COLORED_SEP + '  ', self.colored_instruction])
        return self._line_text