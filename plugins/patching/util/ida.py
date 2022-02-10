import re
import ctypes

import ida_ua
import ida_ida
import ida_idp
import ida_auto
import ida_nalt
import ida_name
import ida_bytes
import ida_lines
import ida_idaapi
import ida_struct
import ida_kernwin
import ida_segment

from .qt import *
from .python import swap_value

#------------------------------------------------------------------------------
# IDA Hooks
#------------------------------------------------------------------------------

class UIHooks(ida_kernwin.UI_Hooks):
    def ready_to_run(self):
        pass
    def get_lines_rendering_info(self, out, widget, rin):
        pass
    def populating_widget_popup(self, widget, popup, ctx):
        pass

class IDPHooks(ida_idp.IDP_Hooks):
    def ev_ending_undo(self, action_name, is_undo):
        pass

class IDBHooks(ida_idp.IDB_Hooks):
    def auto_empty_finally(self):
        pass

#------------------------------------------------------------------------------
# IDA Misc
#------------------------------------------------------------------------------

def is_reg_name(reg_name):
    """
    Return True if the given string is a known register name.
    """
    ri = ida_idp.reg_info_t()
    return bool(ida_idp.parse_reg_name(ri, reg_name))

def is_mnemonic(mnemonic):
    """
    Return True if the given string is a known mnemonic (roughly).

    TODO: remove or offload to Keystone if possible? this is just 'best effort'
    TODO: actually this can probably be removed now? no longer used...
    """

    # cache known mnemonics for the current proc on the first invocation
    if not hasattr(is_mnemonic, 'known_mnemonics'):
        is_mnemonic.known_mnemonics = set([name.upper() for name, _ in ida_idp.ph.instruc])

    # check if the given mnemonic is in the list of known mnemonics
    mnemonic = mnemonic.upper()
    return bool(mnemonic in is_mnemonic.known_mnemonics)

def is_range_patched(start_ea, end_ea=None):
    """
    Return True if a patch exists within the given address range.
    """
    if end_ea == None:
        end_ea = start_ea + 1

    def visitor(ea, file_offset, original_value, patched_value):
        return 1

    return bool(ida_bytes.visit_patched_bytes(start_ea, end_ea, visitor))

def apply_patches(filepath):
    """
    Apply the current IDB patches to the given filepath.
    """

    with open(filepath, 'r+b') as f:

        #
        # a visitor function that will be called for each patched byte.
        #
        # NOTE: this is a python version of IDA's built in 'Apply patches...'
        # routine that has simply been reverse engineered
        #

        def visitor(ea, file_offset, original_value, patched_value):

            # the patched byte does not have a know file address
            if file_offset == ida_idaapi.BADADDR:
                print("%08X: has no file mapping (original: %02X patched: %02X)...skipping...\n" % (ea, original_value, patched_value))
                return 0

            # seek to the patch location
            f.seek(file_offset)

            # fetch the 'number of bits in a byte' for the given address (? lol)
            bits = ida_bytes.nbits(ea)

            # round the number of bits up to bytes
            num_bytes = (bits + 7) // 8

            # IDA does this, basically (swap_value(...)) so we will too
            if ida_ida.inf_is_wide_high_byte_first():
                byte_order = 'big'
            else:
                byte_order = 'little'

            # convert the int/long patch value to bytes (and swap endianess, if needed)
            patched_value = patched_value.to_bytes(num_bytes, byte_order)

            # write the patched byte(s) to the output file
            f.write(patched_value)

            #
            # return 0 so that the visitor keeps going to the next patched bytes
            # instead of stopping after this one.
            #

            return 0

        #
        # RUN THE VISITOR / APPLY PATCHES
        #

        ida_bytes.visit_patched_bytes(0, ida_idaapi.BADADDR, visitor)

        #
        # all done, file will close as we leave this 'with' scoping
        #

        pass

    # done done
    return

#------------------------------------------------------------------------------
# IDA UI
#------------------------------------------------------------------------------

def attach_submenu_to_popup(popup_handle, submenu_name, prev_action_name):
    """
    Create an IDA submenu AFTER the action name specified by prev_action_name.

    TODO/XXX/HACK/Hex-Rays: this is a workaround for not being able to create
    and position submenu groups for rightclick menus
    """
    if not QT_AVAILABLE:
        return None

    # cast an IDA 'popup handle' pointer back to a QMenu object
    p_qmenu = ctypes.cast(int(popup_handle), ctypes.POINTER(ctypes.c_void_p))[0]
    qmenu = sip.wrapinstance(int(p_qmenu), QtWidgets.QMenu)

    # create a Qt (sub)menu that can be injected into an IDA-originating menu
    submenu = QtWidgets.QMenu(submenu_name)

    # search for the target action to insert the submenu next to
    all_actions = list(qmenu.actions())
    for i, current_action in enumerate(all_actions[:-1]):
        if current_action.text() == prev_action_name:
            insertion_point = all_actions[i+1]
            qmenu.insertMenu(insertion_point, submenu)
            break

    #
    # if we did not find the action we wanted to place the new submenu after,
    # simply append it to the end of the menu
    #

    else:
        qmenu.addMenu(submenu)

    #
    # not totally sure if we need to be managing the lifetime of this submenu
    # even after it has been inserted. so we return it here, just in-case.
    #

    return submenu

#------------------------------------------------------------------------------
# Symbols
#------------------------------------------------------------------------------

# TODO: err this might not be a good assumption for mangling... eg '()'
IGNORED_CHARS = R"!,[]{}#+-*:"
IGNORED_CHARS_MAP = {ord(x): ' ' for x in IGNORED_CHARS}
IGNORED_REGISTERS = set()
IGNORED_KEYWORDS = set(
    [
        # x86 / x64
        'byte', 'short', 'word', 'dword', 'qword', 'xword', 'xmmword', 'ymmword', 'tbyte', 'large', 'long', 'near', 'far', 'ptr', 'offset',

        # ARM
        'eq', 'ne', 'cs', 'hs', 'cc', 'lo', 'mi', 'pl', 'vs', 'vc', 'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al'
    ]
)

def scrape_symbols(disassembly_text):
    """
    Attempt to scrape symbol-like values from a line of disassembly.
    """
    global IGNORED_REGISTERS
    symbols = []

    # split a comment off the given disassembly text, if present
    #x, sep, y = disassembly_text.rpartition('; ')
    #dis, cmt = (x, y) if sep else (y, x)
    assert ';' not in disassembly_text

    #
    # TODO: I'm really not sure how we should deal with cpp / demangled-ish
    # symbols in disassembly text. if we see something like foo::bar(...)
    # in the given disassembly text, our code is going to explode
    #
    # so for now we're just going to make no effort to parse out possible
    # cpp symbols and will figure out how to deal with them later :/
    #

    if '::' in disassembly_text or '`' in disassembly_text:
        return []

    # remove common disas chars that will not appear in an IDA name
    dis = disassembly_text.translate(IGNORED_CHARS_MAP)

    #
    # regex match any remaining 'non-whitespace' text, which should have its
    # position preserved from the original string. this should allow us to
    # return the symbols and their index in the given text
    #

    for m in re.finditer(r'\S+', dis):

        # normalize the potential symbol text
        original_symbol = m.group()
        word = original_symbol.lower()

        # ignore previously seen registers (fastpath)
        if word in IGNORED_REGISTERS:
            continue

        # ignore numbers / immediates (only imms can start with a number)
        if word[0] in '0123456789':
            continue

        # ignore IDA keywords (approximate)
        if word in IGNORED_KEYWORDS:
            continue

        # ignore new registers (and cache it for future scrapes)
        if is_reg_name(word):
            IGNORED_REGISTERS.add(word)
            continue

        # XXX: kind of a hack for things like 'movzx   eax, ds:(jump_table_11580-20h)[eax]'
        if original_symbol[0] == '(':
            original_symbol = original_symbol[1:]

        # eg: '$)'
        elif original_symbol[-1] == ')' and '(' not in original_symbol:
            original_symbol = original_symbol[:-1]

        # possible symbol!
        symbols.append((original_symbol, m.span()))

    # return list of likely symbols
    return symbols

def resolve_symbol(from_ea, name):
    """
    Return an address or value for the given symbol.

    TODO/Hex-Rays: this function is overly complex and is probably something
    that should be baked into IDA as more aggressive 'resolve symbol' API imo

    this function will yield matching symbol values (operating as a
    generator). this is because IDA can show 'visually identical' symbols in
    rendered instructions that have different 'true' names.

    eg. a func named '.X.' appears as '_X_' in IDA's x86 disassembly. but
    a second func could be named '.X_' which will also appear as '_X_'

    while this is maybe okay in the context of IDA (where it has concrete
    instruction / address info) ... it is not okay for trying to 'resolve'
    a symbol when your only information is assembly text.

    if the user types in the following instruction:

      eg.     call      _X_

    how can we know which value to select as a jump target?

    (the user will have to decide... through some symbol collision hinting...
    but the point still stands: a function like this has to be able to return
    'multiple' potential values)
    """

    #
    # first, we will attempt to parse the given symbol as a global
    # struct path.
    #
    #    eg. 'g_foo.bar.baz'
    #
    # NOTE: this kind of has to be first, because our second section of
    # symbol resolution (get_name_ea, get_name_value) will incorrectly
    # 'resolve' a global struct path used at a given address.
    #
    # by incorrectly, i mean that global struct path reference in an
    # instruction will resolve to the base address of the global, not
    # the actual referenced field within the global
    #
    # TODO: there's a bug or something in my code still, this is not
    # computing the right offset in some cases (try assemble_all() on
    # ntoskrnl.exe from Windows 11 to see some of the failures)
    #

    global_name, sep, struct_path = name.partition('.')

    #
    # if sep 'exists', that means there is a '.' in the given symbol so it
    # *could* be a global struct path. let's try to walk though it
    #

    if sep:

        resolved_paths = 0

        for global_ea, real_name in resolve_symbol(from_ea, global_name):

            # if the resolved symbol address is not a global struct, ignore it
            if not ida_bytes.is_struct(ida_bytes.get_flags(global_ea)):
                continue

            # get the struct info for the resolved global address
            sid = ida_nalt.get_strid(global_ea)
            sptr = ida_struct.get_struc(sid)

            #
            # walk through the rest of the struct path to compute the offset (and
            # final address) of the referenced field eg. global.foo.bar
            #

            offset = 0
            while struct_path and sptr != None:

                member_name, sep, struct_path = struct_path.partition('.')
                member = ida_struct.get_member_by_name(sptr, member_name)

                if member is None:
                    print(" - INVALID STRUCT MEMBER!", member_name)
                    break

                offset += member.get_soff()
                sptr = ida_struct.get_sptr(member)
                if not sptr:
                    assert not('.' in struct_path), 'Expected end of struct path?'
                    yield (global_ea+offset, name)
                    resolved_paths += 1

        #
        # TODO/XXX: if we yielded at least one struct path... we're *probably*
        # good. I don't think
        #

        if resolved_paths:
            return

    #
    # if the given symbol does not appear to be a global struct path, we
    # will try to use some of IDA's more typical 'name' --> address API's
    #
    # should any of these succeed, they are most certainly to be the symbol
    # value the user / instruction intended
    #

    value = ida_name.get_name_ea(from_ea, name)
    if value != ida_idaapi.BADADDR:
        yield (value, name)
        return

    nt, value = ida_name.get_name_value(from_ea, name)
    if nt != ida_name.NT_NONE:
        yield (value, name)
        return

    if name == '$':
        yield (from_ea, name)
        return

    #
    # yield all matches for a sanitized (codepage-validated?) name
    #
    # TODO/PERF: lol this is ridiculously expensive
    #

    # alias for speed (does this pseudo-optimization even work in py3 anymore? lol)
    get_nlist_ea = ida_name.get_nlist_ea
    get_nlist_name = ida_name.get_nlist_name
    #get_short_name = ida_name.get_short_name
    get_visible_name = ida_name.get_visible_name

    for idx in range(ida_name.get_nlist_size()):
        address = get_nlist_ea(idx)
        #visible_name = get_short_name(address)
        visible_name = get_visible_name(address)
        #visible_name = ida_name.validate_name(real_name, ida_name.VNT_IDENT) # ???
        if visible_name == name:
            real_name = get_nlist_name(idx)
            yield (address, real_name)

def get_dtype_name(dtype, size):
    """
    Return the keyword for the given data type.
    """
    dtype_map = \
    {
        ida_ua.dt_byte: 'byte',      #  8 bit
        ida_ua.dt_word: 'word',      #  16 bit
        ida_ua.dt_dword: 'dword',    #  32 bit
        ida_ua.dt_float: 'dword',    #  4 byte
        ida_ua.dt_double: 'qword',   #  8 byte
        ida_ua.dt_qword: 'qword',    #  64 bit
        ida_ua.dt_byte16: 'xmmword', # 128 bit
        ida_ua.dt_byte32: 'ymmword', # 256 bit
    }

    if dtype == ida_ua.dt_tbyte and size == 10:
      return 'xword'

    return dtype_map.get(dtype, None)

def get_tag_name(scolor):
    """
    Return the name of a given COLOR tag.
    """
    attribute_names = dir(ida_lines)

    for name in attribute_names:
        if not name.startswith('SCOLOR_'):
            continue
        value = getattr(ida_lines, name)
        if value == scolor:
            return name

    return '<UNKNOWN TAG>'

def rewrite_tag_addrs(line, wrap=False):
    """
    Rewrite symbol text with their COLOR values

    TODO: remove?
    """
    if not line:
        return

    og_line = line
    og_index = 0

    while len(line) > 0:

        skipcode_index = ida_lines.tag_skipcode(line)

        if skipcode_index == 0:  # No code found
            line = line[1:]  # Skip one character ahead
            og_index += 1
            continue

        if not(line[0] == ida_lines.COLOR_ON and line[1] == chr(ida_lines.COLOR_ADDR)):
            line = line[skipcode_index:]
            og_index += skipcode_index
            continue

        # parse the hidden text address from the tagged line
        address = int(line[2:skipcode_index], 16)

        # skip past the address to the symbol
        line = line[skipcode_index:]
        og_index += skipcode_index

        # copy the symbol out of the tagged line
        symbol = line[:line.index(ida_lines.COLOR_OFF)]
        symbol_index = og_index
        #print("Found addr: 0x%08X, '%s'" % (address, symbol))

        if wrap:
            address_text = "[0x%X]" % address
        else:
            address_text = "0x%X"

        # write the address text over the place of the original symbol
        og_line = og_line[:symbol_index] + address_text + og_line[symbol_index+len(symbol):]

        # continue past the extracted symbol text
        skipcode_index = ida_lines.tag_skipcode(line)
        line = line[skipcode_index:]
        og_index += len(address_text) # special adjustment, to account for the injected address text

    return ida_lines.tag_remove(og_line)

def get_disassembly_components_slow(ea):
    """
    Return (prefix, mnemonic, [operands]) from IDA's disassembly text.

    TODO: remove?
    """
    if not ida_bytes.is_code(ida_bytes.get_flags(ea)):
        return (None, None, [])

    # alias for simpler code / formatting
    COLOR_OPNDS = [chr(ida_lines.COLOR_OPND1+i) for i in range(7)]

    # tag parsing output
    comps_insn = []
    comps_ops = [None for i in range(7)]

    # tag parsing state
    tag_chars = []
    tag_stack = []

    # fetch the 'colored' (tagged) instruction text from IDA for parsing
    insn_text = ida_lines.generate_disasm_line(ea)

    #
    # using the IDA 'color' tags, we can parse spans of text generated by IDA
    # to determine the different parts of a printed instruction.
    #
    # this is useful because we can let IDA's core / proc module handle the
    # printing of specific features (e.g. instruction prefixes, size
    # annotations, segment references) without trying to re-implement the
    # full insn printing pipeline on our own.
    #

    while insn_text:
        skipcode_index = ida_lines.tag_skipcode(insn_text)

        #
        # if we are not sitting on top of a 'color code' / tag action, then
        # we do not need to take any special parsing action.
        #

        if skipcode_index == 0:
            tag_chars.append(insn_text[0])
            insn_text = insn_text[1:]
            continue

        #print('BYTES', ' '.join(['%02X' % ord(x) for x in insn_text[0:2]]))
        tag_action, tag_type = insn_text[0:2]

        #
        # entering a new color tag / text span
        #

        if tag_action == ida_lines.SCOLOR_ON:

            #
            # address tags do not have a closing tag, so we must consume
            # them immediately.
            #

            if tag_type == ida_lines.SCOLOR_ADDR:

                # parse the 'invisible' address reference
                address = int(insn_text[2:2+ida_lines.COLOR_ADDR_SIZE], 16)
                #symbol = insn_text[2+ida_lines.COLOR_ADDR:skipcode_index]
                #print("FOUND SYMBOL '%s' ADDRESS 0x%8X" % (symbol, address))

                # continue parsing the line
                insn_text = insn_text[skipcode_index:]
                continue

            tag_stack.append((tag_type, tag_chars))
            tag_chars = []

        #
        # exiting a color tag / text span
        #

        elif tag_action == ida_lines.SCOLOR_OFF:
            entered_tag, prev_tag_chars = tag_stack.pop()
            assert entered_tag == tag_type, "EXITED '%s' EXPECTED '%s'" % (get_tag_name(tag_type), get_tag_name(entered_tag))
            tag_text = ''.join(tag_chars).strip()

            # save instruction prefixes or the mnemonic
            if tag_type == ida_lines.SCOLOR_INSN:
                comps_insn.append(tag_text)

            # save instruction operands
            elif tag_type in COLOR_OPNDS:
                op_num = ord(tag_type) - ida_lines.COLOR_OPND1
                #print("ADDRESS 0x%08X OP %u: %s" % (ea, op_num, tag_text))
                comps_ops[op_num] = tag_text

            # ignore the rest? (for now I guess)
            else:
                #print("NOT SAVING: '%s' TAG TYPE '%s' " % (tag_text, get_tag_name(tag_type)))
                pass

            tag_chars = prev_tag_chars + tag_chars

        # continue past the 'color codes' / tag info
        insn_text = insn_text[skipcode_index:]

    # if there is more than one 'insn component', assume they are prefixes
    if len(comps_insn) > 1:
        prefix = ' '.join(comps_insn[:-1])
    else:
        prefix = ''

    # the instruction mnemonic should be the 'last' instruction component
    mnemonic = comps_insn[-1]

    return (prefix, mnemonic, comps_ops)

#
# TODO/XXX: ehh there's no way to really get / enumerate instruction prefixes
# from IDA processor modules
#

KNOWN_PREFIXES = set(['xacquire', 'xrelease', 'lock', 'bnd', 'rep', 'repe', 'repne'])

def get_disassembly_components(ea):
    """
    Return (prefix, mnemonic, operands) instruction components for a given address.
    """
    line_text = ida_lines.tag_remove(ida_lines.generate_disasm_line(ea))
    return parse_disassembly_components(line_text)

def parse_disassembly_components(line_text):
    """
    Return (prefix, mnemonic, operands) from the given instruction text.
    """

    # remove comment (if present)
    insn_text = line_text.split(';', 1)[0]

    # split instruction roughly into its respective elements
    elements = insn_text.split(' ')

    #
    # parse prefixes
    #

    for i, value in enumerate(elements):
        if not (value in KNOWN_PREFIXES):
            break

    #
    # if we didn't break from the loop, that means *every* element in the
    # split text was an instruction prefix. this seems odd, but it can
    # happen, eg the 'lock' instruction... by itself (in x86) is valid
    #
    # in this case, there is no mnemonic, or operands. just a prefix
    #

    else:
        return (' '.join(elements), '', '')

    #
    # there can be multiple instruction prefix 'words' so we stitch them
    # together here, in such cases
    #

    prefix = ' '.join(elements[:i])

    #
    # parse mnemonic
    #

    mnemonic = elements[i]
    i += 1

    #
    # operands
    #

    operands = ' '.join(elements[i:])

    return (prefix, mnemonic, operands)

def all_instruction_addresses(ea=0):
    """
    Return a generator that yields each instruction address in the IDB.
    """

    # alias for speed
    BADADDR = ida_idaapi.BADADDR
    SEG_CODE = ida_segment.SEG_CODE
    get_flags = ida_bytes.get_flags
    get_seg_type = ida_segment.segtype
    get_next_head = ida_bytes.next_head
    is_code = ida_bytes.is_code

    # yield each instruction address in the IDB
    while ea < BADADDR:

        if get_seg_type(ea) != SEG_CODE:
            ea = get_next_head(ea, BADADDR)
            continue

        # skip any address that is not an instruction
        if not is_code(get_flags(ea)):
            ea = get_next_head(ea, BADADDR)
            continue

        # return the current 'instruction' address
        yield ea

        # continue forward to the next address
        ea = get_next_head(ea, BADADDR)

def disassemble_bytes(data, ea):
    """
    Disassemble the given bytes using IDA at the given address.
    """
    old = ida_auto.set_auto_state(False)

    # fetch the current bytes (they could be patched already!)
    original_data = ida_bytes.get_bytes(ea, len(data))

    #
    # temporarily patch in the data we want IDA to disassemble, and fetch
    # the resulting disassembly text
    #

    ida_bytes.patch_bytes(ea, data)
    text = ida_lines.generate_disasm_line(ea)

    # revert the saved bytes back to the prior state
    ida_bytes.patch_bytes(ea, original_data)

    # re-enable the auto analyzer and return the disassembled text
    ida_auto.enable_auto(old)
    return ida_lines.tag_remove(text)

#------------------------------------------------------------------------------
# IDA Viewer Shims
#------------------------------------------------------------------------------

#
# TODO/Hex-Rays:
#
# IDA's simplecustviewer_t() does not support populating/hinting fields of
# the 'ctx' structure passed onto IDA Action handlers
#
# for this reason, we have to do some manual resolution of context for our
# patching viewer. these shims are to help keep the action code above a
# bit cleaner until Hex-Rays can improve simple code viewers
#

def parse_line_ea(colored_line):
    """
    Parse a code / instruction address from a colored line in the patching dialog.
    """
    line = ida_lines.tag_remove(colored_line)
    ea = int(line.split('|')[0], 16)
    return ea

def get_current_ea(ctx):
    """
    Return the current address for the given action context.
    """

    # custom / interactive patching view
    if ida_kernwin.get_widget_title(ctx.widget) == 'PatchingCodeViewer':
        return parse_line_ea(ida_kernwin.get_custom_viewer_curline(ctx.widget, False))

    # normal IDA widgets / viewers
    return ctx.cur_ea

def read_range_selection(ctx):
    """
    Return the currently selected address range for the given action context.
    """

    # custom / interactive patching view
    if ida_kernwin.get_widget_title(ctx.widget) == 'PatchingCodeViewer':

        # no active selection in the patching view, nothing to do...
        if not(ctx.cur_flags & ida_kernwin.ACF_HAS_SELECTION):
            return (False, ida_idaapi.BADADDR, ida_idaapi.BADADDR)

        # extract the start/end cursor locations (place_t) from the given ctx
        splace_from = ida_kernwin.place_t_as_simpleline_place_t(ctx.cur_sel._from.at)
        splace_to = ida_kernwin.place_t_as_simpleline_place_t(ctx.cur_sel.to.at)

        #
        # TODO/Hex-Rays: lol a *BRUTAL HACK* to get the src / dst lines
        #
        # the problem here is that there is no way to get the contents of an
        # arbitrary line (by number) in the custom viewer we created. at least not
        # from here, where we don't have a python reference of simplecustviewer_t()
        #
        # luckily... we can 'generate' (fetch?) the viewer's line through a place_t
        #
        # lol...
        #

        start_line = splace_from.generate(ida_kernwin.get_viewer_user_data(ctx.widget), 1)[0][0]
        end_line = splace_to.generate(ida_kernwin.get_viewer_user_data(ctx.widget), 1)[0][0]

        # parse the leading address from the 'colored' text fetched from the patching window
        start_ea = parse_line_ea(start_line)
        end_ea = parse_line_ea(end_line)
        end_ea = ida_bytes.get_item_end(end_ea)
        #print("Got %08X --> %08X for custom viewer range parse" % (start_ea, end_ea))

        # not a true 'range selection' if the start and end line / number is the same
        if start_ea == end_ea:
            return (False, ida_idaapi.BADADDR, ida_idaapi.BADADDR)

        # return the range of selected lines
        return (True, start_ea, end_ea)

    # normal IDA view
    return ida_kernwin.read_range_selection(ctx.widget)

def remove_ida_actions(popup):
    """
    Remove default IDA actions from a given IDA popup (handle).
    """
    if not QT_AVAILABLE:
        return None

    #
    # TODO/Hex-Rays:
    #
    # so, i'm pretty picky about my UI / interactions. IDA puts items in
    # the right click context menus of custom (code) viewers.
    #
    # these items aren't really relevant (imo) to the plugin's use case
    # so I do some dirty stuff here to filter them out and ensure only
    # my items will appear in the context menu.
    #
    # there's only one right click context item right now, but in the
    # future i'm sure there will be more.
    #

    class FilterMenu(QtCore.QObject):
        def __init__(self, qmenu):
            super(QtCore.QObject, self).__init__()
            self.qmenu = qmenu

        def eventFilter(self, obj, event):
            if event.type() != QtCore.QEvent.Polish:
                return False
            for action in self.qmenu.actions():
                if action.text() in ["&Font...", "&Synchronize with"]: # lol..
                    qmenu.removeAction(action)
            self.qmenu.removeEventFilter(self)
            self.qmenu = None
            return True

    p_qmenu = ctypes.cast(int(popup), ctypes.POINTER(ctypes.c_void_p))[0]
    qmenu = sip.wrapinstance(int(p_qmenu), QtWidgets.QMenu)
    filter = FilterMenu(qmenu)
    qmenu.installEventFilter(filter)

    # return the filter as I think we need to maintain its lifetime in py
    return filter
