import ida_idaapi
import ida_kernwin

from patching.ui.save import SaveController
from patching.ui.preview import PatchingController
from patching.util.ida import get_current_ea, read_range_selection

#-----------------------------------------------------------------------------
# IDA Plugin Actions
#-----------------------------------------------------------------------------

class NopAction(ida_kernwin.action_handler_t):
    NAME = 'patching:nop'
    ICON = 'nop.png'
    TEXT = "NOP"
    TOOLTIP = "NOP the selected instructions (or bytes)"
    HOTKEY = 'CTRL-N'

    def __init__(self, core):
        ida_kernwin.action_handler_t.__init__(self)
        self.core = core

    def activate(self, ctx):

        # fetch the address range selected by the user
        valid_selection, start_ea, end_ea = read_range_selection(ctx)

        # do a range-based NOP if the selection is valid
        if valid_selection:
            print("%08X --> %08X: NOP'd range" % (start_ea, end_ea))
            self.core.nop_range(start_ea, end_ea)
            return 1

        # NOP a single instruction / item
        cur_ea = get_current_ea(ctx)
        if cur_ea == ida_idaapi.BADADDR:
            print("Cannot use NOP here... (Invalid Address)")
            return 0

        print("%08X: NOP'd item" % cur_ea)
        self.core.nop_item(cur_ea)

        # return 1 to refresh the IDA views
        return 1

    def update(self, ctx):

        # the NOP action should only be allowed to execute in the following views
        if ida_kernwin.get_widget_type(ctx.widget) == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        elif ida_kernwin.get_widget_title(ctx.widget) == 'PatchingCodeViewer':
            return ida_kernwin.AST_ENABLE_FOR_WIDGET

        # unknown context / widget, do NOT allow the NOP action to be used here
        return ida_kernwin.AST_DISABLE_FOR_WIDGET

class RevertAction(ida_kernwin.action_handler_t):
    NAME = 'patching:revert'
    ICON = 'revert.png'
    TEXT = "Revert patch"
    TOOLTIP = "Revert patched bytes at the selected address"
    HOTKEY = None

    def __init__(self, core):
        ida_kernwin.action_handler_t.__init__(self)
        self.core = core

    def activate(self, ctx):

        # fetch the address range selected by the user
        valid_selection, start_ea, end_ea = read_range_selection(ctx)

        if valid_selection:
            print("%08X --> %08X: Reverted range" % (start_ea, end_ea))
            self.core.revert_range(start_ea, end_ea)
        else:
            cur_ea = get_current_ea(ctx)
            print("%08X: Reverted patch" % cur_ea)
            self.core.revert_patch(cur_ea)

        # return 1 to refresh the IDA views
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ForceJumpAction(ida_kernwin.action_handler_t):
    NAME = 'patching:forcejump'
    ICON = 'forcejump.png'
    TEXT = "Force jump"
    TOOLTIP = "Patch the selected jump into an unconditional jump"
    HOTKEY = None

    def __init__(self, core):
        ida_kernwin.action_handler_t.__init__(self)
        self.core = core

    def activate(self, ctx):
        cur_ea = get_current_ea(ctx)

        print("%08X: Forced conditional jump" % cur_ea)
        self.core.force_jump(cur_ea)

        # return 1 to refresh the IDA views
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class AssembleAction(ida_kernwin.action_handler_t):
    NAME = 'patching:assemble'
    ICON = 'assemble.png'
    TEXT = "Assemble..."
    TOOLTIP = "Assemble new instructions at the selected address"
    HOTKEY = None

    def __init__(self, core):
        ida_kernwin.action_handler_t.__init__(self)
        self.core = core

    def activate(self, ctx):

        # do not create a new patching dialog if one is already active
        if ida_kernwin.find_widget(PatchingController.WINDOW_TITLE):
            return 1

        wid = PatchingController(self.core, get_current_ea(ctx))

        # return 1 to refresh the IDA views
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ApplyAction(ida_kernwin.action_handler_t):
    NAME = 'patching:apply'
    ICON = 'save.png'
    TEXT = "Apply patches to..."
    TOOLTIP = "Select where to save the patched binary"
    HOTKEY = None

    def __init__(self, core):
        ida_kernwin.action_handler_t.__init__(self)
        self.core = core

    def activate(self, ctx):

        controller = SaveController(self.core)

        if controller.interactive():
            print("Patch successful: %s" % self.core.patched_filepath)
        else:
            print("Patching cancelled...")

        # return 1 to refresh the IDA views
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class QuickApplyAction(ida_kernwin.action_handler_t):
    NAME = 'patching:quickapply'
    ICON = 'save.png'
    TEXT = "Quick apply patches"
    TOOLTIP = "Apply patches using the previously selected patch settings"
    HOTKEY = None

    def __init__(self, core):
        ida_kernwin.action_handler_t.__init__(self)
        self.core = core

    def activate(self, ctx):

        # attempt to perform a quick patch (save), per the user's request
        success, error = self.core.quick_apply()
        if success:
            print("Quick patch successful: %s" % self.core.patched_filepath)
            return 1

        #
        # since the quickpatch FAILED, fallback to popping the interactive
        # patch saving dialog to let the user sort out the issue
        #

        print("Quick patch failed...")
        controller = SaveController(self.core, error)

        if controller.interactive():
            print("Patch successful: %s" % self.core.patched_filepath)
        else:
            print("Patching cancelled...")

        # return 1 to refresh the IDA views
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

#-----------------------------------------------------------------------------
# All Actions
#-----------------------------------------------------------------------------

PLUGIN_ACTIONS = \
[
    NopAction,
    RevertAction,
    ForceJumpAction,
    AssembleAction,
    ApplyAction,
    QuickApplyAction
]
