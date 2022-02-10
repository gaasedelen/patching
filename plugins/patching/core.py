import shutil
import hashlib
import collections

import ida_ua
import ida_auto
import ida_nalt
import ida_bytes
import ida_lines
import ida_idaapi
import ida_loader
import ida_kernwin
import ida_segment
import idautils

from patching.asm import *
from patching.actions import *
from patching.exceptions import *

from patching.util.ida import *
from patching.util.misc import plugin_resource
from patching.util.python import register_callback, notify_callback

#------------------------------------------------------------------------------
# Plugin Core
#------------------------------------------------------------------------------
#
#     The plugin core constitutes the traditional 'main' plugin class. It
#     will host all of the plugin's objects and integrations, taking
#     responsibility for their initialization/teardown/lifetime.
#
#     This pattern of splitting out the plugin core from the IDA plugin_t stub
#     is primarily to help separate the plugin functionality from IDA's and
#     make it easier to 'reload' for development / testing purposes.
#

class PatchingCore(object):

    PLUGIN_NAME    = 'Patching'
    PLUGIN_VERSION = '0.1.2'
    PLUGIN_AUTHORS = 'Markus Gaasedelen'
    PLUGIN_DATE    = '2022'

    def __init__(self, defer_load=False):

        # IDA UI Hooks
        self._ui_hooks = UIHooks()
        self._ui_hooks.ready_to_run = self.load
        self._ui_hooks.hook()

        # IDA 'Processor' Hooks
        self._idp_hooks = IDPHooks()
        self._idp_hooks.ev_ending_undo = self._ida_undo_occurred

        # IDA 'Database' Hooks
        self._idb_hooks = IDBHooks()
        self._idb_hooks.auto_empty_finally = self.load

        #
        # the plugin only uses IDB hooks for IDA Batch mode. specifically, it
        # will load the plugin when the initial auto analysis has finished
        #
        # TODO: does auto_empty_finally trigger if you are loading a
        # pre-existing IDB in IDA batch mode? (probably not, hence TODO)
        #

        if ida_kernwin.cvar.batch:
            self._idb_hooks.hook()

        # the backing engine to assemble instructions for the plugin
        self.assembler = None

        # a set of all addresses patched by the user
        self.patched_addresses = set()

        # the executable filepath that patches were applied to
        self.patched_filepath = None

        # the executable filepath used to apply patches from (the clean file)
        self.backup_filepath = None

        # apply saved patches from a known-good (clean) executable by default
        self.prefer_patch_cleanly = True

        # enable quick save after a successful patch application occurs
        self.prefer_quick_apply = True
        self.__saved_successfully = False

        # plugin events / callbacks
        self._patches_changed_callbacks = []

        #
        # defer fully loading the plugin core until the IDB and UI itself
        # is settled. in this case, self.load() will be called later on
        # by IDA's UI ready_to_run event (or auto_empty_finally in batch)
        #

        if defer_load:
            return

        #
        # if loading is not being deferred, we have to load the plugin core
        # now. this is only used for development purposes such as 'hot
        # reloading' the plugin via the IDA console (DEV)
        #

        self.load()

    #--------------------------------------------------------------------------
    # Initialization / Teardown
    #--------------------------------------------------------------------------

    def load(self):
        """
        Load the plugin core.
        """

        #
        # IDB hooks are *only* ever used to load the patching plugin after
        # initial auto-analysis completes in batch mode. so we should always
        # unhook them here as they will not be used for anything else
        #

        if ida_kernwin.cvar.batch:
            self._idb_hooks.unhook()

        # attempt to initialize an assembler engine matching the database
        self._init_assembler()

        # deactivate the plugin if this is an unsupported architecture
        if not self.assembler:
            self._ui_hooks.unhook()
            return

        # enable additional hooks since the plugin is going live
        self._ui_hooks.populating_widget_popup = self._populating_widget_popup
        self._ui_hooks.get_lines_rendering_info = self._highlight_lines

        # finish loading the plugin and integrating its UI elements / actions
        self._init_actions()
        self._idp_hooks.hook()
        self._refresh_patches()
        ida_kernwin.refresh_idaview_anyway()

        print("[%s] Loaded v%s - (c) %s - %s" % (self.PLUGIN_NAME, self.PLUGIN_VERSION, self.PLUGIN_AUTHORS, self.PLUGIN_DATE))

        # parse / handle command line options for this plugin (DEV)
        self._run_cli_options()

    def unload(self):
        """
        Unload the plugin core.
        """
        self._idb_hooks.unhook()

        if not self.assembler:
            return

        print("[%s] Unloading v%s..." % (self.PLUGIN_NAME, self.PLUGIN_VERSION))

        self._idp_hooks.unhook()
        self._ui_hooks.unhook()
        self._unregister_actions()
        self._unload_assembler()

    def _init_assembler(self):
        """
        Initialize the assembly engine to be used for patching.
        """
        inf = ida_idaapi.get_inf_structure()
        arch_name = inf.procname.lower()

        if arch_name == 'metapc':
            assembler = AsmX86(inf)
        elif arch_name.startswith('arm'):
            assembler = AsmARM(inf)

        #
        # TODO: disabled until v0.2.0
        #
        #elif arch_name.startswith("ppc"):
        #    assembler = AsmPPC(inf)
        #elif arch_name.startswith("mips"):
        #    assembler = AsmMIPS(inf)
        #elif arch_name.startswith("sparc"):
        #    assembler = AsmSPARC(inf)
        #elif arch_name.startswith("systemz") or arch_name.startswith("s390x"):
        #    assembler = AsmSystemZ(inf)
        #

        else:
            assembler = None
            print(" - Unsupported CPU: '%s' (%s)" % (arch_name, ida_nalt.get_input_file_path()))

        self.assembler = assembler

    def _unload_assembler(self):
        """
        Unload the assembly engine.
        """

        #
        # NOTE: this is kind of aggressive attempt at deleting the assembler
        # and Keystone components in an effort to keep things safe if the user
        # is trying to do an easy install (updating) over the existing plugin
        #
        # read the install.py script (easy install) for a bit more context of
        # why we're trying to minimize exposure to Keystone on unload
        #

        del self.assembler._ks
        del self.assembler
        self.assembler = None

    def _init_actions(self):
        """
        Initialize all IDA plugin actions.
        """

        # initialize new actions provided by this plugin
        for action in PLUGIN_ACTIONS:

            # load and register an icon for our action if one is defined
            if action.ICON:
                icon_path = plugin_resource(action.ICON)
                icon_id = ida_kernwin.load_custom_icon(icon_path)
            else:
                icon_id = -1

            # instantiate an action description to register with IDA
            desc = ida_kernwin.action_desc_t(
                action.NAME,
                action.TEXT,
                action(self),
                action.HOTKEY,
                action.TOOLTIP,
                icon_id
            )

            if not ida_kernwin.register_action(desc):
                print("Failed to register action '%s'" % action.NAME)

        # inject plugin's NOP action into IDA's edit submenu
        ida_kernwin.attach_action_to_menu("Edit/Patch program/Change byte...", "patching:nop", ida_kernwin.SETMENU_INS)

        # supersede IDA's default "Assemble" action with our own
        ida_kernwin.update_action_state("Assemble", ida_kernwin.AST_DISABLE_ALWAYS)
        ida_kernwin.update_action_visibility("Assemble", False)
        ida_kernwin.attach_action_to_menu("Edit/Patch program/Change word...", "patching:assemble", ida_kernwin.SETMENU_APP)

        # supersede IDA's default "Apply patches" action with our own
        ida_kernwin.update_action_state("ApplyPatches", ida_kernwin.AST_DISABLE_ALWAYS)
        ida_kernwin.update_action_visibility("ApplyPatches", False)
        ida_kernwin.attach_action_to_menu("Edit/Patch program/Patched bytes...", "patching:apply", ida_kernwin.SETMENU_APP)

    def _unregister_actions(self):
        """
        Remove all plugin actions registered with IDA.
        """
        for action in PLUGIN_ACTIONS:

            # fetch icon ID before we unregister the current action
            valid_id, icon_id = ida_kernwin.get_action_icon(action.NAME)

            # unregister the action from IDA
            if not ida_kernwin.unregister_action(action.NAME):
                print("Failed to unregister action '%s'" % action.NAME)

            # delete the icon now that the action should no longer be using it
            if valid_id:
                ida_kernwin.free_custom_icon(icon_id)

        # restore IDA actions that we had overridden
        ida_kernwin.update_action_state("Assemble", ida_kernwin.AST_ENABLE)
        ida_kernwin.update_action_visibility("Assemble", True)
        ida_kernwin.update_action_state("ApplyPatches", ida_kernwin.AST_ENABLE)
        ida_kernwin.update_action_visibility("ApplyPatches", True)

    def _run_cli_options(self):
        """
        Run plugin actions based on command line flags (DEV).
        """
        options = ida_loader.get_plugin_options('Patching')
        if not options:
            return

        # run the 'assemble_all' test with CLI flag -OPatching:assemble
        for option in options.split(':'):
            if option == 'assemble':
                self.assemble_all()

    #--------------------------------------------------------------------------
    # Plugin API
    #--------------------------------------------------------------------------

    def is_byte_patched(self, ea):
        """
        Return True if the byte at the given address has been patched.
        """
        return self.is_range_patched(ea, ea+1)

    def is_item_patched(self, ea):
        """
        Return True if a patch exists within the item at the given address.
        """
        item_size = ida_bytes.get_item_size(ea)
        return self.is_range_patched(ea, ea+item_size)

    def is_range_patched(self, start_ea, end_ea):
        """
        Return True if a patch exists within the given address range.
        """
        if start_ea == (end_ea + 1):
            return start_ea in self.patched_addresses
        return bool(self.patched_addresses & set(range(start_ea, end_ea)))

    def get_patch_at(self, ea):
        """
        Return information about a patch at the given address.

        On success, returns (True, start_ea, patch_size) for the patch.
        """
        if not self.is_item_patched(ea):
            return (False, ida_idaapi.BADADDR, 0)

        #
        # NOTE: this code seems 'overly complicated' because it tries to group
        # visually contiguous items that appear as 'one' patched region in
        # IDA, even if not all of the bytes within each item were changed.
        #
        # TODO/Hex-Rays: this kind of logic/API is probably something that
        # should be moved in-box as part of a 'patch metadata' overhaul
        #

        if ida_bytes.is_unknown(ida_bytes.get_flags(ea)):
            forward_ea = ea
            reverse_ea = ea - 1
        else:
            forward_ea = ida_bytes.get_item_head(ea)
            reverse_ea = ida_bytes.prev_head(forward_ea, 0)

        # scan forwards for the 'end' of the patched region
        while forward_ea != ida_idaapi.BADADDR:
            item_size = ida_bytes.get_item_size(forward_ea)
            item_addresses = set(range(forward_ea, forward_ea + item_size))
            forward_ea = forward_ea + item_size
            if not (item_addresses & self.patched_addresses):
                forward_ea -= item_size
                break

        # scan backwards for the 'start' of the patched region
        while reverse_ea != ida_idaapi.BADADDR:
            item_size = ida_bytes.get_item_size(reverse_ea)
            item_addresses = set(range(reverse_ea, reverse_ea + item_size))
            if not (item_addresses & self.patched_addresses):
                reverse_ea += item_size # revert to last 'hit' item
                break
            reverse_ea -= item_size

        # info about the discovered patch
        start_ea = reverse_ea
        end_ea = forward_ea
        length = forward_ea - reverse_ea
        #print("Found patch! 0x%08X --> 0x%08X (%u bytes)" % (start_ea, end_ea, length))

        return (True, start_ea, length)

    def assemble(self, assembly, ea):
        """
        Assemble and return bytes for the given assembly text.
        """
        return self.assembler.asm(assembly, ea)

    def nop_item(self, ea):
        """
        NOP the item at the given address.
        """
        nop_size = ida_bytes.get_item_size(ea)
        return self.nop_range(ea, ea+nop_size)

    def nop_range(self, start_ea, end_ea):
        """
        NOP all of the bytes within the given address range.
        """
        if start_ea == end_ea:
            return False

        # generate a buffer of NOP data hinted at by the existing database / instructions
        nop_buffer = self.assembler.nop_buffer(start_ea, end_ea)

        # patch the specified region with NOP bytes
        self.patch(start_ea, nop_buffer, fill_nop=False)
        return True

    def revert_patch(self, ea):
        """
        Revert all the modified bytes within a patch at the given address.
        """
        found, start_ea, length = self.get_patch_at(ea)
        if not found:
            return False
        self.revert_range(start_ea, start_ea+length)
        return True

    def revert_range(self, start_ea, end_ea):
        """
        Revert all the modified bytes within the given address range.
        """

        # revert bytes to their original value within the target region
        for ea in range(start_ea, end_ea):
            ida_bytes.revert_byte(ea)

        # 'undefine' the reverted bytes (helps with re-analysis)
        length = end_ea - start_ea
        ida_bytes.del_items(start_ea, ida_bytes.DELIT_KEEPFUNC, length)

        #
        # if the reverted patch seems to be in a code-ish area, we tell the
        # auto-analyzer to try and analyze it as code
        #

        if ida_bytes.is_code(ida_bytes.get_flags(ida_bytes.prev_head(start_ea, 0))):
            ida_auto.auto_mark_range(start_ea, end_ea, ida_auto.AU_CODE)

        # attempt to re-analyze the reverted region
        ida_auto.plan_and_wait(start_ea, end_ea, True)

        #
        # having just reverted the bytes to their original values on the IDA
        # side of things, we now have to ensure these addresses are no longer
        # tracked by our plugin as 'patched'
        #

        self.patched_addresses -= set(range(start_ea, end_ea))
        ida_kernwin.execute_sync(self._notify_patches_changed, ida_kernwin.MFF_NOWAIT|ida_kernwin.MFF_WRITE)
        return True

    def force_jump(self, ea):
        """
        Force a conditional jump to be unconditional at the given address.
        """
        mnemonic = ida_ua.print_insn_mnem(ea)

        # if the given address is not a conditional jump, ignore the request
        if not self.assembler.is_conditional_jump(mnemonic):
            return False

        # fetch the target address
        target = next(idautils.CodeRefsFrom(ea, False))

        # assemble an unconditional jump with the same jump target
        patch_code = "%s 0x%X" % (self.assembler.UNCONDITIONAL_JUMP, target)
        patch_data = self.assembler.asm(patch_code, ea)

        # write the unconditional jump patch to the database
        self.patch(ea, patch_data)
        return True

    def patch(self, ea, patch_data, fill_nop=True):
        """
        Write patch data / bytes to a given address.
        """
        patch_size = len(patch_data)

        # incoming patch matches existing data, nothing to do
        original_data = ida_bytes.get_bytes(ea, patch_size)
        if original_data == patch_data:
            return

        next_address = ea + patch_size
        inst_start = ida_bytes.get_item_head(next_address)
        if ida_bytes.is_code(ida_bytes.get_flags(inst_start)):

            # if the patch clobbers part of an instruction, fill it with NOP
            if inst_start < next_address:
                inst_size = ida_bytes.get_item_size(inst_start)
                fill_size = (inst_start + inst_size) - next_address
                self.nop_range(next_address, next_address+fill_size)
                ida_auto.auto_make_code(next_address)

        # write the actual patch data to the database
        ida_bytes.patch_bytes(ea, patch_data)

        #
        # record the region of patched addresses
        #

        addresses = set(range(ea, ea+patch_size))
        if is_range_patched(ea, ea+patch_size):
            self.patched_addresses |= addresses

        #
        # according to IDA, none of the 'patched' addresses in the database
        # actually have a different value... so they technically were not
        # patched (eg. maybe they were patched back to their ORIGINAL value!)
        #
        # in this case it means the patching plugin shouldn't see these
        # addresses as patched, either...
        #

        else:
            self.patched_addresses -= addresses

        # request re-analysis of the patched range
        ida_auto.auto_mark_range(ea, ea+patch_size, ida_auto.AU_USED)
        ida_kernwin.execute_sync(self._notify_patches_changed, ida_kernwin.MFF_NOWAIT|ida_kernwin.MFF_WRITE)

    def apply_patches(self, target_filepath, clean=False):
        """
        Apply the current patches to the given filepath.
        """
        self.__saved_successfully = False

        #
        # ensure that a 'clean' source executable exists for this operation,
        # and then write (or overwrite) the target filepath with the clean
        # file so that we can apply patches to it from a known-good state
        #

        if clean:
            self.backup_filepath = self._ensure_clean_backup(target_filepath)

            #
            # due to the variety of errors that may occur from trying to copy
            # a file, we simply trap them all to a more descriptive issue for
            # what action failed in the context of our patching attempt
            #

            try:
                shutil.copyfile(self.backup_filepath, target_filepath)
            except Exception:
                raise PatchTargetError("Failed to overwrite patch target with a clean executable", target_filepath)

        #
        # attempt to apply the patches to the target filepath
        #
        # NOTE: this 'Exception' catch-all is probably a bit too liberal,
        # instead we should probably have apply_patches(...) raise a generic
        # error if opening the target file for writing fails, leaving any
        # other (unexpected!) patching exceptions uncaught
        #

        try:
            apply_patches(target_filepath)
        except Exception:
            raise PatchApplicationError("Failed to write patches into the target file", target_filepath)

        # patching seems successful? update the stored filepath to the patched binary
        self.patched_filepath = target_filepath

        #
        # if we made it this far, we assume the file on disk was patched
        # setting __saved_successfully ensures that we start showing the
        # 'quick apply' right click context menu going forward
        #
        # this is to help cut down on crowding the right click menu only
        # until the user explicitly starts using the patching plugin, but
        # also applying their patches to a a binary
        #

        if self.prefer_quick_apply:
            self.__saved_successfully = True

    def quick_apply(self):
        """
        Apply the current patches using the last-known settings.
        """

        try:
            self.apply_patches(self.patched_filepath, self.prefer_patch_cleanly)
        except Exception as e:
            return (False, e)

        return (True, None)

    #--------------------------------------------------------------------------
    # Plugin Internals
    #--------------------------------------------------------------------------

    def _ensure_clean_backup(self, target_filepath):
        """
        Return True if a clean executable matching the open IDB is available on disk.
        """

        #
        # TODO: what do we do if one/both of these are invalid or blank?
        # such as a blank or tmp IDB? what do they return in this case?
        #

        input_md5 = ida_nalt.retrieve_input_file_md5()
        input_filepath = ida_nalt.get_input_file_path()

        #
        # we will search this list of filepaths for an executable / source
        # file that matches the reported hash of the file used to generate
        # this IDA database
        #

        filepaths = [target_filepath, self.backup_filepath, input_filepath]
        filepaths = list(filter(None, filepaths))

        # search the list of filepaths for a clean file
        while filepaths:

            # get the next filepath to evaluate
            filepath = filepaths.pop(0)

            #
            # if the given filepath does not end with a '.bak', push a version
            # of the current filepath with that extension to make for a more
            # comprehensive search of a clean backup file
            #
            # we insert this at the front of the list because it should be
            # searched next (the list is kind of ordered by relevance already)
            #

            if not filepath.endswith('.bak'):
                filepaths.insert(0, filepath + '.bak')

            #
            # attempt to read (and then hash) each file that is being
            # considered as a possible source for our clean backup
            #

            try:
                disk_data = open(filepath, 'rb').read()
            except Exception as e:
                #print(" - Failed to read '%s' -- Reason: %s" % (filepath, str(e)))
                continue

            disk_md5 = hashlib.md5(disk_data).digest()

            #
            # MD5 of the tested file does not match the ORIGINAL (clean) file
            # so we simply ignore it cuz it is useless for our purposes
            #

            if disk_md5 != input_md5:
                #print(" - MD5: '%s' -- does not match IDB (probably previously patched)" % filepath)
                continue

            #
            # the MD5 matches between the original executable hash provided by
            # IDA and a hashed file on disk. use this as the source filepath
            # for our dialog
            #

            clean_filepath = filepath
            #print(" - Found unpatched binary! '%s'" % filepath)
            break

        #
        # if we did not break from the loop above, that means we could not
        # find an executable with a hash that is deemed valid to cleanly
        # patch from, so there is nothing else we can do
        #

        else:
            raise PatchBackupError("Failed to locate a clean executable")

        #
        # we have verified that a clean version of the executable matching
        # this database exists on-disk.
        #
        # in the case below, the clean file (presumably a '.bak' file that
        # was previously created) is not at risk of getting overwritten as
        # target_filepath is where the resulting / patched binary is going
        # to be written by the ongoing save action
        #
        # nothing else to do but return success
        #

        if clean_filepath != target_filepath:
            return clean_filepath

        #
        # if the clean filepath does not match the target (output) path, we
        # make a copy of the file and add a '.bak' extension to it as we don't
        # want to overwrite potentially the only clean copy of the file
        #
        # in this case, the user is probably patching foo.exe for the first
        # time, so we are going to be creating foo.exe.bak here
        #

        clean_filepath += '.bak'

        #
        # before attempting to make a clean file backup, we can try checking
        # the hash of the existing file (if there is one) ...
        #
        # if the hash matches what we expect of the clean backup, then the
        # file appears to be readable and sufficient to use as a backup as-is
        #

        try:
            clean_md5 = hashlib.md5(open(clean_filepath, 'rb').read()).digest()
            if clean_md5 == input_md5:
                return clean_filepath

        #
        # failed to read/hash file? maybe it doesn't exist... or it's not
        # readable/writable (locked?) in which case the next action will
        # fail and throw the necessary exception for us instead
        #

        except:
            pass

        #
        # finally, attempt to make the backup of our patch target, as it
        # doesn't seem to exist yet (... or we can't seem to read the file,
        # in which case we're trying a last ditch attempt at overwriting it)
        #

        try:
            shutil.copyfile(target_filepath, clean_filepath)

        #
        # if we failed to write (overwrite?) the desired file for our clean
        # backup, then we cannot ensure that a clean backup exists
        #

        except Exception as e:
            raise PatchBackupError("Failed to write backup executable", clean_filepath)

        # all done
        return clean_filepath

    def _refresh_patches(self):
        """
        Refresh the list of patched addresses directly from the database.
        """
        addresses = set()

        def visitor(ea, file_offset, original_value, patched_value):
            addresses.add(ea)
            return 0

        ida_bytes.visit_patched_bytes(0, ida_idaapi.BADADDR, visitor)
        self.patched_addresses = addresses
        ida_kernwin.execute_sync(self._notify_patches_changed, ida_kernwin.MFF_NOWAIT|ida_kernwin.MFF_WRITE)

    #--------------------------------------------------------------------------
    # Plugin Events
    #--------------------------------------------------------------------------

    def patches_changed(self, callback):
        """
        Subscribe a callback for patch change events.
        """
        register_callback(self._patches_changed_callbacks, callback)

    def _notify_patches_changed(self):
        """
        Notify listeners that the patches changed.
        """

        #
        # this function is supposed to notify the plugin components (such as
        # UI) that they should refresh because their data may be stale.
        #
        # currently, the plugin calls this function via async (MFF_FAST)
        # callbacks queued with execute_sync().
        #
        # the reason we do this is because we need to give IDA some time to
        # process pending actions/events/analysis/ui (etc.) after patching
        # or reverting bytes.
        #
        # if we don't execute 'later' (MFF_FAST), some things like generating
        # disassembly text for a patched instruction may be ... wrong or
        # incomplete (eg )
        #

        notify_callback(self._patches_changed_callbacks)

        # for execute_sync(...)
        return 1

    #--------------------------------------------------------------------------
    # IDA Events
    #--------------------------------------------------------------------------

    def _populating_widget_popup(self, widget, popup, ctx):
        """
        IDA is populating the context menu for a widget.
        """
        is_idaview = False

        # IDA disassembly view
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_DISASM:
            is_idaview = True

        # custom / interactive patching view
        elif ida_kernwin.get_widget_title(widget) == 'PatchingCodeViewer':
            pass

        # other IDA views that we don't care to inject actions into
        else:
            return

        # fetch the 'right clicked' instruction address
        clicked_ea = get_current_ea(ctx)

        #
        # check if the user has 'selected' any amount of text in the widget.
        #
        # it is important we use this method/API so that we can best position
        # our patching actions within the right click context menu (by
        # predicting what else will be visible in the menu).
        #

        p0, p1 = ida_kernwin.twinpos_t(), ida_kernwin.twinpos_t()
        range_selected = ida_kernwin.read_selection(widget, p0, p1)

        valid_ea, start_ea, end_ea = read_range_selection(ctx)
        if not valid_ea:
            start_ea = clicked_ea

        # determine if the user selection or right click covers a patch
        if (range_selected and valid_ea):
            #print("User range: 0x%08X --> 0x%08X" % (start_ea, end_ea))
            show_revert = self.is_range_patched(start_ea, end_ea)
        else:
            #print("User click: 0x%08X" % clicked_ea)
            show_revert = self.is_item_patched(clicked_ea)

        # determine if the user right clicked code
        is_code = ida_bytes.is_code(ida_bytes.get_flags(clicked_ea))

        #
        # attempt to 'pin' the patching actions towards the top of the right
        # click context menu. we do this by 'appending' our 'NOP' action after
        # a built-in action that we expect to be near the top of the menu.
        #
        # NOTE: IDA shows 'different' commands based on the context and state
        # during the right click. that is why we try to aggressively identify
        # what will be in the right click menu so that we can consistently
        # pin our actions in the desired location
        #

        if range_selected:

            if ida_segment.segtype(start_ea) == ida_segment.SEG_CODE:
                ida_kernwin.attach_action_to_popup(widget, popup, NopAction.NAME, "Analyze selected area", ida_kernwin.SETMENU_APP)
            else:
                ida_kernwin.attach_action_to_popup(widget, popup, NopAction.NAME, "Abort selection", ida_kernwin.SETMENU_APP)

            #
            # TODO: lol there's probably a better way to do this, but I'm
            # writing this fix a little bit late. we basically are trying to
            # check if the user has a visual selection spanning multiple lines
            #
            # if multiple lines are selected, we don't want to show the
            # 'Assemble' command. as it is unlikely that the user right
            # right clicking a selected range to explicitly assemble
            #
            # that said, if the user only selected a few chars on the SAME
            # line it may have been an unintentional 'range selection' in
            # in which case we DO want to show 'Assemble'
            #

            p0s = p0.place_as_simpleline_place_t()
            p1s = p1.place_as_simpleline_place_t()
            multi_line_selection = p0s.n != p1s.n

        else:
            ida_kernwin.attach_action_to_popup(widget, popup, NopAction.NAME, "Rename", ida_kernwin.SETMENU_APP)
            multi_line_selection = False

        #
        # PREV_ACTION will hold the 'most recent' action we appended to the
        # menu. this is done to simplify the remaining code while appending
        # our subsequent patching actions.
        #

        PREV_ACTION = NopAction.TEXT

        # if the user right clicked a single instruction...
        if is_code and not (range_selected and multi_line_selection):

            # inject the 'assemble' action (but not in the patching dialog)
            if is_idaview:
                ida_kernwin.attach_action_to_popup(widget, popup, AssembleAction.NAME, PREV_ACTION, ida_kernwin.SETMENU_APP)
                PREV_ACTION = AssembleAction.TEXT

            # inject the 'force jump' action if a conditional jump was right clicked
            mnemonic = ida_ua.print_insn_mnem(clicked_ea)
            if self.assembler.is_conditional_jump(mnemonic):
                ida_kernwin.attach_action_to_popup(widget, popup, ForceJumpAction.NAME, PREV_ACTION, ida_kernwin.SETMENU_APP)
                PREV_ACTION = ForceJumpAction.TEXT

        # if the user selected some patched bytes, show the 'revert' action
        if show_revert:
            ida_kernwin.attach_action_to_popup(widget, popup, RevertAction.NAME, PREV_ACTION, ida_kernwin.SETMENU_APP)
            PREV_ACTION = RevertAction.TEXT

        #
        # if the user has 'saved' patches at any point this session, we should
        # show them the quick save option as they are likely going to save
        # patches again at some point...
        #

        if self.__saved_successfully:
            ida_kernwin.attach_action_to_popup(widget, popup, QuickApplyAction.NAME, PREV_ACTION, ida_kernwin.SETMENU_APP)
            PREV_ACTION = QuickApplyAction.TEXT

        #
        # TODO/Hex-Rays: is there no way to define/append a submenu with my
        # action group??? I want to put 'Patching --> ...' after my last action
        # and not at the *very end* of the right click menu...
        #
        #  e.g. +---------------------+
        #       | Rename...           |
        #       |---------------------+
        #       | NOP                 |
        #       | Assemble...         |
        #       | Patching --------------->-+-----------------+
        #       +---------------------+     | Change bytes... |
        #       | Jump to operand     |     |      ...        |
        #       | Jump in a new ...   |     '                 '
        #       |        ...          |
        #
        # for now, we use the following 'HACK' API to create a submenu at the
        # preferred location in the right click context menu
        #

        self._patching_submenu = attach_submenu_to_popup(popup, "Patching", PREV_ACTION)

        # extended list of 'less common' actions saved under a patching submenu
        ida_kernwin.attach_action_to_popup(widget, popup, "PatchByte", "Patching/")
        ida_kernwin.attach_action_to_popup(widget, popup, "PatchedBytes", "Patching/")
        ida_kernwin.attach_action_to_popup(widget, popup, ApplyAction.NAME, "Patching/")

        # insert start spacer before / after our action group
        ida_kernwin.attach_action_to_popup(widget, popup, "-", NopAction.TEXT, ida_kernwin.SETMENU_INS)
        ida_kernwin.attach_action_to_popup(widget, popup, "-", "Patching/", ida_kernwin.SETMENU_APP)

    def _highlight_lines(self, out, widget, rin):
        """
        IDA is drawing disassembly lines and requesting highlighting info.
        """

        # ignore line highlight events that are not for a disassembly view
        if ida_kernwin.get_widget_type(widget) != ida_kernwin.BWN_DISASM:
            return

        # highlight lines/addresses that have been patched by the user
        for section_lines in rin.sections_lines:
            for line in section_lines:
                line_ea = line.at.toea()
                item_len = ida_bytes.get_item_size(line_ea)

                # explode a line / instruction into individual addresses
                line_addresses = set(range(line_ea, line_ea+item_len))

                # if no patched bytes correspond to this line / instruction
                if not(line_addresses & self.patched_addresses):
                    continue

                # highlight the line if it is patched in some way
                e = ida_kernwin.line_rendering_output_entry_t(line)
                e.bg_color = ida_kernwin.CK_EXTRA2
                e.flags = ida_kernwin.LROEF_FULL_LINE

                # save the highlight to the output line highlight list
                out.entries.push_back(e)

    def _ida_undo_occurred(self, action_name, is_undo):
        """
        IDA completed an Undo / Redo action.
        """

        #
        # if the user happens to use IDA's native UNDO or REDO functionality
        # we will completely discard our tracked set of patched addresses and
        # query IDA for the true, current set of patches
        #

        self._refresh_patches()
        return 0

    #--------------------------------------------------------------------------
    # Temp / DEV / Tests
    #--------------------------------------------------------------------------

    #
    # HACKER'S SECRET
    #
    # this section is purely for testing / development / profiling. it may be
    # messy, out of place, transient, incomplete, broken, unsupported etc.
    #
    # if you want to hack on this plugin or are trying to edit / dev on the
    # codebase, you can quickly 'reload' the plugin without actually having
    # to restart IDA to test your changes in *most* cases.
    #
    # in the IDA console, you can use:
    #
    #    patching.reload()
    #
    # additionally, you can call into parts of the loaded plugin instance
    # from the IDA console for testing certain parts:
    #
    #    patching.core.nop_item(here())
    #
    # finally, to 'test' assembling all of the instructions in your IDB (to
    # try and identify assembly issues or unsupported instructions) you can
    # run the following command:
    #
    #    patching.core.assemble_all()
    #
    # this may be slow and take several minutes (sometimes much longer) to
    # run depending on the size of the IDB
    #

    def profile(self):
        """
        Profile assemble_all(...) to

        NOTE: you should probably only call this in 'small' databases.
        """
        import pprofile
        prof = pprofile.Profile()
        with prof():
            self.assemble_all()
        prof.print_stats()

    def parse_all(self):
        for ea in all_instruction_addresses(0):
            ida_auto.show_addr(ea)
            comps = get_disassembly_components(ea)
            if comps[0]:
                print("%08X: %s" % (ea, str(comps)))

    def assemble_all(self):
        """
        Attempt to re-assemble every instruction in the IDB, byte-for-byte.

        TODO: build out some actual dedicated tests
        """
        import time, datetime
        start_time = time.time()
        start = 0

        headless = ida_kernwin.cvar.batch

        # the number of correctly re-assembled instructions
        good = 0
        total = 0
        fallback = 0
        unsupported = 0
        unsupported_map = collections.defaultdict(int)

        slow_limit = -1
        asm_threshold = 0.1

        # track failures
        fail_addrs = collections.defaultdict(list)
        fail_bytes = collections.defaultdict(set)
        alternates = set()

        for ea in all_instruction_addresses(start):

            # update the navbar cursor based on progress (only when in UI)
            if not headless:
                ida_auto.show_addr(ea)

            #
            # skip some instructions to cut down on noise (lots of noise /
            # false positives with NOP)
            #

            mnemonic = ida_ua.print_insn_mnem(ea)

            # probably undefined data in code / can't be disas / bad instructions
            if not mnemonic:
                continue

            mnemonic = mnemonic.upper()

            # ignore instructions that can decode a wild number of ways
            if mnemonic in ['NOP', 'XCHG']:
                continue

            # keep track of how many instructions we care to 'assemble'
            total += 1

            # ignore instructions that simply aren't supported yet
            if mnemonic in self.assembler.UNSUPPORTED_MNEMONICS:
                unsupported += 1
                unsupported_map[mnemonic] += 1
                continue

            # fetch raw info about the instruction
            disas_raw = self.assembler.format_assembly(ea)
            disas_size = ida_bytes.get_item_size(ea)
            disas_bytes = ida_bytes.get_bytes(ea, disas_size)

            #print("0x%08X: ASSEMBLING '%s'" % (ea, disas_raw))
            start_asm = time.time()
            asm_bytes = self.assembler.asm(disas_raw, ea)
            end_asm = time.time()
            asm_time = end_asm - start_asm

            if asm_time > asm_threshold:
                print("%08X: SLOW %0.2fs - %s" % (ea, asm_time, disas_raw))
                slow_limit -= 1
                if slow_limit == 0:
                    break

            # assembled vs expected
            byte_tuple = (asm_bytes, disas_bytes)

            # assembled bytes match what is in the database
            if asm_bytes == disas_bytes or byte_tuple in alternates:
                good += 1
                continue

            asm_bytes = self.assembler.asm(disas_raw, ea)

            byte_tuple = (asm_bytes, disas_bytes)

            # assembled bytes match what is in the database
            if asm_bytes == disas_bytes or byte_tuple in alternates:
                good += 1
                fallback += 1
                continue

            known_text = disas_raw in fail_addrs
            known_bytes = byte_tuple in fail_bytes[disas_raw]

            if not known_bytes and len(asm_bytes):

                # the assembled patch is the same size, or smaller than the og
                if len(asm_bytes) <= len(disas_bytes):
                    ida_before = ida_lines.tag_remove(ida_lines.generate_disasm_line(ea))
                    ida_after = disassemble_bytes(asm_bytes, ea)

                    ida_after = ida_after.split(';')[0]
                    ida_after = ida_after.replace(' short ', ' ')
                    ida_before = ida_before.split(';')[0]

                    okay = False
                    if ida_after == ida_before:
                        okay = True

                    #
                    # BEFORE: 'add     [rax+rax+0], ch'
                    #  AFTER: 'add     [rax+rax], ch
                    # 0x18004830B: NEW FAILURE 'add     [rax+rax+0], ch'
                    #  - IDA: 00 6C 00 00
                    #  - ASM: 00 2C 00
                    #

                    elif ida_before.replace('+0]', ']') == ida_after:
                        okay = True

                    elif '$+5' in ida_before:
                        okay = True

                    if okay:
                        alternates.add(byte_tuple)
                        good += 1
                        continue

                    print("BEFORE: '%s'\n AFTER: '%s" % (ida_before, ida_after))

            fail_addrs[disas_raw].append(ea)
            fail_bytes[disas_raw].add(byte_tuple)

            if known_text and known_bytes:
                continue

            if not known_text:
                print("0x%08X: NEW FAILURE '%s'" % (ea, disas_raw))
            else:
                print("0x%08X: NEW BYTES '%s'" % (ea, disas_raw))

            disas_hex = ' '.join(['%02X' % x for x in disas_bytes])
            asm_hex = ' '.join(['%02X' % x for x in asm_bytes])
            print(" - IDA: %s\n - ASM: %s" % (disas_hex, asm_hex))
            #break

        print("-"*50)
        print("RESULTS")
        print("-"*50)

        for disas_raw in sorted(fail_addrs, key=lambda k: len(fail_addrs[k]), reverse=True):
            print("%-5u Fails -- %-40s -- (%u unique patterns)" % (len(fail_addrs[disas_raw]), disas_raw, len(fail_bytes[disas_raw])))

        if False:

            print("-"*50)
            print("ALTERNATE MAPPINGS")
            print("-"*50)

            for x, y in alternates:
                print('%-20s\t%s' % (' '.join(['%02X' % z for z in x]), ' '.join(['%02X' % z for z in y])))

        if unsupported_map:

            print("-"*50)
            print("(KNOWN) Unsupported Mnemonics")
            print("-"*50)
            
            for mnem, hits in unsupported_map.items():
                print(" - %s - hits %u" % (mnem.ljust(10), hits))

        if total:
            percent = str((good/total)*100)
        else:
            percent = "100.0"

        percent_truncated = percent[:percent.index('.')+3] # truncate! don't round this float...

        inf = ida_idaapi.get_inf_structure()
        arch_name = inf.procname.lower()

        total_failed = total - good
        unknown_fails = total_failed - unsupported
        print("-"*50)
        print(" - Success Rate {percent}% -- {good:,} / {total:,} ({fallback:,} fallbacks, {total_failed:,} failed ({unsupported:,} were unsupported mnem, {unknown_fails:,} were unknown)) -- arch '{arch_name}' -- file '{input_path}'".format(
                percent=percent_truncated.rjust(6, ' '),
                good=good,
                total=total,
                fallback=fallback,
                total_failed=total_failed,
                unsupported=unsupported,
                unknown_fails=unknown_fails,
                arch_name=arch_name,
                input_path=ida_nalt.get_input_file_path()
            )
        )

        total_time = int(time.time() - start_time)
        print(" - Took %s %s..." % (datetime.timedelta(seconds=total_time), 'minutes' if total_time >= 60 else 'seconds'))
