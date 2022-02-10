import hashlib

import ida_nalt

from patching.util.qt import QT_AVAILABLE
from patching.exceptions import *

if QT_AVAILABLE:
    from patching.ui.save_ui import SaveDialog

class SaveController(object):
    """
    The backing logic & model (data) for the patch saving UI.
    """
    WINDOW_TITLE = "Apply patches to..."

    def __init__(self, core, error=None):
        self.core = core
        self.view = None

        # init fields
        self._init_settings()

        # init error (if there was one that caused the dialog to pop)
        self.attempts = 1 if error else 0
        self._set_error(error)

        # only create the UI for the save dialog as needed
        if QT_AVAILABLE:
            self.view = SaveDialog(self)

    def _init_settings(self):
        """
        Initialize dialog settings from the plugin core / IDA state.
        """

        # inherit certain settings from the plugin core
        self.patch_cleanly = self.core.prefer_patch_cleanly
        self.quick_apply = self.core.prefer_quick_apply

        # the target file to patch / apply patches to
        self.target_filepath = self.core.patched_filepath
        if not self.target_filepath:
            self.target_filepath = ida_nalt.get_input_file_path()

    def _set_error(self, exception):
        """
        Set the save dialog error text based on the given exception.
        """

        # no error given, reset message text / color fields
        if exception is None:
            self.status_message = ''
            self.status_color = ''
            return

        #
        # something went wrong trying to ensure a usable backup / clean
        # executable was available for the patching operation. this should
        # only ever occur when the user is attempting to 'patch cleanly'
        #
        # this is most likely because the plugin could not locate a clean
        # version of the executable on disk. if the user would like to try
        # yolo-patching the target file, they can un-check 'Patch cleanly'
        #

        if isinstance(exception, PatchBackupError):
            self.status_message = str(exception) + "\nDisable 'Patch cleanly' to try patching anyway (att #%u)" % self.attempts
            self.status_color = 'red'

        #
        # something went wrong explicitly trying to modify the target / output
        # file for the patching operation.
        #
        # this is most likely because the file is locked, but the target file
        # could also be missing (among other reasons)
        #

        elif isinstance(exception, PatchTargetError) or isinstance(exception, PatchApplicationError):
            self.status_message = str(exception) + "\nIs the filepath above locked? or missing? (att #%u)" % self.attempts
            self.status_color = 'red'

        # unknown / unhandled error?
        else:
            self.status_message = "Unknown error? (att #%u)\n%s" % (self.attempts, str(exception))
            self.status_color = 'red'

    #--------------------------------------------------------------------------
    # Actions
    #--------------------------------------------------------------------------

    def interactive(self):
        """
        Spawn an interactive user dialog and wait for it to close.
        """
        if not self.view:
            return False
        return self.view.exec_()

    def attempt_patch(self, target_filepath, clean):
        """
        Attempt to patch the target binary.
        """

        #
        # increment the 'patch attempt' count over the lifetime of this
        # dialog. the purpose of this counter is simple: it is a visual
        # cue to users who will continue to mash the 'Apply Patches'
        # button even in the face of a big red error message.
        #
        # the idea is that (hopefully) they will see this 'attempt count'
        # updating in the otherwise static error message text to indicate
        # that 'yes, the file is still locked/unavailabe/missing' until
        # they go rectify the issue
        #

        self.attempts += 1

        #
        # attempt to apply patches to the target file on behalf of the
        # interactive dialog / user request
        #

        try:
            self.core.apply_patches(target_filepath, clean)
        except Exception as e:
            self._set_error(e)
            return False

        #
        # if we made it this far, patching must have succeeded, save patch
        # settings to the core plugin
        #

        self.status_message = ''
        self.core.prefer_patch_cleanly = self.patch_cleanly
        self.core.prefer_quick_apply = self.quick_apply

        # return success
        return True

    def update_target(self, target_filepath):
        """
        Update the targeted filepath.
        """
        self.target_filepath = target_filepath
        if self.patch_cleanly:
            return

        #
        # if the UI setting for 'Patch cleanly' is explicitly unchecked but
        # the user *just* updated the target filepath via file dialog, we
        # will quickly try to check if the selected file appears to be
        # a good candidate for making a copy (backup) of during the likely
        # imminent patch save / application operation
        #

        try:
            disk_md5 = hashlib.md5(open(target_filepath, 'rb').read()).digest()
        except Exception:
            return

        # the MD5 hash of the file (executable) used to generate this IDB
        input_md5 = ida_nalt.retrieve_input_file_md5()
        if input_md5 != disk_md5:
            return

        #
        # at this point, the user has explicitly selected a patch target that
        # appears to be clean, yet they have 'Patch cleanly' disabled, so we
        # should provide them with a 'soft' hint / warning that it would be
        # best for them to turn 'Patch cleanly' back on...
        #

        self.status_message = "The patch target appears to be a clean executable,\nit is recommended you turn on 'Patch cleanly'"
        self.status_color = 'orange'
