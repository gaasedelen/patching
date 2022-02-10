import os

from patching.util.qt import *

class SaveDialog(QtWidgets.QDialog):
    """
    The UI components of the Patch Saving dialog.
    """

    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self._ui_init()

    #--------------------------------------------------------------------------
    # Initialization - UI
    #--------------------------------------------------------------------------

    def _ui_init(self):
        """
        Initialize UI elements.
        """
        self.setWindowTitle(self.controller.WINDOW_TITLE)

        # remove auxillary buttons (such as '?') from window title bar
        remove_flags = ~(
            QtCore.Qt.WindowSystemMenuHint |
            QtCore.Qt.WindowContextHelpButtonHint
        )
        self.setWindowFlags(self.windowFlags() & remove_flags)
        self.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)

        # make dialog fixed size (no size grip, etc)
        #self.setWindowFlags(self.windowFlags() | QtCore.Qt.MSWindowsFixedSizeDialogHint)
        #self.setSizeGripEnabled(False)

        # make dialog modal, so users can't click around IDA / change more stuff
        #self.setModal(True)

        # initialize our ui elements
        self._ui_init_fields()
        self._ui_init_options()

        # layout the populated ui just before showing it
        self._ui_layout()

        # connect signals
        self._btn_target.clicked.connect(self.select_target_file)
        self._btn_apply.clicked.connect(self._attempt_patch)
        self._chk_clean.stateChanged.connect(self._checkboxes_changed)
        self._chk_quick.stateChanged.connect(self._checkboxes_changed)

    def _ui_init_fields(self):
        """
        Initialize the interactive text fields for this UI control.
        """
        self._label_target = QtWidgets.QLabel("Patch Target:")
        self._label_target.setAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
        self._line_target = QtWidgets.QLineEdit()
        self._line_target.setText(self.controller.target_filepath)
        self._line_target.setMinimumWidth(360)
        self._btn_target = QtWidgets.QPushButton(" ... ")

        # warning / status message
        self._label_status = QtWidgets.QLabel()
        self._label_status.setWordWrap(True)
        self._label_status.setAlignment(QtCore.Qt.AlignTop | QtCore.Qt.AlignHCenter)
        self._refresh_status_message()

        # apply patches button
        self._btn_apply = QtWidgets.QPushButton("Apply patches")

    def _ui_init_options(self):
        """
        Initialize the interactive options for this UI control.
        """
        self._group_options = QtWidgets.QGroupBox("Options")

        # checkbox options
        self._chk_clean = QtWidgets.QCheckBox("Patch cleanly")
        self._chk_clean.setChecked(self.controller.patch_cleanly)
        self._chk_clean.setToolTip("Maintain a clean (.bak) input file to clone and apply patches to each time")
        self._chk_quick = QtWidgets.QCheckBox("Show quick save")
        self._chk_quick.setChecked(self.controller.quick_apply)
        self._chk_quick.setToolTip("Use the current target filepath for future patch applications")

        # layout the groupbox
        layout = QtWidgets.QVBoxLayout(self._group_options)
        layout.addWidget(self._chk_clean)
        layout.addWidget(self._chk_quick)
        self._group_options.setLayout(layout)

    def _ui_layout(self):
        """
        Layout the major UI elements of the widget.
        """
        layout = QtWidgets.QGridLayout(self)

        # arrange the widgets in a 'grid'         row  col  row span  col span
        layout.addWidget(self._line_target,         0,   1,        1,        1)
        layout.addWidget(self._btn_target,          0,   2,        1,        1)
        layout.addWidget(self._group_options,       0,   0,        2,        1)
        layout.addWidget(self._label_status,        1,   1,        2,        1)
        layout.addWidget(self._btn_apply,           1,   2,        1,        1)
        #layout.setSizeConstraint(QtWidgets.QLayout.SetFixedSize)

        # apply the layout to the widget
        self.setLayout(layout)

    #--------------------------------------------------------------------------
    # Events
    #--------------------------------------------------------------------------

    def showEvent(self, e):
        """
        Overload the showEvent to center the save dialog over the IDA main window.
        """
        center_widget(self)
        return super().showEvent(e)

    def select_target_file(self):
        """
        The user pressed the '...' button to select a file to patch.
        """
        starting_directory = os.path.dirname(self.controller.target_filepath)

        # prompt the user to select a patch target / output file
        dialog = QtWidgets.QFileDialog()
        filepath, _ = dialog.getSaveFileName(caption="Select patch target...", directory=starting_directory)

        # user did not select a file or closed the file dialog
        if not filepath:
            return

        # save the selected patch target
        self.controller.update_target(filepath)
        self._line_target.setText(filepath)

        #
        # update the status text, in-case the controller has something
        # important to tell the user (eg, hinting them to turn clean
        # patching on, if it thinks it will succeed)
        #

        self._refresh_status_message()

    def _attempt_patch(self):
        """
        The user clicked the Apply Patches button.
        """
        target_filepath = self._line_target.text()
        apply_clean = self._chk_clean.isChecked()

        # if patching succeeds, we're all done! close the dialog
        if self.controller.attempt_patch(target_filepath, apply_clean):
            self.accept()
            return

        # patching must have failed, attempt to update the status / error message
        self._refresh_status_message()

    def _checkboxes_changed(self):
        """
        The status of the checkboxes changed.
        """
        self.controller.patch_cleanly = self._chk_clean.isChecked()
        self.controller.quick_apply = self._chk_quick.isChecked()

    #--------------------------------------------------------------------------
    # Refresh
    #--------------------------------------------------------------------------

    def _refresh_status_message(self):
        """
        Refresh the status / error message text based on the underlying UI state.
        """
        self._label_status.setText(self.controller.status_message)
        if self.controller.status_color:
            self._label_status.setStyleSheet("QLabel { font-weight: bold; color: %s; }" % (self.controller.status_color))
        else:
            self._label_status.setStyleSheet(None)
