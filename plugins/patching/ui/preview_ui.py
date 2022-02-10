import ida_name
import ida_kernwin

from patching.util.qt import *
from patching.util.ida import *
from patching.util.python import hexdump

LAST_LINE_IDX = -1

class PatchingDockable(ida_kernwin.PluginForm):
    """
    The UI components of the Patching dialog.
    """

    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self.count = 0

    #--------------------------------------------------------------------------
    # IDA PluginForm Overloads
    #--------------------------------------------------------------------------

    def Show(self):

        # TODO/Hex-Rays/XXX: can't make window Floating? using plgform_show(...) instead
        flags = ida_kernwin.PluginForm.WOPN_DP_FLOATING | ida_kernwin.PluginForm.WOPN_CENTERED
        #super(PatchingDockable, self).Show(self.controller.WINDOW_TITLE, flags)
        ida_kernwin.plgform_show(self.__clink__, self, self.controller.WINDOW_TITLE, flags)
        self._center_dialog()

        #
        # set the initial cursor position to focus on the target address
        #
        # we bump the focus location down a few lines from the top of the
        # window to center the cursor a bit.
        #

        self.set_cursor_pos(self.controller.address, self.controller.address_idx, 0, 6)

        # set the initial keyboard focus the editable assembly line
        self._line_assembly.setFocus(QtCore.Qt.FocusReason.ActiveWindowFocusReason)

    def OnCreate(self, form):
        self._twidget = form
        self.widget = ida_kernwin.PluginForm.TWidgetToPyQtWidget(self._twidget)
        self._ui_init()

    def OnClose(self, form):
        self._edit_timer.stop()
        self._edit_timer = None
        self._code_view = None
        self.controller.view = None
        return super().OnClose(form)

    #--------------------------------------------------------------------------
    # Initialization - UI
    #--------------------------------------------------------------------------

    def _ui_init(self):
        """
        Initialize UI elements.
        """
        self.widget.setMinimumSize(350, 350)

        # setup a monospace font for code / text printing
        self._font = QtGui.QFont("Courier New")
        self._font.setStyleHint(QtGui.QFont.Monospace)

        # initialize our ui elements
        self._ui_init_code()
        self._ui_init_fields()

        # populate the dialog/fields with initial contents from the database
        self.refresh()

        # set the code view to focus on an initial line
        self._code_view.Jump(self._code_view.GetLineNo(), y=5)

        # layout the populated ui just before showing it
        self._ui_layout()

        #
        # NOTE: we 'defer' real-time instruction assembly (while typing) in
        # the patching dialog if we think the database is 'big enough' to
        # make the text input lag due to slow symbol resolution (eg. having
        # to search the entire IDA 'name list' for an invalid symbol)
        #

        self._edit_timer = QtCore.QTimer(self.widget)
        self._edit_timer.setSingleShot(True)
        self._edit_timer.timeout.connect(self._edit_stopped)

        if ida_name.get_nlist_size() > 20000:
            self._line_assembly.textEdited.connect(self._edit_started)
        else:
            self._line_assembly.textEdited.connect(self.controller.edit_assembly)

        # connect signals
        self._line_assembly.returnPressed.connect(self._enter_pressed)

    def _ui_init_fields(self):
        """
        Initialize the interactive text fields for this UI control.
        """
        self._line_address = QtWidgets.QLineEdit()
        self._line_address.setFont(self._font)
        self._line_address.setReadOnly(True)
        self._label_address = QtWidgets.QLabel("Address:")
        self._label_address.setAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)

        # configure the line that displays assembly text
        self._line_assembly = AsmLineEdit(self._code_view)
        self._line_assembly.setFont(self._font)
        self._line_assembly.setMinimumWidth(350)
        self._label_assembly = QtWidgets.QLabel("Assembly:")
        self._label_assembly.setAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)

        # configure the line that displays assembled bytes
        self._line_bytes = QtWidgets.QLineEdit()
        self._line_bytes.setFont(self._font)
        self._line_bytes.setReadOnly(True)
        self._label_bytes = QtWidgets.QLabel("Bytes:")
        self._label_bytes.setAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)

    def _ui_init_code(self):
        """
        Initialize the interactive code view for this UI control.
        """
        self._code_view = PatchingCodeViewer(self.controller)

    def _ui_layout(self):
        """
        Layout the major UI elements of the widget.
        """
        layout = QtWidgets.QGridLayout(self.widget)

        # arrange the widgets in a 'grid'         row  col  row span  col span
        layout.addWidget(self._label_address,       0,   0,        1,        1)
        layout.addWidget(self._line_address,        0,   1,        1,        1)
        layout.addWidget(self._label_assembly,      1,   0,        1,        1)
        layout.addWidget(self._line_assembly,       1,   1,        1,        1)
        layout.addWidget(self._label_bytes,         2,   0,        1,        1)
        layout.addWidget(self._line_bytes,          2,   1,        1,        1)
        layout.addWidget(self._code_view.widget,    3,   0,        1,        2)

        # apply the layout to the widget
        self.widget.setLayout(layout)

    def _center_dialog(self):
        """
        Center the current dialog to the IDA MainWindow.

        TODO/Hex-Rays: WOPN_CENTERED flag?! does it not work? or how do I use it?

        XXX: I have no idea why the get_main_window(...) + center_widget(...)
        code I wrote in qt.py does not work for wid_dialog / IDA dockables even
        though it is effectively identical to this lol

        NOTE: this hack will cause a 'widget flicker' as we are moving the widget
        shortly after it is made visible...
        """
        wid_main, wid_dialog = None, None

        #
        # search upwards through the current dialog/widget's parent widgets
        # until the IDA main window is located
        #

        parent = self.widget.parent()
        while parent:

            if isinstance(parent, QtWidgets.QMainWindow):
                wid_main = parent
                break

            elif isinstance(parent, QtWidgets.QWidget):
                if parent.windowTitle() == self.controller.WINDOW_TITLE:
                    wid_dialog = parent

            parent = parent.parent()

        #
        # fail, could not find the IDA main window and the parent container
        # for this widget (unlikely)
        #

        if not (wid_main and wid_dialog):
            return False

        rect_main = wid_main.geometry()
        rect_dialog = wid_dialog.rect()

        #
        # compute a new position for the dialog such that it will center
        # to the IDA main window
        #

        pos_dialog = rect_main.center() - rect_dialog.center()
        wid_dialog.move(pos_dialog)

    #--------------------------------------------------------------------------
    # Refresh
    #--------------------------------------------------------------------------

    def refresh(self):
        """
        Refresh the entire patching dialog.
        """
        self.refresh_fields()
        self.refresh_code()

    def refresh_fields(self):
        """
        Refresh the patching fields.
        """

        # update the address field to show the currently selected address
        self._line_address.setText('0x%08X' % self.controller.address)

        # update the assembly text to show the currently selected instruction
        if self._line_assembly.text() != self.controller.assembly_text:
            self._line_assembly.setText(self.controller.assembly_text)

        # update the assembly bytes field... which can also show an error message
        if self.controller.status_message:
            self._line_bytes.setText(self.controller.status_message)
        else:
            self._line_bytes.setText(hexdump(self.controller.assembly_bytes))

    def refresh_code(self):
        """
        Refresh the patching code view.
        """
        self._code_view.ClearLines()

        # regenerate the view from the current set of lines in the backing model
        for line in self.controller.instructions:

            #
            # instructions with an 'assembly label' (eg. loc_140004200)
            # attached to their address should have these extra lines visible
            # to better simulate a true IDA disassembly listing
            #

            if line.name:
                self._code_view.AddLine(line.line_blank)
                self._code_view.AddLine(line.line_name)

            # emit the actual instruction text
            self._code_view.AddLine(line.line_instruction)

        self._code_view.Refresh()

    def refresh_cursor(self):
        """
        Refresh the user cursor in the patching code view.
        """

        # get the text based co-ordinates within the IDA code view
        ida_pos = self._code_view.GetPos()
        lineno_sel, x, y = ida_pos if ida_pos else (0, 0, 0)

        # fetch the instruction 'selected' by the controller/model
        insn, lineno_insn = self.controller.get_insn_lineno(self.controller.address)

        if self.controller.address_idx == LAST_LINE_IDX:
            lineno_new = lineno_insn + (insn.num_lines - 1)
        else:
            lineno_new = lineno_insn + self.controller.address_idx

        self._code_view.Jump(lineno_new, x, y)

    #-------------------------------------------------------------------------
    # Events
    #-------------------------------------------------------------------------

    def _edit_started(self):
        """
        The assembly text was changed by the user.
        """
        self._edit_timer.stop()

        assembly_text = self._line_assembly.text()
        _, _, ops = parse_disassembly_components(assembly_text)

        #
        # if there's no symbols that would have to be resolved for the
        # the current input, we should attempt assembly immediately as it
        # should be in-expensive (won't lag the text input)
        #

        if not scrape_symbols(ops):
            self.controller.edit_assembly(assembly_text)
            return

        #
        # in 500ms if the user hasn't typed anything else into the assembly
        # field, we will consider their editing as 'stopped' and attempt
        # to evaluate (assemble) their current input
        #

        self._edit_timer.start(500)

    def _edit_stopped(self):
        """
        Some amount of time has passed since the user last edited the assembly text.
        """
        assembly_text = self._line_assembly.text()
        self.controller.edit_assembly(assembly_text)

    def _enter_pressed(self):
        """
        The user pressed enter while the assembly text line was focused.
        """
        if self._edit_timer.isActive():
            self._edit_timer.stop()
            self.controller.edit_assembly(self._line_assembly.text())
        self.controller.commit_assembly()

    #--------------------------------------------------------------------------
    # Misc
    #--------------------------------------------------------------------------

    def get_cursor(self):
        """
        Return the current view cursor information.
        """

        # the line the view is currently focused on
        view_line = self._code_view.GetCurrentLine()
        view_address = parse_line_ea(view_line)

        # get the text based co-ordinates within the IDA code view
        view_pos = self._code_view.GetPos()
        lineno, x, y = view_pos if view_pos else (0, 0, 0)

        #
        # compute the relative line number within the focused address
        #

        global_idx, relative_idx = 0, -1
        while True:

            # fetch a line from the code view
            line = self._code_view.GetLine(global_idx)
            if not line:
                break

            # unpack the returned code viewer line tuple
            colored_line, _, _ = line
            line_address = parse_line_ea(colored_line)

            if line_address == view_address:

                #
                # found the first instruction line matching our cursor
                # address, start the relative line index counter
                #

                if relative_idx == -1:
                    relative_idx = 0

                # next line
                else:
                    relative_idx += 1

            #
            # we have reached the first line with an address GREATER than the
            # lines with an address matching the view's current selection
            #

            elif line_address > view_address:
                break

            global_idx += 1

        #
        # return a position (like, our own place_t) that can be used to jump
        # the patching view to this exact position again, even if the lines
        # or formatting changes around 'a bit'
        #

        return (view_address, relative_idx, x, y)

    def set_cursor_pos(self, address, idx=0, x=0, y=0):
        """
        TODO
        """
        insn, lineno = self.controller.get_insn_lineno(address)
        if not insn:
            raise ValueError("Failed to jump to given address 0x%08X" % address)

        #
        # idx as -1 is a special case to focus on the *last* line of the
        # instruction at the matching address. for example, this is used to
        # focus on the *ACTUAL* instruction text / line for an address that
        # contains multiple lines (blank line + label line + instruction line)
        #

        if idx == -1:
            idx = insn.num_lines - 1
        elif address != insn.address:
            idx = 0

        final_lineno = lineno + idx
        self._code_view.Jump(final_lineno, x, y)

class AsmLineEdit(QtWidgets.QLineEdit):
    """
    A Qt LineEdit with a few extra tweaks.
    """

    def __init__(self, code_view, parent=None):
        super().__init__()
        self.code_view = code_view

    def keyPressEvent(self, event):
        """
        Key press received.
        """

        # navigate DOWN one line in the asm view if the 'down arrow' key
        if event.key() == QtCore.Qt.Key_Down:
            lineno, x, y = self.code_view.GetPos()

            # clamp to the last line, and jump to it
            lineno = min(lineno+1, self.code_view.Count()-1)
            self.code_view.Jump(lineno, x, y)

            # manually trigger the 'Cursor Position Changed' handler
            self.code_view.OnCursorPosChanged()

            # mark the event as handled
            event.accept()
            return

        # navigate UP one line in the code view if the 'up arrow' key
        elif event.key() == QtCore.Qt.Key_Up:
            lineno, x, y = self.code_view.GetPos()

            # clamp to the first line
            lineno = max(lineno-1, 0)
            self.code_view.Jump(lineno, x, y)

            # manually trigger the 'Cursor Position Changed' handler
            self.code_view.OnCursorPosChanged()

            # mark the event as handled
            event.accept()
            return

        # let the key press be handled normally
        super().keyPressEvent(event)

#------------------------------------------------------------------------------
# IDA Code Viewer
#------------------------------------------------------------------------------

class PatchingCodeViewer(ida_kernwin.simplecustviewer_t):
    """
    An IDA controlled 'code viewer' to simulate a disassembly view.
    """

    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self._ui_hooks = UIHooks()
        self._ui_hooks.get_lines_rendering_info = self._highlight_lines
        self.Create()

    #--------------------------------------------------------------------------
    # IDA Code Viewer Overloads
    #--------------------------------------------------------------------------

    def Create(self):
        if not super().Create('PatchingCodeViewer'):
            return False
        self._twidget = self.GetWidget()
        self.widget = ida_kernwin.PluginForm.TWidgetToPyQtWidget(self._twidget)
        self._ui_hooks.hook()
        return True

    def OnClose(self):
        self._ui_hooks.unhook()
        self._filter = None

    def OnCursorPosChanged(self):

        # get the currently selected line in the code view
        view_line = self.GetCurrentLine()
        view_lineno = self.GetLineNo()
        view_address = parse_line_ea(view_line)

        #
        # get the info about the currently selected instruction from the
        # underlying view controller / model
        #

        insn, insn_lineno = self.controller.get_insn_lineno(view_address)

        # compute the cursor's relative index into lines with the same address
        relative_idx = view_lineno - insn_lineno

        # notify the controller of the updated cursor / selection
        self.controller.select_address(view_address, relative_idx)

    def OnPopup(self, form, popup_handle):
        self._filter = remove_ida_actions(popup_handle)
        return False

    #--------------------------------------------------------------------------
    # Events
    #--------------------------------------------------------------------------

    def _highlight_lines(self, out, widget, rin):
        """
        IDA is drawing disassembly lines and requesting highlighting info.
        """

        # ignore line highlight events that are not for the current code view
        if widget != self._twidget:
            return

        selected_lnnum, x, y = self.GetPos()

        # highlight lines/addresses that have been patched by the user
        assert len(rin.sections_lines) == 1
        for i, line in enumerate(rin.sections_lines[0]):
            splace = ida_kernwin.place_t_as_simpleline_place_t(line.at)
            line_info = self.GetLine(splace.n)
            if not line_info:
                continue

            colored_text, _, _ = line_info
            address = parse_line_ea(colored_text)

            current_insn = self.controller.get_insn(address)
            if not current_insn:
                continue

            # convert (ea, size) to represent the full address of each byte in an instruction
            insn_addresses = set(range(current_insn.address, current_insn.address + current_insn.size))

            # green: selected line
            if splace.n == selected_lnnum:
                color = ida_kernwin.CK_EXTRA1

            # red: clobbered line
            elif current_insn.clobbered:
                color = ida_kernwin.CK_EXTRA11

            # yellow: patched line
            elif insn_addresses & self.controller.core.patched_addresses:
                color = ida_kernwin.CK_EXTRA2

            # no highlighting needed
            else:
                continue

            # highlight the line if it is patched in some way
            e = ida_kernwin.line_rendering_output_entry_t(line)
            e.bg_color = color
            e.flags = ida_kernwin.LROEF_FULL_LINE

            # save the highlight to the output line highlight list
            out.entries.push_back(e)
