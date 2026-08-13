#
# this global is used to indicate whether Qt bindings for python are present
# and whether the plugin should expect to be using UI features
#

QT_AVAILABLE = False

# attempt to load PyQt5
try:
    import PyQt5.QtGui as QtGui
    import PyQt5.QtCore as QtCore
    import PyQt5.QtWidgets as QtWidgets
    from PyQt5 import sip

    # importing PyQt5 went okay, let's see if we're in an IDA Qt context
    try:
        import ida_kernwin
        QT_AVAILABLE = ida_kernwin.is_idaq()
    except ImportError:
        pass

# import failed, PyQt5 is not available
except ImportError:
    pass

#--------------------------------------------------------------------------
# IDA Qt5 Widget Conversion
#--------------------------------------------------------------------------

def twidget_to_qwidget(twidget):
    """Wrap an IDA Qt5 TWidget with PyQt5, never PySide6/Qt6.

    IDA 9.1's generic TWidgetToQtPythonWidget prefers PySide6 when it is
    installed in the selected Python environment. IDA itself uses Qt5, so
    wrapping that pointer as a Qt6 QWidget causes an access violation.
    """
    import ctypes

    if type(twidget).__name__ == 'SwigPyObject':
        address = int(twidget)
    else:
        get_pointer = ctypes.pythonapi.PyCapsule_GetPointer
        get_pointer.restype = ctypes.c_void_p
        get_pointer.argtypes = [ctypes.py_object, ctypes.c_char_p]
        address = get_pointer(twidget, b'$valid$')

    if not address:
        raise RuntimeError("IDA returned an invalid TWidget pointer")

    return sip.wrapinstance(int(address), QtWidgets.QWidget)
#--------------------------------------------------------------------------
# Qt Misc Helpers
#--------------------------------------------------------------------------

def get_main_window():
    """
    Return the Qt Main Window.
    """
    app = QtWidgets.QApplication.instance()
    for widget in app.topLevelWidgets():
        if isinstance(widget, QtWidgets.QMainWindow):
            return widget
    return None

def center_widget(widget):
    """
    Center the given widget to the Qt Main Window.
    """
    main_window = get_main_window()
    if not main_window:
        return False

    #
    # compute a new position for the floating widget such that it will center
    # over the Qt application's main window
    #

    rect_main = main_window.geometry()
    rect_widget = widget.rect()

    centered_position = rect_main.center() - rect_widget.center()
    widget.move(centered_position)

    return True
