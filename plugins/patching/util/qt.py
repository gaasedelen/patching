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
