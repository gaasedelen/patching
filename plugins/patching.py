#------------------------------------------------------------------------------
# Plugin Preflight
#------------------------------------------------------------------------------
#
#    the purpose of this 'preflight' is to test if the plugin is compatible
#    with the environment it is being loaded in. specifically, these preflight
#    checks are designed to be compatible with IDA 7.0+ and Python 2/3
#
#    if the environment does not meet the specifications required by the
#    plugin, this file will gracefully decline to load the plugin without
#    throwing noisy errors (besides a simple print to the IDA console)
#
#    this makes it easy to install the plugin on machines with numerous
#    versions of IDA / Python / virtualenvs which employ a shared plugin
#    directory such as the 'preferred' IDAUSR plugin directory...
#

import sys

# this plugin requires Python 3
SUPPORTED_PYTHON = sys.version_info[0] == 3

# this plugin requires IDA 7.6 or newer
try:
    import idaapi
    import ida_pro
    IDA_GLOBAL_SCOPE = sys.modules['__main__']
    SUPPORTED_IDA = ida_pro.IDA_SDK_VERSION >= 760
except:
    SUPPORTED_IDA = False

# is this deemed to be a compatible environment for the plugin to load?
SUPPORTED_ENVIRONMENT = bool(SUPPORTED_IDA and SUPPORTED_PYTHON)
if not SUPPORTED_ENVIRONMENT:
    print("Patching plugin is not compatible with this IDA/Python version")

#------------------------------------------------------------------------------
# IDA Plugin Stub
#------------------------------------------------------------------------------

if SUPPORTED_ENVIRONMENT:
    import patching
    from patching.util.python import reload_package

def PLUGIN_ENTRY():
    """
    Required plugin entry point for IDAPython plugins.
    """
    return PatchingPlugin()

class PatchingPlugin(idaapi.plugin_t):
    """
    The IDA Patching plugin stub.
    """

    #
    # Plugin flags:
    # - PLUGIN_PROC: Load / unload this plugin when an IDB opens / closes
    # - PLUGIN_HIDE: Hide this plugin from the IDA plugin menu
    # - PLUGIN_UNL:  Unload the plugin after calling run()
    #

    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE | idaapi.PLUGIN_UNL
    comment = "A plugin to enable binary patching in IDA"
    help = ""
    wanted_name = "Patching"
    wanted_hotkey = ""

    def __init__(self):
        self.__updated = getattr(IDA_GLOBAL_SCOPE, 'RESTART_REQUIRED', False)

    #--------------------------------------------------------------------------
    # IDA Plugin Overloads
    #--------------------------------------------------------------------------

    def init(self):
        """
        This is called by IDA when it is loading the plugin.
        """
        if not SUPPORTED_ENVIRONMENT or self.__updated:
            return idaapi.PLUGIN_SKIP

        # load the plugin core
        self.core = patching.PatchingCore(defer_load=True)

        # inject a reference to the plugin context into the IDA console scope
        IDA_GLOBAL_SCOPE.patching = self

        addon = idaapi.addon_info_t()
        addon.id = "github.gaasedelen.patching"
        addon.name = "Patching"
        addon.producer = "Markus Gaasedelen"
        addon.url = "https://github.com/gaasedelen/patching"
        addon.version = "0.3.0.0"
        idaapi.register_addon(addon)

        # mark the plugin as loaded
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        """
        This is called by IDA when this file is loaded as a script.
        """
        pass

    def term(self):
        """
        This is called by IDA when it is unloading the plugin.
        """
        try:
            self.core.unload()
        except Exception as e:
            pass
        self.core = None

    #--------------------------------------------------------------------------
    # Development Helpers
    #--------------------------------------------------------------------------

    def reload(self):
        """
        Hot-reload the plugin.
        """
        if self.core:
            self.core.unload()
        reload_package(patching)
        self.core = patching.PatchingCore()
