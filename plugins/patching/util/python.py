import sys
import struct
import weakref

from types import ModuleType
from importlib import reload

#------------------------------------------------------------------------------
# Python helpers
#------------------------------------------------------------------------------

def hexdump(data, wrap=0):
    """
    Return a spaced string of printed hex bytes for the given data.
    """
    wrap = wrap if wrap else len(data)
    if not data:
        return ''

    lines = []
    for i in range(0, len(data), wrap):
        lines.append(' '.join(['%02X' % x for x in data[i:i+wrap]]))

    return '\n'.join(lines)

def swap_value(value, size):
    """
    Swap endianness of a given value in memory. (size width in bytes)
    """
    if size == 1:
        return value
    if size == 2:
        return struct.unpack("<H", struct.pack(">H", value))[0]
    if size == 4:
        return struct.unpack("<I", struct.pack(">I", value))[0]
    if size == 8:
        return struct.unpack("<Q", struct.pack(">Q", value))[0]
    if size == 16:
        lower64 = swap_value(value & ((1 << 64) - 1), 8)
        upper64 = swap_value((value >> 64), 8)
        return (lower64 << 64) | upper64
    raise ValueError("Invalid input (value %X and size %u" % (value, size))

#------------------------------------------------------------------------------
# Python Callback / Signals
#------------------------------------------------------------------------------

def register_callback(callback_list, callback):
    """
    Register a callable function to the given callback_list.

    Adapted from http://stackoverflow.com/a/21941670
    """

    # create a weakref callback to an object method
    try:
        callback_ref = weakref.ref(callback.__func__), weakref.ref(callback.__self__)

    # create a wweakref callback to a stand alone function
    except AttributeError:
        callback_ref = weakref.ref(callback), None

    # 'register' the callback
    callback_list.append(callback_ref)

def notify_callback(callback_list, *args):
    """
    Notify the given list of registered callbacks of an event.

    The given list (callback_list) is a list of weakref'd callables
    registered through the register_callback() function. To notify the
    callbacks of an event, this function will simply loop through the list
    and call them.

    This routine self-heals by removing dead callbacks for deleted objects as
    it encounters them.

    Adapted from http://stackoverflow.com/a/21941670
    """
    cleanup = []

    #
    # loop through all the registered callbacks in the given callback_list,
    # notifying active callbacks, and removing dead ones.
    #

    for callback_ref in callback_list:
        callback, obj_ref = callback_ref[0](), callback_ref[1]

        #
        # if the callback is an instance method, deference the instance
        # (an object) first to check that it is still alive
        #

        if obj_ref:
            obj = obj_ref()

            # if the object instance is gone, mark this callback for cleanup
            if obj is None:
                cleanup.append(callback_ref)
                continue

            # call the object instance callback
            try:
                callback(obj, *args)

            # assume a Qt cleanup/deletion occurred
            except RuntimeError as e:
                cleanup.append(callback_ref)
                continue

        # if the callback is a static method...
        else:

            # if the static method is deleted, mark this callback for cleanup
            if callback is None:
                cleanup.append(callback_ref)
                continue

            # call the static callback
            callback(*args)

    # remove the deleted callbacks
    for callback_ref in cleanup:
        callback_list.remove(callback_ref)

#------------------------------------------------------------------------------
# Module Reloading
#------------------------------------------------------------------------------

#
# NOTE: these are mostly for DEV / testing and are not required for the
# plugin to actually function. these basically enable hot-reloading plugins
# under the right conditions
#

def reload_package(target_module):
    """
    Recursively reload a 'stateless' python module / package.
    """
    target_name = target_module.__name__
    visited_modules = {target_name: target_module}
    _recursive_reload(target_module, target_name, visited_modules)

def _scrape_module_objects(module):
    """
    Scrape objects from a given module.
    """
    ignore = {"__builtins__", "__cached__", "__doc__", "__file__", "__loader__", "__name__", "__package__", "__spec__", "__path__"}
    values = []

    # scrape objects from the module
    for attribute_name in dir(module):

        # skip objects/refs we don't care about
        if attribute_name in ignore:
            continue

        # fetch the object/class/item definition from the module by its name
        attribute_value = getattr(module, attribute_name)

        # TODO: set/dict/other iterables?
        if type(attribute_value) == list:
            for item in attribute_value:
                values.append(item)
        else:
            values.append(attribute_value)

    # return all the 'interesting' objects scraped from the module
    return values

def _recursive_reload(module, target_name, visited):
    #print("entered", module.__name__)

    # XXX: lol, ignore reloading keystone for now (it probably isn't changing anyway)
    if 'keystone' in module.__name__:
        #reload(module)
        return

    visited[module.__name__] = module
    module_objects = _scrape_module_objects(module)

    for obj in module_objects:

        # ignore simple types
        if type(obj) in [str, int, bytes, bool]:
            continue

        if type(obj) == ModuleType:
            attribute_module_name = obj.__name__
            attribute_module = obj

        elif callable(obj):
            attribute_module_name = obj.__module__
            attribute_module = sys.modules[attribute_module_name]

        # TODO: recursive list obj scraping... / introspection
        elif type(obj) in [list, set, dict, tuple]:
            continue

        #
        # NOTE/XXX: something changed with IDA 7.7 ish to warrant this (module
        # wrappers?) really this should just be something that the ModuleType
        # conditional above catches...
        #

        elif obj.__name__.startswith('ida'):
            continue

        # fail
        else:
            raise ValueError("UNKNOWN TYPE TO RELOAD %s %s" % (obj, type(obj)))

        if not target_name in attribute_module_name:
            #print(" - Not a module of interest...")
            continue

        if "__plugins__" in attribute_module_name:
            #print(" - Skipping IDA base plugin module...")
            continue

        if attribute_module_name in visited:
            continue

        _recursive_reload(attribute_module, target_name, visited)

    #print("Okay done with %s, reloading self!" % module.__name__)
    reload(module)
