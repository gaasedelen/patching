import os

#------------------------------------------------------------------------------
# Plugin Util
#------------------------------------------------------------------------------

PLUGIN_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

def plugin_resource(resource_name):
    """
    Return the full path for a given plugin resource file.
    """
    return os.path.join(
        PLUGIN_PATH,
        "ui",
        "resources",
        resource_name
    )

#------------------------------------------------------------------------------
# Misc / OS Util
#------------------------------------------------------------------------------

def is_file_locked(filepath):
    """
    Checks to see if a file is locked. Performs three checks

        1. Checks if the file even exists

        2. Attempts to open the file for reading. This will determine if the
           file has a write lock. Write locks occur when the file is being
           edited or copied to, e.g. a file copy destination

        3. Attempts to rename the file. If this fails the file is open by some
           other process for reading. The file can be read, but not written to
           or deleted.

    Not perfect, but it doesn't have to be. Source: https://stackoverflow.com/a/63761161
    """
    if not (os.path.exists(filepath)):
        return False

    try:
        f = open(filepath, 'r')
        f.close()
    except IOError:
        return True

    try:
        os.rename(filepath, filepath)
        return False
    except WindowsError:
        return True
