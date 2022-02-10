#------------------------------------------------------------------------------
# Script Preflight
#------------------------------------------------------------------------------

# this plugin requires Python 3
try:
    import os
    import sys
    import glob
    import json
    import shutil
    import zipfile
    import urllib.request
    from pathlib import Path
    SUPPORTED_PYTHON = sys.version_info[0] == 3
except:
    SUPPORTED_PYTHON = False

# this plugin requires IDA 7.6 or newer
try:
    import ida_pro
    import ida_diskio
    import ida_loader
    IDA_GLOBAL_SCOPE = sys.modules['__main__']
    SUPPORTED_IDA = ida_pro.IDA_SDK_VERSION >= 760
except:
    SUPPORTED_IDA = False

# is this deemed to be a compatible environment for the plugin to load?
SUPPORTED_ENVIRONMENT = bool(SUPPORTED_IDA and SUPPORTED_PYTHON)

#------------------------------------------------------------------------------
# IDA Plugin Installer
#------------------------------------------------------------------------------

PLUGIN_NAME = 'Patching'
PLUGIN_URL = 'https://api.github.com/repos/gaasedelen/patching/releases/latest'

def install_plugin():
    """
    Auto-install plugin (or update it).
    """
    print("[*] Starting auto installer for '%s' plugin..." % PLUGIN_NAME)

    # ensure the user plugin directory exists
    plugins_directory = os.path.join(ida_diskio.get_user_idadir(), 'plugins')
    Path(plugins_directory).mkdir(parents=True, exist_ok=True)

    # special handling to rename 'darwin' to macos (a bit more friendly)
    platform_name = sys.platform
    if platform_name == 'darwin':
        platform_name = 'macos'

    # compute the full filename of the plugin package to download from git
    package_name = 'patching_%s.zip' % platform_name

    # fetch the plugin download info from the latest github releases
    print("[*] Fetching info from GitHub...")
    try:
        release_json = urllib.request.urlopen(PLUGIN_URL).read()
        release_info = json.loads(release_json)
        release_tag = release_info['tag_name']
    except:
        print("[-] Failed to fetch info from GitHub")
        return False

    # locate the git asset info that matches our desired plugin package
    for asset in release_info['assets']:
        if asset['name'] == package_name:
            break
    else:
        print("[-] Failed to locate asset '%s' in latest GitHub release" % package_name)
        return False

    print("[*] Downloading %s..." % package_name)

    try:
        package_url = asset['browser_download_url']
        package_data = urllib.request.urlopen(package_url).read()
        package_path = os.path.join(plugins_directory, package_name)
    except Exception as e:
        print("[-] Failed to download %s\nError: %s" % (package_url, e))
        return False

    print("[*] Saving %s to disk..." % package_name)
    try:
        with open(package_path, 'wb') as f:
            f.write(package_data)
    except:
        print("[-] Failed to write to %s" % package_path)
        return False

    patching_directory = os.path.join(plugins_directory, 'patching')
    keystone_directory = os.path.join(patching_directory, 'keystone')

    #
    # if the plugin is already installed into this environment, a few more
    # steps are required to ensure we can replace the existing version
    #

    if os.path.exists(patching_directory):

        #
        # contrary to what this sort of looks like, load_and_run_plugin()
        # will execute and UNLOAD our plugin (if it is in-use) because
        # our plugin has been marked with the PLUGIN_UNL flag
        #
        # NOTE: this is basically just us asking IDA nicely to unload our
        # plugin in a best effort to keep things clean
        #

        if ida_loader.find_plugin(PLUGIN_NAME, False):
            print("[*] Unloading plugin core...")
            ida_loader.load_and_run_plugin(PLUGIN_NAME, 0)

        #
        # pay special attention when trying to remove Keystone. this is the
        # most likely point in failure for the entire plugin update/install
        #
        # even if the plugin is not in use, the Keystone DLL / lib will be
        # loaded into memory by nature of Python imports. we are going to
        # try and AGGRESSIVELY unload it such that we can overwrite it
        #
        # because this is pretty dangerous, we set this flag to ensure the
        # patching plugin is completeley neutered and cannot be used in any
        # form until IDA is restarted
        #

        IDA_GLOBAL_SCOPE.RESTART_REQUIRED = True

        print("[*] Removing existing plugin...")
        if not remove_keystone(keystone_directory):
            print("[-] Could not remove Keystone (file locked?)")
            print("[!] Please ensure no other instance of IDA are running and try again...")
            return False

        # remove the rest of the plugin only IF removing Keystone succeeded
        shutil.rmtree(patching_directory)

    #
    # now we can resume with the actual plugin update / installation
    #

    print("[*] Unzipping %s..." % package_name)
    try:
        with zipfile.ZipFile(package_path, "r") as zip_ref:
            zip_ref.extractall(plugins_directory)
    except:
        print("[-] Failed to unzip %s to %s" % (package_name, plugins_directory))
        return False

    print("[+] %s %s installed successfully!" % (PLUGIN_NAME, release_tag))

    # try and remove the downloaded zip (cleanup)
    try:
        os.remove(package_path)
    except:
        pass

    # do not attempt to load the newly installed plugin if we just updated
    if getattr(IDA_GLOBAL_SCOPE, 'RESTART_REQUIRED', False):
        print("[!] Restart IDA to use the updated plugin")
        return True

    # load the plugin if this was a fresh install
    plugin_path = os.path.join(plugins_directory, 'patching.py')
    ida_loader.load_plugin(plugin_path)

    # if a database appears open, force plugin core to load immediately
    if ida_loader.get_path(ida_loader.PATH_TYPE_IDB):
        IDA_GLOBAL_SCOPE.patching.core.load()

    return True

def remove_keystone(keystone_directory):
    """
    Delete the Keystone directory at the given path and return True on success.
    """
    if sys.platform == 'win32':
        lib_paths = [os.path.join(keystone_directory, 'keystone.dll')]
    else:
        lib_paths = glob.glob(os.path.join(keystone_directory, 'libkeystone*'))

    #
    # it is critical we try and delete the Keystone library first as it can
    # be locked by IDA / Python. if we cannot delete the Keystone library
    # on-disk, then there is no point in proceeding with the update.
    #
    # in a rather aggressive approach to force the Keystone library to unlock,
    # we forcefully unload the backing library from python. this is obviously
    # dangerous, but the plugin should be completely deactivated by this point
    #

    try:

        #
        # attempt to get the handle of the loaded Keystone library and
        # forcefully unload it
        #

        import _ctypes

        keystone = sys.modules['patching.keystone']
        lib_file = keystone.keystone._ks._name
        _ctypes.FreeLibrary(keystone.keystone._ks._handle)

        #
        # failing to delete the library from disk here means that another
        # instance of IDA is is probably still running, keeping it locked
        #

        os.remove(lib_file)

    except:
        pass

    #
    # for good measure, go over all the expected Keystone library files on
    # disk and attempt to remove them
    #

    lib_still_exists = []
    for lib_file in lib_paths:
        try:
            os.remove(lib_file)
        except:
            pass
        lib_still_exists.append(os.path.exists(lib_file))

    # if the library still exist after all this, the update will be canceled
    if any(lib_still_exists):
        return False

    #
    # deleting the library appears to have been successful, now delete the
    # rest of the Keystone directory.
    #

    try:
        shutil.rmtree(keystone_directory)
    except:
        pass

    # return True if Keystone was successfully deleted
    return not(os.path.exists(keystone_directory))

#------------------------------------------------------------------------------
# IDA Plugin Installer
#------------------------------------------------------------------------------

if SUPPORTED_ENVIRONMENT:
    install_plugin()
else:
    print("[-] Plugin is not compatible with this IDA/Python version")