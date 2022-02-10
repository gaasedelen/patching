
#------------------------------------------------------------------------------
# Exception Definitions
#------------------------------------------------------------------------------

class PatchingError(Exception):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

class PatchBackupError(PatchingError):
    def __init__(self, message, filepath=''):
        super().__init__(message)
        self.filepath = filepath

class PatchTargetError(PatchingError):
    def __init__(self, message, filepath):
        super().__init__(message)
        self.filepath = filepath

class PatchApplicationError(PatchingError):
    def __init__(self, message, filepath):
        super().__init__(message)
        self.filepath = filepath