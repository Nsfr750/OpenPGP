"""
Site-specific configuration hook.
This file is automatically imported during Python startup.
"""
import sys

# Only patch if running our application
if 'openpgp.py' in ' '.join(sys.argv):
    # Create a minimal imghdr module
    class ImghdrModule:
        @staticmethod
        def what(file, h=None):
            """Minimal implementation of imghdr.what()"""
            return None
    
    # Patch sys.modules
    sys.modules['imghdr'] = ImghdrModule()
    
    # Also patch builtins for good measure
    import builtins
    builtins.imghdr = sys.modules['imghdr']
