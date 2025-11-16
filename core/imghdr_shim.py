"""
Compatibility shim for the imghdr module.
This provides a minimal implementation of the imghdr module for Python 3.9+.
"""

def what(file, h=None):
    """
    Determine the type of image contained in a file or byte stream.
    
    Args:
        file: Path to the file or file-like object
        h: Optional bytes to test (first few bytes of the file)
        
    Returns:
        str or None: The image type if recognized, None otherwise
    """
    if h is None:
        if hasattr(file, 'read'):
            # File-like object
            pos = file.tell()
            h = file.read(32)
            file.seek(pos)
        else:
            # Assume it's a filename
            with open(file, 'rb') as f:
                h = f.read(32)
    
    if not h:
        return None
    
    # Check for common image formats
    if h.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'png'
    if h.startswith((b'GIF87a', b'GIF89a')):
        return 'gif'
    if h.startswith(b'\xff\xd8'):
        return 'jpeg'
    if h.startswith(b'BM'):
        return 'bmp'
    if h.startswith(b'II*\x00') or h.startswith(b'MM\x00*'):
        return 'tiff'
    if h.startswith(b'\x00\x00\x01\x00'):
        return 'ico'
    if h.startswith(b'\x00\x00\x02\x00'):
        return 'cur'
    
    return None

# Create a minimal module-like object
class ImghdrModule:
    """Minimal implementation of the imghdr module interface."""
    @staticmethod
    def what(file, h=None):
        """Determine the type of image contained in a file or byte stream."""
        return what(file, h)

# This will be used to patch sys.modules
imghdr = ImghdrModule()
