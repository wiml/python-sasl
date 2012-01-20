"""SASL stringprep profile

<http://www.ietf.org/rfc/rfc4013.txt>
<http://www.ietf.org/rfc/rfc3454.txt>

Copyright (C) 2012, Wim Lewis <wiml@hhhh.org>.
"""

from __future__ import absolute_import
from stringprep import *
import unicodedata

__all__ = ( 'prepare', )

def prepare(s):
    """Prepare a Unicode string according to the SASLprep stringprep profile.
    Returns the prepared string, or raises a UnicodeError on failue."""

    # Step 1 - Map
    buf = u''
    for ch in s:
        if in_table_c12(ch):
            buf += u' '
        elif not in_table_b1(ch):
            buf += ch
    
    # Step 2 - Normalize
    buf = unicodedata.normalize('NFKC', buf)
    
    # Step 3 - Prohibited characters
    for ch in buf:
        if ( in_table_c21(ch) or
             in_table_c22(ch) or
             in_table_c3(ch)  or
             in_table_c4(ch)  or
             in_table_c5(ch)  or
             in_table_c6(ch)  or
             in_table_c7(ch)  or
             in_table_c8(ch)  or
             in_table_c9(ch) ):
            raise UnicodeError("Invalid character %r" % (ch,))
    
    # Step 4 - bidi mark checking
    # If there are any characters in categort D1 (randAL), then do extra checks.
    if any(map(in_table_d1, buf)):
        # If there are any R+AL characters, the first and last
        # characters must be R+AL.
        if not in_table_d1(buf[0]) or not in_table_d1(buf[-1]):
            raise UnicodeError("bidi rejected by stringprep (6.3)")
        # And there must not be any L (table d2).
        if any(map(in_table_d2, buf)):
            raise UnicodeError("bidi rejected by stringprep (6.2)")
        
    return buf

