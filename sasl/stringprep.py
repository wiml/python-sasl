"""SASL stringprep_ profiles

Defines functions which implement a few SASL-related stringprep
profiles. Each function takes a (unicode) string and either returns
the prepared string or raises an exception, usually a UnicodeError.

.. _stringprep: http://www.ietf.org/rfc/rfc3454.txt
"""

# Written in 2012 by Wim Lewis <wiml@hhhh.org>.
# This file is in the public domain. It may be used,
# distributed, and modified without restriction.

from __future__ import absolute_import
from stringprep import *
import unicodedata

__all__ = ( 'traceprep', 'saslprep' )
__docformat__ = 'reStructuredText en'

def saslprep(s):
    """Prepare a string according to the SASLprep_ stringprep profile.
    
    >>> saslprep(u'Hi\u2003\uff2d\uff4f\uff4d!')
    u'Hi Mom!'

    >>> saslprep(u'Hi\\rMom!')
    Traceback (most recent call last):
    UnicodeError: Prohibited character u'\\r'
    
    >>> saslprep(u'Num\u00ADber \u2168')
    u'Number IX'
    
    .. _SASLprep: http://www.ietf.org/rfc/rfc4013.txt
    """

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
            raise UnicodeError("Prohibited character %r" % (ch,))

    # Step 4 - bidi mark checking
    _bidi_check(buf)

    return buf

def _bidi_check(buf):
    "Perform the checks from RFC3454 section 6, and raise on failure."
    # If there are any characters in category D1 (R and AL), then do extra checks.
    if any(map(in_table_d1, buf)):
        # If there are any R+AL characters, the first and last
        # characters must be R+AL.
        if not in_table_d1(buf[0]) or not in_table_d1(buf[-1]):
            raise UnicodeError("bidi rejected by stringprep (6.3)")
        # And there must not be any L (table d2).
        if any(map(in_table_d2, buf)):
            raise UnicodeError("bidi rejected by stringprep (6.2)")

def traceprep(s):
    """Prepare a Unicode string according to the trace_ stringprep profile.

    .. _trace: http://www.ietf.org/rfc/rfc4505.txt
    """

    # Trace defines no mapping or normalization.

    # Prohibited characters
    for ch in s:
        if ( in_table_c21(ch) or
             in_table_c22(ch) or
             in_table_c3(ch)  or
             in_table_c4(ch)  or
             in_table_c5(ch)  or
             in_table_c6(ch)  or
             # But not table C.7.
             in_table_c8(ch)  or
             in_table_c9(ch) ):
            raise UnicodeError("Prohibited character %r" % (ch,))

    # Step 4 - bidi mark checking
    _bidi_check(s)

    return s

__test__ = {
    'bidi': """
    >>> _bidi_check(u'\u0627\u0031\u0628')

    >>> _bidi_check(u'\u0627' + u'1')
    Traceback (most recent call last):
    UnicodeError: bidi rejected by stringprep (6.3)

    >>> _bidi_check(u'\u05c0 foo \u05c0')
    Traceback (most recent call last):
    UnicodeError: bidi rejected by stringprep (6.2)
    """
}
