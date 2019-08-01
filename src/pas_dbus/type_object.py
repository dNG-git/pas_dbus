# -*- coding: utf-8 -*-

"""
direct PAS
Python Application Services
----------------------------------------------------------------------------
(C) direct Netware Group - All rights reserved
https://www.direct-netware.de/redirect?pas;dbus

This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can
obtain one at http://mozilla.org/MPL/2.0/.
----------------------------------------------------------------------------
https://www.direct-netware.de/redirect?licenses;mpl2
----------------------------------------------------------------------------
#echo(pasDBusVersion)#
#echo(__FILEPATH__)#
"""

class TypeObject(object):
    """
The "TypeObject" class provides a type hinting mechanism for D-Bus message
values.

:author:     direct Netware Group et al.
:copyright:  (C) direct Netware Group - All rights reserved
:package:    pas
:subpackage: dbus
:since:      v1.0.0
:license:    https://www.direct-netware.de/redirect?licenses;mpl2
             Mozilla Public License, v. 2.0
    """

    DOUBLE = "d"
    """
IEEE 754 double
    """
    SIGNATURE = "g"
    """
D-Bus signature type
    """
    INT16 = "n"
    """
16-bit signed integer
    """
    INT32 = "i"
    """
32-bit signed integer
    """
    INT64 = "x"
    """
64-bit signed integer
    """
    OBJECT_PATH = "o"
    """
D-Bus object path type
    """
    UINT16 = "q"
    """
16-bit unsigned integer
    """
    UINT32 = "u"
    """
32-bit unsigned integer
    """
    UINT64 = "t"
    """
64-bit unsigned integer
    """

    def __init__(self, hint, value):
        """
Constructor __init__(TypeObject)

:param hint: Type hint
:param value: Data

:since: v1.0.0
        """

        self._hint = hint
        """
D-Bus type hint
        """
        self._value = value
        """
D-Bus value
        """
    #

    @property
    def hint(self):
        """
Returns the D-Bus type hint.

:return: (str) D-Bus type
:since:  v1.0.0
        """

        return self._hint
    #

    @property
    def value(self):
        """
Returns the D-Bus value.

:return: (mixed) Data value
:since:  v1.0.0
        """

        return self._value
    #
#
