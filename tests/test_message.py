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

import unittest

from dpt_runtime.binary import Binary
from pas_dbus import Message

class TestMessage(unittest.TestCase):
    """
UnitTest for Message

:since: v1.0.0
    """

    def test_simple_marshaled_data(self):
        test_data = Binary.bytes("l\x01\x03\x01\x03\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x01\x01o\x00\x02\x00\x00\x00/t\x00\x00\x00\x00\x00\x00\x03\x01s\x00\x04\x00\x00\x00test\x00\x00\x00\x00\x08\x01g\x00\x03yyy\x00llo")

        self.assertEqual(60, Message.get_marshaled_message_size(test_data))

        result_data = Message.unmarshal_data("yyyyuua(yv)yyy", test_data, True)

        self.assertEqual(10, len(result_data))
        self.assertIs(list, type(result_data[6]))
        self.assertEqual(3, len(result_data[6]))
        self.assertIs(list, type(result_data[6][0]))
        self.assertEqual(2, len(result_data[6][0]))
        self.assertEqual(Message.HEADER_FIELD_PATH, result_data[6][0][0])
        self.assertEqual("/t", Binary.str(result_data[6][0][1]))

        message = Message.unmarshal(test_data)
        self.assertEqual(Message.TYPE_METHOD_CALL, message.type)
        self.assertEqual(( Message.FLAG_NO_REPLY_EXPECTED | Message.FLAG_NO_AUTO_START ), message.flags)
        self.assertEqual("/t", message.object_path)
        self.assertEqual("test", message.object_member)
        self.assertEqual(1, message.serial)
    #
#

if (__name__ == "__main__"):
    unittest.main()
#
