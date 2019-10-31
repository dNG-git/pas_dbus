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

from struct import pack, unpack
import sys

from dpt_runtime.binary import Binary
from dpt_runtime.io_exception import IOException
from dpt_runtime.value_exception import ValueException

from .type_object import TypeObject

class Message(object):
    """
D-Bus message instance based on D-Bus Specification 0.26.

:author:     direct Netware Group et al.
:copyright:  (C) direct Netware Group - All rights reserved
:package:    pas
:subpackage: dbus
:since:      v1.0.0
:license:    https://www.direct-netware.de/redirect?licenses;mpl2
             Mozilla Public License, v. 2.0
    """

    FLAG_NO_REPLY_EXPECTED = 1
    """
D-Bus flag indicating that even if it is of a type that can have a reply;
the reply can be omitted as an optimization.
    """
    FLAG_NO_AUTO_START = 2
    """
D-Bus flag that the bus must not launch an owner for the destination name
in response to this message.
    """
    HEADER_FIELD_PATH = Binary.bytes("\x01")
    """
D-Bus header field for the object path
    """
    HEADER_FIELD_INTERFACE = Binary.bytes("\x02")
    """
D-Bus header field for the interface
    """
    HEADER_FIELD_MEMBER = Binary.bytes("\x03")
    """
D-Bus header field for the method or signal name
    """
    HEADER_FIELD_ERROR_NAME = Binary.bytes("\x04")
    """
D-Bus header field for the error name
    """
    HEADER_FIELD_REPLY_SERIAL = Binary.bytes("\x05")
    """
D-Bus header field for the serial number of the message this message is a
reply to.
    """
    HEADER_FIELD_DESTINATION = Binary.bytes("\x06")
    """
D-Bus header field for the name of the connection this message is intended
for.
    """
    HEADER_FIELD_SENDER = Binary.bytes("\x07")
    """
D-Bus header field for the unique name of the sending connection
    """
    HEADER_FIELD_SIGNATURE = Binary.bytes("\x08")
    """
D-Bus header field for the signature of the message body
    """
    HEADER_FIELD_UNIX_FDS = Binary.bytes("\x09")
    """
D-Bus header field for number of Unix file descriptors
    """
    NESTED_LEVEL_MAX = 64
    """
Maximum number of nested levels
    """
    PROTOCOL_VERSION = 1
    """
D-Bus protocol version supported
    """
    TYPE_ERROR = Binary.bytes("\x03")
    """
D-Bus error message
    """
    TYPE_METHOD_CALL = Binary.bytes("\x01")
    """
D-Bus method call message
    """
    TYPE_METHOD_REPLY = Binary.bytes("\x02")
    """
D-Bus method reply message
    """
    TYPE_SIGNAL = Binary.bytes("\x04")
    """
D-Bus signal message
    """

    __slots__ = [ "__weakref__",
                  "_body",
                  "_body_signature",
                  "destination",
                  "_error_name",
                  "_flags",
                  "_object_interface",
                  "_object_member",
                  "_object_path",
                  "_reply_serial",
                  "sender",
                  "_serial",
                  "_type",
                  "unix_fds"
                ]
    """
python.org: __slots__ reserves space for the declared variables and prevents
the automatic creation of __dict__ and __weakref__ for each instance.
    """

    def __init__(self, _type = None):
        """
Constructor __init__(Message)

:param _type: Message type

:since: v1.0.0
        """

        self._body = None
        """
D-Bus message body
        """
        self._body_signature = None
        """
D-Bus message body signature
        """
        self.destination = None
        """
D-Bus message destination
        """
        self._error_name = None
        """
D-Bus message error name
        """
        self._flags = 0
        """
D-Bus message flags
        """
        self._object_interface = None
        """
D-Bus message object interface
        """
        self._object_member = None
        """
D-Bus message object member
        """
        self._object_path = None
        """
D-Bus message object path
        """
        self._reply_serial = None
        """
D-Bus message serial of the message this message is a reply to.
        """
        self.sender = None
        """
D-Bus message sender
        """
        self._serial = None
        """
D-Bus message serial
        """
        self._type = _type
        """
D-Bus message type
        """
        self.unix_fds = None
        """
D-Bus message UNIX fds
        """
    #

    @property
    def body(self):
        """
Returns the D-Bus message body.

:return: (mixed) D-Bus message body; None if no body exists
:since:  v1.0.0
        """

        return self._body
    #

    @body.setter
    def body(self, body):
        """
Sets the D-Bus message body.

:param body: D-Bus message body

:since: v1.0.0
        """

        self._body = body
    #

    @property
    def body_signature(self):
        """
Returns the D-Bus message body signature.

:return: (str) D-Bus message body signature; None if no body exists
:since:  v1.0.0
        """

        _return = self._body_signature

        if (_return is None
            and self._body is not None
           ):
            if (type(self._body) is list):
                _return = ""
                for body_element in self._body: _return += Message.get_marshal_type_for_value(body_element)
            else: _return = Message.get_marshal_type_for_value(self._body)
        #

        return _return
    #

    @body_signature.setter
    def body_signature(self, signature):
        """
Sets the D-Bus message body signature.

:param signature: D-Bus message body signature

:since: v1.0.0
        """

        self._body_signature = signature
    #

    @property
    def error_name(self):
        """
Returns the D-Bus message error name.

:return: (str) D-Bus message error name
:since:  v1.0.0
        """

        return self._error_name
    #

    @error_name.setter
    def error_name(self, error_name):
        """
Sets the D-Bus message error name.

:param error_name: D-Bus message error name

:since: v1.0.0
        """

        self._error_name = error_name
        if (self.type is None): self.type = Message.TYPE_ERROR
    #

    @property
    def flags(self):
        """
Returns the D-Bus message flags.

:return: (int) D-Bus message flags
:since:  v1.0.0
        """

        return self._flags
    #

    @flags.setter
    def flags(self, flags):
        """
Sets the D-Bus message flags.

:param flags: D-Bus message flags

:since: v1.0.0
        """

        self._flags = flags
    #

    @property
    def _header_fields(self):
        """
Returns the header fields defined.

:return: (list) List of D-Bus header fields
:since:  v1.0.0
        """

        _return = { }

        if (self._body_signature is not None): _return[Message.HEADER_FIELD_SIGNATURE] = TypeObject(TypeObject.SIGNATURE, self._body_signature)
        if (self.destination is not None): _return[Message.HEADER_FIELD_DESTINATION] = self.destination
        if (self._error_name is not None): _return[Message.HEADER_FIELD_ERROR_NAME] = self._error_name
        if (self._object_interface is not None): _return[Message.HEADER_FIELD_INTERFACE] = self._object_interface
        if (self._object_member is not None): _return[Message.HEADER_FIELD_MEMBER] = self._object_member
        if (self._object_path is not None): _return[Message.HEADER_FIELD_PATH] = TypeObject(TypeObject.OBJECT_PATH, self._object_path)
        if (self._reply_serial is not None): _return[Message.HEADER_FIELD_REPLY_SERIAL] = TypeObject(TypeObject.UINT32, self._reply_serial)
        if (self.sender is not None): _return[Message.HEADER_FIELD_SENDER] = self.sender

        return _return
    #

    @property
    def is_error(self):
        """
Returns true if the message represents an error.

:return: (bool) True if error
:since:  v1.0.0
        """

        return (self.type == Message.TYPE_ERROR)
    #

    @property
    def is_header_valid(self):
        """
Marshals the message for transmission.

:return: (bytes) Wire-formatted message
:since:  v1.0.0
        """

        _type = self.type

        _return = (_type is not None)

        if (_return):
            header_fields = self._header_fields

            if (_type == Message.TYPE_ERROR):
                _return = (Message.HEADER_FIELD_ERROR_NAME in header_fields
                           and Message.HEADER_FIELD_REPLY_SERIAL in header_fields
                          )
            elif (_type == Message.TYPE_METHOD_CALL):
                _return = (Message.HEADER_FIELD_MEMBER in header_fields
                           and Message.HEADER_FIELD_PATH in header_fields
                          )
            elif (_type == Message.TYPE_METHOD_REPLY):
                _return = (Message.HEADER_FIELD_REPLY_SERIAL in header_fields)
            elif (_type == Message.TYPE_SIGNAL):
                _return = (Message.HEADER_FIELD_INTERFACE in header_fields
                           and Message.HEADER_FIELD_MEMBER in header_fields
                           and Message.HEADER_FIELD_PATH in header_fields
                          )
                #
        #

        return _return
    #

    @property
    def is_method_call(self):
        """
Returns true if the message represents a method call.

:return: (bool) True if method call
:since:  v1.0.0
        """

        return (self.type == Message.TYPE_METHOD_CALL)
    #

    @property
    def is_method_reply(self):
        """
Returns true if the message represents a method reply.

:return: (bool) True if method reply
:since:  v1.0.0
        """

        return (self.type == Message.TYPE_METHOD_REPLY)
    #

    @property
    def is_signal(self):
        """
Returns true if the message represents a signal.

:return: (bool) True if signal
:since:  v1.0.0
        """

        return (self.type == Message.TYPE_SIGNAL)
    #

    @property
    def object_interface(self):
        """
Returns the object interface of the D-Bus message.

:return: (str) Object interface
:since:  v1.0.0
        """

        return self._object_interface
    #

    @object_interface.setter
    def object_interface(self, interface):
        """
Sets the object interface of the D-Bus message.

:param interface: Object interface

:since: v1.0.0
        """

        self._object_interface = interface
    #

    @property
    def object_member(self):
        """
Returns the object member of the D-Bus message.

:return: (str) Object member
:since:  v1.0.0
        """

        return self._object_member
    #

    @object_member.setter
    def object_member(self, member):
        """
Sets the object member of the D-Bus message.

:param member: Object member

:since: v1.0.0
        """

        self._object_member = member
    #

    @property
    def object_path(self):
        """
Returns the object path of the D-Bus message.

:return: (str) Object path
:since:  v1.0.0
        """

        return self._object_path
    #

    @object_path.setter
    def object_path(self, path):
        """
Sets the object path of the D-Bus message.

:param path: Object path

:since: v1.0.0
        """

        self._object_path = path
    #

    @property
    def reply_serial(self):
        """
Returns the D-Bus message serial number of the message this message is a
reply to.

:return: (int) D-Bus message serial; None if not defined
:since:  v1.0.0
        """

        return self._reply_serial
    #

    @reply_serial.setter
    def reply_serial(self, serial):
        """
Sets the D-Bus message serial number of the message this message is a reply
to.

:param serial: D-Bus message serial

:since: v1.0.0
        """

        if (serial < 1): raise ValueException("D-Bus message serial must be larger than zero")
        self._reply_serial = serial
    #

    @property
    def serial(self):
        """
Returns the D-Bus message serial used as a cookie by the sender to identify
the reply corresponding to this request.

:return: (int) D-Bus message serial; None if not defined
:since:  v1.0.0
        """

        return self._serial
    #

    @serial.setter
    def serial(self, serial):
        """
Sets the D-Bus message serial used as a cookie by the sender to identify
the reply corresponding to this request.

:param serial: D-Bus message serial

:since: v1.0.0
        """

        if (serial < 1): raise ValueException("D-Bus message serial must be larger than zero")
        self._serial = serial
    #

    @property
    def type(self):
        """
Returns the D-Bus message type.

:return: (str) D-Bus message type byte
:since:  v1.0.0
        """

        return self._type
    #

    @type.setter
    def type(self, _type):
        """
Sets the D-Bus message type.

:param _type: D-Bus message type byte

:since: v1.0.0
        """

        self._type = _type
    #

    def marshal(self, serial = None):
        """
Marshals the message for transmission.

:return: (bytes) Wire-formatted message
:since:  v1.0.0
        """

        _type = self.type
        if (_type is None): raise ValueException("D-Bus message type is not defined")

        if (serial is None): serial = self.serial
        if (serial is None): raise ValueException("D-Bus message serial is not defined")

        if (not self.is_header_valid): raise ValueException("D-Bus message header is not valid")

        body_data = Binary.BYTES_TYPE()
        body_signature = self.body_signature
        body_size = 0

        is_le = (sys.byteorder == "little")

        header_fields = self._header_fields
        header_fields_list = [ ( key, header_fields[key] ) for key in header_fields ]

        if (self._body is not None
            and Message.HEADER_FIELD_SIGNATURE not in header_fields
           ): header_fields_list.append(( Message.HEADER_FIELD_SIGNATURE, body_signature ))

        header_fields_data = Message.marshal_data("a(yv)", [ header_fields_list ], is_le, 12)

        if (self._body is not None):
            body_data = Message.marshal_data(body_signature,
                                             self._body,
                                             is_le,
                                             12 + len(header_fields_data)
                                            )

            body_size = len(body_data)
        #

        header_data = pack("ccBBII",
                           Binary.bytes("l" if (is_le) else "B"),
                           _type,
                           self._flags,
                           self.__class__.PROTOCOL_VERSION,
                           body_size,
                           serial
                          )

        return (header_data + header_fields_data + body_data)
    #

    def _set_header_field(self, field_type, field_value):
        """
Sets header values from raw field data.

:param field_type: Header field type (byte)
:param field_value: Header field value

:since: v1.0.0
        """

        if (field_type == Message.HEADER_FIELD_DESTINATION): self.destination = field_value
        elif (field_type == Message.HEADER_FIELD_ERROR_NAME): self._error_name = field_value
        elif (field_type == Message.HEADER_FIELD_INTERFACE): self._object_interface = field_value
        elif (field_type == Message.HEADER_FIELD_MEMBER): self._object_member = field_value
        elif (field_type == Message.HEADER_FIELD_PATH): self._object_path = field_value
        elif (field_type == Message.HEADER_FIELD_REPLY_SERIAL): self._reply_serial = field_value
        elif (field_type == Message.HEADER_FIELD_SENDER): self.sender = field_value
        elif (field_type == Message.HEADER_FIELD_SIGNATURE): self._body_signature = field_value
        elif (field_type == Message.HEADER_FIELD_UNIX_FDS): self.unix_fds = field_value
    #

    @staticmethod
    def _get_boundary_data(current_offset, _type):
        """
Returns wire-formatted padding to match the boundary of the given D-Bus type
based on the defined offset.

:param current_offset: Current offset
:param _type: D-Bus signature type code (ASCII)

:return: (tuple) Tuple containing the new write offset and wire-formatted
         bytes
:since:  v1.0.0
        """

        boundary_offset = Message._get_boundary_offset(current_offset, Message.get_marshaled_type_boundary(_type))

        return_data = (Binary.BYTES_TYPE()
                       if (current_offset == boundary_offset) else
                       pack("{0:d}x".format(boundary_offset - current_offset))
                      )

        return ( boundary_offset, return_data )
    #

    @staticmethod
    def _get_boundary_offset(current_offset, boundary):
        """
Returns the offset that matches the given boundary.

:param current_offset: Current offset
:param boundary: Boundary in bytes

:return: (int) Offset matching the given boundary
:since:  v1.0.0
        """

        _return = current_offset

        unpadded_bytes = ((current_offset % boundary) if (boundary > 0) else 0)
        if (unpadded_bytes > 0): _return += boundary - unpadded_bytes

        return _return
    #

    @staticmethod
    def get_complete_type_from_signature(signature):
        """
Returns the first complete type from the given signature.

:param signature: D-Bus signature to extract the complete type from

:return: (str) D-Bus complete type signature
:since:  v1.0.0
        """

        _return = ""

        dicts_count = 0
        structs_count = 0
        basic_types = [ "y", "b", "n", "q", "i", "u", "x", "t", "d", "h", "v", "s", "o", "g" ]
        signature_position = 0
        signature_length = len(signature)

        while (signature_position < signature_length):
            signature_char = signature[signature_position:signature_position + 1]
            signature_position += 1

            if (signature_char in basic_types): _return += signature_char
            elif (signature_char == "a"):
                element_signature_type = Message.get_complete_type_from_signature(signature[signature_position:])
                signature_position += len(element_signature_type)

                _return += signature_char + element_signature_type
            elif (signature_char == "("):
                _return += signature_char
                structs_count += 1
            elif (signature_char == ")"):
                _return += signature_char
                structs_count -= 1
            elif (signature_char == "{"):
                _return += signature_char
                dicts_count += 1
            elif (signature_char == "}"):
                _return += signature_char
                dicts_count -= 1
            #

            if (structs_count + dicts_count == 0): break
        #

        if (len(_return) == 0): raise ValueException("Given D-Bus signature does not contain a supported complete type")
        return _return
    #

    @staticmethod
    def get_marshal_type_for_value(value, basic_types_only = False):
        """
Returns the D-Bus signature matching the given value. Python list, tuple and
dict elements must contain at least one element and all elements must use
the same data types. "TypeObject" instances should be used to ensure that
the correct signature is generated.

:param value: Value to generate the D-Bus signature for

:return: (str) D-Bus complete type signature
:since:  v1.0.0
        """

        _type = type(value)

        if (_type in ( list, tuple, dict )):
            if (basic_types_only): raise ValueException("D-Bus basic type is required but complete type was given")
            if (len(value) < 1): raise ValueException("At least one element is required for detection of a D-Bus type")
        #

        if (isinstance(value, TypeObject)):
            _return = value.hint
            if (basic_types_only and len(_return) > 1): raise ValueException("D-Bus basic type is required but complete type was given")
        elif (_type is bool): _return = "b"
        elif (_type is dict):
            key = next(iter(value))
            _return = "a{{{0}v}}".format(Message.get_marshal_type_for_value(key, True))
        elif (_type is float): _return = "d"
        elif (_type is int): _return = "x"
        elif (_type is list): _return = "a" + Message.get_marshal_type_for_value(value[0])
        elif (_type in ( str,
                         (Binary.UNICODE_TYPE if (str != Binary.UNICODE_TYPE) else Binary.BYTES_TYPE )
                       )
             ): _return = "s"
        elif (_type is tuple): _return = "({0})".format(Message.get_marshal_type_for_value(value[0]))
        else: raise ValueException("Given value can not be converted to a D-Bus type")

        return _return
    #

    @staticmethod
    def get_marshaled_data_size(signature, data, is_le = False, position = 0):
        """
Returns the data size based on the given signature and its wire-formatted
content.

:param signature: D-Bus signature
:param data: Wire-formatted data
:param is_le: True if message contains data in little endian byte order
:param position: Current read position in the wire-formatted data

:return: (int) Size in bytes
:since:  v1.0.0
        """

        position_started = position
        signature_length = len(signature)
        signature_position = 0

        while (signature_position < signature_length):
            _type = Message.get_complete_type_from_signature(signature[signature_position:])
            type_length = len(_type)

            if (_type[:1] == "a"):
                ( position, array_size ) = Message._unmarshal_basic_type_data("u", data, is_le, position)

                if (_type[1:2] == "{"):
                    position = Message._get_boundary_offset(position, Message.get_marshaled_type_boundary("e"))

                    for _ in range(0, array_size):
                        position = Message._get_boundary_offset(position, Message.get_marshaled_type_boundary(_type[2:]))
                        position += Message.get_marshaled_data_size(_type[3:-1], data, is_le, position)
                    #
                else:
                    for _ in range(0, array_size):
                        position += Message.get_marshaled_data_size(_type[1:], data, is_le, position)
                    #
                #
            elif (_type[:1] == "v"):
                position = Message._get_boundary_offset(position, Message.get_marshaled_type_boundary("v"))
                ( position, element_signature_type ) = Message._unmarshal_basic_type_data("g", data, is_le, position)

                position += Message.get_marshaled_data_size(element_signature_type, data, is_le, position)
            elif (_type[:1] == "("):
                position = Message._get_boundary_offset(position, Message.get_marshaled_type_boundary("r"))
                position += Message.get_marshaled_data_size(_type[1:-1], data, is_le, position)
            else:
                if (_type in ( "y", "b" )): marshaled_data_size = 1
                elif (_type in ( "n", "q" )): marshaled_data_size = 2
                elif (_type in ( "i", "u", "h" )): marshaled_data_size = 4
                elif (_type in ( "x", "t", "d" )): marshaled_data_size = 8
                elif (_type in ( "s", "o" )):
                    ( position, marshaled_data_size ) = Message._unmarshal_basic_type_data("u", data, is_le, position)
                    marshaled_data_size += 1
                elif (_type == "g"):
                    signature_size_data = data[position:position + 1]
                    if (len(signature_size_data) != 1): raise IOException("D-Bus data truncated")

                    marshaled_data_size = unpack(("<" if (is_le) else ">") + "B", signature_size_data)[0]
                    marshaled_data_size += 1

                    position += 1
                #

                position = Message._get_boundary_offset(position, Message.get_marshaled_type_boundary(_type))
                position += marshaled_data_size
            #

            signature_position += type_length
        #

        return (position - position_started)
    #

    @staticmethod
    def get_marshaled_message_size(data):
        """
Returns the marshaled message size based on the D-Bus message data given.
Raises IOException if not enough data is available for calculation.

:param data: D-Bus message data to calculate the message size for

:return: (int) D-Bus message size
:since:  v1.0.0
        """

        data = Binary.bytes(data)
        data_size = len(data)
        if (data_size < 16): raise IOException("D-Bus message is invalid")

        header = [ Message.unmarshal_data("y", data[:1]) ]
        is_le = (Binary.str(header[0]) == "l")
        header += Message.unmarshal_data("yyyuu", data[:12], is_le, 1)

        _return = 12
        _return += Message.get_marshaled_data_size("a(yv)", data, is_le, 12)
        _return += header[4]

        return _return
    #

    @staticmethod
    def get_marshaled_type_boundary(_type):
        """
Returns the defined boundary corresponding to the D-BUS Specification.

:param _type: D-Bus signature type code (ASCII)

:return: (int) Defined boundary
:since: v1.0.0
        """

        _return = 0

        if (_type in ( "x", "t", "d", "(", "r", "{", "e" )): _return = 8
        elif (_type in ( "b", "i", "u", "h", "s", "o", "a" )): _return = 4
        elif (_type in ( "n", "q" )): _return = 2

        return _return
    #

    @staticmethod
    def _marshal_basic_type_data(_type, data, is_le = False, offset = 0):
        """
Marshals data of a basic type.

:param _type: D-Bus signature type code (ASCII)
:param data: Wire-formatted data
:param is_le: True if message contains data in little endian byte order
:param position: Current read position in the wire-formatted data

:return: (int) Position matching the given boundary
:since:  v1.0.0
        """

        if (isinstance(data, TypeObject)):
            if (data.hint != _type): raise ValueException("D-Bus basic data type does not match requested data type")
            data = data.value
        #

        data_type = type(data)
        marshaled_data = None
        marshaled_size_data = None

        # "<" little endian, ">" big endian
        pack_spec = ("<" if (is_le) else ">")

        if (_type == "y"):
            if (data_type is int): marshaled_data = pack(pack_spec + "B", data)
            elif (data_type in ( str, Binary.BYTES_TYPE )):
                data = Binary.bytes(data)
                marshaled_data = pack(pack_spec + "c", data)
            #
        elif (_type == "b"):
            if (data_type is int): marshaled_data = pack(pack_spec + "B", data)
            elif (data_type is bool): marshaled_data = pack(pack_spec + "?", data)
        elif (_type == "n"):
            if (data_type is int): marshaled_data = pack(pack_spec + "h", data)
        elif (_type == "q"):
            if (data_type is int): marshaled_data = pack(pack_spec + "H", data)
        elif (_type == "i"):
            if (data_type is int): marshaled_data = pack(pack_spec + "i", data)
        elif (_type == "u"):
            if (data_type is int): marshaled_data = pack(pack_spec + "I", data)
        elif (_type == "x"):
            if (data_type is int): marshaled_data = pack(pack_spec + "q", data)
        elif (_type == "t"):
            if (data_type is int): marshaled_data = pack(pack_spec + "Q", data)
        elif (_type == "d"):
            if (data_type in ( float, int )): marshaled_data = pack(pack_spec + "d", data)
        elif (_type == "h"):
            if (data_type is int): marshaled_data = pack(pack_spec + "I", data)
        elif (_type in ( "s", "o" )):
            if (data_type not in ( str, Binary.BYTES_TYPE )): data = str(data)

            data = Binary.utf8_bytes(data)
            data_length = len(data)

            ( offset, marshaled_size_data ) = Message._marshal_basic_type_data("u", data_length, is_le, offset)
            marshaled_data = pack(pack_spec + "{0:d}sx".format(data_length), data)
        elif (_type == "g"):
            if (data_type in ( str, Binary.BYTES_TYPE )):
                data = Binary.utf8_bytes(data)
                data_length = len(data)

                marshaled_size_data = pack(pack_spec + "B", data_length)
                offset += 1

                marshaled_data = pack(pack_spec + "{0:d}sx".format(data_length), data)
            #
        #

        if (marshaled_data is None): raise ValueException("Data given is invalid for the D-Bus basic type defined")

        return_data = (Binary.BYTES_TYPE() if (marshaled_size_data is None) else marshaled_size_data)

        ( offset, boundary_data ) = Message._get_boundary_data(offset, _type)
        if (len(boundary_data) > 0): return_data += boundary_data

        return_data += marshaled_data
        offset += len(marshaled_data)

        return ( offset, return_data )
    #

    @staticmethod
    def marshal_data(signature, parameters, is_le = False, offset = 0):
        """
Marshals data based on the given D-Bus signature.

:param signature: D-Bus signature
:param data: Wire-formatted data
:param is_le: True if message contains data in little endian byte order
:param offset: Offset within the wire-formatted data

:return: (bytes) Wire-formatted bytes
:since:  v1.0.0
        """

        return Message._marshal_data_walker(signature, parameters, is_le, offset)[1]
    #

    @staticmethod
    def _marshal_data_walker(signature, parameters, is_le = False, offset = 0, nested_level = 0):
        """
Marshals data recursively based on the given D-Bus signature.

:param signature: D-Bus signature
:param data: Wire-formatted data
:param is_le: True if message contains data in little endian byte order
:param offset: Offset within the wire-formatted data
:param nested_level: Nested level count

:return: (tuple) Tuple containing the new write offset and wire-formatted
         bytes
:since:  v1.0.0
        """

        if (nested_level > Message.NESTED_LEVEL_MAX): raise IOException("Unsupported number of nested levels in D-Bus signature")

        if (not isinstance(parameters, list)): parameters = [ parameters ]

        parameters_size = len(parameters)
        parameters_position = 0

        return_data = Binary.BYTES_TYPE()

        signature_length = len(signature)
        signature_position = 0

        while (signature_position < signature_length):
            if (parameters_position >= parameters_size): raise ValueException("The parameters given do not match the D-Bus signature defined")

            data = parameters[parameters_position]
            if (isinstance(data, TypeObject)): data = data.value

            data_type = type(data)
            _type = Message.get_complete_type_from_signature(signature[signature_position:])
            type_length = len(_type)

            if (_type[:1] == "a"):
                if (data_type not in ( tuple, list, dict )): raise ValueException("The parameter given at position '{0:d}' do not match the D-Bus signature defined".format(parameters_position))

                ( offset, marshaled_data ) = Message._marshal_basic_type_data("u", len(data), is_le, offset)
                return_data += marshaled_data

                if (_type[1:2] == "{"):
                    if (data_type is not dict): raise ValueException("The parameter given at position '{0:d}' do not match the D-Bus signature defined".format(parameters_position))

                    ( offset, boundary_data ) = Message._get_boundary_data(offset, "e")
                    if (len(boundary_data) > 0): return_data += boundary_data

                    dict_element_key_type = Message.get_complete_type_from_signature(_type[2:3])
                    dict_element_value_signature = Message.get_complete_type_from_signature(_type[3:-1])

                    for dict_element_key in data:
                        dict_element_value = data[dict_element_key]

                        ( offset, dict_element_data ) = Message._marshal_basic_type_data(dict_element_key_type, dict_element_key, is_le, offset)
                        return_data += dict_element_data

                        ( offset, dict_element_data ) = Message._marshal_data_walker(dict_element_value_signature,
                                                                                     [ dict_element_value ],
                                                                                     is_le,
                                                                                     offset,
                                                                                     (1 + nested_level)
                                                                                    )

                        return_data += dict_element_data
                    #
                #
                else:
                    if (data_type is not list): raise ValueException("The parameter given at position '{0:d}' do not match the D-Bus signature defined".format(parameters_position))

                    for array_element in data:
                        ( offset, array_element_data ) = Message._marshal_data_walker(_type[1:],
                                                                                      [ array_element ],
                                                                                      is_le,
                                                                                      offset,
                                                                                      (1 + nested_level)
                                                                                     )

                        return_data += array_element_data
                    #
                #
            elif (_type[:1] == "v"):
                element_signature_type = Message.get_marshal_type_for_value(data)

                ( offset, boundary_data ) = Message._get_boundary_data(offset, "v")
                if (len(boundary_data) > 0): return_data += boundary_data

                ( offset, element_signature_type_data ) = Message._marshal_basic_type_data("g", element_signature_type, is_le, offset)
                return_data += element_signature_type_data

                ( offset, element_data ) = Message._marshal_data_walker(element_signature_type,
                                                                        [ data ],
                                                                        is_le,
                                                                        offset,
                                                                        (1 + nested_level)
                                                                       )

                return_data += element_data
            elif (_type[:1] == "("):
                if (data_type is not tuple): raise ValueException("The parameter given at position '{0:d}' do not match the D-Bus signature defined".format(parameters_position))

                ( offset, boundary_data ) = Message._get_boundary_data(offset, "r")
                if (len(boundary_data) > 0): return_data += boundary_data

                ( offset, struct_data ) = Message._marshal_data_walker(_type[1:-1],
                                                                       list(data),
                                                                       is_le,
                                                                       offset,
                                                                       (1 + nested_level)
                                                                      )

                return_data += struct_data
            else:
                ( offset, marshaled_data ) = Message._marshal_basic_type_data(_type, data, is_le, offset)
                return_data += marshaled_data
            #

            parameters_position += 1
            signature_position += type_length
        #

        return ( offset, return_data )
    #

    @staticmethod
    def unmarshal(data):
        """
Unmarshals a D-Bus message and returns a Message instance.

:param data: Wire-formatted data

:return: (object) Message instance
:since:  v1.0.0
        """

        # pylint: disable=protected-access

        data = Binary.bytes(data)
        data_size = len(data)
        if (data_size < 16): raise IOException("D-Bus message is invalid")

        header = [ Message.unmarshal_data("y", data[:1]) ]
        is_le = (Binary.str(header[0]) == "l")
        header += Message.unmarshal_data("yyyuu", data[:12], is_le, 1)

        header_size = 12
        body_size = header[4]

        header_size += Message.get_marshaled_data_size("a(yv)", data, is_le, 12)
        if (header_size > data_size): raise IOException("D-Bus message is invalid (calculated header size < size)")

        header_fields = Message.unmarshal_data("a(yv)", data[:header_size], is_le, 12)

        if (header_size + body_size > data_size): raise IOException("D-Bus message truncated")
        elif (header_size + body_size < data_size): raise IOException("D-Bus message is invalid (calculated message size < size)")

        _return = Message(header[1])
        _return.flags = unpack(("<" if (is_le) else ">") + "B", header[2])[0]
        _return.serial = header[5]

        for header_field in header_fields: _return._set_header_field(header_field[0], header_field[1])

        if (body_size > 0):
            body_signature = _return.body_signature
            if (body_signature is None): raise IOException("D-Bus message contains a body without a signature header")
            _return.body = Message.unmarshal_data(body_signature, data, is_le, header_size)
        #

        return _return
    #

    @staticmethod
    def _unmarshal_basic_type_data(_type, data, is_le = False, position = 0):
        """
Unmarshals data of a basic type.

:param _type: D-Bus signature type code (ASCII)
:param data: Wire-formatted data
:param is_le: True if message contains data in little endian byte order
:param position: Current read position in the wire-formatted data

:return: (int) Position matching the given boundary
:since:  v1.0.0
        """

        data_size = len(data)
        marshaled_data_size = 0

        # "<" little endian, ">" big endian
        unpack_spec = ("<" if (is_le) else ">")

        if (_type == "y"):
            marshaled_data_size = 1
            unpack_spec += "c"
        elif (_type == "b"):
            marshaled_data_size = 1
            unpack_spec += "?"
        elif (_type == "n"):
            marshaled_data_size = 2
            unpack_spec += "h"
        elif (_type == "q"):
            marshaled_data_size = 2
            unpack_spec += "H"
        elif (_type == "i"):
            marshaled_data_size = 4
            unpack_spec += "i"
        elif (_type == "u"):
            marshaled_data_size = 4
            unpack_spec += "I"
        elif (_type == "x"):
            marshaled_data_size = 8
            unpack_spec += "q"
        elif (_type == "t"):
            marshaled_data_size = 8
            unpack_spec += "Q"
        elif (_type == "d"):
            marshaled_data_size = 8
            unpack_spec += "d"
        elif (_type == "h"):
            marshaled_data_size = 4
            unpack_spec += "I"
        elif (_type in ( "s", "o" )):
            ( position, marshaled_data_size ) = Message._unmarshal_basic_type_data("u", data, is_le, position)
            unpack_spec += "{0:d}s".format(marshaled_data_size)
        elif (_type == "g"):
            if (position >= data_size): raise IOException("D-Bus data truncated")

            marshaled_data_size = unpack(unpack_spec + "B", data[position:position + 1])[0]
            position += 1

            unpack_spec += "{0:d}s".format(marshaled_data_size)
        else: raise ValueException("Given D-Bus signature does contain a unsupported basic type '{0}'".format(_type))

        position = Message._get_boundary_offset(position, Message.get_marshaled_type_boundary(_type))
        if ((position + marshaled_data_size) > data_size): raise IOException("D-Bus data truncated")

        return_data = unpack(unpack_spec, data[position:position + marshaled_data_size])[0]
        position += marshaled_data_size

        if (_type in ( "s", "o", "g" )):
            position += 1
            return_data = Binary.str(return_data)
        #

        return ( position, return_data )
    #

    @staticmethod
    def unmarshal_data(signature, data, is_le = False, position = 0):
        """
Unmarshals data based on the given D-Bus signature.

:param signature: D-Bus signature
:param data: Wire-formatted data
:param is_le: True if message contains data in little endian byte order
:param position: Current read position in the wire-formatted data

:return: (mixed) Single basic type data or list of unmarshaled data
:since:  v1.0.0
        """

        data = Binary.bytes(data)
        return Message._unmarshal_data_walker(signature, data, is_le, position)[1]
    #

    @staticmethod
    def _unmarshal_data_walker(signature, data, is_le = False, position = 0, nested_level = 0):
        """
Unmarshals data recursively based on the given D-Bus signature.

:param signature: D-Bus signature
:param data: Wire-formatted data
:param is_le: True if message contains data in little endian byte order
:param position: Current read position in the wire-formatted data
:param nested_level: Nested level count

:return: (tuple) Tuple containing the new read position and either data of
         a single basic type or list of unmarshaled data
:since:  v1.0.0
        """

        return_data = [ ]

        if (nested_level > Message.NESTED_LEVEL_MAX): raise IOException("Unsupported number of nested levels in D-Bus signature")

        data_size = len(data)
        signature_length = len(signature)
        signature_position = 0

        while (signature_position < signature_length and position < data_size):
            _type = Message.get_complete_type_from_signature(signature[signature_position:])
            type_length = len(_type)

            if (_type[:1] == "a"):
                ( position, array_size ) = Message._unmarshal_basic_type_data("u", data, is_le, position)

                if (_type[1:2] == "{"):
                    position = Message._get_boundary_offset(position, Message.get_marshaled_type_boundary("e"))

                    dict_data = { }
                    dict_element_key_type = Message.get_complete_type_from_signature(_type[2:])
                    dict_element_value_signature = Message.get_complete_type_from_signature(_type[3:])

                    for _ in range(0, array_size):
                        ( position, dict_element_key ) = Message._unmarshal_basic_type_data(dict_element_key_type, data, is_le, position)

                        ( position, dict_element_value ) = Message._unmarshal_data_walker(dict_element_value_signature,
                                                                                          data,
                                                                                          is_le,
                                                                                          position,
                                                                                          (1 + nested_level)
                                                                                         )

                        dict_data[dict_element_key] = dict_element_value
                    #

                    return_data.append(dict_data)
                else:
                    array_data = [ ]

                    for _ in range(0, array_size):
                        ( position, array_element ) = Message._unmarshal_data_walker(_type[1:],
                                                                                     data,
                                                                                     is_le,
                                                                                     position,
                                                                                     (1 + nested_level)
                                                                                    )

                        array_data.append(array_element)
                    #

                    return_data.append(array_data)
                #
            elif (_type[:1] == "v"):
                position = Message._get_boundary_offset(position, Message.get_marshaled_type_boundary("v"))
                ( position, element_signature_type ) = Message._unmarshal_basic_type_data("g", data, is_le, position)

                ( position, element_data ) = Message._unmarshal_data_walker(element_signature_type,
                                                                            data,
                                                                            is_le,
                                                                            position,
                                                                            (1 + nested_level)
                                                                           )

                return_data.append(element_data)
            elif (_type[:1] == "("):
                position = Message._get_boundary_offset(position, Message.get_marshaled_type_boundary("r"))

                ( position, struct_data ) = Message._unmarshal_data_walker(_type[1:-1],
                                                                           data,
                                                                           is_le,
                                                                           position,
                                                                           (1 + nested_level)
                                                                          )

                return_data.append(struct_data)
            else:
                ( position, unmarshaled_data ) = Message._unmarshal_basic_type_data(_type, data, is_le, position)
                return_data.append(unmarshaled_data)
            #

            signature_position += type_length
        #

        if (len(return_data) == 1): return_data = return_data[0]
        return ( position, return_data )
    #
#
