#!/usr/bin/env python3.7
""" ASN1 DER/BER symmetric parser/encoder. """
import enum
from . import oids

def decode_varint(bytearr):
    value = bytearr[0] & 0x7f
    while bytearr.pop(0) & 0x80:
        value = (value << 7) | (bytearr[0] & 0x7f)
    return value

def encode_varint(n):
    res = [n & 0x7f]
    n >>= 7
    while n:
        res.append((n & 0x7f) | 0x80)
        n >>= 7

    return bytes(reversed(res))

class BitField:
    def __init__(self, value=0):
        self.value = value

    def __int__(self):
        return self.value
    def __index__(self):
        return self.value

    def __getitem__(self, sl):
        if isinstance(sl, slice):
            bits = bin(self.value)[2:][::-1]
            return int(bits[sl][::-1] or '0', 2)
        else:
            return (self.value >> sl.__index__()) & 1

    def __setitem__(self, sl, value):
        if isinstance(sl, slice):
            size = max(sl.start or 0, sl.stop or 0, self.value.bit_length())
            bits = list(bin(self.value)[2:].zfill(size)[::-1])
            bits[sl] = list(bin(value)[2:].zfill(len(bits[sl]))[::-1])
            self.value = int(''.join(reversed(bits)), 2)
        else:
            self.value |= (bool(value) << sl.__index__())
    
    def __repr__(self):
        return f'<BitField({self.value:#x})>'

DER_TAG_EXTENDED = 0x1f

class ASN1Tag(enum.IntEnum):
    EOC = 0
    Boolean = 1
    Integer = 2
    BitString = 3
    OctetString = 4
    Null = 5
    OID = 6
    UTF8String = 12
    Sequence = 16
    Set = 17
    PrintableString = 19
    T61String = 20
    IA5String = 22
    UTCTime = 23
    GeneralString = 27
    UniversalString = 28

class ASN1Class(enum.IntEnum):
    Universal = 0
    Application = 1
    Context = 2
    Private = 3

class ASN1Object:
    CONS = CLASS = TAG = None
    def __init__(self, value=None, *, data=None):
        if value is not None and data is not None:
            raise TypeError(f"{self.__class__.__name__}: must supply exactly one of `data`, `value`")
        elif data is None:
            data = b''
        if value is None:
            value = self._decode_value(data)
        self.value = value

    def _encode_value(self, value):
        return bytes(value)
    def _decode_value(self, data):
        return data

    @property
    def data(self):
        return self._encode_value(self.value)

    @data.setter
    def data(self, data):
        self.value = self._decode_value(data)

    def __bytes__(self):
        # hack to suppoprt BER shit
        length = len(self.data)
        if getattr(self, '_indefinite', False):
            length = None
        return self._encode_header(length) + self.data

    @classmethod
    def _encode_header(cls, length):
        tag, asn1cls, cons = cls.TAG, cls.CLASS, cls.CONS
        if tag >= 0x1f:  #extended
            tag = DER_TAG_EXTENDED
        head = BitField()
        head[6:8] = asn1cls
        head[5] = cons
        head[:5] = tag
        data = bytearray([head])
        if tag == DER_TAG_EXTENDED:
            data += encode_varint(cls.TAG)
        if length is None:
            data.append(0x80)
        elif length < 0x80:
            data.append(length)
        else:
            byte_count = (length.bit_length() + 7) // 8
            data.append(0x80 | byte_count)
            data += length.to_bytes(byte_count, 'big')
        return bytes(data)

    @classmethod
    def _decode_header(cls, bytearr):
        head = BitField(bytearr.pop(0))
        asn_cls, cons, tag = head[6:8], head[5], head[:5]
        if tag == DER_TAG_EXTENDED:
            tag = decode_varint(bytearr)
        if len(bytearr) == 0:
            raise ValueError("truncated der header")

        length = bytearr.pop(0)
        if length > 0x80:
            byte_count = length & 0x7f
            if byte_count > len(bytearr):
                raise ValueError("bad der length")
            length = int.from_bytes(bytearr[:byte_count], 'big')
            bytearr[:byte_count] = b''

        elif length == 0x80:
            length = None
        return (tag, cons, asn_cls, length, )

    @classmethod
    def from_bytes(cls, data):
        arr = bytearray(data)
        tag, cons, asn1cls, length = cls._decode_header(arr)
        asn1cls = ASN1Class(asn1cls)
        if length is not None:
            if len(arr) < length:
                raise ValueError("Truncated DER object")
            indefinite = False
        else:
            indefinite = True

        cls = cls.find_class(tag, cons, asn1cls)
        if indefinite:
            value, length = cls._decode_indefinite(arr)
            obj = cls(value=value)
        else:
            obj = cls(data=bytes(arr[:length]))
        obj.header_length = len(data) - len(arr)
        obj.length = obj.header_length + length
        # hack
        obj._indefinite = indefinite
        return obj

    def __repr__(self):
        return f"{self.__class__.__name__}({self.value!r})"

    @classmethod
    def find_class(cls, tag, cons, asn1cls):
        if cls.TAG == tag and cls.CONS == cons and cls.CLASS == asn1cls:
            return cls

        for subclass in cls.__subclasses__():
            found = subclass.find_class(tag, cons, asn1cls)
            if found is not None:
                return found

        if cls.TAG is not None and cls.TAG != tag:
            return None
        if cls.CONS is not None and cls.CONS != cons:
            return None
        if cls.CLASS is not None and cls.CLASS != asn1cls:
            return None

        # class not found; create new
        return type(f"{ASN1Class(asn1cls).name}{'Cons' if cons else 'Prim'}[{tag:#x}]",
                    (cls,), {'TAG': tag, 'CLASS': asn1cls, 'CONS': cons})

    def __eq__(self, other):
        if not isinstance(other, ASN1Object):
            return NotImplemented
        return (self.TAG, self.CLASS, self.CONS) == (other.TAG, other.CLASS, other.CONS) \
                and self.value == other.value

class Constructed(ASN1Object):
    CONS = True

    def _encode_value(self, value):
        return b''.join(bytes(x) for x in value)

    def _decode_value(self, data):
        value = []
        while data:
            decoded = ASN1Object.from_bytes(data)
            value.append(decoded)
            data = data[decoded.length:]
        return value

    @classmethod
    def _decode_indefinite(self, data):
        value = []
        offset = 0
        while offset < len(data):
            decoded = ASN1Object.from_bytes(data[offset:])
            value.append(decoded)
            offset += decoded.length
            if isinstance(decoded, EOC):
                break
        else:
            raise RuntimeError("truncated indefinite BER tag (no EOC marker)")
        return value, offset

    def __iter__(self):
        return iter(self.value)

    def __getitem__(self, index):
        return self.value[index]

    def __len__(self):
        return len(self.value)


class Universal(ASN1Object):
    CLASS = ASN1Class.Universal

class UniversalConstructed(Universal, Constructed):
    pass

class Sequence(UniversalConstructed):
    TAG = ASN1Tag.Sequence

class Set(UniversalConstructed):
    TAG = ASN1Tag.Set

class Primitive(ASN1Object):
    CONS = False

class UniversalPrimitive(Universal, Primitive):
    pass

class EOC(UniversalPrimitive):
    TAG = ASN1Tag.EOC

    def __repr__(self):
        return 'EOC'

class Null(UniversalPrimitive):
    TAG = ASN1Tag.Null
    def _decode_value(self, data):
        assert len(data) == 0, "Null tag with data"
        return None

    def _encode_value(self, value):
        assert value is None, "Null tag with non-None value"
        return b''

class OID(UniversalPrimitive):
    TAG = ASN1Tag.OID
    def __init__(self, value=None, *, data=None):
        if isinstance(value, str):
            value = tuple(int(x) for x in value.split('.'))
        super().__init__(value=value, data=data)

    def _decode_value(self, data):
        oid = []
        oid.append(data[0] // 40)
        oid.append(data[0] % 40)
        d = bytearray(data[1:])
        while d:
            oid.append(decode_varint(d))
        return tuple(oid)

    def _encode_value(self, value):
        data = bytearray()
        data.append(value[0] * 40 + value[1])
        for n in value[2:]:
            data += encode_varint(n)
        return bytes(data)

    def __str__(self):
        return self.string

    def __repr__(self):
        desc = ''
        if self.string in oids.oids:
            desc = f" [{oids.oids[self.string]['Comment']}]"
        return f'OID({self.string!r}){desc}'

    @property
    def string(self):
        return '.'.join(str(x) for x in self.value)

    @string.setter
    def string(self, newstr):
        self.value = tuple(int(x) for x in newstr.split('.'))


class Integer(UniversalPrimitive):
    TAG = ASN1Tag.Integer

    def _decode_value(self, data):
        return int.from_bytes(data, 'big', signed=True)

    def _encode_value(self, value):
        # extra bit for signed int
        byte_length = ((value.bit_length() + 8) // 8 )
        return value.to_bytes(byte_length, 'big', signed=True)

    def __int__(self):
        return int(self.value)

class Boolean(Integer):
    TAG = ASN1Tag.Boolean
    def _decode_value(self, data):
        return bool(int.from_bytes(data, 'big'))

    def _encode_value(self, value):
        if value == True:
            # encode True bool as 0xff
            value = 0xff
        byte_length = ((value.bit_length() + 7) // 8 )
        return value.to_bytes(byte_length, 'big')

    def __int__(self):
        return int(self.value)


class StringType:
    def _decode_value(self, data):
        return data.decode(self.ENCODING)

    def _encode_value(self, value):
        return value.encode(self.ENCODING)

    def __str__(self):
        return str(self.value)

    def __len__(self):
        return len(str(self))

class UTF8String(StringType, UniversalPrimitive):
    TAG = ASN1Tag.UTF8String
    ENCODING = 'utf-8'

class GeneralString(StringType, UniversalPrimitive):
    TAG = ASN1Tag.GeneralString
    ENCODING = 'utf-8'

class UniversalString(StringType, UniversalPrimitive):
    TAG = ASN1Tag.UniversalString
    ENCODING = 'utf-8'

class IA5String(StringType, UniversalPrimitive):
    TAG = ASN1Tag.IA5String
    ENCODING = 'ascii'

class PrintableString(StringType, UniversalPrimitive):
    TAG = ASN1Tag.PrintableString
    ENCODING = 'ascii'

class OctetString(UniversalPrimitive):
    TAG = ASN1Tag.OctetString

    def __len__(self):
        return len(self.value)

    def __getitem__(self, ind):
        return self.value.__getitem__(ind)

    def __setitem__(self, item, value):
        return self.value.__setitem__(item, value)

class BitString(UniversalPrimitive):
    TAG = ASN1Tag.BitString
    def __int__(self):
        return int.from_bytes(self.data, 'big')


def parse(data):
    if hasattr(data, 'read'):
        data = data.read()
    return ASN1Object.from_bytes(data)

