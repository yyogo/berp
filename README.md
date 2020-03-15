# BERP - BER Parsing

Ever wanted to easily parse and build BER/DER/CER structures using Python?
Well, now it's as easy as `import berp`!

## Usage


## Extending

To parse custom ASN1 types, inherit from the appropriate base class in `berp` (e.g `Universal` or `Primitive`), and set the `TAG, CLASS` and `CONS` values to match your ASN1 type.
The decoding and encoding is performed by the `_encode_value()` and `_decode_value()` methods.

Example:
```python
from datetime import datetime

class UTCTimeStamp(berp.Primitive):
	CLASS = berp.ASN1Class.Private
	TAG = 1234

	def _decode_value(self, data):
		return datetime.fromtimestamp(int.from_bytes(data, 'big'))

	def _encode_value(self, value):
		res = int(value.timestamp())
		return res.to_bytes((res.bit_length() + 7) // 8, 'big')


```

