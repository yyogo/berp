try:
    from rupy import pp
except ImportError:
    print('`pip install rupy` for nicer prints')
    from pprint import pprint as pp
import berp

def test_symmetry():
    fin = 'test/Amazon Root CA 1.cer'
    data = open(fin, 'rb').read()
    obj = berp.parse(data)
    assert bytes(obj) == data
    assert berp.parse(bytes(obj)) == obj


def test_print():
    fin = 'test/Amazon Root CA 1.cer'
    data = open(fin, 'rb').read()
    obj = berp.parse(data)
    pp(obj)

if __name__ == '__main__':
    test_symmetry()
    test_print()
