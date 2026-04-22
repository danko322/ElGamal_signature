K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

def _rotr(x, n): return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF
def _ch(x, y, z): return (x & y) ^ (~x & z) & 0xFFFFFFFF
def _maj(x, y, z): return (x & y) ^ (x & z) ^ (y & z)
def _sigma0(x): return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)
def _sigma1(x): return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)
def _gamma0(x): return _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)
def _gamma1(x): return _rotr(x, 17) ^ _rotr(x, 19) ^ (x >> 10)

class SHA256:
    def __init__(self):
        self._h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
        self._buffer = bytearray()
        self._counter = 0

    def update(self, data: bytes):
        self._buffer.extend(data)
        self._counter += len(data)
        while len(self._buffer) >= 64:
            self._process(self._buffer[:64])
            self._buffer = self._buffer[64:]

    def _process(self, chunk):
        w = [0] * 64
        for i in range(16):
            w[i] = int.from_bytes(chunk[i*4:i*4+4], 'big')
        for i in range(16, 64):
            w[i] = (_gamma1(w[i-2]) + w[i-7] + _gamma0(w[i-15]) + w[i-16]) & 0xFFFFFFFF

        a, b, c, d, e, f, g, h = self._h
        for i in range(64):
            t1 = (h + _sigma1(e) + _ch(e, f, g) + K[i] + w[i]) & 0xFFFFFFFF
            t2 = (_sigma0(a) + _maj(a, b, c)) & 0xFFFFFFFF
            h, g, f, e, d, c, b, a = g, f, e, (d + t1) & 0xFFFFFFFF, c, b, a, (t1 + t2) & 0xFFFFFFFF

        for i, val in enumerate([a, b, c, d, e, f, g, h]):
            self._h[i] = (self._h[i] + val) & 0xFFFFFFFF

    def finalize(self):
        """Завершает хэширование и возвращает 32 байта."""
        buf = bytearray(self._buffer)
        orig_len_bits = self._counter * 8
        buf.append(0x80)
        while (len(buf) % 64) != 56:
            buf.append(0x00)
        buf.extend(orig_len_bits.to_bytes(8, 'big'))
        
        for i in range(0, len(buf), 64):
            self._process(buf[i:i+64])
        
        return b''.join(x.to_bytes(4, 'big') for x in self._h)

def get_my_hash(data: str) -> str:
    """Принимает строку, возвращает HEX-хэш."""
    h = SHA256()
    if isinstance(data, str):
        data = data.encode('utf-8')
    h.update(data)
    return h.finalize().hex()
