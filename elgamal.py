import json
from utility import mod_inverse, gcd, generate_large_prime, find_generator, _my_rng
from sha256 import get_my_hash
from aes256 import encrypt_aes256, decrypt_aes256

class ElGamalKeys:
    def __init__(self, p, alpha, y, a=None):
        self.__p = p
        self.__alpha = alpha
        self.__y = y
        self.__a = a

    @classmethod
    def generate(cls, bits=256):
        p = generate_large_prime(bits)
        alpha = find_generator(p)
        a = _my_rng.randint(2,p-2)
        y = pow(alpha, a, p)
        return cls(p, alpha, y, a)

    @property
    def p(self): return self.__p
    
    @property
    def alpha(self): return self.__alpha
    
    @property
    def y(self): return self.__y
    
    @property
    def a(self): return self.__a
    
    def save_private(self, filename="private_key.json", password=None):
        """
        Сохраняет ключи. Если передан пароль, закрытый ключ шифруется AES-256.
        """
        data = {
            "p": hex(self.__p),
            "alpha": hex(self.__alpha),
            "y": hex(self.__y),
        }
        
        if self.__a:
            if password:
                # 1. Получаем 256-битный ключ из пароля с помощью нашего SHA-256
                key_hex = get_my_hash(password)
                # 2. Зашифровываем закрытый ключ (предварительно переведя его в hex-строку)
                a_hex = hex(self.__a)
                data["encrypted_a"] = encrypt_aes256(a_hex, key_hex)

        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"Ключи успешно сохранены в {filename}")

    def save_public(self, filename="public_key.json"):
        # Сохраняет только открытые параметры (p, alpha, y).
        data = {
            "p": hex(self.__p),
            "alpha": hex(self.__alpha),
            "y": hex(self.__y)
        }
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"Открытый ключ сохранен в {filename}")

    @classmethod
    def load_from_file(cls, filename, password=None):
        """Загружает ключи. Если ключ зашифрован, использует пароль для расшифровки."""
        with open(filename, 'r') as f:
            data = json.load(f)

        p = int(data['p'], 16)
        alpha = int(data['alpha'], 16)
        y = int(data['y'], 16)
        a = None

        if "encrypted_a" in data:
            if not password:
                raise ValueError("Файл зашифрован! Введите пароль для доступа к приватному ключу.")
            
            # 1. Восстанавливаем AES-ключ из введенного пароля
            aes_key = get_my_hash(password)
            # 2. Пытаемся расшифровать
            try:
                a_hex = decrypt_aes256(data['encrypted_a'], aes_key)
                a = int(a_hex, 16)
                print("Приватный ключ успешно расшифрован.")
            except Exception:
                raise ValueError("Неверный пароль или данные повреждены!")
        
        elif "a" in data:
            a = int(data['a'], 16)

        return cls(p, alpha, y, a)

class ElGamalSigner:
    def __init__(self, keys: ElGamalKeys):
        self.keys = keys

    def _get_hash(self, message):
        h_hex = get_my_hash(message)
        return int(h_hex, 16)

    def sign(self, message):
        p = self.keys.p
        alpha = self.keys.alpha
        a = self.keys.a 
        
        if a is None:
            raise ValueError("Ошибка: отсутсвует закрытый ключ (a) для создания подписи!")

        h_m = self._get_hash(message)
        
        while True:
            k = _my_rng.randint(2,p-2)
            if gcd(k, p - 1) == 1:
                break
        
        r = pow(alpha, k, p)
        k_inv = mod_inverse(k, p - 1)
        # 3.9: t = k^-1 * (h(m) - a*r) mod (p-1)
        t = (k_inv * (h_m - a * r)) % (p - 1)
        
        return (r, t)

    def verify(self, message, signature):
        r, t = signature
        p = self.keys.p
        alpha = self.keys.alpha
        y = self.keys.y
        
        if not (0 < r < p):
            return False
            
        h_m = self._get_hash(message)
        
        # Проверка по алгоритму 3.10
        # v1 = (y^r * r^t) mod p
        v1 = (pow(y, r, p) * pow(r, t, p)) % p
        # v2 = alpha^h(m) mod p
        v2 = pow(alpha, h_m, p)
        
        return v1 == v2