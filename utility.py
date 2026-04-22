import time

class MyRandom:
    """Линейный конгруэнтный генератор"""
    def __init__(self, seed=None):
        if seed is None:
            seed = int(time.time() * 1000000)
        
        self.state = seed
        
        self.m = 2**256
        self.a = 6364136223846793005  
        self.c = 1442695040888963407
    
    def next(self):
        """Генерирует следующее число в цепочке"""
        self.state = (self.a * self.state + self.c) % self.m
        return self.state

    def randint(self, min_val, max_val):
        """Возвращает число в заданном диапазоне"""
        range_size = max_val - min_val + 1
        return min_val + (self.next() % range_size)

_my_rng = MyRandom()

def is_prime(n , k = 128): # Miller-Rabin
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0: return False
    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1
        
    for _ in range(k):
        a = _my_rng.randint(2,n-2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_large_prime(bits=128):
    print("    (Ищем безопасное простое число p = 2q + 1...)")
    min_q = 1 << (bits - 2)
    max_q = (1 << (bits - 1)) - 1
    while True:
        # Генерируем случайное простое q
        q = _my_rng.randint(min_q,max_q)
        q |= (1 << (bits - 2)) | 1
        if is_prime(q):
            # Проверяем, будет ли p = 2q + 1 тоже простым
            p = 2 * q + 1
            if is_prime(p):
                return p
        
def get_prime_factors(n):
    """Находит уникальные простые множители числа n (упрощенная версия)"""
    factors = set()
    d = 2
    temp = n
    while d * d <= temp:
        if temp % d == 0:
            factors.add(d)
            while temp % d == 0:
                temp //= d
        d += 1
    if temp > 1:
        factors.add(temp)
    return factors

def find_generator(p): # Поиск порождающего элемента группы %alpha
    # Для безопасного простого p = 2q + 1, делители p-1 это 2 и q
    q = (p - 1) // 2
    factors = [2, q]
    
    for g in range(2, p):
        is_gen = True
        for q_factor in factors:
            if pow(g, (p - 1) // q_factor, p) == 1:
                is_gen = False
                break
        if is_gen:
            return g
    return None
        
def mod_inverse(a, m):
    #Вычисляет модульное обратное число (a^-1 mod m)
    m0 = m
    y = 0
    x = 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        t = m
        m = a % m
        a = t
        t = y
        y = x - q * y
        x = t
    if x < 0:
        x = x + m0
    return x

def gcd(a, b):
    """Вычисляет наибольший общий делитель."""
    while b:
        a, b = b, a % b
    return a