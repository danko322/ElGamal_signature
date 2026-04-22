import os
from elgamal import ElGamalKeys, ElGamalSigner

def print_menu():
    print("1. Сгенерировать новую пару ключей")
    print("2. Сохранить ключи в файлы (с паролем)")
    print("3. Загрузить ключи из файла (нужен пароль)")
    print("4. Подписать файл")
    print("5. Проверить подпись файла")
    print("0. Выход")
    print("="*40)

def main():
    keys = None
    signer = None
    
    while True:
        print_menu()
        choice = input("Выберите действие: ")

        if choice == '1':
            try:
                bits_input = input("Введите длину ключа (рекомендуется 256): ")
                bits = int(bits_input) if bits_input else 256
                print("Генерация... это может занять несколько секунд.")
                keys = ElGamalKeys.generate(bits)
                signer = ElGamalSigner(keys)
                print("Пара ключей успешно создана в памяти.")
            except ValueError:
                print("Ошибка: введите числовое значение для длины ключа.")

        elif choice == '2':
            if not keys:
                print("Ошибка: Сначала создайте ключи (пункт 1)!")
                continue
            
            password = input("Придумайте пароль для защиты закрытого ключа: ")
            if not password:
                print("Предупреждение: Ключ будет сохранен без шифрования!")
                confirm = None
            else:
                confirm = input("Повторите пароль для подтверждения: ")
            
            if password == confirm or not password:
                keys.save_private("private_key.json", password=password)
                keys.save_public("public_key.json")
                print("Файлы сохранены. Закрытый ключ защищен AES-256.")
            else:
                print("Ошибка: Пароли не совпадают!")

        elif choice == '3':
            filename = input("Введите имя файла ключа: ")
            if os.path.exists(filename):
                password = input("Введите пароль для этого ключа (если он есть): ")
                try:
                    keys = ElGamalKeys.load_from_file(filename, password=password)
                    signer = ElGamalSigner(keys)
                    if keys.a:
                        print(f"Ключи загружены. Доступна и подпись, и проверка.")
                    else:
                        print(f"Загружен открытый ключ. Доступна только проверка.")
                except Exception as e:
                    print(f"Ошибка доступа: {e}")
            else:
                print("Ошибка: Файл не найден!")

        elif choice == '4':
            if not keys or not keys.a:
                print("Ошибка: У вас нет закрытого ключа (нужно загрузить с паролем)!")
                continue
            
            file_path = input("Введите путь к файлу для подписи: ")
            if os.path.exists(file_path):
                with open(file_path, 'rb') as f:
                    content = f.read()
                
                # Создаем подпись
                r, t = signer.sign(content)
                
                sig_path = file_path + ".sig"
                with open(sig_path, 'w') as f:
                    f.write(f"{r}\n{t}")
                print(f"Подпись создана и сохранена в {sig_path}")
            else:
                print("Ошибка: Файл не найден!")

        elif choice == '5':
            # Для проверки достаточно только открытого ключа (параметры p, alpha, y)
            if not keys:
                print("Ошибка: Сначала загрузите открытый или закрытый ключ!")
                continue
                
            file_path = input("Введите путь к файлу документа: ")
            sig_path = input("Введите путь к файлу подписи (.sig): ")
            
            if os.path.exists(file_path) and os.path.exists(sig_path):
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read()
                    
                    with open(sig_path, 'r') as f:
                        lines = f.readlines()
                        r = int(lines[0].strip())
                        t = int(lines[1].strip())
                    
                    if signer.verify(content, (r, t)):
                        print("ПОДПИСЬ ВЕРНА: Документ подлинный.")
                    else:
                        print("ВНИМАНИЕ: Подпись НЕВЕРНА!")
                except Exception as e:
                    print(f"Ошибка при чтении подписи: {e}")
            else:
                print("Ошибка: Файл документа или подписи не найден!")

        elif choice == '0':
            print("Завершение работы. Безопасного хранения данных!")
            break
        else:
            print("Неверный выбор, попробуйте снова.")

if __name__ == "__main__":
    main()