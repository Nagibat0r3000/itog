from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os

KEY_FILE = "secret.key"


def generate_key():
    key = get_random_bytes(32)  #256

    with open(KEY_FILE, "wb") as f:
        f.write(key)

    print("ключ создан")


def load_key():
    with open(KEY_FILE, "rb") as f:
        return f.read()


def encrypt_file(filename):
    key = load_key()

    with open(filename, "rb") as f:
        data = f.read()

    cipher = AES.new(key, AES.MODE_CBC)

    encrypted_data = cipher.encrypt(
        pad(data, AES.block_size)
    )

    encrypted_file = filename + ".enc"

    with open(encrypted_file, "wb") as f:
        f.write(cipher.iv)
        f.write(encrypted_data)

    print(f"файл зашифрован: {encrypted_file}")


def decrypt_file(filename):
    key = load_key()

    with open(filename, "rb") as f:
        iv = f.read(16)
        encrypted_data = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)

    decrypted_data = unpad(
        cipher.decrypt(encrypted_data),
        AES.block_size
    )

    output_file = "decrypted_" + filename.replace(".enc", "")

    with open(output_file, "wb") as f:
        f.write(decrypted_data)

    print(f"файл расшифрован: {output_file}")



def main():
    while True:
        print("\nAES")
        print("1. создать ключ")
        print("2. зашифровать файл")
        print("3. расшифровать файл")
        print("4. выход")

        choice = input("выбор: ")

        if choice == "1":
            generate_key()

        elif choice == "2":
            filename = input("имя: ")

            if os.path.exists(filename):
                encrypt_file(filename)
            else:
                print("Файл не найден!")

        elif choice == "3":
            filename = input("Имя .enc файла: ")

            if os.path.exists(filename):
                decrypt_file(filename)
            else:
                print("Файл не найден!")

        elif choice == "4":
            break

        else:
            print("неверный выбор!")


if __name__ == "__main__":
    main()
