import os
import base64
from getpass import getpass
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from baselibrary.file import check


class PasswordManager:
    salt_file: str = 'salt.bin'
    vault_file: str = 'vault.enc'

    def __init__(self):
        self.secret = None
        self.credentials = {}

    @staticmethod
    def derive_key(master_password: bytes, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=250_000)
        return base64.urlsafe_b64encode(kdf.derive(master_password))

    def initialization(self):
        if not check.exists(self.salt_file) or not check.exists(self.vault_file):
            if check.exists(self.salt_file):
                os.remove(self.salt_file)
            if check.exists(self.vault_file):
                os.remove(self.vault_file)

        if check.exists(self.salt_file):
            with open(self.salt_file, 'rb') as f:
                salt = f.read()
            master_password = getpass('Enter master password: ')
        else:
            salt = os.urandom(16)
            master_password = getpass('Set master password: ')
            with open(self.salt_file, 'wb') as f:
                f.write(salt)
        key = self.derive_key(master_password.encode(), salt)
        self.secret = Fernet(key)

        if check.exists(self.vault_file):
            with open(self.vault_file, 'r', encoding='utf-8', newline='') as f:
                encrypted_master_password = f.readline().strip().split(':', 1)[1]
                try:
                    self.secret.decrypt(encrypted_master_password.encode()).decode()
                except InvalidToken:
                    print('!!!Wrong Master Password!!!')
                    exit(1)
                for line in f:
                    site, encrypted = line.strip().split(':', 1)
                    self.credentials[site] = self.secret.decrypt(encrypted.encode()).decode()
        else:
            with open(self.vault_file, 'w', encoding='utf-8', newline='') as f:
                pass
            self.add_password('__master__', master_password)

    def add_password(self, site, password):
        if not site or not password:
            return
        self.credentials[site] = password
        with open(self.vault_file, 'a', encoding='utf-8', newline='') as f:
            f.write(site + ':' + self.secret.encrypt(password.encode()).decode() + '\n')

    def get_password(self, site):
        return self.credentials.get(site)

    def get_all_password(self):
        passwords = ''
        for key, value in self.credentials.items():
            if '__master__' != key:
                passwords += f'{key}:{value}\n'
        return passwords


def main():
    pm = PasswordManager()
    pm.initialization()

    print("""
What do you want to do?
    (1) Add a new password
    (2) Get a password
    (3) Get all passwords
    (q) Quit
        """)

    done = False
    while not done:
        choice = input('--- --- --- Enter your choice: ')
        if choice == '1':
            site = input('Enter username: ')
            password = getpass('Enter password: ')
            pm.add_password(site, password)
        elif choice == '2':
            site = input('Enter username: ')
            print(f'{site}:{pm.get_password(site)}')
        elif choice == '3':
            print(pm.get_all_password())
        elif choice == 'q':
            done = True
            print('--- --- --- Bye --- --- ---')
        else:
            print('!!!Invalid choice!!!')


if __name__ == '__main__':
    main()
