import os
import json
import base64
from getpass import getpass
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class PasswordManager:
    @staticmethod
    def create_secret(master_password, salt_file):
        with open(salt_file, 'rb') as f:
            salt = f.read()
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=500_000)
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return Fernet(key)

    @staticmethod
    def load_vault(vault_file):
        with open(vault_file, 'r') as file:
            return json.load(file)

    @staticmethod
    def dump_vault(vault, vault_file):
        with open(vault_file, 'w') as file:
            file.write(json.dumps(vault, indent=4))

    @classmethod
    def init(cls, master_password, salt_file, vault_file):
        salt = os.urandom(16)
        with open(salt_file, 'wb') as f:
            f.write(salt)
        os.chmod(salt_file, 0o600)
        secret = cls.create_secret(master_password, salt_file)
        vault = {'__master__': secret.encrypt(master_password.encode()).decode()}
        cls.dump_vault(vault, vault_file)
        os.chmod(vault_file, 0o600)

    def __init__(self, master_password, salt_file, vault_file):
        self.vault_file = vault_file
        self.secret = self.create_secret(master_password, salt_file)
        self.vault = self.load_vault(vault_file)
        self.validate_master_password(master_password)

    def validate_master_password(self, master_password):
        try:
            encrypted_master_password = self.vault['__master__']
            stored_master_password = self.secret.decrypt(encrypted_master_password.encode()).decode()
            if stored_master_password != master_password:
                raise RuntimeError('Vault file is corrupted.')
        except InvalidToken:
            print('Master password is wrong')
            exit(1)

    def add_password(self, key, password):
        if key == '__master__':
            raise RuntimeError('Updating master password is not allowed.')
        if key in self.vault.keys():
            choice = input('Do you want to replace existing entry (y/n): ')
            if choice.lower() != 'y':
                return
        self.vault[key] = self.secret.encrypt(password.encode()).decode()
        self.dump_vault(self.vault, self.vault_file)

    def get_password(self, key):
        encrypted_password = self.vault.get(key)
        if not encrypted_password:
            return None
        return self.secret.decrypt(encrypted_password.encode()).decode()


def main():
    master_password = ''
    salt_file = 'salt.bin'
    vault_file = 'vault.enc'
    if not os.path.exists(salt_file) and not os.path.exists(vault_file):
        master_password = getpass('Set master password: ')
        PasswordManager.init(master_password, salt_file, vault_file)

    if not os.path.exists(salt_file):
        print(f'FileNotFound Salt: {salt_file}')
        exit(1)
    if not os.path.exists(vault_file):
        print(f'FileNotFound Vault: {vault_file}')
        exit(1)

    master_password = master_password if master_password else getpass('Enter master password: ')
    pm = PasswordManager(master_password, salt_file, vault_file)

    print("""
What do you want to do?
    (1) Add a new password
    (2) Get a password
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
        elif choice == 'q':
            done = True
            print('--- --- --- Bye --- --- ---')
        else:
            print('!!!Invalid choice!!!')


if __name__ == '__main__':
    main()
