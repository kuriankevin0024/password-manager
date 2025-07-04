import os
import json
import base64
import hashlib
from getpass import getpass
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Secret:
    @staticmethod
    def _compute_salt():
        return os.urandom(16)

    def __init__(self, master_password, salt_file, setup=False):
        self._salt_file = salt_file
        if setup:
            self._salt = self._compute_salt()
            self._write_salt()
        else:
            self._validate()
            self._salt = self._read_salt()
        self.__secret = self._compute_secret(master_password)

    def _validate(self):
        if not os.path.exists(self._salt_file):
            raise FileNotFoundError('Salt File Not Found')

    def _compute_secret(self, master_password):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=self._salt, iterations=500_000)
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return Fernet(key)

    def _write_salt(self):
        with open(self._salt_file, 'wb') as f:
            f.write(self._salt)

    def _read_salt(self):
        with open(self._salt_file, 'rb') as f:
            return f.read()

    def get_secret(self):
        return self.__secret


class Vault:
    def __init__(self, vault_file, setup=False):
        self._vault_file = vault_file
        self._vault_checksum_file = self._get_checksum_file()
        if setup:
            self.__vault = {}
            self._write_vault()
        else:
            self._validate()
            self._verify_checksum()
            self.__vault = self._read_vault()

    def _get_checksum_file(self):
        abs_path = self._vault_file if os.path.isabs(self._vault_file) else os.path.abspath(self._vault_file)
        parent_path = os.path.dirname(abs_path)
        filename = os.path.basename(abs_path)
        filename_txt, _ = os.path.splitext(filename)
        return os.path.join(parent_path, f'{filename_txt}_checksum.sha256')

    def _validate(self):
        if not os.path.exists(self._vault_checksum_file):
            raise FileNotFoundError('Vault Checksum File Not Found')
        if not os.path.exists(self._vault_file):
            raise FileNotFoundError('Vault File Not Found')

    def _compute_checksum(self):
        h = hashlib.sha256()
        with open(self._vault_file, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()

    def _write_checksum(self):
        vault_checksum = self._compute_checksum()
        with open(self._vault_checksum_file, 'w') as f:
            f.write(f'{vault_checksum}\n')

    def _read_checksum(self):
        with open(self._vault_checksum_file, 'r') as f:
            return f.readline().strip()

    def _verify_checksum(self):
        actual_checksum = self._compute_checksum()
        expected_checksum = self._read_checksum()
        if actual_checksum != expected_checksum:
            raise RuntimeError('Vault integrity check failed')

    def _write_vault(self):
        with open(self._vault_file, 'w') as file:
            file.write(json.dumps(self.__vault, indent=4))
        self._write_checksum()

    def _read_vault(self):
        with open(self._vault_file, 'r') as file:
            return json.load(file)

    def contains_key(self, key):
        return key in self.__vault

    def add_password(self, key, encrypted_password):
        self.__vault[key] = encrypted_password
        self._write_vault()

    def get_password(self, key):
        return self.__vault.get(key)

    def delete_password(self, key):
        self.__vault.pop(key)
        self._write_vault()

    def get_all_keys(self):
        return self.__vault.keys()


class PasswordManager():
    def __init__(self, master_password, salt_file, vault_file, setup=False):
        self.secret = Secret(master_password, salt_file, setup).get_secret()
        self.vault = Vault(vault_file, setup)
        if setup:
            self.add_password('__master__', master_password)
        else:
            self._validate(master_password)

    def _validate(self, master_password):
        try:
            stored_master_password = self.get_password('__master__')
            if not stored_master_password:
                raise RuntimeError('Master password missing in vault')
            if stored_master_password != master_password:
                raise RuntimeError('Master password integrity check failed')
        except InvalidToken:
            raise RuntimeError('Master password is wrong')

    def add_password(self, key, password):
        if self.vault.contains_key(key):
            print(f'vault contains key {key}')
            return
        self.vault.add_password(key, self.secret.encrypt(password.encode()).decode())

    def update_password(self, key, password):
        if key == '__master__':
            print('Master password update is prohibited')
            return
        self.vault.add_password(key, self.secret.encrypt(password.encode()).decode())

    def get_password(self, key):
        encrypted_password = self.vault.get_password(key)
        if not encrypted_password:
            return None
        return self.secret.decrypt(encrypted_password.encode()).decode()

    def delete_password(self, key):
        if not self.vault.contains_key(key):
            print(f'vault doesnt contains key {key}')
            return
        self.vault.delete_password(key)

    def get_all_keys(self):
        return self.vault.get_all_keys()


def main():
    master_password = ''
    salt_file = 'salt.bin'
    vault_file = 'vault.enc'
    if not os.path.exists(salt_file) and not os.path.exists(vault_file):
        master_password = getpass('Set master password: ')
        PasswordManager(master_password, salt_file, vault_file, True)
        print('Password Manager setup completed.')

    master_password = master_password if master_password else getpass('Enter master password: ')
    pm = PasswordManager(master_password, salt_file, vault_file)

    done = False
    options = 'Options: (1)Add_Password (2)Update_Password (3)Get_Password (4)Delete_Password (5)Get_All_Keys (q)Quit'
    while not done:
        choice = input(f'--- --- --- \n{options}\nEnter your choice: ')
        if choice == '1':
            key = input('Enter username: ')
            password = getpass('Enter password: ')
            pm.add_password(key, password)
        elif choice == '2':
            key = input('Enter username: ')
            password = getpass('Enter password: ')
            pm.update_password(key, password)
        elif choice == '3':
            key = input('Enter username: ')
            print(f'{key}:{pm.get_password(key)}')
        elif choice == '4':
            key = input('Enter username: ')
            pm.delete_password(key)
        elif choice == '5':
            print(f'Keys: {list(pm.get_all_keys())}')
        elif choice == 'q':
            done = True
            print('--- --- --- Bye --- --- ---')
        else:
            print('!!!Invalid choice!!!')


if __name__ == '__main__':
    main()
