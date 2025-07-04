import os
import json
import base64
import hashlib
from getpass import getpass
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Vault:
    def __init__(self, vault_file, setup=False):
        self._vault_file = vault_file
        self._vault_checksum_file = self._get_checksum_file()
        if setup:
            self.__vault = {'__salt__': base64.urlsafe_b64encode(os.urandom(16)).decode()}
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
        return self.__vault[key]

    def delete_password(self, key):
        self.__vault.pop(key)
        self._write_vault()

    def get_keys(self):
        return self.__vault.keys()

    def get_salt(self):
        return base64.urlsafe_b64decode(self.__vault['__salt__'].encode())


class PasswordManager:
    validate_value_constant = 'Vault header used to validate master password'

    @staticmethod
    def _compute_secret(salt, master_password):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=500_000)
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return Fernet(key)

    def __init__(self, master_password, vault_file, setup=False):
        self.vault = Vault(vault_file, setup)
        self.secret = self._compute_secret(self.vault.get_salt(), master_password)
        if setup:
            self.add_password('__validate__', self.validate_value_constant)
        else:
            self._validate()

    def _validate(self):
        try:
            stored_validate_value = self.get_password('__validate__')
            if not stored_validate_value:
                raise RuntimeError('Validate failed as vault doesnt contain key __validate__')
            if stored_validate_value != self.validate_value_constant:
                raise RuntimeError('Validate failed as stored_validate_value is not same as validate_value_constant')
        except InvalidToken:
            raise RuntimeError('Validate failed as provided master password is incorrect')

    def add_password(self, key, password):
        if self.vault.contains_key(key):
            print(f'Add_Password failed as vault already contains key {key}')
            return
        self.vault.add_password(key, self.secret.encrypt(password.encode()).decode())

    def update_password(self, key, password):
        if key == '__salt__' or key == '__validate__':
            print('Update_Password failed as __salt__ and __validate__ update is not allowed')
            return
        self.vault.add_password(key, self.secret.encrypt(password.encode()).decode())

    def get_password(self, key):
        if key == '__salt__':
            print('Get_Password failed as __salt__ get is not allowed')
            return None
        if not self.vault.contains_key(key):
            print(f'Get_Password failed as vault doesnt contains key {key}')
            return None
        return self.secret.decrypt(self.vault.get_password(key).encode()).decode()

    def delete_password(self, key):
        if key == '__salt__' or key == '__validate__':
            print('Delete_Password failed as __salt__ and __validate__ delete is not allowed')
            return
        if not self.vault.contains_key(key):
            print(f'Delete_Password failed as vault doesnt contains key {key}')
            return
        self.vault.delete_password(key)

    def get_keys(self):
        all_keys = list(self.vault.get_keys())
        return [k for k in all_keys if k not in {'__salt__', '__validate__'}]
