from cryptography.fernet import Fernet

from baselibrary.file import check


class PasswordManager:
    secret_file: str = 'secret.key'
    password_file: str = 'passwords.enc'

    def __init__(self):
        self.secret = None
        self.password_dict = {}

    def create_secret_file(self):
        self.secret = Fernet.generate_key()
        with open(self.secret_file, 'wb') as f:
            f.write(self.secret)

    def load_secret_file(self):
        with open(self.secret_file, 'rb') as f:
            self.secret = f.read()

    def create_password_file(self):
        with open(self.password_file, 'w'):
            pass

    def load_password_file(self):
        with open(self.password_file, 'r') as f:
            for line in f:
                site, encrypted = line.split(':')
                self.password_dict[site] = Fernet(self.secret).decrypt(encrypted.encode())

    def add_password(self, site, password):
        if not site or not password:
            return
        self.password_dict[site] = password
        with open(self.password_file, 'a+') as f:
            encrypted = Fernet(self.secret).encrypt(password.encode())
            f.write(site + ':' + encrypted.decode() + '\n')

    def get_password(self, site):
        return self.password_dict.get(site)

    def get_all_password(self):
        passwords = ''
        for site, password in self.password_dict.items():
            passwords += f'{site}:{password}\n'
        return passwords


def main():
    pm = PasswordManager()

    if not check.exists(pm.secret_file):
        pm.create_secret_file()
    if not check.exists(pm.password_file):
        pm.create_password_file()

    pm.load_secret_file()
    pm.load_password_file()

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
            password = input('Enter password: ')
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
