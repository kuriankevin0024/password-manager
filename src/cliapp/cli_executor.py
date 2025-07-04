import os
from getpass import getpass
from password_manager import PasswordManager


def main():
    master_password = ''
    vault_file = 'vault.enc'
    if not os.path.exists(vault_file):
        master_password = getpass('Set master password: ')
        PasswordManager(master_password, vault_file, True)
        print('Password_Manager setup completed.')

    master_password = master_password if master_password else getpass('Enter master password: ')
    pm = PasswordManager(master_password, vault_file)

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
            print(f'Keys: {list(pm.get_keys())}')
        elif choice == 'q':
            done = True
            print('--- --- --- Bye --- --- ---')
        else:
            print('Invalid Choice')


if __name__ == '__main__':
    main()
