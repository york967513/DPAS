from getpass import getpass

from app.database import initialize_database
from app.auth import register_user, authenticate_user
from app.client_storage import save_private_key


def register():
    print("\n=== Registration ===")

    username = input("Username: ").strip()
    password = getpass("Password: ")

    registration_result = register_user(
        username,
        password
    )

    if registration_result:
        save_private_key(
            username,
            registration_result["encrypted_private_key"]
        )

        print("User registered successfully.")
        print("Encrypted private key saved locally.")
    else:
        print(
            "Registration failed. "
            "Username may already exist or password is too weak."
        )


def login():
    print("\n=== Login ===")

    username = input("Username: ").strip()
    password = getpass("Password: ")

    success = authenticate_user(username, password)

    if success:
        print("Authentication successful.")
    else:
        print("Authentication failed.")


def main():

    initialize_database()

    while True:

        print("\n=== DPAS V0.1.1 ===")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Select: ").strip()

        if choice == "1":
            register()

        elif choice == "2":
            login()

        elif choice == "3":
            print("Goodbye.")
            break

        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()