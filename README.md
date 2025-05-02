# MindWave Pass - Secure Password Manager

MindWave Pass is a desktop application that securely stores and manages your passwords in a local database.

## Features

- Secure password storage using encryption.
- Master password protection.
- Add, view, edit, and delete credentials (website/app, username, password, category).
- Password generator.
- Search functionality.
- Copy username/password to clipboard.
- User authentication.

## Installation

1. **Prerequisites:**
  
  - Python 3.x
  - Tkinter (usually included with Python)
  - `pycryptography`
  - `pyperclip` (optional, for enhanced clipboard functionality)
2. **Installation Steps:**
  
  - Clone the repository:
    
    ```bash
    git clone https://github.com/wandertechuniverse/MindWavePass.git
    cd MindWave Pass
    ```
    
  - Create a virtual environment (recommended):
    
    ```bash
    python -m venv venv
    venv\Scripts\activate # On Windows
    source venv/bin/activate # On macOS/Linux
    ```
    
  - Install the required packages:
    
    ```bash
    pip install cryptography
    pip install pyperclip
    ```
    

## Usage

1. **First Run:**
  
  - When you run the application for the first time, you will be prompted to create a master password. This password is used to encrypt your stored credentials.
2. **Login:**
  
  - On subsequent runs, you will be prompted to enter your master password to access your stored credentials.
3. **Dashboard:**
  
  - The dashboard displays a list of your stored credentials.
  - You can see the website/app name, username, category, and date added.
4. **Add New Credential:**
  
  - Click the "Add New" button to add a new credential.
  - You will be prompted to enter the website/app name, username, password, and category.
5. **View/Edit Credential:**
  
  - Double-click on a credential in the list to view and edit its details.
  - You can update the website/app name, username, password, and category.
  - You can also copy the username or password to the clipboard.
6. **Delete Credential:**
  
  - In the view/edit dialog, or by right-clicking on a credential in the main view, you can delete a credential. You will be prompted to confirm the deletion.
7. **Generate Password:**
  
  - Click the "Generate Password" button to open the password generator.
  - You can specify the password length and the character sets to include (uppercase, lowercase, digits, symbols).
  - The generated password will be displayed, and you can copy it to the clipboard.
8. **Search:**
  
  - Use the search bar in the top-right corner to search for credentials.
  - You can search by website/app name, username, or category.
9. **Logout:**
  
  - Click the "Logout" button to logout. The application will clear the current session.

## Important Security Notes:

- **Master Password:** Your master password is crucial. Choose a strong, unique password and keep it safe. If you forget your master password, you will lose access to your stored credentials.
- **Local Storage:** MindWave Pass stores your encrypted credentials in a local SQLite database (`mindwave_pass.db`). Ensure that this file is stored in a secure location on your computer.
- **Encryption:** The application uses the `cryptography` library to encrypt your credentials with a key derived from your master password.
- **Clipboard:** The application uses `pyperclip` (if available) or a Tkinter fallback to copy usernames and passwords to the clipboard. Be aware that clipboard data can sometimes be accessed by other applications.
- **Password Generation:** The built-in password generator creates strong, random passwords using the `secrets` module.

## Troubleshooting

- **`ModuleNotFoundError: No module named 'pyperclip'`:**
  - This error indicates that the `pyperclip` library is not installed. You can either install it using `pip install pyperclip` or continue to use the application with the (less reliable) fallback clipboard mechanism.
- **`ModuleNotFoundError: No module named 'cryptography'`:**
  - This error indicates that the `cryptography` library is not installed. Install it using `pip install cryptography`.

## License

MIT License

Copyright (c) 2025 MindWave Pass

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
