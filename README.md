# MindWave Pass - Your Secure Desktop Password Manager 🔒

MindWave Pass is a user-friendly desktop application designed to securely store and manage your sensitive passwords locally on your computer. Built with Python and Tkinter, it offers a robust solution for organizing your digital credentials and enhancing your online security.

## ✨ Key Features

- **🛡️ Secure Encryption:** Your passwords are encrypted using a strong algorithm, safeguarding them from unauthorized access.
- **🔑 Master Password Protection:** Access to your password vault is controlled by a single, secure master password.
- **➕ Add, View, Edit, Delete:** Easily manage your credentials with intuitive functions to add new entries, view details, modify existing records, and remove outdated information. Each entry includes fields for website/application, username, password, and a customizable category.
- **🔑 Password Generator:** Create strong, unique passwords with customizable length and character sets (uppercase, lowercase, digits, symbols) to enhance your security posture.
- **🔍 Powerful Search:** Quickly find the credentials you need by searching through website/app names, usernames, or categories.
- **📋 Easy Copy to Clipboard:** Effortlessly copy usernames and passwords to your clipboard for quick pasting into login forms.
- **👤 User Authentication:** Ensures that only authorized users with the correct master password can access the stored credentials.

## ⚙️ Installation

Follow these steps to get MindWave Pass up and running on your system:

### 1. Prerequisites

Ensure you have the following installed on your machine:

- **Python 3.x:** Download the latest version from [python.org](https://www.python.org/downloads/).
- **Tkinter:** This graphical user interface toolkit is usually included with standard Python installations.
- **`pycryptography`:** A powerful cryptographic library for Python.
- **`pyperclip` (Optional):** Provides enhanced clipboard functionality. If not installed, the application will use a less robust Tkinter-based fallback.

### 2. Installation Steps

To install MindWave Pass, follow these steps:

1. **Clone the repository:**

   ```bash
   git clone [https://github.com/wandertechuniverse/MindWavePass.git](https://github.com/wandertechuniverse/MindWavePass.git)
   cd MindWavePass```

2. **Create a virtual environment (recommended):**
  
  ```
  python -m venv venv
  ```
  
  - **On Windows:**
    
    ```
    venv\Scripts\activate
    ```
    
  - **On macOS/Linux:**
    
    ```
    source venv/bin/activate
   
    
3. **Install the required packages:**
  
  ```
  pip install cryptography
  pip install pyperclip
  ```
  

## 🚀 Usage

### 1. First Run

- Upon the initial launch of MindWave Pass, you will be prompted to set up a **master password**. This is the key to your encrypted password database, so choose a strong and memorable password.

### 2. Login

- On subsequent launches, you will need to enter your master password to unlock and access your stored credentials.

### 3. Dashboard

- The main dashboard provides an overview of your saved credentials, displaying the website/app name, username, category, and the date the entry was added.

### 4. Add New Credential

- Click the "Add New" button to add a new password entry. You will be asked to provide the website/app name, username, password, and a category for organization.

### 5. View/Edit Credential

- Double-click on any credential in the list to open the view/edit dialog. Here, you can see the full details of the entry, modify any of the fields (website/app, username, password, category), and copy the username or password to your clipboard using the respective buttons.

### 6. Delete Credential

- You can delete a credential either from the view/edit dialog or by right-clicking on an entry in the main list and selecting "Delete". You will be asked to confirm the deletion before the entry is permanently removed.

### 7. Generate Password

- Access the password generator by clicking the "Generate Password" button. You can customize the length of the password and select which character sets to include (uppercase letters, lowercase letters, digits, and symbols). The generated password will be displayed, and you can easily copy it to your clipboard.

### 8. Search

- Utilize the search bar located in the top-right corner to quickly find specific credentials. You can search across website/app names, usernames, and categories.

### 9. Logout

- Click the "Logout" button to securely close your current session. This will clear any active session data.

## 🧪 Running the Application

To start and use MindWave Pass:

1. Open your terminal or command prompt.
  
2. Navigate to the project directory.
  
3. Run the main script:
  
  ```
  python mindwave_pass.py
  ```
  
4. Ensure your virtual environment is activated if you created one during installation.
  

## 📸 Screenshots

### MindWave Pass Login Page

Here's a look at the login page of MindWave Pass:

![MindWave Pass Login Page](https://raw.githubusercontent.com/wandertechuniverse/MindwavePass/refs/heads/main/MindWass%20Pass%20Login%20Page.png)

### MindWave Pass Interface

Here's a look at the main interface of MindWave Pass:

![MindWave Pass Interface](https://raw.githubusercontent.com/wandertechuniverse/MindwavePass/refs/heads/main/MindWave%20Pass%20Interface.png)

## 🔒 Important Security Considerations

- **Master Password is Key:** Your master password is the single point of security for your entire password vault. **Never forget it!** If you lose your master password, you will permanently lose access to your stored credentials as there is no recovery mechanism. Choose a strong, unique password that you don't use elsewhere.
  
- **Local Storage Security:** MindWave Pass stores your encrypted data in a local SQLite database file (`mindwave_pass.db`). Ensure that this file is stored in a secure location on your computer with appropriate file system permissions to prevent unauthorized access.
  
- **Encryption Strength:** The application leverages the `cryptography` library, a well-regarded and robust cryptographic library, to encrypt your sensitive information using a key derived from your master password.
  
- **Clipboard Awareness:** When you copy usernames or passwords to the clipboard, be aware that other applications might potentially access this data. While MindWave Pass aims to minimize the time the data resides on the clipboard, exercise caution, especially on shared or potentially compromised systems. The use of `pyperclip` is recommended for more reliable clipboard interaction.
  
- **Strong Password Generation:** The integrated password generator utilizes the `secrets` module in Python, which is designed for generating cryptographically strong random numbers, ensuring the generated passwords are secure.
  

## 🛠️ Troubleshooting

- **`ModuleNotFoundError: No module named 'pyperclip'`:**
  
  - This error indicates that the `pyperclip` library is not installed. You can resolve this by installing it using pip:
    
    ```
    pip install pyperclip
    ```
    
  - If you choose not to install it, the application will fall back to a less feature-rich Tkinter clipboard mechanism.
    
- **`ModuleNotFoundError: No module named 'cryptography'`:**
  
  - This error means the `cryptography` library is missing. Install it using pip:
    
    ```
    pip install cryptography
    ```
    
  - This library is essential for the security of MindWave Pass.
    

## 📜 License

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

LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT
