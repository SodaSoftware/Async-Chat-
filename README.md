# Async C++ Console Chat 💬

An asynchronous, client-server terminal chat application with end-to-end encryption support.

## 🛠 Tech Stack & Dependencies

* **Language Standard:** C++17 / C++20
* **Networking:** `Boost.Asio` (Asynchronous I/O)
* **Cryptography:** `Crypto++` (RSA-OAEP, AES-GCM for key exchange and encryption)
* **Database:** `SQLite3` (User authentication and persistent storage)

## ⌨️ Command Syntax & Usage

Once connected, navigate the chat using the following built-in slash commands:

* `/open [username]` — Opens a direct chat session with the specified user. Once the session is active, **simply type your message** and press `Enter` to send it instantly without any prefixes.
* `/exit` — Closes the active chat session and safely returns you to the main user list.
* `/help` — Displays the full list of available commands and syntax help.
