This project is a GUI-based Login and Registration System developed using Python and the PyQt framework. The main objective of the project is to design a simple yet secure authentication system that allows users to create an account and later log in using their credentials.

The application consists of two main interfaces:

Register Page

Login Page

On the Register page, the user enters a unique Login ID and a password. The system first validates the inputs by checking whether all fields are filled, whether the password meets the minimum length requirement, and whether the password and confirm password fields match. If the user already exists, the system prevents duplicate registration.

To enhance security, the password is not stored in plain text. Instead, a time-of-typing based encryption technique is used. At the time of registration, the current timestamp is recorded. Each character of the password is encrypted by shifting its ASCII value using a key derived from the timestamp. The system then stores the Login ID, encrypted password, and timestamp in a CSV file.

On the Login page, the user provides their Login ID and password. The system retrieves the corresponding encrypted password and timestamp from the CSV file. Using the same timestamp, the encrypted password is decrypted and compared with the user-entered password. If both match, the user is successfully authenticated; otherwise, an appropriate error message is displayed.

Additional features such as show/hide password, minimum password length validation, and user-existence checking improve usability and reliability.

Overall, this project demonstrates practical implementation of GUI development, file handling, basic encryption concepts, and user authentication logic. It also provides a foundation that can be further extended using stronger encryption methods, databases, and additional security measures.
