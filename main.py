import sys
import csv
import time
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit,
    QPushButton, QVBoxLayout, QMessageBox, QCheckBox
)

DATA_FILE = "users.csv"
MIN_PASS_LEN = 6

# ---------------- Encryption ----------------

def encrypt_password(password, timestamp):
    key = timestamp % 10
    return "".join(chr(ord(c) + key) for c in password)

def decrypt_password(encrypted, timestamp):
    key = timestamp % 10
    return "".join(chr(ord(c) - key) for c in encrypted)

# ---------------- Main App ----------------

class AuthApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Login System")
        self.setGeometry(450, 200, 320, 350)
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)
        self.register_page()

# ---------------- Register Page ----------------

    def register_page(self):
        self.clear()

        title = QLabel("REGISTER")

        self.reg_id = QLineEdit()
        self.reg_id.setPlaceholderText("Login ID")

        self.reg_pass = QLineEdit()
        self.reg_pass.setPlaceholderText("Password")
        self.reg_pass.setEchoMode(QLineEdit.Password)

        self.reg_confirm = QLineEdit()
        self.reg_confirm.setPlaceholderText("Confirm Password")
        self.reg_confirm.setEchoMode(QLineEdit.Password)

        self.show_pass_cb = QCheckBox("Show Password")
        self.show_pass_cb.stateChanged.connect(self.toggle_register_pass)

        btn_register = QPushButton("Register")
        btn_register.clicked.connect(self.register_user)

        btn_login_page = QPushButton("Go to Login")
        btn_login_page.clicked.connect(self.login_page)

        self.layout.addWidget(title)
        self.layout.addWidget(self.reg_id)
        self.layout.addWidget(self.reg_pass)
        self.layout.addWidget(self.reg_confirm)
        self.layout.addWidget(self.show_pass_cb)
        self.layout.addWidget(btn_register)
        self.layout.addWidget(btn_login_page)

# ---------------- Login Page ----------------

    def login_page(self):
        self.clear()

        title = QLabel("LOGIN")

        self.log_id = QLineEdit()
        self.log_id.setPlaceholderText("Login ID")

        self.log_pass = QLineEdit()
        self.log_pass.setPlaceholderText("Password")
        self.log_pass.setEchoMode(QLineEdit.Password)

        self.show_login_cb = QCheckBox("Show Password")
        self.show_login_cb.stateChanged.connect(self.toggle_login_pass)

        btn_login = QPushButton("Login")
        btn_login.clicked.connect(self.login_user)

        btn_back = QPushButton("Back to Register")
        btn_back.clicked.connect(self.register_page)

        self.layout.addWidget(title)
        self.layout.addWidget(self.log_id)
        self.layout.addWidget(self.log_pass)
        self.layout.addWidget(self.show_login_cb)
        self.layout.addWidget(btn_login)
        self.layout.addWidget(btn_back)

# ---------------- Register Logic ----------------

    def user_exists(self, user_id):
        try:
            with open(DATA_FILE, "r") as f:
                for row in csv.reader(f):
                    if len(row) != 3:
                        continue
                    if row[0] == user_id:
                        return True
        except FileNotFoundError:
            pass
        return False


    def register_user(self):
        uid = self.reg_id.text()
        p1 = self.reg_pass.text()
        p2 = self.reg_confirm.text()

        if not uid or not p1 or not p2:
            QMessageBox.warning(self, "Error", "All fields required")
            return

        if len(p1) < MIN_PASS_LEN:
            QMessageBox.warning(self, "Error",
                f"Password must be at least {MIN_PASS_LEN} characters")
            return

        if p1 != p2:
            QMessageBox.warning(self, "Error", "Passwords do not match")
            return

        if self.user_exists(uid):
            QMessageBox.warning(self, "Error", "User already exists")
            return

        timestamp = int(time.time())
        enc = encrypt_password(p1, timestamp)

        with open(DATA_FILE, "a", newline="") as f:
            csv.writer(f).writerow([uid, enc, timestamp])

        QMessageBox.information(self, "Success", "Registration Successful")
        self.reg_id.clear()
        self.reg_pass.clear()
        self.reg_confirm.clear()

# ---------------- Login Logic ----------------

    def login_user(self):
        uid = self.log_id.text().strip()
        pw = self.log_pass.text().strip()

        try:
            with open(DATA_FILE, "r") as f:
                for row in csv.reader(f):
                    if len(row) != 3:
                        continue

                    stored_id, enc_pass, ts = row
                    if stored_id == uid:
                        original = decrypt_password(enc_pass, int(ts))

                        if original == pw:
                            QMessageBox.information(self, "Success", "Login Successful")
                        else:
                            QMessageBox.warning(self, "Error", "Wrong Password")
                        return

            QMessageBox.warning(self, "Error", "User not found")

        except FileNotFoundError:
            QMessageBox.warning(self, "Error", "No users registered yet")


# ---------------- Utilities ----------------

    def toggle_register_pass(self):
        mode = QLineEdit.Normal if self.show_pass_cb.isChecked() else QLineEdit.Password
        self.reg_pass.setEchoMode(mode)
        self.reg_confirm.setEchoMode(mode)

    def toggle_login_pass(self):
        mode = QLineEdit.Normal if self.show_login_cb.isChecked() else QLineEdit.Password
        self.log_pass.setEchoMode(mode)

    def clear(self):
        while self.layout.count():
            child = self.layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

# ---------------- Run ----------------

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AuthApp()
    window.show()
    sys.exit(app.exec_())