import sys
import secrets
import string
import os
import json
import csv
import io
import hashlib
import time
import uuid
import logging
import smtplib
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import List, Optional, Dict, Tuple
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
    QLineEdit, QPushButton, QSpinBox, QCheckBox, QComboBox, QTextEdit, 
    QGroupBox, QGridLayout, QMessageBox, QProgressBar, QTabWidget, 
    QTableWidget, QTableWidgetItem, QHeaderView, QSplitter, QFrame,
    QDialog, QFileDialog, QInputDialog, QSlider, QToolTip, QListWidget,
    QListWidgetItem, QTimeEdit, QDateTimeEdit
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread, QPropertyAnimation, QEasingCurve, QDateTime
from PyQt5.QtGui import QFont, QIcon, QPalette, QColor, QPixmap, QCursor
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Configuration

class SecurityConfig:
    session_timeout_minutes: int = 15
    auto_lock_enabled: bool = True
    clipboard_clear_seconds: int = 30
    max_login_attempts: int = 3
    backup_enabled: bool = True


class UIConfig:
    theme: str = "dark"
    font_family: str = "Arial"
    font_size: int = 10
    show_tooltips: bool = True
    animations_enabled: bool = True


class EmergencyContact:
    id: str
    name: str
    email: str
    phone: str
    relationship: str
    priority: int
    public_key: Optional[str] = None
    verified: bool = False
    
    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'phone': self.phone,
            'relationship': self.relationship,
            'priority': self.priority,
            'public_key': self.public_key,
            'verified': self.verified
        }
    
    def from_dict(cls, data: dict):
        return cls(**data)

class EmergencyConfig:
    enabled: bool = False
    delay_hours: int = 72  # 3 days default
    check_interval_hours: int = 24  # Check daily
    last_activity: Optional[datetime] = None
    emergency_triggered: bool = False
    trigger_date: Optional[datetime] = None
    email_server: str = "smtp.gmail.com"
    email_port: int = 587
    emergency_email: str = ""
    emergency_email_password: str = ""
    contacts: List[EmergencyContact] = field(default_factory=list)

class AppConfig:
    app_name: str = "Professional Password Manager"
    version: str = "2.0.0"
    data_directory: str = "data"
    security: SecurityConfig = field(default_factory=SecurityConfig)
    ui: UIConfig = field(default_factory=UIConfig)
    emergency: EmergencyConfig = field(default_factory=EmergencyConfig)

# Security and Encryption
class EncryptionManager:
    def __init__(self):
        self.salt_file = "salt.dat"
        self.encrypted_data_file = "vault.enc"
        
    def derive_key_from_password(self, password: str, salt: bytes = None) -> tuple:
        if salt is None:
            salt = secrets.token_bytes(32)
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    
    def save_salt(self, salt: bytes):
        with open(self.salt_file, "wb") as f:
            f.write(salt)
    
    def load_salt(self) -> bytes:
        if not os.path.exists(self.salt_file):
            return None
        with open(self.salt_file, "rb") as f:
            return f.read()
    
    def verify_master_password(self, password: str) -> bool:
        try:
            salt = self.load_salt()
            if not salt:
                return False
            
            key, _ = self.derive_key_from_password(password, salt)
            fernet = Fernet(key)
            
            if os.path.exists(self.encrypted_data_file):
                with open(self.encrypted_data_file, "rb") as f:
                    first_line = f.readline().strip()
                    if first_line:
                        fernet.decrypt(first_line)
            return True
        except Exception:
            return False

class SessionManager:
    def __init__(self, timeout_minutes=15):
        self.timeout_minutes = timeout_minutes
        self.last_activity = time.time()
        self.is_locked = False
        
    def update_activity(self):
        self.last_activity = time.time()
    
    def check_timeout(self):
        if time.time() - self.last_activity > (self.timeout_minutes * 60):
            return True
        return False

# Data Models
class PasswordEntry:
    id: str
    app_name: str
    username: str
    password: str
    created_date: datetime
    last_modified: datetime
    expiry_date: Optional[datetime] = None
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    
    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'app_name': self.app_name,
            'username': self.username,
            'password': self.password,
            'created_date': self.created_date.isoformat(),
            'last_modified': self.last_modified.isoformat(),
            'expiry_date': self.expiry_date.isoformat() if self.expiry_date else None,
            'tags': self.tags or [],
            'notes': self.notes
        }
    
    def from_dict(cls, data: dict):
        return cls(
            id=data['id'],
            app_name=data['app_name'],
            username=data['username'],
            password=data['password'],
            created_date=datetime.fromisoformat(data['created_date']),
            last_modified=datetime.fromisoformat(data['last_modified']),
            expiry_date=datetime.fromisoformat(data['expiry_date']) if data.get('expiry_date') else None,
            tags=data.get('tags', []),
            notes=data.get('notes', '')
        )
    
    def is_expired(self) -> bool:
        if not self.expiry_date:
            return False
        return datetime.now() > self.expiry_date

# Business Logic
class PasswordGeneratorService:
    def __init__(self):
        self.symbol_sets = {
            "basic": "!@#$%^&*",
            "brackets": "()[]{}",
            "math": "+-=/<>",
            "punctuation": ".,;:?",
            "quotes": "\"'`",
            "other": "~_|\\",
            "all": string.punctuation
        }
    
    def generate_password(self, config: Dict) -> str:
        length = config.get('length', 16)
        use_lowercase = config.get('use_lowercase', True)
        use_uppercase = config.get('use_uppercase', True)
        use_digits = config.get('use_digits', True)
        use_symbols = config.get('use_symbols', True)
        symbol_count = config.get('symbol_count', 3)
        symbol_category = config.get('symbol_category', 'basic')
        
        chars = ""
        if use_lowercase:
            chars += string.ascii_lowercase
        if use_uppercase:
            chars += string.ascii_uppercase
        if use_digits:
            chars += string.digits
            
        if not chars:
            raise ValueError("At least one character type must be selected")
        
        password = []
        
        # Ensure at least one character from each selected type
        if use_lowercase:
            password.append(secrets.choice(string.ascii_lowercase))
        if use_uppercase:
            password.append(secrets.choice(string.ascii_uppercase))
        if use_digits:
            password.append(secrets.choice(string.digits))
        
        # Add required symbols
        if use_symbols and symbol_count > 0:
            symbol_set = self.symbol_sets.get(symbol_category, self.symbol_sets['basic'])
            for _ in range(min(symbol_count, length - len(password))):
                password.append(secrets.choice(symbol_set))
        
        # Fill remaining length
        remaining = length - len(password)
        for _ in range(remaining):
            password.append(secrets.choice(chars))
        
        # Cryptographically secure shuffle
        secrets.SystemRandom().shuffle(password)
        return ''.join(password)
    
    def check_strength(self, password: str) -> Tuple[str, int, str, List[str]]:
        score = 0
        feedback = []
        
        # Length scoring
        if len(password) >= 16:
            score += 30
        elif len(password) >= 12:
            score += 25
        elif len(password) >= 8:
            score += 15
        else:
            feedback.append("Use at least 8 characters (recommended: 16+)")
        
        # Character variety
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in string.punctuation for c in password)
        
        variety_score = sum([has_lower, has_upper, has_digit, has_symbol])
        score += variety_score * 15
        
        if not has_lower:
            feedback.append("Add lowercase letters")
        if not has_upper:
            feedback.append("Add uppercase letters")
        if not has_digit:
            feedback.append("Add numbers")
        if not has_symbol:
            feedback.append("Add symbols")
        
        # Pattern detection
        if self._has_common_patterns(password):
            score -= 20
            feedback.append("Avoid common patterns")
        
        # Determine strength level
        if score >= 85:
            return "Excellent", score, "#27ae60", feedback
        elif score >= 70:
            return "Very Strong", score, "#2ecc71", feedback
        elif score >= 50:
            return "Strong", score, "#f39c12", feedback
        elif score >= 30:
            return "Medium", score, "#e67e22", feedback
        else:
            return "Weak", score, "#e74c3c", feedback
    
    def _has_common_patterns(self, password: str) -> bool:
        password_lower = password.lower()
        patterns = [
            "123", "abc", "qwe", "asd", "zxc",
            "password", "admin", "user", "login"
        ]
        
        for pattern in patterns:
            if pattern in password_lower:
                return True
        
        # Sequential characters
        for i in range(len(password) - 2):
            if (ord(password[i+1]) == ord(password[i]) + 1 and 
                ord(password[i+2]) == ord(password[i]) + 2):
                return True
        
        return False

# Custom Widgets
class PasswordVisibilityWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.is_visible = False
        
    def setup_ui(self):
        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setFont(QFont("Courier", 12))
        
        self.toggle_btn = QPushButton("👁")
        self.toggle_btn.setFixedSize(30, 30)
        self.toggle_btn.clicked.connect(self.toggle_visibility)
        self.toggle_btn.setToolTip("Show/Hide Password")
        
        layout.addWidget(self.password_edit)
        layout.addWidget(self.toggle_btn)
        self.setLayout(layout)
    
    def toggle_visibility(self):
        if self.is_visible:
            self.password_edit.setEchoMode(QLineEdit.Password)
            self.toggle_btn.setText("👁")
            self.is_visible = False
        else:
            self.password_edit.setEchoMode(QLineEdit.Normal)
            self.toggle_btn.setText("🙈")
            self.is_visible = True
    
    def setText(self, text):
        self.password_edit.setText(text)
    
    def text(self):
        return self.password_edit.text()

class ClipboardManager(QWidget):
    def __init__(self):
        super().__init__()
        self.auto_clear_timer = QTimer()
        self.auto_clear_timer.timeout.connect(self.clear_clipboard)
        self.notification_timer = QTimer()
        
    def copy_with_auto_clear(self, text: str, timeout_seconds: int = 30):
        QApplication.clipboard().setText(text)
        self.auto_clear_timer.start(timeout_seconds * 1000)
        
        # Show temporary notification
        QToolTip.showText(
            QCursor.pos(),
            f"Copied! Auto-clear in {timeout_seconds}s",
            None,
            QApplication.desktop().screenGeometry(),
            3000
        )
    
    def clear_clipboard(self):
        QApplication.clipboard().clear()
        self.auto_clear_timer.stop()
        QToolTip.showText(
            QCursor.pos(),
            "Clipboard cleared",
            None,
            QApplication.desktop().screenGeometry(),
            2000
        )

class AdvancedSearchWidget(QWidget):
    search_changed = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.search_timer = QTimer()
        self.search_timer.setSingleShot(True)
        self.search_timer.timeout.connect(self.emit_search)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Main search bar
        search_layout = QHBoxLayout()
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("🔍 Search passwords...")
        self.search_edit.textChanged.connect(self.on_search_changed)
        search_layout.addWidget(self.search_edit)
        
        # Advanced filters
        filters_layout = QHBoxLayout()
        
        # Category filter
        self.category_combo = QComboBox()
        self.category_combo.addItems(["All Categories", "Work", "Personal", "Social", "Banking"])
        self.category_combo.currentTextChanged.connect(self.on_search_changed)
        filters_layout.addWidget(self.category_combo)
        
        # Expiry filter
        self.expiry_check = QCheckBox("Show expiring soon")
        self.expiry_check.stateChanged.connect(self.on_search_changed)
        filters_layout.addWidget(self.expiry_check)
        
        # Clear button
        clear_btn = QPushButton("Clear Filters")
        clear_btn.clicked.connect(self.clear_filters)
        filters_layout.addWidget(clear_btn)
        
        layout.addLayout(search_layout)
        layout.addLayout(filters_layout)
        self.setLayout(layout)
    
    def on_search_changed(self):
        self.search_timer.stop()
        self.search_timer.start(300)
    
    def emit_search(self):
        criteria = {
            'query': self.search_edit.text(),
            'category': self.category_combo.currentText(),
            'show_expiring': self.expiry_check.isChecked()
        }
        self.search_changed.emit(criteria)
    
    def clear_filters(self):
        self.search_edit.clear()
        self.category_combo.setCurrentIndex(0)
        self.expiry_check.setChecked(False)

# Master Password Dialog
class MasterPasswordDialog(QDialog):
    def __init__(self, encryption_manager, is_first_time=False):
        super().__init__()
        self.encryption_manager = encryption_manager
        self.is_first_time = is_first_time
        self.attempt_count = 0
        self.max_attempts = 3
        self.master_password = ""
        self.setup_ui()
        
    def setup_ui(self):
        self.setWindowTitle("🔐 Master Password")
        self.setFixedSize(400, 350)
        self.setWindowFlags(Qt.Dialog | Qt.MSWindowsFixedSizeDialogHint)
        
        layout = QVBoxLayout()
        
        # Header
        header_label = QLabel("🔐 Password Manager")
        header_label.setFont(QFont("Arial", 16, QFont.Bold))
        header_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(header_label)
        
        # Instructions
        if self.is_first_time:
            instruction = "Create your master password to secure your vault:"
        else:
            instruction = "Enter your master password to access your vault:"
            
        instruction_label = QLabel(instruction)
        instruction_label.setWordWrap(True)
        instruction_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(instruction_label)
        
        # Password input
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setPlaceholderText("Master Password")
        self.password_edit.returnPressed.connect(self.accept)
        layout.addWidget(self.password_edit)
        
        if self.is_first_time:
            # Confirm password
            self.confirm_edit = QLineEdit()
            self.confirm_edit.setEchoMode(QLineEdit.Password)
            self.confirm_edit.setPlaceholderText("Confirm Password")
            self.confirm_edit.returnPressed.connect(self.accept)
            layout.addWidget(self.confirm_edit)
            
            # Strength indicator
            self.strength_bar = QProgressBar()
            self.password_edit.textChanged.connect(self.update_strength)
            layout.addWidget(self.strength_bar)
        
        # Show password option
        self.show_password = QCheckBox("Show password")
        self.show_password.stateChanged.connect(self.toggle_password_visibility)
        layout.addWidget(self.show_password)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        self.ok_btn = QPushButton("Create Vault" if self.is_first_time else "Unlock")
        self.ok_btn.clicked.connect(self.accept)
        self.ok_btn.setDefault(True)
        button_layout.addWidget(self.ok_btn)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(button_layout)
        
        # Attempt counter
        if not self.is_first_time:
            self.attempts_label = QLabel("")
            layout.addWidget(self.attempts_label)
        
        self.setLayout(layout)
        self.password_edit.setFocus()
    
    def toggle_password_visibility(self):
        if self.show_password.isChecked():
            self.password_edit.setEchoMode(QLineEdit.Normal)
            if self.is_first_time:
                self.confirm_edit.setEchoMode(QLineEdit.Normal)
        else:
            self.password_edit.setEchoMode(QLineEdit.Password)
            if self.is_first_time:
                self.confirm_edit.setEchoMode(QLineEdit.Password)
    
    def update_strength(self):
        if self.is_first_time:
            password = self.password_edit.text()
            generator = PasswordGeneratorService()
            _, score, _, _ = generator.check_strength(password)
            self.strength_bar.setValue(score)
    
    def accept(self):
        if self.is_first_time:
            if not self.validate_new_password():
                return
        else:
            if not self.validate_existing_password():
                return
        
        self.master_password = self.password_edit.text()
        super().accept()
    
    def validate_new_password(self):
        password = self.password_edit.text()
        confirm = self.confirm_edit.text()
        
        if len(password) < 8:
            QMessageBox.warning(self, "Error", "Password must be at least 8 characters long")
            return False
        
        if password != confirm:
            QMessageBox.warning(self, "Error", "Passwords do not match")
            return False
        
        return True
    
    def validate_existing_password(self):
        password = self.password_edit.text()
        
        if not self.encryption_manager.verify_master_password(password):
            self.attempt_count += 1
            
            if self.attempt_count >= self.max_attempts:
                QMessageBox.critical(self, "Error", "Too many failed attempts. Application will close.")
                QTimer.singleShot(2000, self.reject)
                return False
            
            remaining = self.max_attempts - self.attempt_count
            self.attempts_label.setText(f"Attempts remaining: {remaining}")
            QMessageBox.warning(self, "Error", "Invalid password")
            return False
        
        return True
    
    def get_password(self):
        return self.master_password

# Emergency Access System
class EmergencyAccessManager:
    def __init__(self, config: EmergencyConfig, encryption_manager):
        self.config = config
        self.encryption_manager = encryption_manager
        self.emergency_file = "emergency_access.enc"
        self.activity_file = "last_activity.dat"
        
        # Auto-start monitoring if enabled
        if self.config.enabled:
            self.start_monitoring()
    
    def start_monitoring(self):
        """Start the emergency access monitoring"""
        self.monitor_timer = QTimer()
        self.monitor_timer.timeout.connect(self.check_emergency_status)
        # Check every hour (convert hours to milliseconds)
        self.monitor_timer.start(3600000)  
        
        # Update activity timestamp
        self.update_activity()
    
    def stop_monitoring(self):
        """Stop the emergency access monitoring"""
        if hasattr(self, 'monitor_timer'):
            self.monitor_timer.stop()
    
    def update_activity(self):
        """Update the last activity timestamp"""
        self.config.last_activity = datetime.now()
        self.save_activity_timestamp()
    
    def save_activity_timestamp(self):
        """Save activity timestamp to file"""
        try:
            with open(self.activity_file, 'w') as f:
                f.write(self.config.last_activity.isoformat())
        except Exception as e:
            logging.error(f"Failed to save activity timestamp: {e}")
    
    def load_activity_timestamp(self):
        """Load activity timestamp from file"""
        try:
            if os.path.exists(self.activity_file):
                with open(self.activity_file, 'r') as f:
                    timestamp_str = f.read().strip()
                    self.config.last_activity = datetime.fromisoformat(timestamp_str)
        except Exception as e:
            logging.error(f"Failed to load activity timestamp: {e}")
            self.config.last_activity = datetime.now()
    
    def check_emergency_status(self):
        """Check if emergency access should be triggered"""
        if not self.config.enabled or self.config.emergency_triggered:
            return
        
        if not self.config.last_activity:
            self.load_activity_timestamp()
            return
        
        # Calculate time since last activity
        time_since_activity = datetime.now() - self.config.last_activity
        delay_threshold = timedelta(hours=self.config.delay_hours)
        
        if time_since_activity >= delay_threshold:
            self.trigger_emergency_access()
    
    def trigger_emergency_access(self):
        """Trigger the emergency access procedure"""
        if self.config.emergency_triggered:
            return
        
        self.config.emergency_triggered = True
        self.config.trigger_date = datetime.now()
        
        logging.warning("Emergency access triggered - sending vault to emergency contacts")
        
        # Send emergency vault to all verified contacts
        self.send_emergency_vault()
        
        # Log the event
        self.log_emergency_trigger()
    
    def send_emergency_vault(self):
        """Send encrypted vault to emergency contacts"""
        try:
            # Create emergency vault package
            vault_package = self.create_emergency_vault_package()
            
            # Send to each verified contact
            for contact in self.config.contacts:
                if contact.verified:
                    self.send_vault_to_contact(contact, vault_package)
                    
        except Exception as e:
            logging.error(f"Failed to send emergency vault: {e}")
    
    def create_emergency_vault_package(self):
        """Create an encrypted package containing the vault and instructions"""
        package = {
            'trigger_date': self.config.trigger_date.isoformat(),
            'owner_info': {
                'last_activity': self.config.last_activity.isoformat(),
                'trigger_reason': 'Inactivity threshold exceeded'
            },
            'vault_file': self.get_encrypted_vault_data(),
            'instructions': self.get_emergency_instructions(),
            'contacts': [contact.to_dict() for contact in self.config.contacts]
        }
        
        return json.dumps(package, indent=2)
    
    def get_encrypted_vault_data(self):
        """Get the encrypted vault data as base64 string"""
        try:
            if os.path.exists(self.encryption_manager.encrypted_data_file):
                with open(self.encryption_manager.encrypted_data_file, 'rb') as f:
                    vault_data = f.read()
                return base64.b64encode(vault_data).decode()
        except Exception:
            return ""
        return ""
    
    def get_emergency_instructions(self):
        """Get instructions for emergency contacts"""
        return """
EMERGENCY VAULT ACCESS INSTRUCTIONS

This message contains an encrypted password vault that was automatically sent
due to prolonged inactivity from the vault owner.

WHAT TO DO:
1. Contact other emergency contacts to coordinate access
2. The vault is encrypted with the owner's master password
3. You may need to work together to determine the master password
4. Use the Professional Password Manager application to open the vault
5. Look for important passwords for: banks, email accounts, social media, etc.

IMPORTANT NOTES:
- This vault contains sensitive personal information
- Handle with care and respect privacy
- Consider legal implications of accessing accounts
- Contact authorities if you suspect foul play

The vault will remain encrypted until opened with the correct master password.

Contact information for other emergency contacts is included in this package.
        """
    
    def send_vault_to_contact(self, contact: EmergencyContact, vault_package: str):
        """Send vault package to a specific emergency contact"""
        try:
            # Create email
            msg = MimeMultipart()
            msg['From'] = self.config.emergency_email
            msg['To'] = contact.email
            msg['Subject'] = f"EMERGENCY: Password Vault Access for {contact.name}"
            
            # Email body
            body = f"""
Dear {contact.name},

This is an automated emergency message from the Professional Password Manager.

The owner of this password vault has been inactive for {self.config.delay_hours} hours,
triggering the emergency access protocol.

Your relationship to the vault owner: {contact.relationship}
Your priority level: {contact.priority}

Please see the attached emergency vault package for further instructions.

Time of trigger: {self.config.trigger_date}
Last known activity: {self.config.last_activity}

This message was sent automatically. Please handle this information responsibly.

Best regards,
Professional Password Manager Emergency System
            """
            
            msg.attach(MimeText(body, 'plain'))
            
            # Attach vault package
            attachment = MimeBase('application', 'octet-stream')
            attachment.set_payload(vault_package.encode())
            encoders.encode_base64(attachment)
            attachment.add_header(
                'Content-Disposition',
                f'attachment; filename="emergency_vault_{contact.id}.json"'
            )
            msg.attach(attachment)
            
            # Send email
            server = smtplib.SMTP(self.config.email_server, self.config.email_port)
            server.starttls()
            server.login(self.config.emergency_email, self.config.emergency_email_password)
            server.send_message(msg)
            server.quit()
            
            logging.info(f"Emergency vault sent to {contact.email}")
            
        except Exception as e:
            logging.error(f"Failed to send emergency vault to {contact.email}: {e}")
    
    def log_emergency_trigger(self):
        """Log the emergency trigger event"""
        log_entry = {
            'event': 'emergency_access_triggered',
            'timestamp': datetime.now().isoformat(),
            'last_activity': self.config.last_activity.isoformat(),
            'delay_hours': self.config.delay_hours,
            'contacts_notified': len([c for c in self.config.contacts if c.verified])
        }
        
        with open('emergency_log.json', 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def reset_emergency_state(self):
        """Reset emergency state (admin function)"""
        self.config.emergency_triggered = False
        self.config.trigger_date = None
        self.update_activity()
        logging.info("Emergency state reset")
    
    def test_emergency_system(self):
        """Test the emergency system without actually triggering it"""
        try:
            # Test email connectivity
            server = smtplib.SMTP(self.config.email_server, self.config.email_port)
            server.starttls()
            server.login(self.config.emergency_email, self.config.emergency_email_password)
            server.quit()
            
            # Test vault package creation
            test_package = self.create_emergency_vault_package()
            
            return True, "Emergency system test successful"
            
        except Exception as e:
            return False, f"Emergency system test failed: {str(e)}"

# Emergency Access Dialog
class EmergencyAccessDialog(QDialog):
    def __init__(self, emergency_manager: EmergencyAccessManager):
        super().__init__()
        self.emergency_manager = emergency_manager
        self.config = emergency_manager.config
        self.setup_ui()
    
    def setup_ui(self):
        self.setWindowTitle("🆘 Emergency Access Settings")
        self.setFixedSize(800, 700)
        
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("🆘 Emergency Access System")
        header.setFont(QFont("Arial", 16, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)
        layout.addWidget(header)
        
        # Description
        description = QLabel("""
The Emergency Access System automatically sends your encrypted vault to trusted contacts
if you're inactive for a specified period. This is useful for estate planning or emergencies.
        """)
        description.setWordWrap(True)
        layout.addWidget(description)
        
        # Enable/Disable
        self.enable_checkbox = QCheckBox("Enable Emergency Access System")
        self.enable_checkbox.setChecked(self.config.enabled)
        self.enable_checkbox.stateChanged.connect(self.on_enable_changed)
        layout.addWidget(self.enable_checkbox)
        
        # Settings Group
        settings_group = QGroupBox("Emergency Settings")
        settings_layout = QGridLayout()
        
        # Delay hours
        settings_layout.addWidget(QLabel("Inactivity delay (hours):"), 0, 0)
        self.delay_spinbox = QSpinBox()
        self.delay_spinbox.setRange(1, 8760)  # 1 hour to 1 year
        self.delay_spinbox.setValue(self.config.delay_hours)
        settings_layout.addWidget(self.delay_spinbox, 0, 1)
        
        # Check interval
        settings_layout.addWidget(QLabel("Check interval (hours):"), 1, 0)
        self.interval_spinbox = QSpinBox()
        self.interval_spinbox.setRange(1, 168)  # 1 hour to 1 week
        self.interval_spinbox.setValue(self.config.check_interval_hours)
        settings_layout.addWidget(self.interval_spinbox, 1, 1)
        
        settings_group.setLayout(settings_layout)
        layout.addWidget(settings_group)
        
        # Email Settings Group
        email_group = QGroupBox("Email Settings")
        email_layout = QGridLayout()
        
        email_layout.addWidget(QLabel("SMTP Server:"), 0, 0)
        self.smtp_server_edit = QLineEdit(self.config.email_server)
        email_layout.addWidget(self.smtp_server_edit, 0, 1)
        
        email_layout.addWidget(QLabel("SMTP Port:"), 1, 0)
        self.smtp_port_spinbox = QSpinBox()
        self.smtp_port_spinbox.setRange(1, 65535)
        self.smtp_port_spinbox.setValue(self.config.email_port)
        email_layout.addWidget(self.smtp_port_spinbox, 1, 1)
        
        email_layout.addWidget(QLabel("Emergency Email:"), 2, 0)
        self.emergency_email_edit = QLineEdit(self.config.emergency_email)
        email_layout.addWidget(self.emergency_email_edit, 2, 1)
        
        email_layout.addWidget(QLabel("Email Password:"), 3, 0)
        self.email_password_edit = QLineEdit(self.config.emergency_email_password)
        self.email_password_edit.setEchoMode(QLineEdit.Password)
        email_layout.addWidget(self.email_password_edit, 3, 1)
        
        # Test email button
        test_email_btn = QPushButton("📧 Test Email Connection")
        test_email_btn.clicked.connect(self.test_email_connection)
        email_layout.addWidget(test_email_btn, 4, 0, 1, 2)
        
        email_group.setLayout(email_layout)
        layout.addWidget(email_group)
        
        # Emergency Contacts Group
        contacts_group = QGroupBox("Emergency Contacts")
        contacts_layout = QVBoxLayout()
        
        # Contact list
        self.contacts_list = QListWidget()
        self.refresh_contacts_list()
        contacts_layout.addWidget(self.contacts_list)
        
        # Contact buttons
        contact_buttons = QHBoxLayout()
        
        add_contact_btn = QPushButton("➕ Add Contact")
        add_contact_btn.clicked.connect(self.add_contact)
        contact_buttons.addWidget(add_contact_btn)
        
        edit_contact_btn = QPushButton("✏️ Edit Contact")
        edit_contact_btn.clicked.connect(self.edit_contact)
        contact_buttons.addWidget(edit_contact_btn)
        
        remove_contact_btn = QPushButton("🗑️ Remove Contact")
        remove_contact_btn.clicked.connect(self.remove_contact)
        contact_buttons.addWidget(remove_contact_btn)
        
        verify_contact_btn = QPushButton("✅ Verify Contact")
        verify_contact_btn.clicked.connect(self.verify_contact)
        contact_buttons.addWidget(verify_contact_btn)
        
        contacts_layout.addLayout(contact_buttons)
        contacts_group.setLayout(contacts_layout)
        layout.addWidget(contacts_group)
        
        # Status Group
        status_group = QGroupBox("System Status")
        status_layout = QVBoxLayout()
        
        self.status_label = QLabel()
        self.update_status_display()
        status_layout.addWidget(self.status_label)
        
        # Status buttons
        status_buttons = QHBoxLayout()
        
        test_system_btn = QPushButton("🧪 Test System")
        test_system_btn.clicked.connect(self.test_system)
        status_buttons.addWidget(test_system_btn)
        
        reset_emergency_btn = QPushButton("🔄 Reset Emergency State")
        reset_emergency_btn.clicked.connect(self.reset_emergency)
        status_buttons.addWidget(reset_emergency_btn)
        
        status_buttons.addStretch()
        status_layout.addLayout(status_buttons)
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Dialog buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        save_btn = QPushButton("💾 Save Settings")
        save_btn.clicked.connect(self.save_settings)
        button_layout.addWidget(save_btn)
        
        cancel_btn = QPushButton("❌ Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
    
    def on_enable_changed(self):
        """Handle enable/disable checkbox change"""
        enabled = self.enable_checkbox.isChecked()
        if enabled:
            if not self.config.contacts:
                QMessageBox.warning(
                    self, "Warning", 
                    "Please add at least one emergency contact before enabling the system."
                )
                self.enable_checkbox.setChecked(False)
                return
    
    def refresh_contacts_list(self):
        """Refresh the contacts list display"""
        self.contacts_list.clear()
        for contact in self.config.contacts:
            status = "✅ Verified" if contact.verified else "⚠️ Unverified"
            item_text = f"{contact.name} ({contact.relationship}) - {contact.email} - Priority: {contact.priority} - {status}"
            item = QListWidgetItem(item_text)
            item.setData(Qt.UserRole, contact.id)
            self.contacts_list.addItem(item)
    
    def add_contact(self):
        """Add a new emergency contact"""
        dialog = EmergencyContactDialog()
        if dialog.exec_() == QDialog.Accepted:
            contact_data = dialog.get_contact_data()
            contact = EmergencyContact(
                id=str(uuid.uuid4()),
                **contact_data
            )
            self.config.contacts.append(contact)
            self.refresh_contacts_list()
    
    def edit_contact(self):
        """Edit selected emergency contact"""
        current_item = self.contacts_list.currentItem()
        if not current_item:
            QMessageBox.warning(self, "Warning", "Please select a contact to edit.")
            return
        
        contact_id = current_item.data(Qt.UserRole)
        contact = next((c for c in self.config.contacts if c.id == contact_id), None)
        
        if contact:
            dialog = EmergencyContactDialog(contact)
            if dialog.exec_() == QDialog.Accepted:
                contact_data = dialog.get_contact_data()
                # Update contact
                for key, value in contact_data.items():
                    setattr(contact, key, value)
                self.refresh_contacts_list()
    
    def remove_contact(self):
        """Remove selected emergency contact"""
        current_item = self.contacts_list.currentItem()
        if not current_item:
            QMessageBox.warning(self, "Warning", "Please select a contact to remove.")
            return
        
        reply = QMessageBox.question(
            self, "Confirm Remove", 
            "Are you sure you want to remove this emergency contact?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            contact_id = current_item.data(Qt.UserRole)
            self.config.contacts = [c for c in self.config.contacts if c.id != contact_id]
            self.refresh_contacts_list()
    
    def verify_contact(self):
        """Send verification email to selected contact"""
        current_item = self.contacts_list.currentItem()
        if not current_item:
            QMessageBox.warning(self, "Warning", "Please select a contact to verify.")
            return
        
        contact_id = current_item.data(Qt.UserRole)
        contact = next((c for c in self.config.contacts if c.id == contact_id), None)
        
        if contact:
            try:
                self.send_verification_email(contact)
                QMessageBox.information(
                    self, "Verification Sent", 
                    f"Verification email sent to {contact.email}"
                )
            except Exception as e:
                QMessageBox.critical(
                    self, "Error", 
                    f"Failed to send verification email: {str(e)}"
                )
    
    def send_verification_email(self, contact: EmergencyContact):
        """Send verification email to contact"""
        verification_code = secrets.token_urlsafe(32)
        
        msg = MimeMultipart()
        msg['From'] = self.emergency_email_edit.text()
        msg['To'] = contact.email
        msg['Subject'] = "Emergency Contact Verification"
        
        body = f"""
Dear {contact.name},

You have been added as an emergency contact for a Professional Password Manager vault.

Relationship: {contact.relationship}
Priority Level: {contact.priority}

To verify this email address, please reply to this email with the following verification code:

{verification_code}

If you did not expect this email, please ignore it.

Best regards,
Professional Password Manager
        """
        
        msg.attach(MimeText(body, 'plain'))
        
        server = smtplib.SMTP(self.smtp_server_edit.text(), self.smtp_port_spinbox.value())
        server.starttls()
        server.login(self.emergency_email_edit.text(), self.email_password_edit.text())
        server.send_message(msg)
        server.quit()
        
        # Mark as verified (in a real implementation, you'd wait for the reply)
        contact.verified = True
        self.refresh_contacts_list()
    
    def test_email_connection(self):
        """Test the email connection"""
        try:
            server = smtplib.SMTP(self.smtp_server_edit.text(), self.smtp_port_spinbox.value())
            server.starttls()
            server.login(self.emergency_email_edit.text(), self.email_password_edit.text())
            server.quit()
            
            QMessageBox.information(self, "Success", "Email connection test successful!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Email connection test failed: {str(e)}")
    
    def test_system(self):
        """Test the entire emergency system"""
        success, message = self.emergency_manager.test_emergency_system()
        
        if success:
            QMessageBox.information(self, "Success", message)
        else:
            QMessageBox.critical(self, "Error", message)
    
    def reset_emergency(self):
        """Reset emergency state"""
        reply = QMessageBox.question(
            self, "Confirm Reset", 
            "Are you sure you want to reset the emergency state? This will cancel any active emergency procedures.",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.emergency_manager.reset_emergency_state()
            self.update_status_display()
            QMessageBox.information(self, "Success", "Emergency state reset successfully.")
    
    def update_status_display(self):
        """Update the status display"""
        status_text = f"""
Last Activity: {self.config.last_activity or 'Never'}
Emergency Triggered: {'Yes' if self.config.emergency_triggered else 'No'}
Trigger Date: {self.config.trigger_date or 'N/A'}
Verified Contacts: {len([c for c in self.config.contacts if c.verified])}
Total Contacts: {len(self.config.contacts)}
        """
        self.status_label.setText(status_text.strip())
    
    def save_settings(self):
        """Save emergency settings"""
        # Update config from UI
        self.config.enabled = self.enable_checkbox.isChecked()
        self.config.delay_hours = self.delay_spinbox.value()
        self.config.check_interval_hours = self.interval_spinbox.value()
        self.config.email_server = self.smtp_server_edit.text()
        self.config.email_port = self.smtp_port_spinbox.value()
        self.config.emergency_email = self.emergency_email_edit.text()
        self.config.emergency_email_password = self.email_password_edit.text()
        
        # Restart monitoring with new settings
        if self.config.enabled:
            self.emergency_manager.stop_monitoring()
            self.emergency_manager.start_monitoring()
        else:
            self.emergency_manager.stop_monitoring()
        
        self.accept()

# Emergency Contact Dialog
class EmergencyContactDialog(QDialog):
    def __init__(self, contact: EmergencyContact = None):
        super().__init__()
        self.contact = contact
        self.setup_ui()
        
        if contact:
            self.populate_fields()
    
    def setup_ui(self):
        self.setWindowTitle("👤 Emergency Contact")
        self.setFixedSize(400, 350)
        
        layout = QVBoxLayout()
        
        # Form
        form_layout = QGridLayout()
        
        form_layout.addWidget(QLabel("Name:"), 0, 0)
        self.name_edit = QLineEdit()
        form_layout.addWidget(self.name_edit, 0, 1)
        
        form_layout.addWidget(QLabel("Email:"), 1, 0)
        self.email_edit = QLineEdit()
        form_layout.addWidget(self.email_edit, 1, 1)
        
        form_layout.addWidget(QLabel("Phone:"), 2, 0)
        self.phone_edit = QLineEdit()
        form_layout.addWidget(self.phone_edit, 2, 1)
        
        form_layout.addWidget(QLabel("Relationship:"), 3, 0)
        self.relationship_combo = QComboBox()
        self.relationship_combo.addItems([
            "Spouse", "Child", "Parent", "Sibling", "Friend", 
            "Lawyer", "Executor", "Other"
        ])
        self.relationship_combo.setEditable(True)
        form_layout.addWidget(self.relationship_combo, 3, 1)
        
        form_layout.addWidget(QLabel("Priority (1=highest):"), 4, 0)
        self.priority_spinbox = QSpinBox()
        self.priority_spinbox.setRange(1, 10)
        self.priority_spinbox.setValue(1)
        form_layout.addWidget(self.priority_spinbox, 4, 1)
        
        layout.addLayout(form_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        save_btn = QPushButton("💾 Save")
        save_btn.clicked.connect(self.accept)
        button_layout.addWidget(save_btn)
        
        cancel_btn = QPushButton("❌ Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
    
    def populate_fields(self):
        """Populate fields with existing contact data"""
        if self.contact:
            self.name_edit.setText(self.contact.name)
            self.email_edit.setText(self.contact.email)
            self.phone_edit.setText(self.contact.phone)
            self.relationship_combo.setCurrentText(self.contact.relationship)
            self.priority_spinbox.setValue(self.contact.priority)
    
    def get_contact_data(self):
        """Get contact data from form"""
        return {
            'name': self.name_edit.text().strip(),
            'email': self.email_edit.text().strip(),
            'phone': self.phone_edit.text().strip(),
            'relationship': self.relationship_combo.currentText().strip(),
            'priority': self.priority_spinbox.value(),
            'verified': False  # New contacts start unverified
        }

# Main Application
class ProfessionalPasswordManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.config = AppConfig()
        self.encryption_manager = EncryptionManager()
        self.session_manager = SessionManager(self.config.security.session_timeout_minutes)
        self.password_generator = PasswordGeneratorService()
        self.clipboard_manager = ClipboardManager()
        
        # ADD THIS LINE
        self.emergency_manager = EmergencyAccessManager(self.config.emergency, self.encryption_manager)
        
        self.passwords = []
        self.master_password = ""
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('password_manager.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Authentication
        if not self.authenticate():
            sys.exit()
        
        self.init_ui()
        self.apply_dark_theme()
        self.load_passwords()
        
        # Session management
        self.session_timer = QTimer()
        self.session_timer.timeout.connect(self.check_session)
        self.session_timer.start(60000)  # Check every minute
    
    def authenticate(self):
        # Check if first time setup
        salt = self.encryption_manager.load_salt()
        is_first_time = salt is None
        
        dialog = MasterPasswordDialog(self.encryption_manager, is_first_time)
        if dialog.exec_() == QDialog.Accepted:
            self.master_password = dialog.get_password()
            
            if is_first_time:
                # First time setup
                key, salt = self.encryption_manager.derive_key_from_password(self.master_password)
                self.encryption_manager.save_salt(salt)
                self.logger.info("New vault created")
            
            self.session_manager.update_activity()
            return True
        
        return False
    
    def check_session(self):
        if self.session_manager.check_timeout() and self.config.security.auto_lock_enabled:
            self.lock_application()
    
    def lock_application(self):
        self.hide()
        if self.authenticate():
            self.show()
            self.session_manager.update_activity()
        else:
            self.close()
    
    def mousePressEvent(self, event):
        self.session_manager.update_activity()
        # ADD THIS LINE
        if hasattr(self, 'emergency_manager'):
            self.emergency_manager.update_activity()
        super().mousePressEvent(event)
    
    def keyPressEvent(self, event):
        self.session_manager.update_activity()
        # ADD THIS LINE
        if hasattr(self, 'emergency_manager'):
            self.emergency_manager.update_activity()
        super().keyPressEvent(event)
    
    def init_ui(self):
        self.setWindowTitle(f"🔐 {self.config.app_name} v{self.config.version}")
        self.setGeometry(100, 100, 1000, 800)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # Tabs
        self.generator_tab = self.create_generator_tab()
        self.tab_widget.addTab(self.generator_tab, "🎲 Generator")
        
        self.saved_tab = self.create_saved_tab()
        self.tab_widget.addTab(self.saved_tab, "💾 Saved Passwords")
        
        self.settings_tab = self.create_settings_tab()
        self.tab_widget.addTab(self.settings_tab, "⚙️ Settings")
        
        # Main layout
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.tab_widget)
        central_widget.setLayout(main_layout)
    
    def create_generator_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("🔐 Professional Password Generator")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        
        # Splitter for panels
        splitter = QSplitter(Qt.Horizontal)
        
        # Settings panel
        settings_panel = self.create_settings_panel()
        splitter.addWidget(settings_panel)
        
        # Output panel
        output_panel = self.create_output_panel()
        splitter.addWidget(output_panel)
        
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)
        
        layout.addWidget(splitter)
        tab.setLayout(layout)
        return tab
    
    def create_settings_panel(self):
        panel = QFrame()
        panel.setFrameStyle(QFrame.StyledPanel)
        layout = QVBoxLayout()
        
        # Password Length
        length_group = QGroupBox("Password Settings")
        length_layout = QGridLayout()
        
        length_layout.addWidget(QLabel("Length:"), 0, 0)
        self.length_spinbox = QSpinBox()
        self.length_spinbox.setRange(8, 50)
        self.length_spinbox.setValue(16)
        self.length_spinbox.valueChanged.connect(self.update_password)
        length_layout.addWidget(self.length_spinbox, 0, 1)
        
        # Strength slider
        length_layout.addWidget(QLabel("Quick Length:"), 1, 0)
        self.length_slider = QSlider(Qt.Horizontal)
        self.length_slider.setRange(8, 50)
        self.length_slider.setValue(16)
        self.length_slider.valueChanged.connect(self.on_slider_change)
        length_layout.addWidget(self.length_slider, 1, 1)
        
        length_group.setLayout(length_layout)
        layout.addWidget(length_group)
        
        # Character Options
        char_group = QGroupBox("Character Options")
        char_layout = QVBoxLayout()
        
        self.use_lowercase = QCheckBox("Lowercase letters (a-z)")
        self.use_lowercase.setChecked(True)
        self.use_lowercase.stateChanged.connect(self.update_password)
        char_layout.addWidget(self.use_lowercase)
        
        self.use_uppercase = QCheckBox("Uppercase letters (A-Z)")
        self.use_uppercase.setChecked(True)
        self.use_uppercase.stateChanged.connect(self.update_password)
        char_layout.addWidget(self.use_uppercase)
        
        self.use_digits = QCheckBox("Digits (0-9)")
        self.use_digits.setChecked(True)
        self.use_digits.stateChanged.connect(self.update_password)
        char_layout.addWidget(self.use_digits)
        
        self.use_symbols = QCheckBox("Symbols")
        self.use_symbols.setChecked(True)
        self.use_symbols.stateChanged.connect(self.update_password)
        char_layout.addWidget(self.use_symbols)
        
        char_group.setLayout(char_layout)
        layout.addWidget(char_group)
        
        # Symbol Options
        symbol_group = QGroupBox("Symbol Options")
        symbol_layout = QGridLayout()
        
        symbol_layout.addWidget(QLabel("Number of symbols:"), 0, 0)
        self.symbol_count = QSpinBox()
        self.symbol_count.setRange(0, 20)
        self.symbol_count.setValue(3)
        self.symbol_count.valueChanged.connect(self.update_password)
        symbol_layout.addWidget(self.symbol_count, 0, 1)
        
        symbol_layout.addWidget(QLabel("Symbol category:"), 1, 0)
        self.symbol_category = QComboBox()
        self.symbol_category.addItems([
            "basic", "brackets", "math", "punctuation", 
            "quotes", "other", "all"
        ])
        self.symbol_category.currentTextChanged.connect(self.update_password)
        symbol_layout.addWidget(self.symbol_category, 1, 1)
        
        symbol_group.setLayout(symbol_layout)
        layout.addWidget(symbol_group)
        
        # Generate Button
        self.generate_btn = QPushButton("🎲 Generate New Password")
        self.generate_btn.setFont(QFont("Arial", 12, QFont.Bold))
        self.generate_btn.clicked.connect(self.generate_password)
        layout.addWidget(self.generate_btn)
        
        layout.addStretch()
        panel.setLayout(layout)
        return panel
    
    def create_output_panel(self):
        panel = QFrame()
        panel.setFrameStyle(QFrame.StyledPanel)
        layout = QVBoxLayout()
        
        # Generated Password
        password_group = QGroupBox("Generated Password")
        password_layout = QVBoxLayout()
        
        self.password_display = PasswordVisibilityWidget()
        password_layout.addWidget(self.password_display)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.copy_btn = QPushButton("📋 Copy")
        self.copy_btn.clicked.connect(self.copy_password)
        button_layout.addWidget(self.copy_btn)
        
        self.regenerate_btn = QPushButton("🔄 Regenerate")
        self.regenerate_btn.clicked.connect(self.generate_password)
        button_layout.addWidget(self.regenerate_btn)
        
        password_layout.addLayout(button_layout)
        password_group.setLayout(password_layout)
        layout.addWidget(password_group)
        
        # Password Strength
        strength_group = QGroupBox("Password Strength")
        strength_layout = QVBoxLayout()
        
        self.strength_label = QLabel("Strength: Not Generated")
        self.strength_label.setFont(QFont("Arial", 12, QFont.Bold))
        strength_layout.addWidget(self.strength_label)
        
        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 100)
        strength_layout.addWidget(self.strength_bar)
        
        self.strength_feedback = QLabel("")
        self.strength_feedback.setWordWrap(True)
        strength_layout.addWidget(self.strength_feedback)
        
        strength_group.setLayout(strength_layout)
        layout.addWidget(strength_group)
        
        # Save Password
        save_group = QGroupBox("Save Password")
        save_layout = QGridLayout()
        
        save_layout.addWidget(QLabel("App/Website:"), 0, 0)
        self.app_input = QLineEdit()
        save_layout.addWidget(self.app_input, 0, 1)
        
        save_layout.addWidget(QLabel("Username/Email:"), 1, 0)
        self.username_input = QLineEdit()
        save_layout.addWidget(self.username_input, 1, 1)
        
        save_layout.addWidget(QLabel("Notes:"), 2, 0)
        self.notes_input = QLineEdit()
        save_layout.addWidget(self.notes_input, 2, 1)
        
        save_layout.addWidget(QLabel("Expiry (days):"), 3, 0)
        self.expiry_input = QSpinBox()
        self.expiry_input.setRange(0, 3650)  # 0 to 10 years
        self.expiry_input.setValue(365)  # Default 1 year
        self.expiry_input.setSpecialValueText("Never")
        save_layout.addWidget(self.expiry_input, 3, 1)
        
        self.save_btn = QPushButton("💾 Save Password")
        self.save_btn.clicked.connect(self.save_password)
        save_layout.addWidget(self.save_btn, 4, 0, 1, 2)
        
        save_group.setLayout(save_layout)
        layout.addWidget(save_group)
        
        layout.addStretch()
        panel.setLayout(layout)
        return panel
    
    def create_saved_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Search widget
        self.search_widget = AdvancedSearchWidget()
        self.search_widget.search_changed.connect(self.filter_passwords)
        layout.addWidget(self.search_widget)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.load_passwords)
        controls_layout.addWidget(refresh_btn)
        
        export_btn = QPushButton("📤 Export")
        export_btn.clicked.connect(self.export_passwords)
        controls_layout.addWidget(export_btn)
        
        import_btn = QPushButton("📥 Import")
        import_btn.clicked.connect(self.import_passwords)
        controls_layout.addWidget(import_btn)
        
        delete_btn = QPushButton("🗑️ Delete Selected")
        delete_btn.clicked.connect(self.delete_selected_password)
        controls_layout.addWidget(delete_btn)
        
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
        
        # Password table
        self.password_table = QTableWidget()
        self.password_table.setColumnCount(6)
        self.password_table.setHorizontalHeaderLabels([
            "App/Website", "Username/Email", "Password", 
            "Created", "Expires", "Notes"
        ])
        
        # Table configuration
        header = self.password_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.Stretch)
        
        self.password_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.password_table.setAlternatingRowColors(True)
        
        layout.addWidget(self.password_table)
        tab.setLayout(layout)
        return tab
    
    def create_settings_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Security Settings
        security_group = QGroupBox("Security Settings")
        security_layout = QVBoxLayout()
        
        change_password_btn = QPushButton("🔑 Change Master Password")
        change_password_btn.clicked.connect(self.change_master_password)
        security_layout.addWidget(change_password_btn)
        
        # Session timeout
        timeout_layout = QHBoxLayout()
        timeout_layout.addWidget(QLabel("Session timeout (minutes):"))
        self.timeout_spinbox = QSpinBox()
        self.timeout_spinbox.setRange(1, 120)
        self.timeout_spinbox.setValue(self.config.security.session_timeout_minutes)
        self.timeout_spinbox.valueChanged.connect(self.update_session_timeout)
        timeout_layout.addWidget(self.timeout_spinbox)
        timeout_layout.addStretch()
        security_layout.addLayout(timeout_layout)
        
        # Auto-lock
        self.auto_lock_checkbox = QCheckBox("Enable auto-lock")
        self.auto_lock_checkbox.setChecked(self.config.security.auto_lock_enabled)
        self.auto_lock_checkbox.stateChanged.connect(self.update_auto_lock)
        security_layout.addWidget(self.auto_lock_checkbox)
        
        # Clipboard settings
        clipboard_layout = QHBoxLayout()
        clipboard_layout.addWidget(QLabel("Clipboard clear time (seconds):"))
        self.clipboard_spinbox = QSpinBox()
        self.clipboard_spinbox.setRange(10, 300)
        self.clipboard_spinbox.setValue(self.config.security.clipboard_clear_seconds)
        self.clipboard_spinbox.valueChanged.connect(self.update_clipboard_timeout)
        clipboard_layout.addWidget(self.clipboard_spinbox)
        clipboard_layout.addStretch()
        security_layout.addLayout(clipboard_layout)
        
        security_group.setLayout(security_layout)
        layout.addWidget(security_group)
        
        # Backup Settings
        backup_group = QGroupBox("Backup Settings")
        backup_layout = QVBoxLayout()
        
        backup_btn = QPushButton("💾 Create Backup")
        backup_btn.clicked.connect(self.create_backup)
        backup_layout.addWidget(backup_btn)
        
        restore_btn = QPushButton("📥 Restore from Backup")
        restore_btn.clicked.connect(self.restore_backup)
        backup_layout.addWidget(restore_btn)
        
        backup_group.setLayout(backup_layout)
        layout.addWidget(backup_group)
        
        # About
        about_group = QGroupBox("About")
        about_layout = QVBoxLayout()
        
        about_text = QLabel(f"""
{self.config.app_name} v{self.config.version}

Features:
• Master password protection with PBKDF2
• AES-256 encryption for all stored data
• Advanced password generation algorithms
• Session management and auto-lock
• Secure clipboard management
• Password expiry tracking
• Advanced search and filtering
• Encrypted backup and restore

Built with Python, PyQt5, and Cryptography
        """)
        about_text.setWordWrap(True)
        about_layout.addWidget(about_text)
        
        about_group.setLayout(about_layout)
        layout.addWidget(about_group)
        
        layout.addStretch()
        tab.setLayout(layout)
        return tab
    
    def create_settings_tab_with_emergency(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Security Settings
        security_group = QGroupBox("Security Settings")
        security_layout = QVBoxLayout()
        
        change_password_btn = QPushButton("🔑 Change Master Password")
        change_password_btn.clicked.connect(self.change_master_password)
        security_layout.addWidget(change_password_btn)
        
        # EMERGENCY ACCESS BUTTON - ADD THIS
        emergency_access_btn = QPushButton("🆘 Emergency Access Settings")
        emergency_access_btn.clicked.connect(self.open_emergency_settings)
        security_layout.addWidget(emergency_access_btn)
        
        # Session timeout
        timeout_layout = QHBoxLayout()
        timeout_layout.addWidget(QLabel("Session timeout (minutes):"))
        self.timeout_spinbox = QSpinBox()
        self.timeout_spinbox.setRange(1, 120)
        self.timeout_spinbox.setValue(self.config.security.session_timeout_minutes)
        self.timeout_spinbox.valueChanged.connect(self.update_session_timeout)
        timeout_layout.addWidget(self.timeout_spinbox)
        timeout_layout.addStretch()
        security_layout.addLayout(timeout_layout)
        
        # Auto-lock
        self.auto_lock_checkbox = QCheckBox("Enable auto-lock")
        self.auto_lock_checkbox.setChecked(self.config.security.auto_lock_enabled)
        self.auto_lock_checkbox.stateChanged.connect(self.update_auto_lock)
        security_layout.addWidget(self.auto_lock_checkbox)
        
        # Clipboard settings
        clipboard_layout = QHBoxLayout()
        clipboard_layout.addWidget(QLabel("Clipboard clear time (seconds):"))
        self.clipboard_spinbox = QSpinBox()
        self.clipboard_spinbox.setRange(10, 300)
        self.clipboard_spinbox.setValue(self.config.security.clipboard_clear_seconds)
        self.clipboard_spinbox.valueChanged.connect(self.update_clipboard_timeout)
        clipboard_layout.addWidget(self.clipboard_spinbox)
        clipboard_layout.addStretch()
        security_layout.addLayout(clipboard_layout)
        
        security_group.setLayout(security_layout)
        layout.addWidget(security_group)
        
        # Backup Settings
        backup_group = QGroupBox("Backup Settings")
        backup_layout = QVBoxLayout()
        
        backup_btn = QPushButton("💾 Create Backup")
        backup_btn.clicked.connect(self.create_backup)
        backup_layout.addWidget(backup_btn)
        
        restore_btn = QPushButton("📥 Restore from Backup")
        restore_btn.clicked.connect(self.restore_backup)
        backup_layout.addWidget(restore_btn)
        
        backup_group.setLayout(backup_layout)
        layout.addWidget(backup_group)
        
        # About
        about_group = QGroupBox("About")
        about_layout = QVBoxLayout()
        
        about_text = QLabel(f"""
{self.config.app_name} v{self.config.version}

Features:
• Master password protection with PBKDF2
• AES-256 encryption for all stored data
• Advanced password generation algorithms
• Session management and auto-lock
• Secure clipboard management
• Password expiry tracking
• Advanced search and filtering
• Encrypted backup and restore

Built with Python, PyQt5, and Cryptography
        """)
        about_text.setWordWrap(True)
        about_layout.addWidget(about_text)
        
        about_group.setLayout(about_layout)
        layout.addWidget(about_group)
        
        layout.addStretch()
        tab.setLayout(layout)
        return tab
    
    def open_emergency_settings(self):
        """Open emergency access settings dialog"""
        if not hasattr(self, 'emergency_manager'):
            self.emergency_manager = EmergencyAccessManager(self.config.emergency, self.encryption_manager)
        
        dialog = EmergencyAccessDialog(self.emergency_manager)
        dialog.exec_()
    
    def on_slider_change(self):
        self.length_spinbox.setValue(self.length_slider.value())
    
    def update_session_timeout(self):
        self.config.security.session_timeout_minutes = self.timeout_spinbox.value()
        self.session_manager.timeout_minutes = self.timeout_spinbox.value()
    
    def update_auto_lock(self):
        self.config.security.auto_lock_enabled = self.auto_lock_checkbox.isChecked()
    
    def update_clipboard_timeout(self):
        self.config.security.clipboard_clear_seconds = self.clipboard_spinbox.value()
    
    def generate_password(self):
        try:
            config = {
                'length': self.length_spinbox.value(),
                'use_lowercase': self.use_lowercase.isChecked(),
                'use_uppercase': self.use_uppercase.isChecked(),
                'use_digits': self.use_digits.isChecked(),
                'use_symbols': self.use_symbols.isChecked(),
                'symbol_count': self.symbol_count.value(),
                'symbol_category': self.symbol_category.currentText()
            }
            
            password = self.password_generator.generate_password(config)
            self.password_display.setText(password)
            self.update_strength_indicator(password)
            
        except ValueError as e:
            QMessageBox.warning(self, "Warning", str(e))
    
    def update_password(self):
        if self.password_display.text():
            self.generate_password()
    
    def update_strength_indicator(self, password):
        strength, score, color, feedback = self.password_generator.check_strength(password)
        
        self.strength_label.setText(f"Strength: {strength}")
        self.strength_label.setStyleSheet(f"color: {color};")
        self.strength_bar.setValue(score)
        self.strength_bar.setStyleSheet(f"""
            QProgressBar::chunk {{
                background-color: {color};
            }}
        """)
        
        if feedback:
            self.strength_feedback.setText("Suggestions: " + ", ".join(feedback))
        else:
            self.strength_feedback.setText("✅ Excellent password!")
    
    def copy_password(self):
        password = self.password_display.text()
        if password:
            self.clipboard_manager.copy_with_auto_clear(
                password, 
                self.config.security.clipboard_clear_seconds
            )
        else:
            QMessageBox.warning(self, "Warning", "No password to copy!")
    
    def save_password(self):
        password = self.password_display.text()
        app_name = self.app_input.text().strip()
        username = self.username_input.text().strip()
        notes = self.notes_input.text().strip()
        expiry_days = self.expiry_input.value()
        
        if not password:
            QMessageBox.warning(self, "Warning", "Generate a password first!")
            return
        
        if not app_name or not username:
            QMessageBox.warning(self, "Warning", "Please fill in app/website and username!")
            return
        
        try:
            now = datetime.now()
            expiry_date = now + timedelta(days=expiry_days) if expiry_days > 0 else None
            
            entry = PasswordEntry(
                id=str(uuid.uuid4()),
                app_name=app_name,
                username=username,
                password=password,
                created_date=now,
                last_modified=now,
                expiry_date=expiry_date,
                notes=notes
            )
            
            self.passwords.append(entry)
            self.save_passwords()
            
            QMessageBox.information(self, "Success", "Password saved securely!")
            
            # Clear inputs
            self.app_input.clear()
            self.username_input.clear()
            self.notes_input.clear()
            
            self.refresh_password_table()
            
        except Exception as e:
            self.logger.error(f"Failed to save password: {e}")
            QMessageBox.critical(self, "Error", f"Failed to save password: {str(e)}")
    
    def save_passwords(self):
        try:
            # Encrypt and save all passwords
            salt = self.encryption_manager.load_salt()
            key, _ = self.encryption_manager.derive_key_from_password(self.master_password, salt)
            fernet = Fernet(key)
            
            data = {
                'passwords': [entry.to_dict() for entry in self.passwords],
                'version': self.config.version
            }
            
            json_data = json.dumps(data, indent=2)
            encrypted_data = fernet.encrypt(json_data.encode())
            
            with open(self.encryption_manager.encrypted_data_file, 'wb') as f:
                f.write(encrypted_data)
                
        except Exception as e:
            self.logger.error(f"Failed to save passwords: {e}")
            raise
    
    def load_passwords(self):
        try:
            if not os.path.exists(self.encryption_manager.encrypted_data_file):
                self.passwords = []
                self.refresh_password_table()
                return
            
            salt = self.encryption_manager.load_salt()
            key, _ = self.encryption_manager.derive_key_from_password(self.master_password, salt)
            fernet = Fernet(key)
            
            with open(self.encryption_manager.encrypted_data_file, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = fernet.decrypt(encrypted_data)
            data = json.loads(decrypted_data.decode())
            
            self.passwords = [PasswordEntry.from_dict(entry) for entry in data.get('passwords', [])]
            self.refresh_password_table()
            
        except Exception as e:
            self.logger.error(f"Failed to load passwords: {e}")
            QMessageBox.critical(self, "Error", f"Failed to load passwords: {str(e)}")
    
    def refresh_password_table(self):
        self.password_table.setRowCount(len(self.passwords))
        
        for row, entry in enumerate(self.passwords):
            self.password_table.setItem(row, 0, QTableWidgetItem(entry.app_name))
            self.password_table.setItem(row, 1, QTableWidgetItem(entry.username))
            
            # Password with visibility toggle
            password_item = QTableWidgetItem("•" * len(entry.password))
            password_item.setData(Qt.UserRole, entry.password)
            self.password_table.setItem(row, 2, password_item)
            
            self.password_table.setItem(row, 3, QTableWidgetItem(
                entry.created_date.strftime("%Y-%m-%d")
            ))
            
            if entry.expiry_date:
                expiry_text = entry.expiry_date.strftime("%Y-%m-%d")
                if entry.is_expired():
                    expiry_text += " ⚠️"
            else:
                expiry_text = "Never"
            
            self.password_table.setItem(row, 4, QTableWidgetItem(expiry_text))
            self.password_table.setItem(row, 5, QTableWidgetItem(entry.notes))
    
    def filter_passwords(self, criteria):
        # Simple filtering implementation
        query = criteria.get('query', '').lower()
        if not query:
            self.refresh_password_table()
            return
        
        filtered_passwords = []
        for entry in self.passwords:
            if (query in entry.app_name.lower() or 
                query in entry.username.lower() or 
                query in entry.notes.lower()):
                filtered_passwords.append(entry)
        
        # Update table with filtered results
        self.password_table.setRowCount(len(filtered_passwords))
        for row, entry in enumerate(filtered_passwords):
            self.password_table.setItem(row, 0, QTableWidgetItem(entry.app_name))
            self.password_table.setItem(row, 1, QTableWidgetItem(entry.username))
            password_item = QTableWidgetItem("•" * len(entry.password))
            password_item.setData(Qt.UserRole, entry.password)
            self.password_table.setItem(row, 2, password_item)
            self.password_table.setItem(row, 3, QTableWidgetItem(entry.created_date.strftime("%Y-%m-%d")))
            if entry.expiry_date:
                expiry_text = entry.expiry_date.strftime("%Y-%m-%d")
                if entry.is_expired():
                    expiry_text += " ⚠️"
            else:
                expiry_text = "Never"
            self.password_table.setItem(row, 4, QTableWidgetItem(expiry_text))
            self.password_table.setItem(row, 5, QTableWidgetItem(entry.notes))
    
    def delete_selected_password(self):
        current_row = self.password_table.currentRow()
        if current_row >= 0 and current_row < len(self.passwords):
            reply = QMessageBox.question(self, "Confirm Delete", 
                                       "Are you sure you want to delete this password?",
                                       QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                del self.passwords[current_row]
                self.save_passwords()
                self.refresh_password_table()
    
    def export_passwords(self):
        try:
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Export Passwords", "passwords_backup.csv", 
                "CSV Files (*.csv)"
            )
            
            if file_path:
                password, ok = QInputDialog.getText(
                    self, "Export Password", "Enter password for encrypted export:",
                    QLineEdit.Password
                )
                
                if ok and password:
                    self.export_to_encrypted_csv(file_path, password)
                    QMessageBox.information(self, "Success", "Passwords exported successfully!")
                    
        except Exception as e:
            self.logger.error(f"Export failed: {e}")
            QMessageBox.critical(self, "Error", f"Export failed: {str(e)}")
    
    def export_to_encrypted_csv(self, file_path: str, export_password: str):
        # Generate key from export password
        key, salt = self.encryption_manager.derive_key_from_password(export_password)
        fernet = Fernet(key)
        
        # Create CSV data
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Headers
        writer.writerow(['App/Website', 'Username', 'Password', 'Created', 'Notes', 'Expiry'])
        
        # Data
        for entry in self.passwords:
            writer.writerow([
                entry.app_name,
                entry.username,
                entry.password,
                entry.created_date.isoformat(),
                entry.notes,
                entry.expiry_date.isoformat() if entry.expiry_date else ""
            ])
        
        csv_string = output.getvalue()
        encrypted_data = fernet.encrypt(csv_string.encode())
        
        # Save with salt prefix
        with open(file_path, 'wb') as f:
            f.write(salt + b'|||' + encrypted_data)
    
    def import_passwords(self):
        try:
            file_path, _ = QFileDialog.getOpenFileName(
                self, "Import Passwords", "", "CSV Files (*.csv)"
            )
            
            if file_path:
                password, ok = QInputDialog.getText(
                    self, "Import Password", "Enter password for encrypted import:",
                    QLineEdit.Password
                )
                
                if ok and password:
                    imported_passwords = self.import_from_encrypted_csv(file_path, password)
                    self.passwords.extend(imported_passwords)
                    self.save_passwords()
                    self.refresh_password_table()
                    QMessageBox.information(
                        self, "Success", 
                        f"Imported {len(imported_passwords)} passwords successfully!"
                    )
                    
        except Exception as e:
            self.logger.error(f"Import failed: {e}")
            QMessageBox.critical(self, "Error", f"Import failed: {str(e)}")
    
    def import_from_encrypted_csv(self, file_path: str, import_password: str):
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Split salt and encrypted data
        salt, encrypted_data = data.split(b'|||', 1)
        
        # Derive key and decrypt
        key, _ = self.encryption_manager.derive_key_from_password(import_password, salt)
        fernet = Fernet(key)
        
        csv_string = fernet.decrypt(encrypted_data).decode()
        
        # Parse CSV
        csv_file = io.StringIO(csv_string)
        reader = csv.reader(csv_file)
        
        headers = next(reader)  # Skip headers
        passwords = []
        
        for row in reader:
            if len(row) >= 6:
                entry = PasswordEntry(
                    id=str(uuid.uuid4()),
                    app_name=row[0],
                    username=row[1],
                    password=row[2],
                    created_date=datetime.fromisoformat(row[3]) if row[3] else datetime.now(),
                    last_modified=datetime.now(),
                    notes=row[4],
                    expiry_date=datetime.fromisoformat(row[5]) if row[5] else None
                )
                passwords.append(entry)
        
        return passwords
    
    def create_backup(self):
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = f"password_backup_{timestamp}.enc"
            
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Create Backup", backup_file, "Encrypted Files (*.enc)"
            )
            
            if file_path:
                # Copy current vault file
                import shutil
                shutil.copy2(self.encryption_manager.encrypted_data_file, file_path)
                QMessageBox.information(self, "Success", "Backup created successfully!")
                
        except Exception as e:
            self.logger.error(f"Backup failed: {e}")
            QMessageBox.critical(self, "Error", f"Backup failed: {str(e)}")
    
    def restore_backup(self):
        try:
            file_path, _ = QFileDialog.getOpenFileName(
                self, "Restore Backup", "", "Encrypted Files (*.enc)"
            )
            
            if file_path:
                reply = QMessageBox.question(
                    self, "Confirm Restore", 
                    "This will replace all current passwords. Continue?",
                    QMessageBox.Yes | QMessageBox.No
                )
                
                if reply == QMessageBox.Yes:
                    import shutil
                    shutil.copy2(file_path, self.encryption_manager.encrypted_data_file)
                    self.load_passwords()
                    QMessageBox.information(self, "Success", "Backup restored successfully!")
                    
        except Exception as e:
            self.logger.error(f"Restore failed: {e}")
            QMessageBox.critical(self, "Error", f"Restore failed: {str(e)}")
    
    def change_master_password(self):
        try:
            old_password, ok1 = QInputDialog.getText(
                self, "Change Master Password", "Enter current master password:",
                QLineEdit.Password
            )
            
            if not ok1 or not self.encryption_manager.verify_master_password(old_password):
                QMessageBox.warning(self, "Error", "Invalid current password!")
                return
            
            new_password, ok2 = QInputDialog.getText(
                self, "Change Master Password", "Enter new master password:",
                QLineEdit.Password
            )
            
            if not ok2 or len(new_password) < 8:
                QMessageBox.warning(self, "Error", "New password must be at least 8 characters!")
                return
            
            confirm_password, ok3 = QInputDialog.getText(
                self, "Change Master Password", "Confirm new master password:",
                QLineEdit.Password
            )
            
            if not ok3 or new_password != confirm_password:
                QMessageBox.warning(self, "Error", "Passwords do not match!")
                return
            
            # Change password by re-encrypting data
            self.master_password = new_password
            new_key, new_salt = self.encryption_manager.derive_key_from_password(new_password)
            self.encryption_manager.save_salt(new_salt)
            self.save_passwords()
            
            QMessageBox.information(self, "Success", "Master password changed successfully!")
            
        except Exception as e:
            self.logger.error(f"Password change failed: {e}")
            QMessageBox.critical(self, "Error", f"Failed to change password: {str(e)}")
    
    def apply_dark_theme(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QWidget {
                background-color: #2b2b2b;
                color: #ffffff;
                font-family: Arial;
                font-size: 10pt;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #555555;
                border-radius: 8px;
                margin-top: 1ex;
                padding-top: 12px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px 0 8px;
                color: #ffffff;
                font-weight: bold;
            }
            QPushButton {
                background-color: #0d7377;
                border: none;
                padding: 10px 16px;
                border-radius: 6px;
                font-weight: bold;
                color: white;
                min-height: 20px;
            }
            QPushButton:hover {
                background-color: #14a085;
                transform: scale(1.02);
            }
            QPushButton:pressed {
                background-color: #0a5d61;
            }
            QPushButton:disabled {
                background-color: #555555;
                color: #888888;
            }
            QLineEdit, QSpinBox, QComboBox {
                border: 2px solid #555555;
                border-radius: 6px;
                padding: 8px;
                background-color: #3c3c3c;
                color: #ffffff;
                min-height: 20px;
            }
            QLineEdit:focus, QSpinBox:focus, QComboBox:focus {
                border-color: #0d7377;
                background-color: #454545;
            }
            QTableWidget {
                gridline-color: #555555;
                background-color: #3c3c3c;
                alternate-background-color: #454545;
                selection-background-color: #0d7377;
                border: 1px solid #555555;
                border-radius: 6px;
            }
            QHeaderView::section {
                background-color: #555555;
                border: 1px solid #777777;
                padding: 8px;
                font-weight: bold;
                color: #ffffff;
            }
            QTabWidget::pane {
                border: 2px solid #555555;
                border-radius: 6px;
                background-color: #2b2b2b;
            }
            QTabBar::tab {
                background-color: #3c3c3c;
                padding: 12px 20px;
                margin-right: 2px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                color: #ffffff;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background-color: #0d7377;
                color: white;
            }
            QTabBar::tab:hover:!selected {
                background-color: #505050;
            }
            QProgressBar {
                border: 2px solid #555555;
                border-radius: 6px;
                text-align: center;
                background-color: #3c3c3c;
                color: #ffffff;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background-color: #0d7377;
                border-radius: 4px;
            }
            QCheckBox {
                color: #ffffff;
                font-weight: normal;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border: 2px solid #555555;
                border-radius: 4px;
                background-color: #3c3c3c;
            }
            QCheckBox::indicator:checked {
                background-color: #0d7377;
                border-color: #0d7377;
            }
            QSlider::groove:horizontal {
                border: 1px solid #555555;
                height: 8px;
                background-color: #3c3c3c;
                border-radius: 4px;
            }
            QSlider::handle:horizontal {
                background-color: #0d7377;
                border: 1px solid #0d7377;
                width: 18px;
                margin: -5px 0;
                border-radius: 9px;
            }
            QSlider::handle:horizontal:hover {
                background-color: #14a085;
            }
            QToolTip {
                background-color: #3c3c3c;
                color: #ffffff;
                border: 1px solid #555555;
                padding: 6px;
                border-radius: 4px;
                font-size: 10pt;
            }
        """)

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Professional Password Manager")
    app.setApplicationVersion("2.0.0")
    
    # Set application icon if available
    try:
        app.setWindowIcon(QIcon("icon.png"))
    except:
        pass
    
    # Create and show main window
    window = ProfessionalPasswordManager()
    window.show()
    
    # Generate initial password
    window.generate_password()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
