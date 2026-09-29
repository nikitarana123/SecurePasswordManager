from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)
import secrets
import string
import os

from cryptography.fernet import Fernet


app = Flask(__name__)


# ============================================================
# FLASK CONFIGURATION
# ============================================================

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///password_manager.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Secret key for securely signing Flask sessions
SECRET_KEY = os.environ.get("PASSWORD_MANAGER_SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError(
        "PASSWORD_MANAGER_SECRET_KEY environment variable is not set."
    )

app.config["SECRET_KEY"] = SECRET_KEY

# Session security settings
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Use secure cookies when the application is deployed over HTTPS.
# Keep False for local HTTP development.
app.config["SESSION_COOKIE_SECURE"] = False


# ============================================================
# DATABASE
# ============================================================

db = SQLAlchemy(app)


# ============================================================
# CSRF PROTECTION
# ============================================================

csrf = CSRFProtect(app)


# ============================================================
# ENCRYPTION CONFIGURATION
# ============================================================

ENCRYPTION_KEY = os.environ.get("PASSWORD_MANAGER_KEY")

if not ENCRYPTION_KEY:
    raise RuntimeError(
        "PASSWORD_MANAGER_KEY environment variable is not set."
    )

try:
    cipher = Fernet(ENCRYPTION_KEY)
except Exception as error:
    raise RuntimeError(
        "PASSWORD_MANAGER_KEY is invalid."
    ) from error


# ============================================================
# DATABASE MODELS
# ============================================================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(80),
        unique=True,
        nullable=False
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    credentials = db.relationship(
        "Credential",
        backref="owner",
        lazy=True,
        cascade="all, delete-orphan"
    )


class Credential(db.Model):
    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    website = db.Column(
        db.String(255),
        nullable=False
    )

    website_username = db.Column(
        db.String(120),
        nullable=False
    )

    encrypted_password = db.Column(
        db.Text,
        nullable=False
    )


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def user_is_logged_in():
    """Check whether a user is authenticated."""
    return "user_id" in session


def validate_registration(username, email, password):
    """Validate registration input."""

    if not username:
        return "Username is required."

    if not email:
        return "Email is required."

    if not password:
        return "Password is required."

    if len(username) > 80:
        return "Username is too long."

    if len(email) > 120:
        return "Email is too long."

    if len(password) < 8:
        return "Password must contain at least 8 characters."

    return None


def validate_credential(website, website_username, password):
    """Validate saved credential input."""

    if not website:
        return "Website is required."

    if not website_username:
        return "Website username is required."

    if not password:
        return "Website password is required."

    if len(website) > 255:
        return "Website name is too long."

    if len(website_username) > 120:
        return "Website username is too long."

    return None


# ============================================================
# HOME PAGE
# ============================================================

@app.route("/")
def home():

    if user_is_logged_in():
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))

# ============================================================
# REGISTRATION
# ============================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        validation_error = validate_registration(
            username,
            email,
            password
        )

        if validation_error:
            return validation_error, 400

        existing_user = User.query.filter(
            (User.username == username) |
            (User.email == email)
        ).first()

        if existing_user:
            return "Username or email already exists.", 409

        # Hash the account password.
        # The password itself is never stored.
        password_hash = generate_password_hash(password)

        new_user = User(
            username=username,
            email=email,
            password_hash=password_hash
        )

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for("login"))

    return render_template("register.html")


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if not username or not password:
            return "Username and password are required.", 400

        user = User.query.filter_by(
            username=username
        ).first()

        if user and check_password_hash(
            user.password_hash,
            password
        ):

            # Clear any previous session data
            session.clear()

            session["user_id"] = user.id
            session["username"] = user.username

            return redirect(url_for("dashboard"))

        return "Invalid username or password.", 401

    return render_template("login.html")


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
def dashboard():

    if not user_is_logged_in():
        return redirect(url_for("login"))

    return render_template("dashboard.html")


# ============================================================
# PASSWORD GENERATOR
# ============================================================

@app.route("/generate-password")
def generate_password():

    if not user_is_logged_in():
        return redirect(url_for("login"))

    characters = (
        string.ascii_letters
        + string.digits
        + string.punctuation
    )

    generated_password = "".join(
        secrets.choice(characters)
        for _ in range(16)
    )

    return render_template(
        "generate_password.html",
        generated_password=generated_password
    )


# ============================================================
# ADD CREDENTIAL
# ============================================================

@app.route("/add-credential", methods=["GET", "POST"])
def add_credential():

    if not user_is_logged_in():
        return redirect(url_for("login"))

    if request.method == "POST":

        website = request.form.get(
            "website",
            ""
        ).strip()

        website_username = request.form.get(
            "website_username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        validation_error = validate_credential(
            website,
            website_username,
            password
        )

        if validation_error:
            return validation_error, 400

        # Encrypt website password before database storage.
        encrypted_password = cipher.encrypt(
            password.encode()
        ).decode()

        new_credential = Credential(
            user_id=session["user_id"],
            website=website,
            website_username=website_username,
            encrypted_password=encrypted_password
        )

        db.session.add(new_credential)
        db.session.commit()

        return redirect(url_for("credentials"))

    return render_template("add_credential.html")


# ============================================================
# VIEW CREDENTIALS
# ============================================================

@app.route("/credentials")
def credentials():

    if not user_is_logged_in():
        return redirect(url_for("login"))

    # Only retrieve credentials belonging to
    # the currently authenticated user.
    saved_credentials = Credential.query.filter_by(
        user_id=session["user_id"]
    ).all()

    credential_list = []

    for credential in saved_credentials:

        decrypted_password = cipher.decrypt(
            credential.encrypted_password.encode()
        ).decode()

        credential_list.append({
            "id": credential.id,
            "website": credential.website,
            "website_username": credential.website_username,
            "password": decrypted_password
        })

    return render_template(
        "credentials.html",
        credentials=credential_list
    )


# ============================================================
# EDIT CREDENTIAL
# ============================================================

@app.route(
    "/edit-credential/<int:credential_id>",
    methods=["GET", "POST"]
)
def edit_credential(credential_id):

    if not user_is_logged_in():
        return redirect(url_for("login"))

    # Authorization check:
    # the credential must belong to the logged-in user.
    credential = Credential.query.filter_by(
        id=credential_id,
        user_id=session["user_id"]
    ).first()

    if not credential:
        return "Credential not found.", 404

    if request.method == "POST":

        website = request.form.get(
            "website",
            ""
        ).strip()

        website_username = request.form.get(
            "website_username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        validation_error = validate_credential(
            website,
            website_username,
            password
        )

        if validation_error:
            return validation_error, 400

        encrypted_password = cipher.encrypt(
            password.encode()
        ).decode()

        credential.website = website
        credential.website_username = website_username
        credential.encrypted_password = encrypted_password

        db.session.commit()

        return redirect(url_for("credentials"))

    # Decrypt only the credential belonging
    # to the authenticated user.
    decrypted_password = cipher.decrypt(
        credential.encrypted_password.encode()
    ).decode()

    credential_data = {
        "id": credential.id,
        "website": credential.website,
        "website_username": credential.website_username,
        "password": decrypted_password
    }

    return render_template(
        "edit_credential.html",
        credential=credential_data
    )


# ============================================================
# DELETE CREDENTIAL
# ============================================================

@app.route(
    "/delete-credential/<int:credential_id>",
    methods=["POST"]
)
def delete_credential(credential_id):

    if not user_is_logged_in():
        return redirect(url_for("login"))

    # Authorization check:
    # only the owner can delete the credential.
    credential = Credential.query.filter_by(
        id=credential_id,
        user_id=session["user_id"]
    ).first()

    if not credential:
        return "Credential not found.", 404

    db.session.delete(credential)
    db.session.commit()

    return redirect(url_for("credentials"))


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout", methods=["POST"])
def logout():

    session.clear()

    return redirect(url_for("login"))


# ============================================================
# CREATE DATABASE TABLES AND START APPLICATION
# ============================================================

if __name__ == "__main__":

    with app.app_context():
        db.create_all()

    # Debug mode is disabled by default.
    app.run(debug=False)