from flask import Flask, render_template, request, redirect, session, flash, url_for
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import uuid
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# --------------------
# App Initialization
# --------------------
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "myverysecretkey")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "notes.db")

# --------------------
# Mail Config (EMAIL RESET + CONTACT)
# --------------------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_USERNAME")

mail = Mail(app)

# --------------------
# Database Helper
# --------------------
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# --------------------
# Home
# --------------------
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect('/viewall')
    return redirect('/login')

# --------------------
# Register
# --------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        email = request.form.get('email','').strip()
        password = request.form.get('password','')

        if not username or not email or not password:
            flash("Please fill all fields.", "danger")
            return redirect('/register')

        hashed_pw = generate_password_hash(password)

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cur.fetchone():
            flash("Username already taken.", "danger")
            conn.close()
            return redirect('/register')

        cur.execute(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
            (username, email, hashed_pw)
        )
        conn.commit()
        conn.close()

        flash("Registration successful! You can now log in.", "success")
        return redirect('/login')

    return render_template('register.html')

# --------------------
# Login
# --------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash("Missing credentials", "danger")
            return redirect('/login')

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect('/viewall')

        flash("Invalid login", "danger")
        return redirect('/login')

    return render_template('login.html')

# --------------------
# About & Contact
# --------------------
@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact', methods=['GET','POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')

        if not name or not email or not message:
            flash("All fields required", "danger")
            return redirect('/contact')

        msg = Message(
            subject=f"📩 New Contact Message from {name}",
            recipients=[os.getenv("MAIL_USERNAME")]
        )
        msg.body = f"""
Name: {name}
Email: {email}

Message:
{message}
"""
        mail.send(msg)

        flash("Message sent successfully!", "success")
        return redirect('/contact')

    return render_template('contact.html')

# --------------------
# Logout
# --------------------
@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out", "info")
    return redirect('/login')

# --------------------
# Add Note
# --------------------
@app.route('/addnote', methods=['GET','POST'])
def addnote():
    if 'user_id' not in session:
        return redirect('/login')

    if request.method == 'POST':
        title = request.form['title'].strip()
        content = request.form['content'].strip()

        if not title or not content:
            flash("Title and content required", "danger")
            return redirect('/addnote')

        conn = get_db_connection()
        conn.execute(
            "INSERT INTO notes (title, content, user_id) VALUES (?, ?, ?)",
            (title, content, session['user_id'])
        )
        conn.commit()
        conn.close()

        flash("Note added", "success")
        return redirect('/viewall')

    return render_template('addnote.html')

# --------------------
# View All Notes
# --------------------
@app.route('/viewall')
def viewall():
    if 'user_id' not in session:
        return redirect('/login')

    conn = get_db_connection()
    notes = conn.execute(
        "SELECT * FROM notes WHERE user_id=? ORDER BY created_at DESC",
        (session['user_id'],)
    ).fetchall()
    conn.close()

    return render_template('viewnotes.html', notes=notes)

# --------------------
# View Single Note
# --------------------
@app.route('/viewnotes/<int:note_id>')
def viewnotes(note_id):
    if 'user_id' not in session:
        return redirect('/login')

    conn = get_db_connection()
    note = conn.execute(
        "SELECT * FROM notes WHERE id=? AND user_id=?",
        (note_id, session['user_id'])
    ).fetchone()
    conn.close()

    if not note:
        flash("Access denied", "danger")
        return redirect('/viewall')

    return render_template('singlenote.html', note=note)

# --------------------
# Update Note
# --------------------
@app.route('/updatenote/<int:note_id>', methods=['GET','POST'])
def updatenote(note_id):
    if 'user_id' not in session:
        return redirect('/login')

    conn = get_db_connection()
    note = conn.execute(
        "SELECT * FROM notes WHERE id=? AND user_id=?",
        (note_id, session['user_id'])
    ).fetchone()

    if not note:
        conn.close()
        flash("Unauthorized", "danger")
        return redirect('/viewall')

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']

        conn.execute(
            "UPDATE notes SET title=?, content=? WHERE id=?",
            (title, content, note_id)
        )
        conn.commit()
        conn.close()

        flash("Note updated", "success")
        return redirect('/viewall')

    conn.close()
    return render_template('updatenote.html', note=note)

# --------------------
# Delete Note
# --------------------
@app.route('/deletenote/<int:note_id>', methods=['POST'])
def deletenote(note_id):
    if 'user_id' not in session:
        return redirect('/login')

    conn = get_db_connection()
    conn.execute(
        "DELETE FROM notes WHERE id=? AND user_id=?",
        (note_id, session['user_id'])
    )
    conn.commit()
    conn.close()

    flash("Note deleted", "info")
    return redirect('/viewall')

# --------------------
# Forgot Password (EMAIL)
# --------------------
@app.route('/forgot-password', methods=['GET','POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email','').strip()

        if not email:
            flash("Enter email", "danger")
            return redirect('/forgot-password')

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE email=?",
            (email,)
        ).fetchone()

        if not user:
            conn.close()
            flash("Email not registered", "danger")
            return redirect('/forgot-password')

        token = str(uuid.uuid4())

        conn.execute(
            "UPDATE users SET reset_token=? WHERE email=?",
            (token, email)
        )
        conn.commit()
        conn.close()

        reset_link = f"http://127.0.0.1:5000/reset/{token}"

        msg = Message(
            subject="🔐 Reset Your NotesApp Password",
            recipients=[email]
        )
        msg.body = f"""
Hello,

Click the link below to reset your password:
{reset_link}

If you did not request this, ignore this email.
"""
        mail.send(msg)

        flash("Password reset link sent to your email.", "success")
        return redirect('/login')

    return render_template('forgot_password.html')

# --------------------
# Reset Password
# --------------------
@app.route('/reset/<token>', methods=['GET','POST'])
def reset(token):
    conn = get_db_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE reset_token=?",
        (token,)
    ).fetchone()

    if not user:
        conn.close()
        flash("Invalid token", "danger")
        return redirect('/forgot-password')

    if request.method == 'POST':
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')

        if password != confirm:
            flash("Passwords do not match", "danger")
            return redirect(request.url)

        hashed = generate_password_hash(password)
        conn.execute(
            "UPDATE users SET password=?, reset_token=NULL WHERE id=?",
            (hashed, user['id'])
        )
        conn.commit()
        conn.close()

        flash("Password reset successful", "success")
        return redirect('/login')

    conn.close()
    return render_template('reset.html')

# --------------------
# Search Notes
# --------------------
@app.route('/search')
def search_notes():
    if 'user_id' not in session:
        return redirect('/login')

    query = request.args.get('q','')

    conn = get_db_connection()
    notes = conn.execute(
        """SELECT * FROM notes
           WHERE user_id=?
           AND (title LIKE ? OR content LIKE ?)
           ORDER BY created_at DESC""",
        (session['user_id'], f"%{query}%", f"%{query}%")
    ).fetchall()
    conn.close()

    return render_template('search_results.html', notes=notes, query=query)

# --------------------
# Run App
# --------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
