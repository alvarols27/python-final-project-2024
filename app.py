from flask import Flask, request, jsonify, send_file, render_template, redirect, session
import matplotlib.pyplot as plt
from datetime import datetime
import os
import sqlite3
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import re

app = Flask(__name__)

app.secret_key = os.urandom(24)

#Firewall
# IP Blocking setup
BLOCKED_IPS = set() #I don't want to block my own IP
# BLOCKED_IPS = {'127.0.0.1'}

def check_ip(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.remote_addr in BLOCKED_IPS:
            print("Blocked IP detected")
            return jsonify({'error': 'blocked'}), 403
        return f(*args, **kwargs)
    return wrapper

# Encryption
load_dotenv()
encryption_key = os.getenv('ENCRYPTION_KEY')

if not encryption_key:
    encryption_key = Fernet.generate_key()
    with open('.env', 'a') as f:
        f.write(f"\nENCRYPTION_KEY={encryption_key.decode()}")
    print("Encryption key generated")

fernet = Fernet(encryption_key.encode())

DATABASE = 'database/databases.db'

def init_db():
    print("Initializing database")
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            amount REAL NOT NULL, -- Encrypted
            date TEXT NOT NULL,
            username TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    conn.commit()
    conn.close()
    print("Database initialized")
init_db()

def encrypt_data(data: str) -> str:
    print(f"Encrypting data...")
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str) -> str:
    print(f"Decrypting data...")
    return fernet.decrypt(encrypted_data.encode()).decode()

def save_transaction(transaction_type, amount, date, username):
    print(f"Inserting transaction...")
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    encrypted_amount = encrypt_data(str(amount))
    cursor.execute(
        'INSERT INTO transactions (type, amount, date, username) VALUES (?, ?, ?, ?)',
        (transaction_type, encrypted_amount, date, username)
    )
    conn.commit()
    print(f"Transaction inserted successfully!")
    conn.close()

def load_transactions():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    username = session.get('username')  # Get the current user's username from the session
    cursor.execute('SELECT * FROM transactions WHERE username = ?', (username,))
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        print("No transactions found!")
        return {'error': 'There are no transactions to visualize.'}

    transactions = [
        {'id': row[0], 'type': row[1], 'amount': float(decrypt_data(row[2])), 'date': row[3]}
        for row in rows
    ]
    print("Loaded transactions")
    return transactions

def visualize_spending():
    transactions = load_transactions()
    print("Visualizing spending...")
    if not isinstance(transactions, list):
        return None

    # Separate transactions into different types
    income_transactions = [t for t in transactions if t['type'] == 'income']
    expense_transactions = [t for t in transactions if t['type'] == 'expense']
    withdrawal_transactions = [t for t in transactions if t['type'] == 'withdrawal']

    # Plot income transactions
    plt.figure(figsize=(10, 5))
    plt.plot([datetime.strptime(t['date'], "%Y-%m-%d") for t in income_transactions],
             [t['amount'] for t in income_transactions], marker='o', color='g', label='Income')

    # Plot expense transactions
    plt.plot([datetime.strptime(t['date'], "%Y-%m-%d") for t in expense_transactions],
             [t['amount'] for t in expense_transactions], marker='o', color='r', label='Expense')

    # Plot withdrawal transactions
    plt.plot([datetime.strptime(t['date'], "%Y-%m-%d") for t in withdrawal_transactions],
             [t['amount'] for t in withdrawal_transactions], marker='o', color='b', label='Withdrawal')

    plt.title("Spending Over Time")
    plt.xlabel("Date")
    plt.ylabel("Amount ($)")
    plt.xticks(rotation=45)
    plt.grid(True)
    plt.tight_layout()

    # Add legend to distinguish between the transaction types
    plt.legend()

    plt.savefig('static/spending_plot.png')
    print(f"Spending visualization saved.")
    return 'static/spending_plot.png'

def validate_password(password):
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Password must contain at least one special character."
    return None

#This is the main root (OUR START PAGE)
@app.route('/', methods=['GET'])
@check_ip
def root():
    print("GET / - Checking session")
    if 'username' in session:
        print(f"User {session['username']} is logged in. Redirecting to /index.")
        return redirect('/index')
    print("No user logged in. Redirecting to /login.")
    return redirect('/login')

#IF WE WANT TO CLICK 'login' IN SIGNUP PAGE
@app.route('/login', methods=['GET'])
@check_ip
def login_form():
    print("GET /login - Rendering login form")
    return render_template('login.html')

@app.route('/login', methods=['POST'])
@check_ip
def login():
    print("POST /login - Attempting to log in")
    username = request.form.get('username')
    password = request.form.get('password')
    print(f"Login attempt for username: {username}")

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        print(f"User {username} not found!")
        return render_template('login.html', error="User not found. Create it!")

    #The password hash is in the third column (index 3)
    if not check_password_hash(user[3], password):
        print(f"Incorrect password provided.")
        return render_template('login.html', error="Incorrect password")

    print(f"User {username} has logged in.")
    session['username'] = username
    return redirect('/index')

@app.route('/signup', methods=['GET'])
@check_ip
def signup_form():
    print("GET /signup - Rendering signup form")
    return render_template('signup.html')

@app.route('/signup', methods=['POST'])
@check_ip
def signup():
    print("POST /signup - Attempting to sign up")
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    print(f"New signup for username: {username}; Email: {email}")

    # Validate password
    password_error = validate_password(password)
    if password_error:
        print(f"Password validation error.")
        return render_template('signup.html', error=password_error)

    # Hash the password
    password_hash = generate_password_hash(password)

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    if cursor.fetchone():
        print("Username already taken.")
        conn.close()
        return render_template('signup.html', error="Username already taken")

    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    if cursor.fetchone():
        print("Email already registered.")
        conn.close()
        return render_template('signup.html', error="Email already registered")

    cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                   (username, email, password_hash))
    conn.commit()
    conn.close()
    print(f"User {username} added successfully.")
    return render_template('signup.html', success="User added successfully!")

@app.route('/index', methods=['GET'])
@check_ip
def index():
    print("GET /index - Checking session")
    if 'username' not in session:
        print("No user in session. Redirecting to /")
        return redirect('/')
    print(f"User {session['username']} accessing index.")
    return render_template('index.html')

@app.route('/logout')
@check_ip
def logout():
    print(f"User {session.get('username')} has logged out.")
    session.pop('username', None)
    return redirect('/')

@app.route('/add_transaction', methods=['POST'])
@check_ip
def add_transaction():
    print(f"POST /add_transaction - Data received: {request.form}")
    transaction_type = request.form.get('type').lower()
    amount_str = request.form.get('amount')
    date = request.form.get('date')

    # Get the current user's username from the session
    username = session.get('username')

    try:
        amount = float(amount_str)
    except ValueError:
        print("Invalid amount entered.")
        return jsonify({'error': 'Amount must be a valid number'}), 400

    if transaction_type not in ['income', 'expense', 'withdrawal']:
        print("Invalid transaction type entered.")
        return jsonify({'error': 'Invalid transaction type'}), 400
    if amount <= 0:
        print("Invalid amount (must be positive).")
        return jsonify({'error': 'Amount must be a positive number'}), 400
    try:
        datetime.strptime(date, "%Y-%m-%d")
    except ValueError as e:
        print("Invalid date format")
        return jsonify({'error': 'Invalid date format. Try employing the presented format (YYYY-MM-DD)'}), 400

    print(f"Transaction added successfully for user {username}")
    save_transaction(transaction_type, float(amount), date, username)  # Pass the username
    return jsonify({'message': 'Transaction added successfully'})


@app.route('/get_transactions', methods=['GET'])
@check_ip
def get_transactions():
    print(f"GET /get_transactions - Fetching transactions for user: {session.get('username')}")
    transactions = load_transactions()
    print("Transactions retrieved.")
    return jsonify(transactions)

@app.route('/visualize_spending', methods=['GET'])
@check_ip
def get_spending_plot():
    print(f"GET /visualize_spending...Generating spending plot for user: {session.get('username')}")
    plot_path = visualize_spending()
    if plot_path:
        print(f"Spending plot generated successfully.")
        return send_file(plot_path, mimetype='image/png')
    else:
        print("Spending visualization failed (there are no transactions).")
        return jsonify({'error': 'You do not have transactions, therefore we can not process your diagram.'
                                   ' To get started, add a new transaction!'}), 400

@app.route('/update_transaction', methods=['POST'])
@check_ip
def update_transaction():
    print(f"POST /update_transaction - Data received: {request.form}")
    transaction_id = request.form.get('id')
    new_type = request.form.get('type')
    new_amount = request.form.get('amount')
    new_date = request.form.get('date')

    if not transaction_id or not new_type or not new_amount or not new_date:
        print("Error: All fields are required for updating a transaction.")
        return jsonify({'error': 'All fields are required'}), 400

    try:
        new_amount = float(new_amount)
        if new_amount <= 0:
            print("Invalid amount.")
            return jsonify({'error': 'Please the amount must be higher than 0.'})
        datetime.strptime(new_date, "%Y-%m-%d")

    except ValueError:
        print("Error in data validation.")
        return jsonify({'error': 'Invalid date form'}), 400

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    encrypted_amount = encrypt_data(str(new_amount))
    cursor.execute('''
        UPDATE transactions
        SET type = ?, amount = ?, date = ?
        WHERE id = ?
    ''', (new_type.lower(), encrypted_amount, new_date, transaction_id))
    print(f"Updating transaction - ID: {transaction_id}...")
    conn.commit()
    conn.close()
    print(f"Transaction {transaction_id} updated successfully.")
    return jsonify({'message': 'Transaction updated successfully!'})

@app.route('/delete_transaction', methods=['POST'])
@check_ip
def delete_transaction():
    print(f"POST /delete_transaction - Data received: {request.form}")
    transaction_id = request.form.get('id')

    if not transaction_id:
        print("Transaction ID is required.")
        return jsonify({'error': 'Please select a transaction.'}), 400

    print(f"Deleting transaction - ID: {transaction_id}")
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM transactions WHERE id = ?', (transaction_id,))
    print(f"Transaction {transaction_id} deleted successfully.")
    conn.commit()
    conn.close()

    return jsonify({'message': 'Transaction deleted successfully!'})

if __name__ == '__main__':
    print("Starting application...")
    app.run(debug=True)