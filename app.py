import datetime
from flask import Flask, request, jsonify, send_file, render_template, redirect, session
import matplotlib.pyplot as plt
from datetime import datetime
import os
import sqlite3
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from functools import wraps
from matplotlib.pyplot import connect
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.secret_key = os.urandom(24)

load_dotenv()
encryption_key = os.getenv('ENCRYPTION_KEY')

if not encryption_key:
    encryption_key = Fernet.generate_key()
    with open('.env', 'a') as f:
        f.write(f"\nENCRYPTION_KEY={encryption_key.decode()}")

fernet = Fernet(encryption_key.encode())

# IP Blocking setup
BLOCKED_IPS = set() #I don't want to block my own IP
# BLOCKED_IPS = {'127.0.0.1'}

DATABASE = 'database/databases.db'

def check_ip(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.remote_addr in BLOCKED_IPS:
            return jsonify({'error': 'blocked'}), 403
        return f(*args, **kwargs)
    return wrapper

def init_db():
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

init_db()

def encrypt_data(data: str) -> str:
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str) -> str:
    return fernet.decrypt(encrypted_data.encode()).decode()

def save_transaction(transaction_type, amount, date, username):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    encrypted_amount = encrypt_data(str(amount))
    cursor.execute(
        'INSERT INTO transactions (type, amount, date, username) VALUES (?, ?, ?, ?)',
        (transaction_type, encrypted_amount, date, username)
    )
    conn.commit()
    conn.close()

def load_transactions():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    username = session.get('username')  # Get the current user's username from the session
    cursor.execute('SELECT * FROM transactions WHERE username = ?', (username,))
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        return {'error': 'There are no transactions to visualize.'}

    transactions = [
        {'id': row[0], 'type': row[1], 'amount': float(decrypt_data(row[2])), 'date': row[3]}
        for row in rows
    ]
    return transactions

def visualize_spending():
    transactions = load_transactions()

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
    return 'static/spending_plot.png'

#This is the main root (OUR START PAGE)
@app.route('/', methods=['GET'])
def root():
    if 'username' in session:
        return redirect('/index')
    return redirect('/login')

#IF WE WANT TO CLICK 'login' IN SIGNUP PAGE
@app.route('/login', methods=['GET'])
def login_form():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
        username = request.form.get('username')
        password = request.form.get('password')

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()

        if not user:
            return render_template('login.html', error="User not found. Create it!")

        # Assuming the password hash is in the third column (index 3)
        if not check_password_hash(user[3], password):
            return render_template('login.html', error="Incorrect password")

        session['username'] = username
        return redirect('/index')

@app.route('/signup', methods=['GET'])
def signup_form():
    return render_template('signup.html')

@app.route('/signup', methods=['POST'])
def signup():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    password_hash = generate_password_hash(password)

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    if cursor.fetchone():
        conn.close()
        return render_template('signup.html', error="Username already taken")

    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    if cursor.fetchone():
        conn.close()
        return render_template('signup.html', error="Email already registered")

    cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                   (username, email, password_hash))
    conn.commit()
    conn.close()

    return render_template('signup.html', success="User added successfully!")

@app.route('/index', methods=['GET'])
def index():
    if 'username' not in session:
        return redirect('/')
    return render_template('index.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/')

@app.route('/add_transaction', methods=['POST'])
@check_ip
def add_transaction():
    transaction_type = request.form.get('type').lower()
    amount_str = request.form.get('amount')
    date = request.form.get('date')

    # Get the current user's username from the session
    username = session.get('username')

    try:
        amount = float(amount_str)
    except ValueError:
        return jsonify({'error': 'Amount must be a valid number'}), 400

    if transaction_type not in ['income', 'expense', 'withdrawal']:
        return jsonify({'error': 'Invalid transaction type'}), 400
    if amount <= 0:
        return jsonify({'error': 'Amount must be a positive number'}), 400
    try:
        datetime.strptime(date, "%Y-%m-%d")
    except ValueError:
        return jsonify({'error': 'Invalid date format. Try employing the presented format (YYYY-MM-DD)'}), 400

    save_transaction(transaction_type, float(amount), date, username)  # Pass the username
    return jsonify({'message': 'Transaction added successfully'})


@app.route('/get_transactions', methods=['GET'])
@check_ip
def get_transactions():
    transactions = load_transactions()
    return jsonify(transactions)

@app.route('/visualize_spending', methods=['GET'])
@check_ip
def get_spending_plot():
    plot_path = visualize_spending()
    if plot_path:
        return send_file(plot_path, mimetype='image/png')
    else:
        return jsonify({'error': 'You do not have transactions, therefore we can not process your diagram.'
                                   ' To get started, add a new transaction!'}), 400

@app.route('/update_transaction', methods=['POST'])
@check_ip
def update_transaction():
    transaction_id = request.form.get('id')
    new_type = request.form.get('type')
    new_amount = request.form.get('amount')
    new_date = request.form.get('date')

    if not transaction_id or not new_type or not new_amount or not new_date:
        return jsonify({'error': 'All fields are required'}), 400

    try:
        new_amount = float(new_amount)
        if new_amount <= 0:
            return jsonify({'error': 'Please the amount must be higher than 0.'})
        datetime.strptime(new_date, "%Y-%m-%d")

    except ValueError:
        return jsonify({'error': 'Invalid date form'}), 400

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    encrypted_amount = encrypt_data(str(new_amount))
    cursor.execute('''
        UPDATE transactions
        SET type = ?, amount = ?, date = ?
        WHERE id = ?
    ''', (new_type.lower(), encrypted_amount, new_date, transaction_id))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Transaction updated successfully!'})

@app.route('/delete_transaction', methods=['POST'])
@check_ip
def delete_transaction():
    transaction_id = request.form.get('id')

    if not transaction_id:
        return jsonify({'error': 'Please select a transaction.'}), 400

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM transactions WHERE id = ?', (transaction_id,))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Transaction deleted successfully!'})

if __name__ == '__main__':
    app.run(debug=True)