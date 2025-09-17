from flask import Flask, render_template, request, redirect, url_for, flash
from datetime import datetime
import sqlite3
import re

app = Flask(__name__)
app.secret_key = 'your_super_secret_key'
LOG_DB = 'security_logs.db'

# Yaygın SQL enjeksiyonu kalıpları
SQL_INJECTION_PATTERNS = [
    r"'(or|union|select|drop|--|\#)",
    r"1=1",
    r"\'",
    r"\""
]

def init_db():
    conn = sqlite3.connect(LOG_DB)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            username TEXT,
            password TEXT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL UNIQUE,
            reason TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Uygulama başladığında veritabanını başlat
with app.app_context():
    init_db()

@app.route('/')
def home():
    ip_address = request.remote_addr
    conn = sqlite3.connect(LOG_DB)
    cursor = conn.cursor()
    cursor.execute('SELECT 1 FROM blocked_ips WHERE ip_address = ?', (ip_address,))
    is_blocked = cursor.fetchone()
    conn.close()

    if is_blocked:
        return "IP adresiniz engellendi.", 403
    
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    ip_address = request.remote_addr
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    is_sql_injection = False
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, username, re.IGNORECASE) or re.search(pattern, password, re.IGNORECASE):
            is_sql_injection = True
            break
    
    conn = sqlite3.connect(LOG_DB)
    cursor = conn.cursor()
    event_type = "SQL_INJECTION" if is_sql_injection else "BRUTE_FORCE_ATTEMPT"
    
    cursor.execute('''
        INSERT INTO security_events (ip_address, username, password, timestamp, event_type)
        VALUES (?, ?, ?, ?, ?)
    ''', (ip_address, username, password, timestamp, event_type))
    conn.commit()
    conn.close()
    
    flash("Giriş başarısız. Lütfen bilgilerinizi kontrol edin.", "error")
    return redirect(url_for('home'))

@app.route('/admin', methods=['GET', 'POST'])
def admin_panel():
    conn = sqlite3.connect(LOG_DB)
    cursor = conn.cursor()
    
    if request.method == 'POST':
        blocked_ip = request.form.get('block_ip')
        if blocked_ip:
            try:
                cursor.execute('INSERT INTO blocked_ips (ip_address) VALUES (?)', (blocked_ip,))
                conn.commit()
                flash(f"{blocked_ip} başarıyla engellendi.", "success")
            except sqlite3.IntegrityError:
                flash(f"{blocked_ip} zaten engelli.", "error")

    filter_type = request.args.get('filter_type', 'all')
    search_term = request.args.get('search_term', '')

    query = "SELECT * FROM security_events"
    params = []

    if search_term:
        query += " WHERE ip_address LIKE ?"
        params.append(f'%{search_term}%')

    if filter_type != 'all':
        if not search_term:
            query += " WHERE"
        else:
            query += " AND"
        query += " event_type = ?"
        params.append(filter_type)
    
    query += " ORDER BY id DESC"
    
    cursor.execute(query, params)
    logs = cursor.fetchall()

    cursor.execute('SELECT ip_address FROM blocked_ips')
    blocked_ips = [row[0] for row in cursor.fetchall()]
    
    conn.close()
    
    return render_template('admin_panel.html', logs=logs, blocked_ips=blocked_ips, filter_type=filter_type, search_term=search_term)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)