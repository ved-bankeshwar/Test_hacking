# app.py
from flask import Flask, request, render_template_string, Response, redirect
import os
import subprocess
import sqlite3

app = Flask(__name__)

# --- Database Setup for SQLi ---
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('DROP TABLE IF EXISTS users')
    cursor.execute('CREATE TABLE users (id TEXT, name TEXT)')
    cursor.execute("INSERT INTO users (id, name) VALUES ('1', 'admin')")
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return "<h1>Vulnerable Test App for SAST/DAST Correlation</h1>"

# --- Vulnerability 1: SQL Injection ---
# SAST should find the f-string in cursor.execute and map it to this route.
# DAST should target GET /user with the 'id' parameter.
@app.route('/user', methods=['GET'])
def get_user():
    user_id = request.args.get('id')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    try:
        # VULNERABLE: Unsafe f-string query construction
        query = f"SELECT name FROM users WHERE id = '{user_id}'"
        cursor.execute(query)
        result = cursor.fetchone()
        return f"User Found: {result[0] if result else 'Not Found'}"
    except Exception as e:
        return f"DB Error: {e}"
    finally:
        conn.close()

# --- Vulnerability 2: Reflected XSS ---
# SAST should find the tainted input from request.args flowing into render_template_string.
# DAST should target GET /search with the 'query' parameter.
@app.route('/search')
def search():
    query = request.args.get('query', '')
    # VULNERABLE: Directly rendering user input without escaping
    return render_template_string(f"<h2>Search results for: {query}</h2>")

# --- Vulnerability 3: Path Traversal ---
# SAST should find the tainted input from request.form flowing into the 'open()' sink.
# DAST should target POST /download with the 'filename' parameter.
@app.route('/download', methods=['POST'])
def download_file():
    filename = request.form.get('filename', '')
    try:
        # VULNERABLE: Directly using user-provided path
        with open(filename, 'r') as f:
            return Response(f.read(), mimetype='text/plain')
    except Exception as e:
        return f"Error reading file: {e}", 404

# --- Vulnerability 4: Command Injection ---
# SAST should find the tainted input from request.args flowing into a subprocess sink.
# DAST should target GET /dns-lookup with the 'host' parameter.
@app.route('/dns-lookup')
def dns_lookup():
    host = request.args.get('host', '')
    # VULNERABLE: User input is passed directly to a shell command
    try:
        # This is a very dangerous pattern.
        output = subprocess.check_output(f"nslookup {host}", shell=True)
        return Response(output, mimetype='text/plain')
    except subprocess.CalledProcessError as e:
        return f"Error executing command: {e.output.decode()}", 500

if __name__ == '__main__':
    init_db()
    # Use 0.0.0.0 to make it accessible on the network if deployed
    app.run(host='0.0.0.0', port=5000)
