# app.py
from flask import Flask, request, render_template_string, redirect, Response
import sqlite3
import os

app = Flask(__name__)

# --- Database Setup for SQLi ---
def init_db():
    # Use a file in the instance folder for persistence in some environments
    db_path = 'database.db'
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('DROP TABLE IF EXISTS users')
    cursor.execute('CREATE TABLE users (id TEXT, name TEXT)')
    cursor.execute("INSERT INTO users (id, name) VALUES ('1', 'admin')")
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return """
    <h1>Vulnerable App Sandbox</h1>
    <p>This application contains intentional vulnerabilities for security testing.</p>
    <ul>
        <li><a href="/search?q=test">Test XSS Link</a></li>
        <li><a href="/user?id=1">Test SQLi Link</a></li>
        <li><a href="/download?filename=test.txt">Test Path Traversal Link (requires 'test.txt' file)</a></li>
        <li><a href="/redirect?next_url=https://www.google.com">Test Unvalidated Redirect Link</a></li>
    </ul>

    <h2>Forms to Test</h2>
    <form action="/search" method="GET" style="margin-bottom: 1em;">
        <label for="search_q">Search (XSS):</label>
        <input type="text" id="search_q" name="q" placeholder="<script>alert(1)</script>">
        <input type="submit" value="Search">
    </form>
    
    <form action="/user" method="GET" style="margin-bottom: 1em;">
        <label for="user_id">User ID (SQLi):</label>
        <input type="text" id="user_id" name="id" placeholder="' OR 1=1 --">
        <input type="submit" value="Get User">
    </form>
    
    <form action="/download" method="GET" style="margin-bottom: 1em;">
        <label for="filename_pt">Filename (Path Traversal):</label>
        <input type="text" id="filename_pt" name="filename" placeholder="../../app.py">
        <input type="submit" value="Download">
    </form>
    
    <form action="/redirect" method="GET" style="margin-bottom: 1em;">
        <label for="redirect_url">Redirect URL:</label>
        <input type="text" id="redirect_url" name="next_url" placeholder="https://example.com">
        <input type="submit" value="Redirect">
    </form>
    """

# --- Vulnerability 1: Reflected XSS ---
@app.route('/search')
def search():
    query = request.args.get('q', '')
    # VULNERABLE: Directly rendering user input without escaping
    return render_template_string(f"<h2>Search results for: {query}</h2>")

# --- Vulnerability 2: SQL Injection ---
@app.route('/user')
def get_user():
    user_id = request.args.get('id', '')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    try:
        # VULNERABLE: Unsafe f-string query construction
        query = f"SELECT name FROM users WHERE id = '{user_id}'"
        cursor.execute(query)
        result = cursor.fetchone()
        return f"User found: {result[0] if result else 'Not Found'}"
    except Exception as e:
        return f"Database error: {e}"
    finally:
        conn.close()

# --- Vulnerability 3: Path Traversal ---
@app.route('/download')
def download_file():
    filename = request.args.get('filename', '')
    # VULNERABLE: Directly using user-provided path without validation
    try:
        # This is extremely insecure. Never do this in production.
        with open(filename, 'r') as f:
            return Response(f.read(), mimetype='text/plain')
    except Exception as e:
        return f"Error reading file: {e}", 404

# --- Vulnerability 4: Unvalidated Redirect ---
@app.route('/redirect')
def redirect_to_url():
    next_url = request.args.get('next_url', '/')
    # VULNERABLE: Redirecting to a user-controlled URL
    return redirect(next_url, code=302)

if __name__ == '__main__':
    # Initialize the database when the app starts
    init_db()
    # Create a dummy file for the path traversal example
    with open('test.txt', 'w') as f:
        f.write('This is a test file.')
    # Use 0.0.0.0 to make it accessible on the network
    app.run(host='0.0.0.0', port=5000)
