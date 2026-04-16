import json
import os
from http.server import SimpleHTTPRequestHandler, HTTPServer

DB_FILE = 'database.json'

# Create a default database file if it doesn't exist yet
if not os.path.exists(DB_FILE):
    with open(DB_FILE, 'w') as f:
        json.dump({
            "admin": {"username": "admin", "password": "adminpassword"},
            "users": []
        }, f, indent=4)

def load_db():
    with open(DB_FILE, 'r') as f:
        return json.load(f)

def save_db(data):
    with open(DB_FILE, 'w') as f:
        json.dump(data, f, indent=4)

class SecureGatewayServer(SimpleHTTPRequestHandler):

    # --- SPEED FIX: Disable DNS reverse-lookup to stop the login lag ---
    def address_string(self):
        return self.client_address[0]

    def do_GET(self):
        # Block any direct browser requests to the API or the JSON file
        if self.path.startswith('/api') or self.path.endswith('.json'):
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b'Forbidden')
            return

        # Otherwise, serve index.html and standard web files
        super().do_GET()

    def do_POST(self):
        # Read the incoming JSON data from the frontend
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        try:
            payload = json.loads(post_data.decode('utf-8'))
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            return

        db = load_db()

        # --- LOGIN ENDPOINT ---
        if self.path == '/api/login':
            u = payload.get('username')
            p = payload.get('password')

            # 1. Check if Admin
            if u == db['admin']['username'] and p == db['admin']['password']:
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                # Send the whole DB so the admin can manage users
                self.wfile.write(json.dumps({"role": "admin", "db": db}).encode())
                return

            # 2. Check if Standard User
            for user in db['users']:
                if u == user['username'] and p == user['password']:
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    # ONLY send this specific user's info. Keep others hidden.
                    safe_user_data = {
                        "username": user['username'],
                        "config": user['config'],
                        "enabled": user['enabled']
                    }
                    self.wfile.write(json.dumps({"role": "user", "user_data": safe_user_data}).encode())
                    return

            # 3. Failed Login
            self.send_response(401)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"error": "Unauthorized"}')

        # --- SAVE ENDPOINT (ADMIN ONLY) ---
        elif self.path == '/api/save':
            req_u = payload.get('auth_user')
            req_p = payload.get('auth_pass')
            new_db = payload.get('db')

            # Verify credentials again on the server side before allowing a file write
            if req_u == db['admin']['username'] and req_p == db['admin']['password']:
                save_db(new_db)
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"status":"saved"}')
            else:
                self.send_response(403)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"error": "Forbidden"}')

if __name__ == '__main__':
    port = 8080
    print(f"Secure Server running on port {port}...")
    print("Press Ctrl+C to stop.")
    HTTPServer(('', port), SecureGatewayServer).serve_forever()