import os
import secrets
import hashlib
import base64
import csv
import io
from urllib.parse import urlencode, parse_qs
from datetime import datetime

from flask import Flask, render_template, request, redirect, session, jsonify, send_file
import requests
from authlib.integrations.flask_client import OAuth
from simple_salesforce import Salesforce

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Salesforce OAuth Configuration
SF_CLIENT_ID = os.environ.get('SF_CLIENT_ID')
SF_CLIENT_SECRET = os.environ.get('SF_CLIENT_SECRET')
SF_REDIRECT_URI = os.environ.get('SF_REDIRECT_URI', 'http://localhost:5000/callback')
SF_AUTH_URL = 'https://login.salesforce.com/services/oauth2/authorize'
SF_TOKEN_URL = 'https://login.salesforce.com/services/oauth2/token'
SF_API_VERSION = 'v60.0'

oauth = OAuth(app)
salesforce = oauth.register(
    'salesforce',
    client_id=SF_CLIENT_ID,
    client_secret=SF_CLIENT_SECRET,
    access_token_url=SF_TOKEN_URL,
    authorize_url=SF_AUTH_URL,
    api_base_url='https://login.salesforce.com',
    client_kwargs={'scope': 'api refresh_token offline_access'},
)

# Generate PKCE parameters
def generate_pkce():
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode().rstrip('=')
    return code_verifier, code_challenge

@app.route('/')
def index():
    if 'access_token' in session:
        return redirect('/dashboard')
    return render_template('login.html')

@app.route('/login')
def login():
    state = secrets.token_urlsafe(16)
    code_verifier, code_challenge = generate_pkce()
    
    session['oauth_state'] = state
    session['pkce_verifier'] = code_verifier
    
    auth_url = f"{SF_AUTH_URL}?{urlencode({
        'response_type': 'code',
        'client_id': SF_CLIENT_ID,
        'redirect_uri': SF_REDIRECT_URI,
        'state': state,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256',
    })}"
    
    return redirect(auth_url)

@app.route('/callback')
def callback():
    # Verify state parameter (CSRF protection)
    returned_state = request.args.get('state')
    if returned_state != session.get('oauth_state'):
        return render_template('error.html', error='CSRF attack detected'), 400
    
    # Handle OAuth errors
    error = request.args.get('error')
    if error:
        error_description = request.args.get('error_description', 'Unknown error')
        return render_template('error.html', error=f"{error}: {error_description}"), 400
    
    code = request.args.get('code')
    if not code:
        return render_template('error.html', error='No authorization code received'), 400
    
    # Exchange code for token using PKCE
    try:
        token_data = {
            'grant_type': 'authorization_code',
            'client_id': SF_CLIENT_ID,
            'client_secret': SF_CLIENT_SECRET,
            'redirect_uri': SF_REDIRECT_URI,
            'code': code,
            'code_verifier': session.get('pkce_verifier'),
        }
        
        response = requests.post(SF_TOKEN_URL, data=token_data)
        response.raise_for_status()
        
        token_response = response.json()
        
        # Store tokens in session
        session['access_token'] = token_response.get('access_token')
        session['refresh_token'] = token_response.get('refresh_token')
        session['instance_url'] = token_response.get('instance_url')
        session['token_expires_at'] = datetime.utcnow().timestamp() + token_response.get('expires_in', 3600)
        
        # Get user info
        user_info_response = requests.get(
            f"{session['instance_url']}/services/oauth2/userinfo",
            headers={'Authorization': f"Bearer {session['access_token']}"}
        )
        user_info = user_info_response.json()
        session['user_name'] = user_info.get('name')
        session['user_email'] = user_info.get('email')
        
        return redirect('/dashboard')
    
    except Exception as e:
        return render_template('error.html', error=f"Token exchange failed: {str(e)}"), 400

@app.route('/dashboard')
def dashboard():
    if 'access_token' not in session:
        return redirect('/')
    
    return render_template('dashboard.html', 
                          user_name=session.get('user_name'),
                          user_email=session.get('user_email'))

@app.route('/api/execute-query', methods=['POST'])
def execute_query():
    if 'access_token' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    soql_query = data.get('query', '').strip()
    
    if not soql_query:
        return jsonify({'error': 'Query cannot be empty'}), 400
    
    try:
        # Initialize Salesforce connection
        sf = Salesforce(
            instance_url=session['instance_url'],
            session_id=session['access_token'],
            version=SF_API_VERSION.replace('v', '')
        )
        
        # Execute SOQL query
        start_time = datetime.utcnow()
        result = sf.query(soql_query)
        end_time = datetime.utcnow()
        execution_time = (end_time - start_time).total_seconds()
        
        # Format results
        records = result.get('records', [])
        total_size = result.get('totalSize', 0)
        
        if not records:
            return jsonify({
                'records': [],
                'columns': [],
                'totalSize': 0,
                'executionTime': execution_time
            })
        
        # Extract columns from first record
        columns = [key for key in records[0].keys() if key != 'attributes']
        
        # Format records for display
        formatted_records = []
        for record in records:
            formatted_record = {}
            for col in columns:
                value = record.get(col, '')
                # Handle nested objects
                if isinstance(value, dict):
                    value = str(value)
                formatted_record[col] = value
            formatted_records.append(formatted_record)
        
        return jsonify({
            'records': formatted_records,
            'columns': columns,
            'totalSize': total_size,
            'executionTime': execution_time
        })
    
    except Exception as e:
        return jsonify({'error': f"Query execution failed: {str(e)}"}), 400

@app.route('/api/download-csv', methods=['POST'])
def download_csv():
    if 'access_token' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    records = data.get('records', [])
    columns = data.get('columns', [])
    
    if not records or not columns:
        return jsonify({'error': 'No data to export'}), 400
    
    # Create CSV in memory
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=columns)
    writer.writeheader()
    writer.writerows(records)
    
    # Convert to bytes
    csv_bytes = io.BytesIO(output.getvalue().encode('utf-8'))
    csv_bytes.seek(0)
    
    return send_file(
        csv_bytes,
        mimetype='text/csv',
        as_attachment=True,
        download_name=f"salesforce_query_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    )

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error='Page not found'), 404

@app.errorhandler(500)
def server_error(error):
    return render_template('error.html', error='Internal server error'), 500

if __name__ == '__main__':
    app.run(debug=False)
