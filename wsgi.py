# PythonAnywhere WSGI Configuration for TrustFile Monitor
# Copy this content into:  /var/www/Goldkiting_pythonanywhere_com_wsgi.py
#
# Or if PythonAnywhere auto-generates a flask_app.py, paste this into:
# /home/Goldkiting/mysite/flask_app.py

import sys
import os
from dotenv import load_dotenv

# Path to your project directory on PythonAnywhere
path = '/home/Goldkiting/mysite'
if path not in sys.path:
    sys.path.append(path)

# Load environment variables from .env
load_dotenv(os.path.join(path, '.env'))

# Import your Flask app (PythonAnywhere expects 'application')
from app_firebase import app as application
