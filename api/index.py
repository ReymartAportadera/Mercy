import sys
import os

# Ensure root workspace directory is in sys.path for Vercel serverless environment
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from app_firebase import app

# Expose WSGI application object for Vercel Python serverless runner
application = app
