import os
import sys
import shutil
from pathlib import Path

# Add project root and backend_django to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / 'backend_django'))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend_django.settings')

# Ensure SQLite database is copied to writable /tmp on Vercel Serverless cold start
if os.environ.get('VERCEL') or os.environ.get('AWS_LAMBDA_FUNCTION_NAME'):
    tmp_data_dir = Path('/tmp/academiq_data')
    tmp_data_dir.mkdir(parents=True, exist_ok=True)
    dest_db = tmp_data_dir / 'multischool.sqlite'
    src_db = BASE_DIR / 'data' / 'multischool.sqlite'
    if not dest_db.exists() and src_db.exists():
        try:
            shutil.copy2(str(src_db), str(dest_db))
            print(f"[Vercel Django] Bootstrapped /tmp database from {src_db}")
        except Exception as e:
            print(f"[Vercel Django] Database bootstrap note: {e}")

from django.core.wsgi import get_wsgi_application
app = get_wsgi_application()
