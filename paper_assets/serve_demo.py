import sys
from pathlib import Path
root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root))
import dtem.data.database as database
database.DB_PATH = Path(__file__).resolve().with_name('demo-working-copy.sqlite')
import uvicorn
import dtem.web.app as web
# Keep the screenshot demo deterministic and offline. It uses only records in the copied DB.
web.collector_manager.collect = lambda *args, **kwargs: []
uvicorn.run(web.app, host='127.0.0.1', port=8000, log_level='warning')
