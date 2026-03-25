import os
import time
import sqlite3
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from backend.hash_utils import sha256_file
from backend.database import log_tamper_event, DB_PATH

class IntegrityHandler(FileSystemEventHandler):
    def __init__(self, monitored_dir):
        self.monitored_dir = monitored_dir
        
    def _check_file(self, event):
        if event.is_directory:
            return
            
        file_path = event.src_path
        filename = os.path.basename(file_path)
        
        # Allow time for file writes to finish
        time.sleep(0.1) 
        
        try:
            with sqlite3.connect(DB_PATH, timeout=10) as db:
                db.row_factory = sqlite3.Row
                row = db.execute("SELECT * FROM files WHERE original_name=?", (filename,)).fetchone()
                
                if row:
                    old_hash = row["sha256"]
                    new_hash = sha256_file(file_path)
                    
                    if new_hash and old_hash != new_hash:
                        # Tamper detected
                        db.execute("UPDATE files SET sha256=?, status='tampered', last_check=? WHERE id=?", 
                                   (new_hash, time.strftime("%Y-%m-%d %H:%M:%S"), row["id"]))
                        db.commit()
                        
                        log_tamper_event(
                            event_type="modified",
                            file_path=file_path,
                            old_hash=old_hash,
                            new_hash=new_hash
                        )
        except Exception as e:
            print(f"Monitor error for {filename}: {e}")

    def on_modified(self, event):
        self._check_file(event)

def start_monitoring(path_to_watch):
    if not os.path.exists(path_to_watch):
        os.makedirs(path_to_watch)
        
    event_handler = IntegrityHandler(path_to_watch)
    observer = Observer()
    observer.schedule(event_handler, path=path_to_watch, recursive=False)
    observer.start()
    return observer
