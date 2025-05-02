import time
import threading
from core import openai_decision
from core import gan_generator
from utils.helpers import yellow
from config import DECISION_INTERVAL

# Track the running thread to prevent duplicates
_analysis_thread = None
_thread_lock = threading.Lock()
_stop_event = threading.Event()

def analysis_job():
    print(yellow("[*] Running scheduled analysis + decoy generation..."))
    log_summary = openai_decision.run_log_analysis()
    gan_generator.generate_decoys_from_logs(log_summary)

def schedule_analysis():
    global _analysis_thread, _stop_event
    
    with _thread_lock:
        # Stop any existing thread
        if _analysis_thread and _analysis_thread.is_alive():
            _stop_event.set()
            _analysis_thread.join(timeout=5)
            _stop_event.clear()
            
        # Create new thread
        def loop():
            while not _stop_event.is_set():
                try:
                    analysis_job()
                except Exception as e:
                    print(f"Error in analysis job: {e}")
                finally:
                    # Use event wait instead of sleep to allow proper shutdown
                    _stop_event.wait(DECISION_INTERVAL)
    
        _analysis_thread = threading.Thread(target=loop, daemon=True)
        _analysis_thread.start()
        return _analysis_thread