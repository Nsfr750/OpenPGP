from gui.main_window import MainWindow
import sys
import traceback

# Global exception hook to log all uncaught exceptions
LOG_FILE = 'traceback.log'

def log_info(msg):
    print(f'[INFO] {msg}')
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(f'[INFO] {msg}\n')

def log_warning(msg):
    print(f'[WARNING] {msg}')
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(f'[WARNING] {msg}\n')

def log_error(msg):
    print(f'[ERROR] {msg}')
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(f'[ERROR] {msg}\n')

def global_exception_hook(exc_type, exc_value, exc_tb):
    # Save last traceback for LogViewer
    sys.last_type = exc_type
    sys.last_value = exc_value
    sys.last_traceback = exc_tb
    # Write to log file
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write('\n--- Uncaught Exception ---\n')
        traceback.print_exception(exc_type, exc_value, exc_tb, file=f)
    # Call default hook (prints to stderr)
    sys.__excepthook__(exc_type, exc_value, exc_tb)

sys.excepthook = global_exception_hook

def main():
    app = MainWindow()
    app.mainloop()

if __name__ == "__main__":
    main()
