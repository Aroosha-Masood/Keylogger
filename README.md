import os
import sys
import time
import csv
import json
import base64
import hashlib
import threading
import subprocess
import signal
from datetime import datetime
import warnings
warnings.filterwarnings("ignore")

# ============================================================================
# AUTO-INSTALL MISSING MODULES
# ============================================================================
def install_required_modules():
    """Install all required modules silently"""
    required = [
        "pyautogui",
        "pynput", 
        "pyperclip",
        "psutil",
        "opencv-python",
        "sounddevice",
        "soundfile",
        "pandas",
        "numpy",
        "matplotlib",
        "python-docx",
        "regex",
        "uiautomation",
        "pywin32"
    ]
    
    import subprocess
    import sys
    
    for package in required:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            try:
                subprocess.run([sys.executable, "-m", "pip", "install", package, "--quiet"], 
                             capture_output=True, check=False)
            except:
                pass

install_required_modules()

# ============================================================================
# IMPORT WITH ERROR HANDLING
# ============================================================================
modules = {}
try:
    import pyautogui
    modules['pyautogui'] = pyautogui
except:
    modules['pyautogui'] = None

try:
    from pynput import keyboard, mouse
    modules['keyboard'] = keyboard
    modules['mouse'] = mouse
except:
    modules['keyboard'] = None
    modules['mouse'] = None

try:
    import pyperclip
    modules['pyperclip'] = pyperclip
except:
    modules['pyperclip'] = None

try:
    import psutil
    modules['psutil'] = psutil
except:
    modules['psutil'] = None

try:
    import cv2
    modules['cv2'] = cv2
except:
    modules['cv2'] = None

try:
    import sounddevice as sd
    import soundfile as sf
    modules['sd'] = sd
    modules['sf'] = sf
except:
    modules['sd'] = None
    modules['sf'] = None

try:
    import pandas as pd
    modules['pd'] = pd
except:
    modules['pd'] = None

try:
    import numpy as np
    modules['np'] = np
except:
    modules['np'] = None

try:
    import matplotlib.pyplot as plt
    modules['plt'] = plt
except:
    modules['plt'] = None

try:
    from docx import Document
    modules['Document'] = Document
except:
    modules['Document'] = None

try:
    import regex
    modules['regex'] = regex
except:
    modules['regex'] = None

try:
    import uiautomation as auto
    modules['auto'] = auto
except:
    modules['auto'] = None

try:
    import win32gui
    import win32process
    modules['win32gui'] = win32gui
    modules['win32process'] = win32process
except:
    modules['win32gui'] = None
    modules['win32process'] = None

# ============================================================================
# GLOBAL STATE MANAGEMENT
# ============================================================================
class GlobalState:
    running = True
    threads = []
    lock = threading.Lock()
    
    @classmethod
    def stop_all(cls):
        """Stop all monitoring"""
        with cls.lock:
            cls.running = False
    
    @classmethod
    def is_running(cls):
        """Check if system is running"""
        with cls.lock:
            return cls.running
    
    @classmethod
    def add_thread(cls, thread):
        """Add thread to management list"""
        with cls.lock:
            cls.threads.append(thread)
    
    @classmethod
    def stop_threads(cls):
        """Stop all threads gracefully"""
        with cls.lock:
            for thread in cls.threads:
                if thread and thread.is_alive():
                    try:
                        thread.join(timeout=2)
                    except:
                        pass

# ============================================================================
# SIGNAL HANDLER FOR GRACEFUL SHUTDOWN
# ============================================================================
def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n\n[SYSTEM] Stopping forensic monitoring...")
    GlobalState.stop_all()
    time.sleep(1)  # Give threads time to clean up
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# ============================================================================
# CONFIGURATION
# ============================================================================
OUT_DIR = "forensic_output"
SCREENSHOT_DIR = os.path.join(OUT_DIR, "screenshots")
AUDIO_DIR = os.path.join(OUT_DIR, "audio")
VIDEO_DIR = os.path.join(OUT_DIR, "video")
os.makedirs(SCREENSHOT_DIR, exist_ok=True)
os.makedirs(AUDIO_DIR, exist_ok=True)
os.makedirs(VIDEO_DIR, exist_ok=True)

# CSV file with timestamp
CSV_FILE = os.path.join(OUT_DIR, f"forensic_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")

# Timing configuration
SCREENSHOT_INTERVAL = 5
AUDIO_INTERVAL = 30
VIDEO_INTERVAL = 60

# ============================================================================
# LOGGING SYSTEM
# ============================================================================
class ForensicLogger:
    def __init__(self):
        self.csv_file = CSV_FILE
        self.setup_csv()
        
    def setup_csv(self):
        """Setup CSV file with headers"""
        with open(self.csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'timestamp', 'event_type', 'application', 
                'window_title', 'data', 'script', 'screenshot', 
                'audio', 'video'
            ])
    
    def log(self, event_type, data="", screenshot="", audio="", video=""):
        """Log event to CSV"""
        try:
            # Get active window info
            app = "Unknown"
            title = "Unknown"
            
            if modules['win32gui'] and modules['win32process'] and modules['psutil']:
                try:
                    hwnd = win32gui.GetForegroundWindow()
                    title = win32gui.GetWindowText(hwnd)
                    _, pid = win32process.GetWindowThreadProcessId(hwnd)
                    app = modules['psutil'].Process(pid).name()
                except:
                    pass
            
            # Detect script if data exists
            script = "Unknown"
            if data and modules['regex']:
                try:
                    if regex.search(r'\p{Arabic}', data):
                        script = "Arabic"
                    elif regex.search(r'\p{Han}', data):
                        script = "Chinese"
                    elif regex.search(r'\p{Hiragana}|\p{Katakana}', data):
                        script = "Japanese"
                    elif regex.search(r'\p{Hangul}', data):
                        script = "Korean"
                    elif regex.search(r'\p{Cyrillic}', data):
                        script = "Cyrillic"
                    elif regex.search(r'\p{Devanagari}', data):
                        script = "Indic"
                    elif regex.search(r'\p{Latin}', data):
                        script = "Latin"
                except:
                    pass
            
            # Write to CSV
            with open(self.csv_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    datetime.now().isoformat(),
                    event_type,
                    app,
                    title,
                    str(data)[:500],
                    script,
                    screenshot,
                    audio,
                    video
                ])
            
            # Print to console
            print(f"[LOG] {event_type}: {str(data)[:50]}")
            
        except Exception as e:
            print(f"[LOG ERROR] {e}")

# ============================================================================
# AUDIO RECORDER (NEW FEATURE)
# ============================================================================
class AudioRecorder:
    def __init__(self, logger):
        self.logger = logger
        self.is_recording = False
        
    def record_chunk(self, duration=5):
        """Record audio chunk"""
        if not modules['sd'] or not modules['sf']:
            return None
        
        try:
            filename = f"audio_{datetime.now().strftime('%Y%m%d_%H%M%S')}.wav"
            filepath = os.path.join(AUDIO_DIR, filename)
            
            # Record audio
            sample_rate = 16000
            recording = sd.rec(
                int(duration * sample_rate),
                samplerate=sample_rate,
                channels=1,
                dtype='float32'
            )
            sd.wait()
            
            # Save file
            sf.write(filepath, recording, sample_rate)
            
            # Log
            self.logger.log("AUDIO_RECORDING", f"Duration: {duration}s", audio=filepath)
            
            return filepath
            
        except Exception as e:
            print(f"[AUDIO ERROR] {e}")
            return None
    
    def continuous_recording(self):
        """Continuous audio recording"""
        while GlobalState.is_running():
            try:
                self.record_chunk(5)
                
                # Wait for interval
                for _ in range(AUDIO_INTERVAL * 2):
                    if not GlobalState.is_running():
                        break
                    time.sleep(0.5)
                    
            except Exception as e:
                print(f"[AUDIO LOOP ERROR] {e}")
                time.sleep(5)

# ============================================================================
# VIDEO RECORDER (NEW FEATURE)
# ============================================================================
class VideoRecorder:
    def __init__(self, logger):
        self.logger = logger
        self.camera = None
        self.init_camera()
        
    def init_camera(self):
        """Initialize webcam"""
        if not modules['cv2']:
            return
        
        try:
            self.camera = cv2.VideoCapture(0)
            if self.camera.isOpened():
                print("[VIDEO] Camera initialized")
            else:
                print("[VIDEO] Camera not available")
        except Exception as e:
            print(f"[CAMERA INIT ERROR] {e}")
    
    def record_webcam(self, duration=10):
        """Record from webcam"""
        if not modules['cv2'] or not self.camera or not self.camera.isOpened():
            return None
        
        try:
            filename = f"webcam_{datetime.now().strftime('%Y%m%d_%H%M%S')}.avi"
            filepath = os.path.join(VIDEO_DIR, filename)
            
            # Get camera properties
            width = int(self.camera.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(self.camera.get(cv2.CAP_PROP_FRAME_HEIGHT))
            fps = 15
            
            # Create video writer
            fourcc = cv2.VideoWriter_fourcc(*'XVID')
            out = cv2.VideoWriter(filepath, fourcc, fps, (width, height))
            
            start_time = time.time()
            frames = 0
            
            while (time.time() - start_time) < duration and GlobalState.is_running():
                ret, frame = self.camera.read()
                if ret:
                    # Add timestamp
                    cv2.putText(frame, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 
                              (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
                    out.write(frame)
                    frames += 1
                else:
                    break
            
            out.release()
            
            if frames > 0:
                self.logger.log("WEBCAM_VIDEO", f"Frames: {frames}", video=filepath)
                return filepath
            
        except Exception as e:
            print(f"[WEBCAM ERROR] {e}")
        
        return None
    
    def record_screen(self, duration=10):
        """Record screen"""
        if not modules['pyautogui'] or not modules['cv2']:
            return None
        
        try:
            filename = f"screen_{datetime.now().strftime('%Y%m%d_%H%M%S')}.avi"
            filepath = os.path.join(VIDEO_DIR, filename)
            
            # Get screen size
            screen_size = pyautogui.size()
            width, height = screen_size.width // 2, screen_size.height // 2
            fps = 10
            
            # Create video writer
            fourcc = cv2.VideoWriter_fourcc(*'XVID')
            out = cv2.VideoWriter(filepath, fourcc, fps, (width, height))
            
            start_time = time.time()
            frames = 0
            
            while (time.time() - start_time) < duration and GlobalState.is_running():
                try:
                    # Capture screen
                    screenshot = pyautogui.screenshot()
                    
                    # Convert and resize
                    if modules['np']:
                        frame = cv2.cvtColor(np.array(screenshot), cv2.COLOR_RGB2BGR)
                        frame = cv2.resize(frame, (width, height))
                        
                        # Add timestamp
                        cv2.putText(frame, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 
                                  (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
                        
                        out.write(frame)
                        frames += 1
                except:
                    break
            
            out.release()
            
            if frames > 0:
                self.logger.log("SCREEN_VIDEO", f"Frames: {frames}", video=filepath)
                return filepath
            
        except Exception as e:
            print(f"[SCREEN VIDEO ERROR] {e}")
        
        return None
    
    def continuous_recording(self):
        """Continuous video recording"""
        while GlobalState.is_running():
            try:
                # Record webcam
                self.record_webcam(10)
                
                # Record screen
                self.record_screen(10)
                
                # Wait for interval
                for _ in range(VIDEO_INTERVAL * 2):
                    if not GlobalState.is_running():
                        break
                    time.sleep(0.5)
                    
            except Exception as e:
                print(f"[VIDEO LOOP ERROR] {e}")
                time.sleep(5)

# ============================================================================
# ORIGINAL FEATURES (FROM YOUR DESIGN)
# ============================================================================
class OriginalFeatures:
    def __init__(self, logger):
        self.logger = logger
        self.last_clipboard = ""
        self.last_text = ""
        
    def uia_text_watcher(self):
        """UI Automation text capture"""
        if not modules['auto']:
            return
        
        while GlobalState.is_running():
            try:
                focused = auto.GetFocusedControl()
                if focused:
                    text = focused.GetValuePattern().Value
                    if text and text != self.last_text:
                        self.logger.log("UIA_TEXT", text)
                        self.last_text = text
            except:
                pass
            
            time.sleep(0.5)
    
    def clipboard_watcher(self):
        """Clipboard monitoring"""
        if not modules['pyperclip']:
            return
        
        while GlobalState.is_running():
            try:
                data = pyperclip.paste()
                if data and data != self.last_clipboard:
                    self.last_clipboard = data
                    self.logger.log("CLIPBOARD", data)
            except:
                pass
            
            time.sleep(0.5)
    
    def screenshot_worker(self):
        """Periodic screenshots"""
        if not modules['pyautogui']:
            return
        
        while GlobalState.is_running():
            try:
                filename = f"screenshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
                filepath = os.path.join(SCREENSHOT_DIR, filename)
                
                pyautogui.screenshot(filepath)
                self.logger.log("SCREENSHOT", "Periodic screenshot", screenshot=filepath)
                
                # Wait for interval
                for _ in range(SCREENSHOT_INTERVAL * 10):
                    if not GlobalState.is_running():
                        break
                    time.sleep(0.1)
                    
            except Exception as e:
                print(f"[SCREENSHOT ERROR] {e}")
                time.sleep(5)
    
    def key_listener(self):
        """Keyboard monitoring"""
        if not modules['keyboard']:
            return
        
        def on_press(key):
            try:
                # Get key string
                try:
                    if hasattr(key, 'char') and key.char:
                        key_str = key.char
                    else:
                        key_str = str(key).replace("Key.", "")
                except:
                    key_str = str(key)
                
                # Log key
                self.logger.log("KEYSTROKE", key_str)
                
                # Stop on ESC
                if key == keyboard.Key.esc:
                    print("\n[SYSTEM] ESC pressed - Stopping...")
                    GlobalState.stop_all()
                    return False
                    
            except Exception as e:
                pass
        
        # Start listener
        with keyboard.Listener(on_press=on_press) as listener:
            listener.join()
    
    def rdp_detection(self):
        """RDP session detection"""
        while GlobalState.is_running():
            try:
                # Check for RDP
                result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True, shell=True)
                if '3389' in result.stdout and 'ESTABLISHED' in result.stdout:
                    self.logger.log("RDP_DETECTED", "Active RDP session")
                
                # Check via qwinsta
                result = subprocess.run(['qwinsta'], capture_output=True, text=True, shell=True)
                if 'rdp' in result.stdout.lower():
                    self.logger.log("RDP_SESSION", "RDP session found")
                    
            except:
                pass
            
            time.sleep(30)
    
    def wifi_monitor(self):
        """Wi-Fi context monitoring"""
        while GlobalState.is_running():
            try:
                result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                                      capture_output=True, text=True, shell=True)
                
                for line in result.stdout.split('\n'):
                    if 'SSID' in line and 'BSSID' not in line:
                        ssid = line.split(':')[-1].strip()
                        if ssid:
                            self.logger.log("WIFI_CONTEXT", f"Connected to: {ssid}")
                            break
                            
            except:
                pass
            
            time.sleep(60)
    
    def process_monitor(self):
        """Process monitoring"""
        if not modules['psutil']:
            return
        
        suspicious = ['anydesk.exe', 'teamviewer.exe', 'rustdesk.exe', 
                     'vnc.exe', 'radmin.exe', 'supremo.exe']
        
        while GlobalState.is_running():
            try:
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        proc_name = proc.info['name'].lower()
                        if any(susp in proc_name for susp in suspicious):
                            self.logger.log("SUSPICIOUS_PROCESS", proc_name)
                    except:
                        pass
            except:
                pass
            
            time.sleep(10)

# ============================================================================
# REPORT GENERATION
# ============================================================================
class ReportGenerator:
    @staticmethod
    def generate_all_reports():
        """Generate all reports"""
        print("\n[REPORT] Generating forensic reports...")
        
        # Generate integrity report
        ReportGenerator.generate_integrity_report()
        
        # Generate text report
        ReportGenerator.generate_text_report()
        
        # Generate Word report if available
        if modules['Document']:
            ReportGenerator.generate_word_report()
        
        # Generate timeline if available
        if modules['pd'] and modules['plt'] and modules['np']:
            ReportGenerator.generate_timeline()
    
    @staticmethod
    def generate_integrity_report():
        """Generate integrity report with hashes"""
        integrity_file = os.path.join(OUT_DIR, "integrity_report.txt")
        
        with open(integrity_file, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("FORENSIC EVIDENCE INTEGRITY REPORT\n")
            f.write("=" * 60 + "\n\n")
            
            # Hash CSV file
            if os.path.exists(CSV_FILE):
                hash_value = ReportGenerator.calculate_hash(CSV_FILE)
                f.write(f"Main Log: {CSV_FILE}\n")
                f.write(f"SHA256: {hash_value}\n\n")
            
            # Hash screenshots
            f.write("SCREENSHOTS:\n")
            for file in os.listdir(SCREENSHOT_DIR):
                if file.endswith('.png'):
                    filepath = os.path.join(SCREENSHOT_DIR, file)
                    hash_value = ReportGenerator.calculate_hash(filepath)
                    f.write(f"  {file}: {hash_value}\n")
            
            # Hash audio
            f.write("\nAUDIO RECORDINGS:\n")
            for file in os.listdir(AUDIO_DIR):
                if file.endswith('.wav'):
                    filepath = os.path.join(AUDIO_DIR, file)
                    hash_value = ReportGenerator.calculate_hash(filepath)
                    f.write(f"  {file}: {hash_value}\n")
            
            # Hash video
            f.write("\nVIDEO RECORDINGS:\n")
            for file in os.listdir(VIDEO_DIR):
                if file.endswith('.avi'):
                    filepath = os.path.join(VIDEO_DIR, file)
                    hash_value = ReportGenerator.calculate_hash(filepath)
                    f.write(f"  {file}: {hash_value}\n")
        
        print(f"[REPORT] Integrity report: {integrity_file}")
    
    @staticmethod
    def calculate_hash(filepath):
        """Calculate SHA256 hash"""
        try:
            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except:
            return "ERROR"
    
    @staticmethod
    def generate_text_report():
        """Generate simple text report"""
        if not os.path.exists(CSV_FILE):
            return
        
        report_file = CSV_FILE.replace('.csv', '_report.txt')
        
        try:
            # Read CSV
            data = []
            with open(CSV_FILE, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                headers = next(reader)
                for row in reader:
                    data.append(row)
            
            # Write report
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write("=" * 70 + "\n")
                f.write("FORENSIC MONITORING REPORT\n")
                f.write("=" * 70 + "\n\n")
                
                f.write(f"Report generated: {datetime.now()}\n")
                f.write(f"Total events: {len(data)}\n\n")
                
                f.write("EVENT SUMMARY:\n")
                f.write("-" * 50 + "\n")
                
                # Count events
                event_counts = {}
                for row in data:
                    if len(row) > 1:
                        event_type = row[1]
                        event_counts[event_type] = event_counts.get(event_type, 0) + 1
                
                for event_type, count in event_counts.items():
                    f.write(f"{event_type}: {count} events\n")
                
                f.write("\nDETAILED LOG (Last 50 events):\n")
                f.write("=" * 70 + "\n")
                
                for row in data[-50:]:
                    if len(row) >= 5:
                        f.write(f"{row[0]} - {row[1]}: {row[4][:100]}\n")
            
            print(f"[REPORT] Text report: {report_file}")
            
        except Exception as e:
            print(f"[REPORT ERROR] {e}")
    
    @staticmethod
    def generate_word_report():
        """Generate Word document report"""
        if not os.path.exists(CSV_FILE):
            return
        
        try:
            doc = Document()
            doc.add_heading('Forensic Monitoring Report', 0)
            
            doc.add_paragraph(f'Generated: {datetime.now()}')
            doc.add_paragraph(f'Evidence Directory: {OUT_DIR}')
            
            # Add summary
            doc.add_heading('Summary', level=1)
            doc.add_paragraph('Complete forensic monitoring including audio/video recording.')
            
            # Save
            docx_file = CSV_FILE.replace('.csv', '_report.docx')
            doc.save(docx_file)
            print(f"[REPORT] Word document: {docx_file}")
            
        except Exception as e:
            print(f"[WORD REPORT ERROR] {e}")
    
    @staticmethod
    def generate_timeline():
        """Generate timeline visualization"""
        if not os.path.exists(CSV_FILE):
            return
        
        try:
            # Read CSV with pandas
            df = pd.read_csv(CSV_FILE)
            
            # Create timeline
            plt.figure(figsize=(12, 6))
            
            # Plot events
            event_types = df['event_type'].unique()
            colors = plt.cm.rainbow(np.linspace(0, 1, len(event_types)))
            
            for i, event_type in enumerate(event_types):
                mask = df['event_type'] == event_type
                plt.scatter(df.loc[mask, 'timestamp'], 
                          [i] * mask.sum(), 
                          label=event_type, 
                          alpha=0.6,
                          s=30)
            
            plt.xlabel('Time')
            plt.ylabel('Event Type')
            plt.title('Forensic Activity Timeline')
            plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
            plt.xticks(rotation=45)
            plt.tight_layout()
            
            timeline_file = CSV_FILE.replace('.csv', '_timeline.png')
            plt.savefig(timeline_file, dpi=150)
            plt.close()
            
            print(f"[REPORT] Timeline: {timeline_file}")
            
        except Exception as e:
            print(f"[TIMELINE ERROR] {e}")

# ============================================================================
# MAIN SYSTEM
# ============================================================================
class ForensicSystem:
    def __init__(self):
        print("\n" + "="*70)
        print("FORENSIC MONITORING SYSTEM v4.1")
        print("="*70)
        print("FEATURES:")
        print("✓ Text capture (UIA + Clipboard)")
        print("✓ Keystroke logging")
        print("✓ Screenshot capture")
        print("✓ Audio recording")
        print("✓ Video recording (Webcam + Screen)")
        print("✓ RDP detection")
        print("✓ Wi-Fi monitoring")
        print("✓ Process monitoring")
        print("✓ Integrity verification")
        print("="*70)
        print("Press ESC to stop or Ctrl+C to exit")
        print("="*70 + "\n")
        
        # Create logger
        self.logger = ForensicLogger()
        
        # Create components
        self.audio_recorder = AudioRecorder(self.logger)
        self.video_recorder = VideoRecorder(self.logger)
        self.original_features = OriginalFeatures(self.logger)
        
        # Log startup
        self.logger.log("SYSTEM_START", "Forensic monitoring started")
    
    def start(self):
        """Start all monitoring threads"""
        # Start all threads
        threads = []
        
        # Original features
        threads.append(threading.Thread(target=self.original_features.uia_text_watcher, daemon=True))
        threads.append(threading.Thread(target=self.original_features.clipboard_watcher, daemon=True))
        threads.append(threading.Thread(target=self.original_features.screenshot_worker, daemon=True))
        threads.append(threading.Thread(target=self.original_features.rdp_detection, daemon=True))
        threads.append(threading.Thread(target=self.original_features.wifi_monitor, daemon=True))
        threads.append(threading.Thread(target=self.original_features.process_monitor, daemon=True))
        
        # New features
        threads.append(threading.Thread(target=self.audio_recorder.continuous_recording, daemon=True))
        threads.append(threading.Thread(target=self.video_recorder.continuous_recording, daemon=True))
        
        # Start all threads
        for thread in threads:
            thread.start()
            GlobalState.add_thread(thread)
        
        print(f"[SYSTEM] Started {len(threads)} monitoring threads")
        print("[SYSTEM] All features active...\n")
        
        # Start keyboard listener (blocking - runs in main thread)
        try:
            self.original_features.key_listener()
        except Exception as e:
            print(f"[KEYBOARD LISTENER ERROR] {e}")
        
        # If we get here, system is stopping
        self.stop()
    
    def stop(self):
        """Stop the system and generate reports"""
        print("\n[SYSTEM] Stopping forensic monitoring...")
        
        # Stop all threads
        GlobalState.stop_all()
        time.sleep(1)  # Give threads time to finish
        
        # Generate reports
        ReportGenerator.generate_all_reports()
        
        print("\n" + "="*70)
        print("FORENSIC MONITORING COMPLETE")
        print("="*70)
        print(f"Evidence saved to: {OUT_DIR}")
        print(f"Log file: {CSV_FILE}")
        print("="*70)

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================
def main():
    """Main entry point"""
    try:
        # Create and start system
        system = ForensicSystem()
        system.start()
        
    except KeyboardInterrupt:
        print("\n\n[SYSTEM] Interrupted by user")
        GlobalState.stop_all()
        sys.exit(0)
        
    except Exception as e:
        print(f"\n[SYSTEM ERROR] {e}")
        GlobalState.stop_all()
        sys.exit(1)

# ============================================================================
# RUN
# ============================================================================
if __name__ == "__main__":
    main() 
