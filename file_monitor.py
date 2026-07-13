import os
import time
import threading
import hashlib
import json
import shutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime
import requests
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RealTimeSystemMonitor(FileSystemEventHandler):
    """Windows Defender-style real-time file monitor"""
    
    def __init__(self, api_url, config, db_callback=None):
        self.api_url = api_url
        self.config = config
        self.db_callback = db_callback
        self.scanning_queue = []
        self.queue_lock = threading.Lock()
        self.processed_cache = {}  # Prevent duplicate scans
        self.cache_timeout = 30  # Seconds to remember processed files
        
        # File extensions to monitor (skip system/temp files)
        self.monitored_extensions = {
            # Executables
            '.exe', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.py',
            # Office documents (macro threats)
            '.docm', '.xlsm', '.pptm', '.doc', '.xls', '.ppt',
            # Archives (can contain malware)
            '.zip', '.rar', '.7z', '.tar', '.gz',
            # Scripts
            '.sh', '.rb', '.pl', '.php', '.jse', '.vbe',
            # PDF (can have exploits)
            '.pdf',
            # Shortcuts
            '.lnk', '.url'
        }
        
        # Folders to EXCLUDE (performance & noise reduction)
        self.excluded_paths = self.get_excluded_paths()
        
        # Queued file processing
        self.processing_thread = threading.Thread(target=self._process_queue, daemon=True)
        self.processing_thread.start()
        
        logger.info("[Monitor] Real-Time System Monitor Initialized")
        logger.info(f"[Monitor] Monitoring {len(self.get_monitored_paths())} locations")
        logger.info(f"[Monitor] Excluding {len(self.excluded_paths)} system folders")
    
    def get_monitored_paths(self):
        """Get ALL user-accessible drives and folders"""
        monitored = []
        
        if os.name == 'nt':  # Windows
            # 1. Get all drives (C:\, D:\, etc.)
            import string
            from ctypes import windll
            
            drives = []
            bitmask = windll.kernel32.GetLogicalDrives()
            for letter in string.ascii_uppercase:
                if bitmask & 1:
                    drive = f"{letter}:\\"
                    if os.path.exists(drive):
                        monitored.append(drive)
                bitmask >>= 1
            
            # 2. Critical user folders
            user_profile = os.path.expanduser("~")
            critical_folders = [
                user_profile,
                os.path.join(user_profile, "Desktop"),
                os.path.join(user_profile, "Downloads"),
                os.path.join(user_profile, "Documents"),
                os.path.join(user_profile, "Pictures"),
                os.path.join(user_profile, "Videos"),
                os.path.join(user_profile, "Music"),
                os.path.join(user_profile, "AppData", "Local", "Temp"),
                os.path.join(user_profile, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu"),
                os.path.join(user_profile, "AppData", "Roaming", "Microsoft", "Windows", "Recent"),
                # Common malware locations
                "C:\\ProgramData",
                "C:\\Temp",
                "C:\\Windows\\Temp",
            ]
            
            for folder in critical_folders:
                if os.path.exists(folder) and folder not in monitored:
                    monitored.append(folder)
        
        else:  # Linux/Mac
            home = os.path.expanduser("~")
            monitored = [
                home,
                os.path.join(home, "Desktop"),
                os.path.join(home, "Downloads"),
                os.path.join(home, "Documents"),
                "/tmp",
                "/var/tmp"
            ]
        
        return list(set(monitored))
    
    def get_excluded_paths(self):
        """Paths to NEVER monitor (system files, caches, etc.)"""
        excludes = []
        
        # System folders (Windows)
        system_folders = [
            "C:\\Windows\\System32",
            "C:\\Windows\\SysWOW64",
            "C:\\Windows\\Microsoft.NET",
            "C:\\Program Files",
            "C:\\Program Files (x86)",
            "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
            "C:\\System Volume Information",
            "C:\\$Recycle.Bin",
            "C:\\Windows\\Prefetch",
            "C:\\Windows\\Installer",
            "C:\\Windows\\WinSxS",
        ]
        
        # Browser caches (too many small files)
        user_profile = os.path.expanduser("~")
        cache_folders = [
            os.path.join(user_profile, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Cache"),
            os.path.join(user_profile, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Cache"),
            os.path.join(user_profile, "AppData", "Local", "Mozilla", "Firefox", "Profiles"),
            os.path.join(user_profile, "AppData", "Local", "Temp"),
            os.path.join(user_profile, ".cache"),
            os.path.join(user_profile, "Library", "Caches"),
        ]
        
        # Python/Node cache folders
        dev_caches = [
            "__pycache__",
            "node_modules",
            ".git",
            ".venv",
            "venv",
            "env",
            ".idea",
            ".vscode"
        ]
        
        excludes.extend(system_folders)
        excludes.extend(cache_folders)
        
        # Add pattern exclusions
        for dev_cache in dev_caches:
            excludes.append(dev_cache)
        
        return [os.path.normpath(p).lower() for p in excludes if p]
    
    def should_scan(self, file_path):
        """Determine if file needs scanning"""
        try:
            # Check if file exists and is not a directory
            if not os.path.isfile(file_path):
                return False
            

            
            # Check extension
            ext = os.path.splitext(file_path)[1].lower()
            if ext and ext not in self.monitored_extensions:
                # Only skip if extension is explicitly not monitored
                # But always scan files without extensions (potential malware)
                if ext:
                    return False
            
            # Check if path is excluded
            path_lower = os.path.normpath(file_path).lower()
            for excluded in self.excluded_paths:
                if excluded in path_lower:
                    return False
            
            # Check if recently scanned
            current_time = time.time()
            if file_path in self.processed_cache:
                if current_time - self.processed_cache[file_path] < self.cache_timeout:
                    return False
            
            # Skip temporary files
            temp_patterns = ['.tmp', '.temp', '.crdownload', '.part', '~']
            if any(file_path.lower().endswith(p) for p in temp_patterns):
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error checking file {file_path}: {e}")
            return False
    
    def on_created(self, event):
        """File/folder created - SCAN IMMEDIATELY"""
        if not event.is_directory:
            self.queue_file(event.src_path)
            self.show_system_notification(f"New file detected: {os.path.basename(event.src_path)}", "info")
    
    def on_modified(self, event):
        """File modified - scan if suspicious"""
        if not event.is_directory:
            # Only scan modified if it's an executable or script
            ext = os.path.splitext(event.src_path)[1].lower()
            if ext in ['.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.js']:
                self.queue_file(event.src_path)
    
    def on_moved(self, event):
        """File moved into monitored area"""
        if not event.is_directory:
            self.queue_file(event.dest_path)
            self.show_system_notification(f"File moved: {os.path.basename(event.dest_path)}", "info")
    
    def queue_file(self, file_path):
        """Add file to processing queue"""
        if self.should_scan(file_path):
            with self.queue_lock:
                if file_path not in self.scanning_queue:
                    self.scanning_queue.append(file_path)
                    self.processed_cache[file_path] = time.time()
                    logger.info(f"[Monitor] Queued for scan: {file_path}")
    
    def _process_queue(self):
        """Background thread to process queued files"""
        while True:
            try:
                file_to_scan = None
                with self.queue_lock:
                    if self.scanning_queue:
                        file_to_scan = self.scanning_queue.pop(0)
                
                if file_to_scan:
                    self.scan_file(file_to_scan)
                
                time.sleep(0.5)  # Small delay between scans
                
            except Exception as e:
                logger.error(f"Queue processor error: {e}")
                time.sleep(1)
    
    def scan_file(self, file_path):
        """Perform actual malware scan"""
        try:
            if not os.path.exists(file_path):
                return
            
            filename = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            
            logger.info(f"[Monitor] SCANNING: {filename} ({file_size} bytes)")
            
            # Send to Flask app for comprehensive scanning
            with open(file_path, 'rb') as f:
                files = {'file': (filename, f)}
                
                # Use longer timeout for larger files
                timeout = max(60, int(file_size / 1024 / 1024) * 5)  # 5 sec per MB
                
                response = requests.post(
                    f"{self.api_url}/api/auto_scan",
                    files=files,
                    timeout=timeout
                )
                
                if response.status_code == 200:
                    result = response.json()
                    self.handle_scan_result(file_path, filename, result)
                else:
                    logger.error(f"Scan API error: {response.status_code}")
                    
        except requests.exceptions.Timeout:
            logger.error(f"Scan timeout for {file_path}")
        except Exception as e:
            logger.error(f"Scan error for {file_path}: {e}")
    
    def handle_scan_result(self, file_path, filename, result):
        """Process scan results and take action"""
        risk_score = result.get('risk_score', 0)
        threat_level = result.get('threat_level', 'Unknown')
        status = result.get('status', 'Unknown')
        
        # Determine if threat
        is_threat = threat_level in ["Critical", "High", "Medium"]
        
        # Show notification based on threat level
        if is_threat:
            self.show_system_notification(
                f"⚠️ THREAT DETECTED: {filename}\n"
                f"Level: {threat_level} | Risk: {risk_score}%\n"
                f"Action: Review immediately!",
                "critical"
            )
            
            # Play alert sound if configured
            if self.config.get('alert_sound', True):
                self.play_alert_sound()
        else:
            if self.config.get('notify_safe', False):
                self.show_system_notification(
                    f"✓ Safe: {filename} is clean",
                    "info"
                )
        
        # Auto-quarantine for critical threats
        if threat_level == "Critical" and self.config.get('auto_quarantine', True):
            self.quarantine_file(file_path, filename, result)
        
        # Save to database via callback
        if self.db_callback:
            self.db_callback(filename, file_path, result)
        
        # Log to local security log
        self.log_to_security_log(filename, file_path, threat_level, risk_score, status)
        
        logger.info(f"[Monitor] Scan complete: {filename} - {threat_level} ({risk_score}%)")
    
    def quarantine_file(self, file_path, filename, result):
        """Move infected file to quarantine"""
        try:
            # Create quarantine folder on Desktop
            desktop = os.path.join(os.path.expanduser("~"), "Desktop")
            quarantine_folder = os.path.join(desktop, "TrustFile_Quarantine")
            os.makedirs(quarantine_folder, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_name = f"{timestamp}_{filename}"
            quarantine_path = os.path.join(quarantine_folder, quarantine_name)
            
            # Move file to quarantine
            shutil.move(file_path, quarantine_path)
            
            # Save metadata
            meta_path = quarantine_path + ".json"
            with open(meta_path, 'w') as f:
                json.dump({
                    'original_path': file_path,
                    'original_name': filename,
                    'quarantine_time': datetime.now().isoformat(),
                    'threat_level': result.get('threat_level'),
                    'risk_score': result.get('risk_score'),
                    'ai_analysis': result.get('ai_analysis')
                }, f, indent=2)
            
            logger.info(f"[Monitor] QUARANTINED: {filename}")
            self.show_system_notification(
                f"[QUARANTINED] {filename}\n"
                f"Threat: {result.get('threat_level')}\n"
                f"Location: {quarantine_folder}",
                "warning"
            )
            
        except Exception as e:
            logger.error(f"Quarantine failed for {filename}: {e}")
    
    def show_system_notification(self, message, level="info"):
        """Show native OS notification"""
        try:
            import platform
            system = platform.system()
            
            title = "TrustFile Security"
            if level == "critical":
                title = "[!] CRITICAL THREAT DETECTED"
            elif level == "warning":
                title = "TrustFile Alert"
            
            if system == "Windows":
                from win10toast import ToastNotifier
                toaster = ToastNotifier()
                toaster.show_toast(title, message, duration=10, threaded=True)
            elif system == "Darwin":  # macOS
                os.system(f'osascript -e \'display notification "{message}" with title "{title}"\'')
            else:  # Linux
                urgency = "critical" if level == "critical" else "normal"
                os.system(f'notify-send -u {urgency} "{title}" "{message}"')
                
        except Exception as e:
            logger.debug(f"Notification failed: {e}")
    
    def play_alert_sound(self):
        """Play alert sound for critical threats"""
        try:
            import platform
            if platform.system() == "Windows":
                import winsound
                winsound.MessageBeep(winsound.MB_ICONHAND)
        except:
            pass
    
    def log_to_security_log(self, filename, file_path, threat_level, risk_score, status):
        """Write to persistent security log"""
        log_file = os.path.join(os.path.expanduser("~"), "Desktop", "TrustFile_Security_Log.txt")
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {threat_level.upper()} | {risk_score}% | {status} | {filename} | {file_path}\n"
        
        try:
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry)
        except:
            pass


class FullSystemMonitor:
    """Main monitoring service"""
    
    def __init__(self, api_base_url="http://localhost:5000", config=None, db_callback=None):
        self.api_url = api_base_url
        self.config = config or {}
        self.db_callback = db_callback
        self.observers = []
        self.running = False
        self.event_handler = None
    
    def start(self):
        """Start monitoring all drives and critical folders"""
        self.event_handler = RealTimeSystemMonitor(self.api_url, self.config, self.db_callback)
        
        monitored_paths = self.event_handler.get_monitored_paths()
        
        logger.info("=" * 60)
        logger.info("[TrustFile] REAL-TIME PROTECTION ACTIVATED")
        logger.info("=" * 60)
        
        for path in monitored_paths:
            if os.path.exists(path):
                try:
                    observer = Observer()
                    observer.schedule(self.event_handler, path, recursive=True)
                    observer.start()
                    self.observers.append(observer)
                    logger.info(f"   [+] Monitoring: {path}")
                except PermissionError:
                    logger.info(f"   [!] Permission denied: {path}")
                except Exception as e:
                    logger.error(f"   ✗ Failed: {path} - {e}")
        
        self.running = True
        self.show_startup_notification()
        
        logger.info(f"\n Monitoring {len(self.observers)} locations")
        logger.info(f" Quarantine folder on Desktop")
        logger.info(f" Security log on Desktop")
        logger.info("=" * 60)
    
    def show_startup_notification(self):
        """Show Windows Defender-style startup notification"""
        try:
            from win10toast import ToastNotifier
            toaster = ToastNotifier()
            toaster.show_toast(
                "TrustFile Security",
                "Real-time protection is ACTIVE\nMonitoring your entire system for threats",
                duration=5,
                threaded=True
            )
        except:
            pass
    
    def stop(self):
        """Stop all monitoring"""
        for observer in self.observers:
            observer.stop()
            observer.join()
        self.running = False
        logger.info(" Real-time protection STOPPED")
    
    def get_status(self):
        """Get monitoring status"""
        return {
            'running': self.running,
            'monitored_paths': len(self.observers),
            'api_url': self.api_url,
            'config': self.config
        }

# Singleton for global access
_monitor_instance = None

def get_monitor():
    return _monitor_instance

def start_system_monitor(api_url, config, db_callback=None):
    global _monitor_instance
    if _monitor_instance:
        _monitor_instance.stop()
    
    _monitor_instance = FullSystemMonitor(api_url, config, db_callback)
    _monitor_instance.start()
    return _monitor_instance

def stop_system_monitor():
    global _monitor_instance
    if _monitor_instance:
        _monitor_instance.stop()
        _monitor_instance = None