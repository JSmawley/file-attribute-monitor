#!/usr/bin/env python3
"""
File Attribute Monitor (Windows Only for now)
This Python script  monitors file and folder attributes for changes on Windows systems.
Detects changes in permissions, attributes, deletion, creation and file content.
NOT RECOMMENDED FOR LARGE FILE SYSTEMS (TOO SLOW).
"""

import os
import sys
import json
import time
import logging
import stat
import hashlib
from pathlib import Path
from typing import Dict, Optional, Any
from datetime import datetime

if sys.platform == "win32":
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.detach())
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.detach())

import win32api
import win32con
import win32security

class ColoredConsoleHandler(logging.StreamHandler):
    """Custom logging handler that colors WARNING messages red."""
    
    def emit(self, record):
        try:
            msg = self.format(record)
            if record.levelname == 'WARNING':
                msg = f"\033[91m{msg}\033[0m"
            self.stream.write(msg + self.terminator)
            self.flush()
        except Exception:
            self.handleError(record)

class FileAttributeMonitor:
    """Monitors file and folder attributes for changes on Windows systems."""
    
    def __init__(self, directory: str, attr_file: str = "file_attributes.json", 
                 check_interval: int = 5, monitor_access_time: bool = False):
        """
        Initialize the file attribute monitor.
        
        Args:
            directory: Directory to monitor
            attr_file: File to store attribute database
            check_interval: Seconds between checks
            monitor_access_time: Whether to monitor access time changes (may cause feedback loop)
        """
        self.directory = Path(directory).resolve()
        self.attr_file = Path(attr_file)
        self.check_interval = check_interval
        self.monitor_access_time = monitor_access_time
        self.running = False

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('attribute_monitor.log', encoding='utf-8'),
                ColoredConsoleHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        self.file_attributes = self._load_attributes()
    
    def _load_attributes(self) -> Dict[str, Dict[str, Any]]:
        """Load existing file attributes from storage (if they exist)."""
        if self.attr_file.exists():
            try:
                with open(self.attr_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                self.logger.warning(f"Could not load existing attributes: {e}")
        return {}
    
    def _save_attributes(self) -> None:
        """Save current file attributes to storage."""
        try:
            with open(self.attr_file, 'w') as f:
                json.dump(self.file_attributes, f, indent=2)
        except IOError as e:
            self.logger.error(f"Could not save attributes: {e}")
    
    def _calculate_file_hash(self, file_path: Path) -> Optional[str]:
        """Calculate SHA256 hash of a file."""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except (IOError, OSError) as e:
            self.logger.error(f"Error calculating hash for {file_path}: {e}")
            return None
    
    def _format_sid(self, sid_str: str) -> str:
        """Convert SID to more readable format when possible."""
        try:
            if sid_str.startswith('PySID:'):
                sid_str = sid_str[6:]
            elif sid_str.startswith('S-1-'):
                pass
            else:
                import win32security
                sid_obj = win32security.ConvertStringSidToSid(sid_str)
                sid_str = str(sid_obj)
            
            import win32security
            account_name, domain, account_type = win32security.LookupAccountSid(None, sid_str)
            
            if domain and domain != account_name:
                return f"{domain}\\{account_name}"
            else:
                return account_name
        except Exception as e:
            return sid_str
    
    def _get_file_attributes(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Get comprehensive file/folder attributes."""
        try:
            stat_info = file_path.stat()
            
            attributes = {
                'is_file': file_path.is_file(),
                'is_dir': file_path.is_dir(),
                'size': stat_info.st_size,
                'mode': oct(stat_info.st_mode)[-3:],
                'permissions': stat.S_IMODE(stat_info.st_mode),
                'uid': stat_info.st_uid,
                'gid': stat_info.st_gid,
                'mtime': stat_info.st_mtime,
                'atime': stat_info.st_atime,
                'ctime': stat_info.st_ctime,
                'inode': stat_info.st_ino,
                'device': stat_info.st_dev,
                'nlink': stat_info.st_nlink,
            }  
            
            try:
                sd = win32security.GetFileSecurity(str(file_path), win32security.OWNER_SECURITY_INFORMATION)
                owner_sid = sd.GetSecurityDescriptorOwner()
                owner_name, _, _ = win32security.LookupAccountSid(None, owner_sid)
                attributes['owner'] = owner_name
            except:
                attributes['owner'] = f"uid_{stat_info.st_uid}"
            
            try:
                sd = win32security.GetFileSecurity(str(file_path), win32security.GROUP_SECURITY_INFORMATION)
                group_sid = sd.GetSecurityDescriptorGroup()
                group_name, _, _ = win32security.LookupAccountSid(None, group_sid)
                attributes['group'] = group_name
            except:
                attributes['group'] = f"gid_{stat_info.st_gid}"
            
            try:
                win_attrs = win32api.GetFileAttributes(str(file_path))
                attributes['win_attributes'] = {
                    'readonly': bool(win_attrs & win32con.FILE_ATTRIBUTE_READONLY),
                    'hidden': bool(win_attrs & win32con.FILE_ATTRIBUTE_HIDDEN),
                    'system': bool(win_attrs & win32con.FILE_ATTRIBUTE_SYSTEM),
                    'archive': bool(win_attrs & win32con.FILE_ATTRIBUTE_ARCHIVE),
                    'compressed': bool(win_attrs & win32con.FILE_ATTRIBUTE_COMPRESSED),
                    'encrypted': bool(win_attrs & win32con.FILE_ATTRIBUTE_ENCRYPTED),
                    'not_content_indexed': bool(win_attrs & win32con.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED),
                    'offline': bool(win_attrs & win32con.FILE_ATTRIBUTE_OFFLINE),
                    'temporary': bool(win_attrs & win32con.FILE_ATTRIBUTE_TEMPORARY),
                }
                
                try:
                    sd = win32security.GetFileSecurity(str(file_path), win32security.DACL_SECURITY_INFORMATION)
                    dacl = sd.GetSecurityDescriptorDacl()
                    
                    owner_sid = sd.GetSecurityDescriptorOwner()
                    group_sid = sd.GetSecurityDescriptorGroup()
                    
                    attributes['win_security'] = {
                        'owner_sid': str(owner_sid),
                        'group_sid': str(group_sid),
                        'dacl_present': dacl is not None,
                        'dacl_count': dacl.GetAceCount() if dacl else 0,
                    }
                    
                    if dacl:
                        aces = []
                        for i in range(dacl.GetAceCount()):
                            ace = dacl.GetAce(i)
                            ace_info = {
                                'type': ace[0][0],
                                'flags': ace[0][1],
                                'mask': ace[1],
                                'sid': str(ace[2])
                            }
                            aces.append(ace_info)
                        attributes['win_security']['aces'] = aces
                    
                except Exception as e:
                    self.logger.debug(f"Could not get detailed security info for {file_path}: {e}")
                    attributes['win_security'] = {'error': str(e)}
            except Exception as e:
                self.logger.debug(f"Could not get Windows attributes for {file_path}: {e}")
            
            attributes['mtime_readable'] = datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            attributes['atime_readable'] = datetime.fromtimestamp(stat_info.st_atime).strftime('%Y-%m-%d %H:%M:%S')
            attributes['ctime_readable'] = datetime.fromtimestamp(stat_info.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
            
            if file_path.is_file():
                file_hash = self._calculate_file_hash(file_path)
                if file_hash:
                    attributes['file_hash'] = file_hash
                else:
                    attributes['file_hash'] = "ERROR_CALCULATING_HASH"
            else:
                attributes['file_hash'] = "DIRECTORY"
            
            return attributes
            
        except (IOError, OSError, PermissionError) as e:
            self.logger.error(f"Error getting attributes for {file_path}: {e}")
            return None
    
    def _scan_directory(self) -> Dict[str, Dict[str, Any]]:
        """Scan directory and collect attributes for all files and folders."""
        current_attributes = {}
        
        excluded_files = {
            'file_attributes.json',
            'attribute_monitor.log',
            'FileAttributeMonitor.py',
            'file_hashes.json',
            'integrity_monitor.log',
            'FileIntegrityChecker.py'
        }
        
        try:
            for root, dirs, files in os.walk(self.directory):
                for file in files:
                    file_path = Path(root) / file
                    try:
                        if file_path.name in excluded_files:
                            continue
                        
                        if file_path == self.attr_file:
                            continue
                        
                        attrs = self._get_file_attributes(file_path)
                        if attrs:
                            rel_path = file_path.relative_to(self.directory)
                            current_attributes[str(rel_path)] = attrs
                    except Exception as e:
                        self.logger.error(f"Error processing {file_path}: {e}")
                
                for dir_name in dirs:
                    dir_path = Path(root) / dir_name
                    try:
                        if dir_name in excluded_files:
                            continue
                        
                        attrs = self._get_file_attributes(dir_path)
                        if attrs:
                            rel_path = dir_path.relative_to(self.directory)
                            current_attributes[f"{str(rel_path)}/"] = attrs
                    except Exception as e:
                        self.logger.error(f"Error processing directory {dir_path}: {e}")
                        
        except Exception as e:
            self.logger.error(f"Error scanning directory {self.directory}: {e}")
        
        return current_attributes
    
    def _detect_changes(self, current_attributes: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Detect changes between current and stored attributes."""
        changes = {}
        
        for file_path, current_attrs in current_attributes.items():
            if file_path in self.file_attributes:
                stored_attrs = self.file_attributes[file_path]
                attribute_changes = {}
                
                skip_attributes = set()
                if not self.monitor_access_time:
                    skip_attributes = {'atime', 'atime_readable'}
                
                for attr_name, current_value in current_attrs.items():
                    if attr_name in skip_attributes:
                        continue
                        
                    if attr_name in stored_attrs:
                        if stored_attrs[attr_name] != current_value:
                            attribute_changes[attr_name] = {
                                'old': stored_attrs[attr_name],
                                'new': current_value
                            }
                    else:
                        attribute_changes[attr_name] = {
                            'old': None,
                            'new': current_value
                        }
                
                for attr_name, stored_value in stored_attrs.items():
                    if attr_name not in current_attrs and attr_name not in skip_attributes:
                        attribute_changes[attr_name] = {
                            'old': stored_value,
                            'new': None
                        }
                
                if attribute_changes:
                    if file_path.endswith('/'):
                        changes[file_path] = {
                            'type': 'MODIFIED_DIRECTORY',
                            'changes': attribute_changes
                        }
                    else:
                        changes[file_path] = {
                            'type': 'MODIFIED',
                            'changes': attribute_changes
                        }
            else:
                if file_path.endswith('/'):
                    changes[file_path] = {
                        'type': 'NEW_DIRECTORY',
                        'changes': {attr: {'old': None, 'new': value} for attr, value in current_attrs.items()}
                    }
                else:
                    changes[file_path] = {
                        'type': 'NEW',
                        'changes': {attr: {'old': None, 'new': value} for attr, value in current_attrs.items()}
                    }
        
        for file_path in self.file_attributes:
            if file_path not in current_attributes:
                if file_path.endswith('/'):
                    changes[file_path] = {
                        'type': 'DELETED_DIRECTORY',
                        'changes': {attr: {'old': value, 'new': None} for attr, value in self.file_attributes[file_path].items()}
                    }
                else:
                    changes[file_path] = {
                        'type': 'DELETED',
                        'changes': {attr: {'old': value, 'new': None} for attr, value in self.file_attributes[file_path].items()}
                    }
        
        return changes
    
    def _format_attribute_change(self, attr_name: str, change_info: Dict[str, Any]) -> str:
        """Format an attribute change for display."""
        old_val = change_info.get('old')
        new_val = change_info.get('new')
        
        if attr_name in ['mtime', 'atime', 'ctime']:
            if old_val:
                old_val = datetime.fromtimestamp(old_val).strftime('%Y-%m-%d %H:%M:%S')
            if new_val:
                new_val = datetime.fromtimestamp(new_val).strftime('%Y-%m-%d %H:%M:%S')
        elif attr_name == 'mode':
            if old_val:
                old_val = f"0o{old_val}"
            if new_val:
                new_val = f"0o{new_val}"
        elif attr_name == 'permissions':
            if old_val:
                old_val = f"0o{oct(old_val)[-3:]}"
            if new_val:
                new_val = f"0o{oct(new_val)[-3:]}"
        elif attr_name == 'win_attributes':
            if old_val and new_val and isinstance(old_val, dict) and isinstance(new_val, dict):
                changed_attrs = []
                for key in set(old_val.keys()) | set(new_val.keys()):
                    old_attr = old_val.get(key, False)
                    new_attr = new_val.get(key, False)
                    if old_attr != new_attr:
                        changed_attrs.append(f"  ~ {key}: {old_attr} -> {new_attr}")
                
                if changed_attrs:
                    return "\n".join(changed_attrs)
                else:
                    return f"  ~ {attr_name}: {old_val} -> {new_val}"
        elif attr_name == 'win_security':
            if old_val and new_val and isinstance(old_val, dict) and isinstance(new_val, dict):
                changed_attrs = []
                
                for key in ['owner_sid', 'group_sid', 'dacl_present', 'dacl_count']:
                    if key in old_val and key in new_val and old_val[key] != new_val[key]:
                        changed_attrs.append(f"  ~ {key}: {old_val[key]} -> {new_val[key]}")
                
                if 'aces' in old_val and 'aces' in new_val:
                    old_aces = old_val['aces']
                    new_aces = new_val['aces']
                    if old_aces != new_aces:
                        changed_attrs.append(f"  ~ aces: {len(old_aces)} entries -> {len(new_aces)} entries")
                        
                        if len(old_aces) != len(new_aces):
                            changed_attrs.append(f"    (ACE count changed: {len(old_aces)} -> {len(new_aces)})")
                            
                            if len(new_aces) > len(old_aces):
                                for i in range(len(old_aces), len(new_aces)):
                                    ace = new_aces[i]
                                    readable_sid = self._format_sid(ace['sid'])
                                    changed_attrs.append(f"    + Added ACE {i+1}: {readable_sid} (type={ace['type']}, mask={ace['mask']})")
                            else:
                                for i in range(len(new_aces), len(old_aces)):
                                    ace = old_aces[i]
                                    readable_sid = self._format_sid(ace['sid'])
                                    changed_attrs.append(f"    - Removed ACE {i+1}: {readable_sid} (type={ace['type']}, mask={ace['mask']})")
                        else:
                            for i, (old_ace, new_ace) in enumerate(zip(old_aces, new_aces)):
                                if old_ace != new_ace:
                                    old_readable = self._format_sid(old_ace['sid'])
                                    new_readable = self._format_sid(new_ace['sid'])
                                    changed_attrs.append(f"    ~ ACE {i+1} changed:")
                                    changed_attrs.append(f"      Old: {old_readable} (type={old_ace['type']}, mask={old_ace['mask']})")
                                    changed_attrs.append(f"      New: {new_readable} (type={new_ace['type']}, mask={new_ace['mask']})")
                
                if changed_attrs:
                    return "\n".join(changed_attrs)
                else:
                    return f"  ~ {attr_name}: {old_val} -> {new_val}"
        
        if old_val is None:
            return f"  + {attr_name}: {new_val}"
        elif new_val is None:
            return f"  - {attr_name}: {old_val}"
        else:
            return f"  ~ {attr_name}: {old_val} -> {new_val}"
    
    def run_initial_scan(self) -> None:
        """Run initial scan to establish baseline attributes."""
        self.logger.info(f"Running initial scan of {self.directory}")
        current_attributes = self._scan_directory()
        
        if not current_attributes:
            self.logger.warning("No files found in directory")
            return
        
        self.file_attributes = current_attributes
        self._save_attributes()
        
        self.logger.info(f"Initial scan complete. Found {len(current_attributes)} files and directories.")
    
    def run_monitoring(self) -> None:
        """Run continuous monitoring."""
        self.running = True
        self.logger.info(f"Starting file attribute monitoring of {self.directory}")
        self.logger.info(f"Check interval: {self.check_interval} seconds")
        
        try:
            first_scan = True
            while self.running:
                current_attributes = self._scan_directory()
                
                changes = self._detect_changes(current_attributes)
                
                if changes:
                    if not first_scan:
                        self.logger.warning("******************************************************\n")
                    
                    self.logger.warning(f"Detected {len(changes)} changes:")
                    for i, (file_path, change_info) in enumerate(changes.items()):
                        if i > 0:
                            self.logger.warning("******************************************************\n")
                        
                        change_type = change_info['type']
                        self.logger.warning(f"{change_type}: {file_path}")
                        
                        if 'file_hash' in change_info['changes']:
                            hash_change = change_info['changes']['file_hash']
                            old_hash = hash_change.get('old', 'N/A')
                            new_hash = hash_change.get('new', 'N/A')
                            if old_hash != 'N/A' and new_hash != 'N/A':
                                self.logger.warning(f"  HASH COMPARISON:")
                                self.logger.warning(f"    Old Hash: {old_hash}")
                                self.logger.warning(f"    New Hash: {new_hash}")
                        
                        for attr_name, attr_change in change_info['changes'].items():
                            if attr_name != 'file_hash': 
                                formatted_change = self._format_attribute_change(attr_name, attr_change)
                                for line in formatted_change.split('\n'):
                                    self.logger.warning(line)
                    
                    self.file_attributes = current_attributes
                    self._save_attributes()
                else:
                    self.logger.debug("No changes detected")
                
                first_scan = False
                time.sleep(self.check_interval)
                
        except KeyboardInterrupt:
            self.logger.info("Monitoring stopped by user")
        except Exception as e:
            self.logger.error(f"Error during monitoring: {e}")
        finally:
            self.running = False

def get_directory_input():
    """Get directory path from user input with validation."""
    while True:
        print("\n" + "="*60)
        print("FILE ATTRIBUTE MONITOR")
        print("="*60)
        
        directory = input("\nEnter the directory path to monitor: ").strip()

        if not directory:
            print("Error: Please enter a directory path.")
            continue

        if directory.startswith('"') and directory.endswith('"'):
            directory = directory[1:-1]
        elif directory.startswith("'") and directory.endswith("'"):
            directory = directory[1:-1]

        if directory.startswith("~"):
            directory = os.path.expanduser(directory)
        elif not os.path.isabs(directory):
            directory = os.path.abspath(directory)

        if not os.path.exists(directory):
            print(f"Error: Directory '{directory}' does not exist.")
            retry = input("Try again? (y/n): ").strip().lower()
            if retry != 'y':
                return None
            continue
        
        if not os.path.isdir(directory):
            print(f"Error: '{directory}' is not a directory.")
            retry = input("Try again? (y/n): ").strip().lower()
            if retry != 'y':
                return None
            continue

        return directory

def get_monitoring_options():
    """Get monitoring options from user."""
    print("\n" + "-"*40)
    print("MONITORING OPTIONS")
    print("-"*40)
    
    while True:
        try:
            interval_input = input(f"Check interval in seconds (default: 5): ").strip()
            if not interval_input:
                interval = 5
                break
            interval = int(interval_input)
            if interval < 1:
                print("Error: Interval must be at least 1 second.")
                continue
            break
        except ValueError:
            print("Error: Please enter a valid number.")
    
    init_only_input = input("Run initial scan only? (y/n, default: n): ").strip().lower()
    init_only = init_only_input == 'y'
    
    return {
        'interval': interval,
        'init_only': init_only
    }

def main():
    try:
        directory = get_directory_input()
        if directory is None:
            print("Exiting...")
            return
        
        options = get_monitoring_options()

        print("\n" + "="*60)
        print("CONFIGURATION")
        print("="*60)
        print(f"Directory: {directory}")
        print(f"Check interval: {options['interval']} seconds")
        print(f"Attribute file: file_attributes.json")
        print(f"Mode: {'Initial scan only' if options['init_only'] else 'Continuous monitoring'}")
        print("="*60)

        if not options['init_only']:
            confirm = input("\nStart monitoring? (y/n, default: y): ").strip().lower()
            if confirm and confirm != 'y':
                print("Monitoring cancelled.")
                return

        monitor = FileAttributeMonitor(
            directory=directory,
            attr_file="file_attributes.json",
            check_interval=options['interval']
        )
        
        if options['init_only']:
            monitor.run_initial_scan()
            print("\nInitial scan completed successfully!")
        else:
            print("\nEstablishing baseline file attributes...")
            monitor.run_initial_scan()
            
            print(f"\nStarting file attribute monitoring...")
            print("Press Ctrl+C to stop monitoring.")
            monitor.run_monitoring()

    except KeyboardInterrupt:
        print("\n\nMonitoring stopped by user.")
    except Exception as e:
        print(f"\nError: {e}")
        input("Press Enter to exit...")
        sys.exit(1)

if __name__ == "__main__":
    main()
