# File Attribute Monitor

A Python script that monitors file and folder attributes for changes on Windows systems.

## What it does

- Monitors file and folder attributes for changes
- Detects changes in permissions, Windows attributes, and file content
- Tracks file creation, modification, and deletion
- Provides detailed logging of all changes with timestamps

## Requirements

- **Windows only** - This script is designed specifically for Windows systems
- Python 3.x
- Windows-specific modules: `win32api`, `win32con`, `win32security`

## Installation

```bash
pip install pywin32
```

## Usage

1. Run the script:
   ```bash
   python FileAttributeMonitor.py
   ```

2. Enter the directory path you want to monitor when prompted

3. Choose monitoring options:
   - Check interval (default: 5 seconds)
   - Run initial scan only or continuous monitoring (default: continuous monitoring)

4. The script will create:
   - `file_attributes.json` - Database of file attributes
   - `attribute_monitor.log` - Log file with all changes

## Important Warnings

**Windows Only**: This script is only intended for Windows systems and will not work on other operating systems.

**Small File Systems Only**: This script is NOT RECOMMENDED FOR LARGE FILE SYSTEMS as it can be very slow. It's intended for small to medium folder structures until it can be optimized for better performance.

## Output

The script logs all detected changes to both the console and the log file. Changes include:
- File/folder creation, modification, and deletion
- Permission changes
- Attribute changes (hidden, readonly, etc.)
- File content changes (via hash comparison)
- Security descriptor changes

## Stopping the Script

Press `Ctrl+C` to stop the monitoring process.
