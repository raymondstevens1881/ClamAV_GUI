# ClamAV GUI (macOS and Linux Supported, working on Windows support in a future update)

ClamAV GUI is a Python-based graphical user interface for **ClamAV**, a popular open-source antivirus engine. This project makes it easier to use ClamAV by providing an intuitive interface for scanning files, directories, and managing ClamAV functionalities.

## Features
- **User-Friendly Interface**: Built with Tkinter for simplicity and accessibility.

- **File Scanning**: Scan individual files for malware.
- **Directory Scanning**: Recursively scan directories for threats.
- **Application Window**: Shows which files are being scanned in directory.
- **Updated Interface**: Features a more modern look with changes to GUI.
- **Results in Real-Time**: Shows affected files in the user directory.
- **Customization Features**: Change the color of the progress bar, and change the appearance between light and dark.
- **Live File Count**: Shows affected files in the specific directory.
- **Live Progress Tracking**: Shows results for: Known viruses in the system, results in scanned directories,the number of files scanned, number of infected files found, and the data read and scanned by the application.

- **New Features: **
-    **Platform** was added to detect the user's operating system, which now includes support for Windows.
-    **Time** was added for managing scan duration and progress

## Requirements
- Python 3.8+
- ClamAV installed on your system
-    Windows users need to download ClamAV from the official website first **BEFORE** using this project.
-    Also works for macOS and Linux
- `Tkinter` (Python's built-in GUI library)
- `subprocess` (built into Python for calling ClamAV commands)
- `threading` (built into Python for scanning director[ies])
- `platform` (for detecting the operating system)
- `time` (for managing scan duration and progress)

## Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/raymondstevens1881/ClamAV_GUI.git
