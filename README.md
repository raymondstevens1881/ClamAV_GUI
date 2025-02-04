# ClamAV GUI

ClamAV GUI is a Python-based graphical user interface for **ClamAV**, a popular open-source antivirus engine. This project makes it easier to use ClamAV by providing an intuitive interface for scanning files, directories, and managing ClamAV functionalities.

## Features
- **User-Friendly Interface**: Built with Tkinter for simplicity and accessibility.

- **File Scanning**: Scan individual files for malware.
- **Directory Scanning**: Recursively scan directories for threats.
- **Updated Interface**: Features a more modern look with changes to GUI
- **Results in Real-Time**: Shows affected files in the user directory
- **Customization Features**: Change the color of the progress bar, and change the appearance between light and dark
- **Live File Count**: Shows affected files in the specific directory

## Requirements
- Python 3.8+
- ClamAV installed on your system
- `Tkinter` (Python's built-in GUI library)
- `subprocess` (built into Python for calling ClamAV commands)
- `threading` (built into Python for scanning director[ies])

## Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/raymondstevens1881/ClamAV_GUI.git
