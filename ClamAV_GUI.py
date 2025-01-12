import os
import subprocess
import threading
from tkinter import Tk, filedialog, ttk, Label, Button


class ClamAVScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("ClamAV GUI")
        self.root.geometry("500x300")

        self.label = Label(root, text="Select a directory to scan:")
        self.label.pack(pady=10)

        self.progress = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate")
        self.progress.pack(pady=20)

        self.progress_label = Label(root, text="Progress: 0%")
        self.progress_label.pack()

        self.scan_button = Button(root, text="Start Scan", command=self.start_scan_thread)
        self.scan_button.pack(pady=10)

        self.stop_button = Button(root, text="Stop Scan", command=self.stop_scan, state="disabled")
        self.stop_button.pack(pady=10)

        self.scanning = False

    def start_scan_thread(self):
        # Use a thread to prevent UI freezing
        threading.Thread(target=self.start_scan).start()

    def start_scan(self):
        # Reset progress
        self.scanning = True
        self.progress["value"] = 0
        self.progress_label.config(text="Progress: 0%")
        self.scan_button.config(state="disabled")
        self.stop_button.config(state="normal")

        scan_dir = filedialog.askdirectory(title="Select Directory to Scan")
        if not scan_dir:
            self.scan_button.config(state="normal")
            self.stop_button.config(state="disabled")
            return

        try:
            # Calculate total files upfront for progress calculation
            total_files = sum(len(files) for _, _, files in os.walk(scan_dir))
            print(f"Total files to scan: {total_files}")  # Debugging

            if total_files == 0:
                self.progress_label.config(text="No files to scan.")
                self.scan_button.config(state="normal")
                self.stop_button.config(state="disabled")
                return

            cmd = ["clamscan", "--recursive", scan_dir]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            scanned_files = set()  # Use a set to avoid duplicate file counting
            for line in process.stdout:
                if not self.scanning:  # Stop if the scan was interrupted
                    process.terminate()
                    break

                if ":" in line:  # Process lines indicating scanned files
                    filepath = line.split(":")[0].strip()  # Extract file path
                    if filepath not in scanned_files:
                        scanned_files.add(filepath)  # Add to set to prevent duplicates
                        progress = (len(scanned_files) / total_files) * 100
                        self.progress["value"] = progress
                        self.progress_label.config(text=f"Progress: {int(progress)}%")

            process.wait()  # Ensure the subprocess finishes
            self.progress_label.config(text="Scan Complete!" if self.scanning else "Scan Stopped")
        except Exception as e:
            self.progress_label.config(text=f"Error: {str(e)}")
            print(f"Exception: {e}")  # Debugging
        finally:
            self.scanning = False
            self.scan_button.config(state="normal")
            self.stop_button.config(state="disabled")

    def stop_scan(self):
        self.scanning = False


# Run the application
if __name__ == "__main__":
    root = Tk()
    app = ClamAVScanner(root)
    root.mainloop()
