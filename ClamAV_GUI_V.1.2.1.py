import os
import subprocess
import threading
import platform
import time
import tkinter as tk
from tkinter import filedialog, ttk, Menu

class ClamAVScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("ClamAV GUI")
        self.root.geometry("700x600")

        self.bg_color = "#ffffff"
        self.fg_color = "#000000"
        self.progress_color = "#00bfff"

        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.update_colors()

        self.menu_bar = Menu(root)
        root.config(menu=self.menu_bar)

        self.settings_menu = Menu(self.menu_bar, tearoff=0)
        self.settings_menu.add_command(label="Dark Mode", command=self.dark_mode)
        self.settings_menu.add_command(label="Light Mode", command=self.light_mode)
        self.settings_menu.add_command(label="Change Progress Color", command=self.change_progress_color)
        self.menu_bar.add_cascade(label="Settings", menu=self.settings_menu)

        self.label = ttk.Label(root, text="Select a directory to scan:")
        self.label.pack(pady=10)

        self.progress = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate", style="Custom.Horizontal.TProgressbar")
        self.progress.pack(pady=20)

        self.progress_label = ttk.Label(root, text="Progress: 0%")
        self.progress_label.pack()

        self.file_list = tk.Text(root, height=10, wrap="word", state="disabled")
        self.file_list.pack(pady=10, padx=10, fill="both", expand=True)

        self.scan_button = ttk.Button(root, text="Start Scan", command=self.start_scan_thread)
        self.scan_button.pack(pady=5)

        self.stop_button = ttk.Button(root, text="Stop Scan", command=self.stop_scan, state="disabled")
        self.stop_button.pack(pady=5)

        self.results_frame = ttk.Frame(root)
        self.results_frame.pack(pady=10, fill="x")

        self.results_labels = {}
        self.results_data = [
            "Infected files", "Scanned files", "Scanned directories",
            "Total files", "Total directories"
        ]
        for item in self.results_data:
            frame = ttk.Frame(self.results_frame)
            frame.pack(fill="x", padx=10, pady=2)
            label = ttk.Label(frame, text=f"{item}:", width=20, anchor="w")
            label.pack(side="left")
            value = ttk.Label(frame, text="--", anchor="w")
            value.pack(side="left", fill="x", expand=True)
            self.results_labels[item] = value

        self.scanning = False
        self.total_files = 1  
        self.scanned_files = 1
        self.scanned_dirs = 1
        self.start_time = None
        self.infected_count = 0

    def update_colors(self):
        self.root.configure(bg=self.bg_color)
        self.style.configure("TLabel", background=self.bg_color, foreground=self.fg_color)
        self.style.configure("TButton", background=self.bg_color, foreground=self.fg_color)
        self.style.configure("Custom.Horizontal.TProgressbar", troughcolor=self.bg_color, background=self.progress_color)

    def dark_mode(self):
        self.bg_color = "#1e1e1e"
        self.fg_color = "#ffffff"
        self.update_colors()

    def light_mode(self):
        self.bg_color = "#ffffff"
        self.fg_color = "#000000"
        self.update_colors()

    def change_progress_color(self):
        colors = ["#00bfff", "#ff4500", "#32cd32", "#ff1493"]
        self.progress_color = colors[(colors.index(self.progress_color) + 1) % len(colors)]
        self.update_colors()

    def start_scan_thread(self):
        """Start the scan in a separate thread to prevent blocking the GUI."""
        self.scan_thread = threading.Thread(target=self.start_scan, daemon=True)
        self.scan_thread.start()

    def start_scan(self):
        """Run the ClamAV scan with real-time updates."""
        self.scanning = True
        self.progress["value"] = 0
        self.progress_label.config(text="Progress: 0%")

        # Reset UI results
        for label in self.results_labels.values():
            label.config(text="--")

        self.file_list.config(state="normal")
        self.file_list.delete(1.0, tk.END)
        self.file_list.config(state="disabled")

        self.scan_button.config(state="disabled")
        self.stop_button.config(state="normal")

        scan_dir = filedialog.askdirectory(title="Select Directory to Scan")
        if not scan_dir:
            self.scan_button.config(state="normal")
            self.stop_button.config(state="disabled")
            return

        # Count total files and directories
        total_files = sum(len(files) for _, _, files in os.walk(scan_dir))
        total_dirs = sum(1 for _, dirs, _ in os.walk(scan_dir))

        self.scanned_count = 0
        self.scanned_dirs = set()
        self.start_time = time.time()

        # Ignore lines with these keywords
        ignore_keywords = [
            "Known viruses", "Engine version", "Scanned directories",
            "Scanned files", "Data scanned", "Data read", "Time", "Signatures",
            "Infected files", "Start Date", "End Date"
        ]

        # Detect OS and use the correct ClamAV command
        is_windows = platform.system() == "Windows"
        clam_cmd = "clamscan.exe" if is_windows else "clamscan"

        try:
            cmd = [clam_cmd, "--recursive", scan_dir]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)

            scanned_files = set()

            for line in process.stdout:
                if not self.scanning:
                    process.terminate()
                    break

                line = line.strip()

                # Ignore summary lines and metadata
                if any(keyword in line for keyword in ignore_keywords):
                    continue  

                # Process scanned files
                if ":" in line:
                    filepath = line.split(":")[0].strip()

                    if os.path.isdir(filepath):
                        self.scanned_dirs.add(filepath)

                    if filepath not in scanned_files:
                        scanned_files.add(filepath)
                        self.scanned_count += 1

                        self.file_list.config(state="normal")
                        self.file_list.insert(tk.END, filepath + "\n")
                        self.file_list.config(state="disabled")
                        self.file_list.see(tk.END)

                        # Update live progress
                        self.update_live_progress(total_files)

            process.wait()
            stdout_data, stderr_data = process.communicate()

            # Final result parsing
            self.parse_scan_results(stdout_data + "\n" + stderr_data, total_files, total_dirs)

            if self.scanning:
                self.progress["value"] = 100
                self.progress_label.config(text="Scan Complete!")

        except Exception as e:
            print(f"Error: {e}")  # Print error details for debugging
            self.progress_label.config(text=f"Error: {str(e)}")
        finally:
            self.scanning = False
            self.scan_button.config(state="normal")
            self.stop_button.config(state="disabled")

    def update_live_progress(self, total_files):
        """Update the live progress and scanned counts."""
        progress_value = int((self.scanned_count / total_files) * 100) if total_files else 0
        self.root.after(0, lambda: self.progress.config(value=progress_value))  # Update on main thread
        self.root.after(0, lambda: self.progress_label.config(text=f"Progress: {progress_value}%"))  # Update on main thread
        self.root.after(0, lambda: self.results_labels["Scanned files"].config(text=str(self.scanned_count)))  # Update on main thread
        self.root.after(0, lambda: self.results_labels["Scanned directories"].config(text=str(len(self.scanned_dirs))))  # Update on main thread

    def parse_scan_results(self, output, total_files, total_dirs):
        """Extract and display all scan results."""
        end_time = time.time()
        scan_duration = round(end_time - self.start_time, 2)
        infected_count = 0

        for line in output.split("\n"):
            if "Infected files" in line:
                infected_count = int(line.split(":")[-1].strip()) or 0

        # Update results after the scan
        self.root.after(0, lambda: self.results_labels["Infected files"].config(text=str(infected_count)))  # Update on main thread
        self.root.after(0, lambda: self.results_labels["Total files"].config(text=str(total_files)))  # Update on main thread
        self.root.after(0, lambda: self.results_labels["Total directories"].config(text=str(total_dirs)))  # Update on main thread
        self.root.after(0, lambda: self.results_labels["Scan time"].config(text=f"{scan_duration} seconds"))  # Update on main thread

    def stop_scan(self):
        self.scanning = False

if __name__ == "__main__":
    root = tk.Tk()
    scanner = ClamAVScanner(root)
    root.mainloop()
