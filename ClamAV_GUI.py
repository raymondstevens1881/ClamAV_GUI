import os
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, ttk, Menu

class ClamAVScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("ClamAV GUI")
        self.root.geometry("700x600")

        # Default color scheme
        self.bg_color = "#ffffff"
        self.fg_color = "#000000"
        self.progress_color = "#00bfff"

        # Configure theme
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.update_colors()

        # Menu Bar
        self.menu_bar = Menu(root)
        root.config(menu=self.menu_bar)

        self.settings_menu = Menu(self.menu_bar, tearoff=0)
        self.settings_menu.add_command(label="Dark Mode", command=self.dark_mode)
        self.settings_menu.add_command(label="Light Mode", command=self.light_mode)
        self.settings_menu.add_command(label="Change Progress Color", command=self.change_progress_color)
        self.menu_bar.add_cascade(label="Settings", menu=self.settings_menu)

        # Widgets
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

        # Results labels
        self.results_frame = ttk.Frame(root)
        self.results_frame.pack(pady=10, fill="x")
        
        self.results_labels = {}
        self.results_data = ["Known viruses", "Scanned directories", "Scanned files", "Infected files", "Data scanned", "Data read"]
        for item in self.results_data:
            frame = ttk.Frame(self.results_frame)
            frame.pack(fill="x", padx=10, pady=2)
            label = ttk.Label(frame, text=f"{item}:", width=20, anchor="w")
            label.pack(side="left")
            value = ttk.Label(frame, text="--", anchor="w")
            value.pack(side="left", fill="x", expand=True)
            self.results_labels[item] = value

        self.scanning = False

    def update_colors(self):
        """Update UI colors dynamically."""
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
        """Run the scan in a separate thread to prevent UI freezing."""
        threading.Thread(target=self.start_scan, daemon=True).start()

    def start_scan(self):
        self.scanning = True
        self.progress["value"] = 0
        self.progress_label.config(text="Progress: 0%")
        
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

        total_files = sum(len(files) for _, _, files in os.walk(scan_dir))  # Count total files
        scanned_count = 0

        EXCLUDED_KEYS = [
            "Known viruses", "Engine version", "Scanned directories",
            "Scanned files", "Infected files", "Data scanned",
            "Data read", "Time", "Start Date", "End Date"
        ]

        try:
            cmd = ["clamscan", "--recursive", scan_dir]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)

            scanned_files = set()
            
            for line in process.stdout:
                if not self.scanning:
                    process.terminate()
                    break

                if any(line.startswith(key) for key in EXCLUDED_KEYS):
                    continue  # Skip redundant summary lines

                if ":" in line:
                    filepath = line.split(":")[0].strip()
                    if filepath not in scanned_files:
                        scanned_files.add(filepath)
                        scanned_count += 1

                        self.file_list.config(state="normal")
                        self.file_list.insert(tk.END, filepath + "\n")
                        self.file_list.config(state="disabled")
                        self.file_list.see(tk.END)

                        # Update progress bar
                        progress_value = int((scanned_count / total_files) * 100) if total_files else 0
                        self.progress["value"] = progress_value
                        self.progress_label.config(text=f"Progress: {progress_value}%")

            process.wait()
            stdout_data, stderr_data = process.communicate()
            self.parse_scan_results(stdout_data + "\n" + stderr_data)

            if self.scanning:
                self.progress["value"] = 100
                self.progress_label.config(text="Scan Complete!")
        except Exception as e:
            self.progress_label.config(text=f"Error: {str(e)}")
        finally:
            self.scanning = False
            self.scan_button.config(state="normal")
            self.stop_button.config(state="disabled")

    def parse_scan_results(self, output):
        """Extract relevant scan results and update UI."""
        for line in output.split("\n"):
            for key in self.results_data:
                if line.startswith(key):
                    value = line.split(":")[-1].strip() or "--"
                    self.results_labels[key].config(text=value)
                    break

    def stop_scan(self):
        """Stop the scanning process."""
        self.scanning = False

if __name__ == "__main__":
    root = tk.Tk()
    app = ClamAVScanner(root)
    root.mainloop()
