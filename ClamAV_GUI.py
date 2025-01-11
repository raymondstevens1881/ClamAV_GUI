import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from tkinter import tkk
import subprocess

def start_scan():
	# Clear the log output #
	
	output_area.delete("1.0", tk.END)

# Get a directory to scan #
	scan_dir = filedialog.askdirectory(title="Select Directory to Scan: ")
	if not scan_dir:
		return_event

# Run clamscan as subprocess #
	try:
		process = subprocess.Popen(
			["clamscan", "-r", scan_dir],
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE,
			text=True
			)

		# Display output in real time #
		for line in process.stdout:
			output_area.insert(tk.END, line)
			output_area.see(tk.END)
		process.wait()
		messagebox.showinfo("Scan Complete", "ClamAV scan finished.")
	except Exception as e:
		messagebox.showerror("Error", f"An error occurred: {str(e)}")

def update_database():
	try:
		process = subprocess.run(
			["freshclam"],
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE,
			text=True
		)
		messagebox.showinfo("Update Complete", process.stdout)
	except Exception as e:
		messagebox.showerror("Error", f"An error  occurred: {str(e)})


# Main GUI #
root = tk.Tk()
root.title("Clam AV GUI")
root.geometry("800x600")

# Buttons #
btn_frame = tk.Frame(root)
btn_frame.pack(pady=10)

tk.Button(btn_frame, text="Start Scan", command=start_scan, width=15).grid(row=0, column=0, padx=5)
tk.Button(btn_frame, text="Update Database", command=update_database, width=15).grid(row=0, column=1. padx=5)

# Log Area #
output_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height 30)
output_area.pack(pady=10)

root.mainloop()
