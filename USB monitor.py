import wmi
import ctypes
import logging
import time
import os
import hashlib
import json
import datetime
from plyer import notification  # For system tray notifications (pip install plyer)
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.platypus import Table, TableStyle
import threading
import pythoncom
from queue import Queue
import queue


event_queue = Queue()
# Configurations
MALICIOUS_HASH_DB = "malicious_hashes.json"
LOG_FILE = "usb_monitor_debug.log"
SCAN_REPORTS_FILE = "scan_reports.json"
ALLOWED_EXTENSIONS = {'.exe', '.dll', '.doc', '.docx', '.xls', '.xlsx', '.pdf', '.txt'}

# Setup Logging
logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG, format='%(asctime)s - %(message)s')

# Global dictionary to hold watchdog observers per USB drive
usb_monitors = {}

def list_existing_usb_drives():
    return [p.device for p in psutil.disk_partitions() if 'removable' in p.opts]

def notify_user(title, message):
    try:
        notification.notify(title=title, message=message, timeout=5)
    except Exception as e:
        logging.warning(f"Notification failed: {e}")

def load_malicious_hashes():
    try:
        with open("malicious_hashes.json", "r") as f:
            hashes = json.load(f)
            print(f"[INFO] Loaded {len(hashes)} malicious hashes.")
            return hashes
    except Exception as e:
        print(f"[ERROR] Could not load malicious hashes: {e}")
        return []

def calculate_sha256(file_path):
    try:
        with open(file_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        print(f"[ERROR] Failed to hash {file_path}: {e}")
        return None


def is_relevant_file(file_path):
    excluded = ('.tmp', '.log', '.bak', '.dll', '.sys', '.exe')
    if file_path.lower().endswith(excluded):
        print(f"[SKIP] Excluded file: {file_path}")
        return False
    return True


def save_scan_report(drive, total, malicious_files,scanned_files):
    
    report = {
        "drive": drive,
        #"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_files_scanned": total,
        "malicious_files": malicious_files
    }
    report["scanned_files"] = scanned_files  # A list like ["file1.txt", "file2.docx"]

    try:
        with open(SCAN_REPORTS_FILE, "a") as f:
            json.dump(report, f)
            f.write("\n")
    except Exception as e:
        logging.error(f"Failed to write scan report: {e}")

def scan_usb_drive(drive_path):
    logging.info(f"Started scanning USB drive: {drive_path}")
    print(f"[SCAN] Scanning USB drive: {drive_path}")
    event_queue.put(("log", f"Started scanning USB drive: {drive_path}"))

    malicious_hashes = load_malicious_hashes()
    print(f"[INFO] Malicious hashes loaded: {len(malicious_hashes)}")

    total_files = 0
    malicious_files = []
    scanned_files = []
    scanned_file_paths = []
    for root, dirs, files in os.walk(drive_path):
        print(f"[DIR] Scanning folder: {root}")
        for file in files:
            file_path = os.path.join(root, file)
            scanned_file_paths.append(file_path)
            if not os.path.isfile(file_path):
                continue

            if not is_relevant_file(file_path):
                continue

            print(f"[Scanning] {file_path}")
            hash_val = calculate_sha256(file_path)
            if hash_val is None:
                print(f"[SKIP] Could not hash: {file_path}")
                continue

            total_files += 1
            scanned_files.append(file_path)

            if hash_val in malicious_hashes:
                malicious_files.append(file_path)
                logging.warning(f"Malicious file detected: {file_path}")
                print(f"[ALERT] Malicious file: {file_path}")

    for sf in scanned_files:
        logging.info(f"Scanned: {sf}")

    logging.info(f"Scan Complete: {total_files} files scanned. {len(malicious_files)} malicious files found.")
    if malicious_files:
        notify_user("USB Malware Alert", f"{len(malicious_files)} malicious file(s) found on {drive_path}!")

    save_scan_report(drive_path, total_files, malicious_files,scanned_file_paths)
    event_queue.put(("scan_result", {
        "drive": drive_path,
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total": total_files,
        "malicious": len(malicious_files)
    }))

    event_queue.put(("log", f"Scan Complete: {total_files} files scanned. {len(malicious_files)} malicious files found."))



class USBFileWriteHandler(FileSystemEventHandler):
    def __init__(self, drive_path):
        super().__init__()
        self.drive_path = drive_path

    def on_created(self, event):
        if not event.is_directory:
            logging.info(f"[COPY] File copied to USB: {event.src_path}")
            print(f"[copy]File copied to Usb:{event.src_path}")
            notify_user("File Copied to USB", f"File: {os.path.basename(event.src_path)}")

    def on_modified(self, event):
        if not event.is_directory:
            logging.info(f"[MODIFY] File modified on USB: {event.src_path}")

def start_usb_write_monitor(drive_path):
    event_handler = USBFileWriteHandler(drive_path)
    observer = Observer()
    observer.schedule(event_handler, drive_path, recursive=True)
    observer.start()
    logging.info(f"Started monitoring write activity on {drive_path}")
    return observer

def detect_usb_insertion():
    pythoncom.CoInitialize()  # <--- Initialize COM in this thread at the very start

    scanned_drives = set()
    for drive in list_existing_usb_drives():
        print(f"[STARTUP SCAN] Found USB Drive: {drive}")
        logging.info(f"Startup USB Detected: {drive}")
        scanned_drives.add(drive)
        scan_usb_drive(drive)
        observer = start_usb_write_monitor(drive)
        usb_monitors[drive] = observer

    c = wmi.WMI()
    try:
        watcher = c.Win32_DeviceChangeEvent.watch_for()
        while True:
            event = watcher()
            logging.info(f"Device change event detected at {timestamp}")
            current_drives = set(list_existing_usb_drives())

            new_drives = current_drives - scanned_drives
            for drive in new_drives:
                logging.info(f"New USB inserted: {drive}")
                scan_usb_drive(drive)
                observer = start_usb_write_monitor(drive)
                usb_monitors[drive] = observer
                scanned_drives.add(drive)

            removed_drives = scanned_drives - current_drives
            for drive in removed_drives:
                if drive in usb_monitors:
                    logging.info(f"USB Removed: {drive}")
                    usb_monitors[drive].stop()
                    usb_monitors[drive].join()
                    del usb_monitors[drive]
                scanned_drives.remove(drive)

    except Exception as e:
        logging.error(f"WMI watcher error: {e}")
    finally:
        pythoncom.CoUninitialize()  # <--- Optional: uninitialize COM on thread exit


class USBMonitorDashboard(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("USB Monitor Dashboard")
        self.geometry("950x600")
        self.configure(bg="#f0f0f0")
        self.scan_data = []
        self.scan_file_details = {}  # key: tree item ID, value: list of scanned files
        self.create_widgets()
        self.load_scan_reports()
        self.load_event_log()
        self.after(100, self.process_queue)
          # To store full scan reports including file lists
    event_queue = Queue()
    
    def create_widgets(self):
        tk.Label(self, text="USB Monitor Interactive Dashboard", font=("Helvetica", 18, "bold"), bg="#f0f0f0").pack(pady=10)

        self.tree = ttk.Treeview(self, columns=("Drive", "Time", "Total Files", "Malicious Files"), show="headings")
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor="center")
        self.tree.pack(padx=10, pady=10, fill="x")
        self.tree.bind("<Double-1>", self.on_tree_double_click)


        tk.Label(self, text="Event Log (Device Metadata, Actions)", bg="#f0f0f0", font=("Helvetica", 12)).pack(pady=(10, 0))
        self.event_text = tk.Text(self, height=12, wrap="none")
        self.event_text.pack(padx=10, pady=5, fill="both")
        btn_frame = tk.Frame(self, bg="#f0f0f0")
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Start Scanning", command=self.start_scanning, width=15).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Refresh", command=self.refresh_data, width=15).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Export CSV", command=self.export_csv, width=15).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Export PDF", command=self.export_pdf, width=20).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Clear Logs", command=self.clear_logs, width=15).pack(side="left", padx=5)
    def process_queue(self):
        try:
            while True:
                msg_type, data = event_queue.get_nowait()

                if msg_type == "log":
                    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    self.event_text.insert(tk.END, f"{timestamp} - {data}\n")
                    self.event_text.see(tk.END)

                elif msg_type == "scan_result":
                    # Find the most recent report (since it's not part of event data)
                    if os.path.exists(SCAN_REPORTS_FILE):
                        with open(SCAN_REPORTS_FILE, "r") as f:
                            last_line = list(f)[-1]
                            report = json.loads(last_line)

                            item_id = self.tree.insert("", "end", values=(
                                report.get("drive", "N/A"),
                                report.get("timestamp", "N/A"),
                                report.get("total_files_scanned", 0),
                                len(report.get("malicious_files", []))
                            ))

                            self.scan_data.append(report)
                            self.scan_file_details[item_id] = report.get("scanned_files", [])

        except queue.Empty:
            pass
        self.after(100, self.process_queue)


    def load_scan_reports(self):
        self.tree.delete(*self.tree.get_children())
        self.scan_data.clear()
        self.scan_file_details = {}  # 👈 Add this line to store scanned files per row

        if os.path.exists(SCAN_REPORTS_FILE):
            with open(SCAN_REPORTS_FILE, "r") as f:
                for line in f:
                    try:
                        report = json.loads(line)
                        self.scan_data.append(report)  # Store full report

                        item_id = self.tree.insert("", "end", values=(
                            report.get("drive", "N/A"),
                            report.get("timestamp", "N/A"),
                            report.get("total_files_scanned", 0),
                            len(report.get("malicious_files", []))
                        ))

                        # 👇 Store scanned files by Treeview item ID
                        self.scan_file_details[item_id] = report.get("scanned_files", [])

                    except json.JSONDecodeError:
                        continue


    def load_event_log(self):
        self.event_text.delete("1.0", tk.END)
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as f:
                lines = f.readlines()[-100:]
                for line in lines:
                    self.event_text.insert(tk.END, line)
    def on_tree_double_click(self, event):
        item_id = self.tree.focus()
        file_list = self.scan_file_details.get(item_id, [])

        if file_list:
            files_str = "\n".join(file_list)
        else:
            files_str = "No scanned files recorded."

        messagebox.showinfo("Scanned Files", f"Files scanned:\n{files_str}")

    def show_file_popup(self, files):
        popup = tk.Toplevel(self)
        popup.title("Scanned Files")
        popup.geometry("500x400")
        popup.grab_set()

        tk.Label(popup, text="Files Scanned:", font=("Helvetica", 12, "bold")).pack(pady=10)

        listbox = tk.Listbox(popup, width=80, height=20)
        listbox.pack(padx=10, pady=10, fill="both", expand=True)

        if files:
            for file in files:
                listbox.insert(tk.END, file)
        else:
            listbox.insert(tk.END, "No file list available.")
    def start_scanning(self):
        # Start the USB detection and scanning in a new thread
        threading.Thread(target=detect_usb_insertion, daemon=True).start()
        self.event_text.insert(tk.END, "Scanning started...\n")
        self.event_text.see(tk.END)
    def export_csv(self):
        export_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if export_path:
            try:
                with open(export_path, "w", encoding="utf-8") as f:
                    f.write("Drive,Timestamp,Total Files,Malicious Files,Scanned Files\n")
                    for row in self.tree.get_children():
                        values = self.tree.item(row)["values"]
                        scanned_files = self.scan_file_details.get(row, [])
                        scanned_str = "; ".join(scanned_files)  # Semicolon-separated to avoid CSV confusion
                        f.write(",".join(str(v) for v in values) + f",\"{scanned_str}\"\n")
                messagebox.showinfo("Export Successful", f"Report exported to: {export_path}")
            except Exception as e:
                messagebox.showerror("Export Error", str(e))

    def export_pdf(self):
        export_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF Files", "*.pdf")])
        if export_path:
            try:
                c = canvas.Canvas(export_path, pagesize=letter)
                width, height = letter
                margin = 50
                y = height - margin

                # Title - IEEE Style
                c.setFont("Helvetica-Bold", 16)
                c.drawCentredString(width / 2, y, "USB Scan Report")
                y -= 20

                # Timestamp
                c.setFont("Helvetica", 11)
                c.drawCentredString(width / 2, y, f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                y -= 30

                # Loop over scan records
                for row in self.tree.get_children():
                    values = self.tree.item(row)["values"]
                    drive, timestamp, total, malicious = values
                    scanned_files = self.scan_file_details.get(row, [])

                    # Section Header
                    c.setFont("Helvetica-Bold", 12)
                    c.drawString(margin, y, f"USB insertion found scanning the Drive: {drive}")
                    y -= 15

                    c.setFont("Helvetica", 10)
                    c.drawString(margin, y, f"Timestamp: {timestamp}")
                    y -= 13
                    c.drawString(margin, y, f"Total Files Scanned: {total}")
                    y -= 13
                    c.drawString(margin, y, f"Malicious Files Detected: {malicious}")
                    y -= 18

                    # Scanned Files Section
                    if scanned_files:
                        c.setFont("Helvetica-Bold", 11)
                        c.drawString(margin, y, "Scanned File List:")
                        y -= 14

                        c.setFont("Helvetica", 9)
                        for fpath in scanned_files:
                            if y < 60:
                                c.showPage()
                                y = height - margin
                                c.setFont("Helvetica", 9)
                            truncated_path = (fpath[:100] + "...") if len(fpath) > 100 else fpath
                            c.drawString(margin + 15, y, f"- {truncated_path}")
                            y -= 12

                    y -= 20
                    if y < 60:
                        c.showPage()
                        y = height - margin

                c.save()
                messagebox.showinfo("Export Successful", f"PDF exported to: {export_path}")
            except Exception as e:
                messagebox.showerror("PDF Export Error", str(e))
    def clear_logs(self):
        if messagebox.askyesno("Confirm", "Are you sure you want to clear all logs?"):
            open(SCAN_REPORTS_FILE, 'w').close()
            open(LOG_FILE, 'w').close()
            self.refresh_data()

    def refresh_data(self):
        self.load_scan_reports()
        self.load_event_log()

if __name__ == "__main__":
    threading.Thread(target=detect_usb_insertion, daemon=True).start()
    app = USBMonitorDashboard()
    app.mainloop()
