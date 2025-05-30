import sqlite3
import random
import re
import time
import threading
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import win32clipboard
import os
import csv
import sys
from io import BytesIO

# For PDF generation
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas as pdf_canvas
    from reportlab.lib import colors
    from reportlab.platypus import Table, TableStyle, SimpleDocTemplate, Paragraph, Spacer, Image, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_JUSTIFY, TA_CENTER
except ImportError:
    print("Warning: reportlab not installed, PDF export will be disabled.")

# For system tray notification
try:
    import win32api
    import win32con
    import win32gui
except ImportError:
    print("Warning: pywin32 modules for notifications not installed. Notifications will be disabled.")

DATABASE = 'dlp_incidents.db'

# Regex for sensitive data detection
cc_regex = re.compile(r"\b(?:\d[ -]*?){13,19}\b")  # Credit card
emp_regex = re.compile(r"\bEMP-\d{4,6}\b", re.IGNORECASE)  # Employee IDs
email_regex = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.\w{2,}\b")  # Email addresses
password_regex = re.compile(r"password\s*[:=]\s*\S+", re.IGNORECASE)  # Passwords
file_path_regex = re.compile(r"\b[\w/\\:]+\.(?:docx|pdf|xlsx|txt|pptx)\b")  # File paths

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def initialize_database():
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                data_type TEXT NOT NULL,
                sample TEXT NOT NULL,
                user TEXT
            )
        """)
        conn.commit()
    except sqlite3.OperationalError as e:
        print(f"Database error: {e}")
    finally:
        conn.close()

def get_logged_in_user():
    try:
        import getpass
        return getpass.getuser()
    except Exception:
        try:
            return os.getlogin()
        except Exception:
            return "UnknownUser "

class DLPDashboard(tk.Toplevel):  # ✅ Changed from tk.Tk to tk.Toplevel
    def __init__(self, master=None):
        super().__init__(master)
        self.title("Data Loss Prevention Dashboard")
        self.geometry("960x700")
        self.configure(bg="#f4f6f8")

        initialize_database()

        self.risk_level_label = tk.Label(self, text="Loading risk level...", font=("Segoe UI", 16), bg="#f4f6f8")
        self.risk_level_label.pack(pady=10)

        self.current_clipboard_label = tk.Label(self, text="", font=("Segoe UI", 12), bg="#f4f6f8", fg="blue")
        self.current_clipboard_label.pack(pady=5)

        # Treeview to show all incidents including safe contents
        self.tree = ttk.Treeview(self, columns=("Timestamp", "User ", "Data Type", "Content Sample"), show="headings", height=15)
        self.tree.heading("Timestamp", text="Timestamp")
        self.tree.heading("User ", text="User ")
        self.tree.heading("Data Type", text="Data Type")
        self.tree.heading("Content Sample", text="Content Sample")
        self.tree.column("Timestamp", width=180)
        self.tree.column("User ", width=160)
        self.tree.column("Data Type", width=120)
        self.tree.column("Content Sample", width=460)
        self.tree.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Style to mark rows with sensitive data in red
        style = ttk.Style(self)
        style.configure("Treeview", font=("Segoe UI", 10))
        style.map('Red.Treeview', foreground=[('!disabled', 'red')])

        button_frame = tk.Frame(self, bg="#f4f6f8")
        button_frame.pack(pady=(0,10))

        self.export_csv_button = tk.Button(button_frame, text="Export to CSV", command=self.export_to_csv, bg="#007ACC", fg="white",
                                           font=("Segoe UI", 10), relief=tk.RAISED, padx=10, pady=5)
        self.export_csv_button.pack(side=tk.LEFT, padx=5)

        self.export_pdf_button = tk.Button(button_frame, text="Export to PDF", command=self.export_to_pdf, bg="#007ACC", fg="white",
                                           font=("Segoe UI", 10), relief=tk.RAISED, padx=10, pady=5)
        self.export_pdf_button.pack(side=tk.LEFT, padx=5)

        self.fig, self.ax = plt.subplots(figsize=(8, 3), dpi=100)
        self.canvas = FigureCanvasTkAgg(self.fig, master=self)
        self.canvas.get_tk_widget().pack(padx=10, pady=10, fill=tk.BOTH)

        self.stop_event = threading.Event()
        self.monitor_thread = threading.Thread(target=self.monitor_clipboard, daemon=True)
        self.monitor_thread.start()
        self.refresh_dashboard()
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.hwnd = None
        self._register_notification_window()

    def _register_notification_window(self):
        message_map = {}
        class_name = "DLPNotificationWindow"
        wc = win32gui.WNDCLASS()
        wc.lpszClassName = class_name
        wc.style = win32con.CS_VREDRAW | win32con.CS_HREDRAW
        wc.hInstance = win32api.GetModuleHandle(None)
        wc.lpfnWndProc = message_map
        try:
            class_atom = win32gui.RegisterClass(wc)
            self.hwnd = win32gui.CreateWindow(class_name, "DLP Monitor Hidden Window",
                                              0, 0, 0, 0, 0, 0, 0, wc.hInstance, None)
        except Exception as e:
            print(f"Error registering notification window: {e}")

    def show_notification(self, title, msg):
        if not msg:  # Check if msg is None or empty
            print("Notification message is empty or None. Not showing notification.")
            return
        try:
            if not self.hwnd:
                self._register_notification_window()
            flags = win32gui.NIF_INFO
            win32gui.Shell_NotifyIcon(win32gui.NIM_ADD, (self.hwnd, 0, win32gui.NIF_ICON | win32gui.NIF_MESSAGE | flags, 0, 0, None, ""))
            newdata = (self.hwnd, 0, win32gui.NIF_INFO, 0, 0, None, msg, 200, title)
            win32gui.Shell_NotifyIcon(win32gui.NIM_MODIFY, newdata)
        except Exception as e:
            print(f"")

    def on_close(self):
        self.stop_event.set()
        self.monitor_thread.join(timeout=2)
        self.destroy()

    def log_incident_terminal(self, data_type, sample):
        red = "\033[91m"
        green = "\033[92m"
        reset = "\033[0m"
        if data_type in ['Password', 'CreditCard', 'EmployeeID', 'Email', 'FilePath']:
            print(f"{red}⚠ ALERT: Sensitive {data_type} copied! Sample: {sample}{reset}")
            notification_msg = f"{data_type} copied: {sample}" if sample else f"{data_type} copied."
            self.show_notification("DLP Alert", notification_msg)
        else:
            print(f"{green}✅ OK: Safe content copied. Sample: {sample}{reset}")

    def monitor_clipboard(self):
        last_clip = None
        while not self.stop_event.is_set():
            try:
                win32clipboard.OpenClipboard()
                if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_UNICODETEXT):
                    clip = win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
                else:
                    clip = None
                win32clipboard.CloseClipboard()

                if clip and clip != last_clip:
                    last_clip = clip
                    data_type = None
                    if cc_regex.search(clip):
                        data_type = 'CreditCard'
                    elif emp_regex.search(clip):
                        data_type = 'EmployeeID'
                    elif email_regex.search(clip):
                        data_type = 'Email'
                    elif password_regex.search(clip):
                        data_type = 'Password'
                    elif file_path_regex.search(clip):
                        data_type = 'FilePath'
                    else:
                        data_type = 'Safe'

                    self.log_incident_terminal(data_type if data_type else 'Safe', clip[:50])

                    # Insert all clipboard contents into the DB, marking data_type as 'Safe' if none matches
                    user = get_logged_in_user()
                    conn = get_db_connection()
                    cursor = conn.cursor()
                    cursor.execute(
                        "INSERT INTO incidents (timestamp, data_type, sample, user) VALUES (?, ?, ?, ?)",
                        (datetime.now().isoformat(), data_type, clip[:50], user)
                    )
                    conn.commit()
                    conn.close()

                    self.after(0, self.update_current_clipboard, clip, data_type)
                    self.after(0, self.refresh_dashboard)

            except Exception as e:
                print(f"Error accessing clipboard: {e}")
            time.sleep(1)

    def update_current_clipboard(self, content, data_type):
        display_type = data_type if data_type else "Safe"
        self.current_clipboard_label.config(text=f"Current Clipboard [{display_type}]: {content[:80]}")

    def load_incidents(self):
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT timestamp, user, data_type, sample FROM incidents ORDER BY timestamp DESC LIMIT 50")
        incidents = cur.fetchall()
        conn.close()
        return incidents

    def load_risk_level(self):
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT data_type, COUNT(*) as count FROM incidents GROUP BY data_type")
        counts = cur.fetchall()
        conn.close()
        score_map = {
            'CreditCard': 5,
            'EmployeeID': 4,
            'Email': 3,
            'Password': 6,
            'FilePath': 2,
            'Safe': 0
        }
        risk_score = 0
        for row in counts:
            risk_score += score_map.get(row['data_type'], 1) * row['count']
        if risk_score >= 50:
            return 'High', 'red', risk_score
        elif risk_score >= 20:
            return 'Medium', 'darkorange', risk_score
        else:
            return 'Low', 'green', risk_score

    def load_activity(self):
        conn = get_db_connection()
        cur = conn.cursor()
        today = datetime.now().date()
        dates = [(today - timedelta(days=i)).isoformat() for i in range(6, -1, -1)]
        activity = {date: 0 for date in dates}
        cur.execute("""
            SELECT DATE(timestamp) as day, COUNT(*) as count
            FROM incidents
            WHERE DATE(timestamp) BETWEEN ? AND ?
            GROUP BY day
        """, (dates[0], dates[-1]))
        rows = cur.fetchall()
        conn.close()
        for row in rows:
            if row['day'] in activity:
                activity[row['day']] = row['count']
        counts = [activity[date] for date in dates]
        dates_dt = [datetime.fromisoformat(date) for date in dates]
        return dates_dt, counts

    def refresh_dashboard(self):
        level, color, score = self.load_risk_level()
        self.risk_level_label.config(text=f"Current Risk Level: {level} (Score: {score})", fg=color)

        # Clear tree
        for row in self.tree.get_children():
            self.tree.delete(row)

        incidents = self.load_incidents()
        for inc in incidents:
            who = inc['user'] if inc['user'] else f"user{random.randint(1,5)}@company.com"
            style = ''
            if inc['data_type'] in ['Password', 'CreditCard', 'EmployeeID', 'Email', 'FilePath']:
                style = 'Red.Treeview'
            self.tree.insert('', tk.END, values=(inc['timestamp'], who, inc['data_type'], inc['sample']), tags=(style,))

        # Apply tag config for red color
        self.tree.tag_configure('Red.Treeview', foreground='red')

        dates, counts = self.load_activity()
        self.ax.clear()
        # Use bar chart
        self.ax.bar(dates, counts, color='#007ACC', alpha=0.7)
        self.ax.set_title("Incidents in Past Week")
        self.ax.set_ylim(bottom=0)
        self.ax.xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter('%b %d'))
        self.ax.grid(True, linestyle='--', alpha=0.5)
        self.fig.tight_layout()
        self.canvas.draw()

        self.after(30000, self.refresh_dashboard)

    def export_to_csv(self):
        incidents = self.load_incidents()
        if not incidents:
            messagebox.showinfo("Export CSV", "No incidents to export.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension='.csv',
                                                 filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                                                 title="Save incidents to CSV")
        if not file_path:
            return
        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["Timestamp", "User ", "Data Type", "Content Sample"])
                for inc in incidents:
                    writer.writerow([inc['timestamp'], inc['user'], inc['data_type'], inc['sample']])
            messagebox.showinfo("Export CSV", f"Incidents exported successfully to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Export CSV", f"Failed to export CSV:\n{e}")

    def export_to_pdf(self):
        incidents = self.load_incidents()
        if not incidents:
            messagebox.showinfo("Export PDF", "No incidents to export.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension='.pdf',
                                                 filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")],
                                                 title="Save incidents to PDF")
        if not file_path:
            return
        try:
            buf = BytesIO()
            self.fig.savefig(buf, format='png')
            buf.seek(0)

            doc = SimpleDocTemplate(file_path, pagesize=letter,
                                    rightMargin=72, leftMargin=72,
                                    topMargin=72, bottomMargin=18)
            styles = getSampleStyleSheet()
            styles.add(ParagraphStyle(name='IEEEtitle', fontName='Times-Bold', fontSize=16, alignment=TA_CENTER, spaceAfter=12))
            styles.add(ParagraphStyle(name='IEEEheading', fontName='Times-Bold', fontSize=12, spaceBefore=12, spaceAfter=6))
            base_body = styles['BodyText']
            body_style = ParagraphStyle('CustomBodyText', parent=base_body, fontName='Times-Roman', fontSize=10, leading=12, alignment=TA_JUSTIFY)
            styles.add(body_style)

            elements = []
            title = Paragraph("DLP Incidents Report", styles['IEEEtitle'])
            elements.append(title)

            elements.append(Spacer(1, 12))

            abstract_title = Paragraph("Abstract", styles['IEEEheading'])
            elements.append(abstract_title)

            elements.append(Spacer(1, 24))

            im = Image(buf)
            im.drawHeight = 3 * 72
            im.drawWidth = 6 * 72
            elements.append(Paragraph("Figure 1: Incidents Activity in Past Week", styles['CustomBodyText']))
            elements.append(im)

            elements.append(PageBreak())

            table_title = Paragraph("I. Incident Logs", styles['IEEEheading'])
            elements.append(table_title)

            data = [["Timestamp", "User ", "Data Type", "Content Sample"]]
            for inc in incidents:
                timestamp = inc['timestamp'].split('.')[0] if '.' in inc['timestamp'] else inc['timestamp']
                user_str = inc['user'] if inc['user'] else "Unknown"
                data.append([timestamp, user_str, inc['data_type'], inc['sample']])
            col_widths = [110, 110, 80, 210]

            t = Table(data, colWidths=col_widths, repeatRows=1)
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#003366')),
                ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
                ('ALIGN',(0,0),(-1,-1),'LEFT'),
                ('FONTNAME', (0,0), (-1,0), 'Times-Bold'),
                ('FONTSIZE', (0,0), (-1,0), 11),
                ('BOTTOMPADDING', (0,0), (-1,0), 8),
                ('BACKGROUND', (0,1), (-1,-1), colors.white),
                ('TEXTCOLOR', (0,1), (-1,-1), colors.black),
                ('FONTNAME', (0,1), (-1,-1), 'Times-Roman'),
                ('FONTSIZE', (0,1), (-1,-1), 9),
                ('GRID', (0,0), (-1,-1), 0.25, colors.grey),
            ]))
            elements.append(t)

            doc.build(elements)

            messagebox.showinfo("Export PDF", f"Incidents exported successfully in IEEE format to:\n{file_path}")

        except Exception as e:
            messagebox.showerror("Export PDF", f"Failed to export PDF:\n{e}")

def main():
    app = DLPDashboard()
    app.mainloop()

if __name__ == "__main__":
    main()


