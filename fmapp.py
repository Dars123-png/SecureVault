import re
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileOpenedEvent, FileModifiedEvent, FileClosedEvent
import time
import os
import hashlib
import getpass
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import csv
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import Paragraph
from reportlab.platypus import Table, TableStyle, SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import Counter
import time
import io
from reportlab.lib.utils import ImageReader
import getpass
#import docx

# === Sensitive content regex ===
email_regex = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}')
ssn_regex = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
credit_card_regex = re.compile(r'\b(?:\d[ -]*?){13,16}\b')
phone_regex = re.compile(r"(\d{3})-(\d{3})-(\d{4})")  # returns tuples

risk_keywords = ['password', 'secret', 'confidential']


def calculate_hash(content): 
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


class SensitiveHandler(FileSystemEventHandler):
    OPEN_TIMEOUT = 30  # seconds, adjust as needed

    def __init__(self, gui_callback):
        super().__init__()
        self.last_processed_content = {}
        self.hash_to_path = {}
        self.gui_callback = gui_callback
        self.open_files = set()                # track currently open files
        self.open_file_timestamps = {}         # file_path -> last open time
        self.allowed_extensions = (
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pdf',
            '.txt', '.csv', '.json', '.xml', '.py', '.java', '.cpp'
        )
        self.excluded_extensions = (
            '.tmp', '.log', '.bak', '.dll', '.sys', '.exe'
        )
        self.last_access_times = {}
        self.last_opened_report = {} # file_path -> last time OPENED event sent
        self.open_event_debounce = 10  # seconds to debounce OPENED events

    def cleanup_open_files(self):
        while True:
            now = time.time()
            to_close = []
            for filepath, last_open_time in list(self.open_file_timestamps.items()):
                if filepath in self.open_files and (now - last_open_time) > self.OPEN_TIMEOUT:
                    to_close.append(filepath)
            for filepath in to_close:
                self.open_files.discard(filepath)
                self.open_file_timestamps.pop(filepath, None)
                print(f"DEBUG: Marking file as CLOSED due to timeout: {filepath}")
            time.sleep(5)


    def on_opened(self, event):
        if not event.is_directory:
            filepath = event.src_path
            if filepath not in self.open_files:
                self.open_files.add(filepath)
                print(f"OPENED: {filepath} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
            else:
                # This file is already open, ignoring repeated opened event
                pass

    def on_created(self, event):
        if not event.is_directory:
            self.process_event(event.src_path, "CREATED")
            #log_event("File Open", event.src_path, "Low")

    def on_modified(self, event):
        if not event.is_directory:
            self.process_event(event.src_path, "MODIFIED")
            #log_event("File Edit", event.src_path, "Medium")

    def on_deleted(self, event):
        if not event.is_directory:
            self.send_event(time.strftime('%Y-%m-%d %H:%M:%S'), "DELETED", os.path.basename(event.src_path), 'Low', [], getpass.getuser(), event.src_path)
            #log_event("File Copy", f"{event.src_path} → {event.dest_path}", "High")

    def on_moved(self, event):
        if not event.is_directory:
            src_dir = os.path.dirname(event.src_path)
            dest_dir = os.path.dirname(event.dest_path)
            action = "RENAMED" if src_dir == dest_dir else "MOVED"
            self.process_event(event.dest_path, action)

    def poll_access_times(self):
        while True:
            time.sleep(2)
            now = time.time()
            for root, _, files in os.walk(r"E:\project"):
                for f in files:
                    file_path = os.path.join(root, f)

                    if not self.should_monitor(file_path):
                        continue

                    try:
                        atime = os.path.getatime(file_path)
                        last_atime = self.last_access_times.get(file_path)

                        if last_atime is not None and atime != last_atime:
                            last_report_time = self.last_opened_report.get(file_path, 0)
                            if (now - last_report_time) > self.open_event_debounce:

                                # Detect sensitive data and risk level
                                risk = "Low"
                                sensitive_data = []
                                try:
                                    ext = os.path.splitext(file_path)[1].lower()
                                    text = ""
                                    if ext == '.pdf':
                                        text = self.extract_text_from_pdf(file_path)
                                    elif ext in ['.txt', '.csv', '.json', '.xml', '.py', '.java', '.cpp']:
                                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                            text = f.read()

                                    emails = email_regex.findall(text)
                                    ssns = ssn_regex.findall(text)
                                    credit_cards = credit_card_regex.findall(text)
                                    phones = phone_regex.findall(text)

                                    if emails or ssns or credit_cards or phones:
                                        sensitive_data.extend(emails + ssns + credit_cards + phones)
                                        if ssns or credit_cards:
                                            risk = "High"
                                        else:
                                            risk = "Medium"

                                    # Example risk keywords detection
                                    risk_keywords = ['password', 'confidential', 'secret', 'ssn', 'credit card']
                                    if any(word in os.path.basename(file_path).lower() for word in risk_keywords):
                                        risk = "High"
                                except Exception as e:
                                    print(f"[ERROR] Analyzing risk in poll_access_times for {file_path}: {e}")

                                # Mark as open and update timestamp for cleanup
                                self.open_files.add(file_path)
                                self.open_file_timestamps[file_path] = now

                                self.send_event(time.strftime('%Y-%m-%d %H:%M:%S'), "OPENED", os.path.basename(file_path), risk, sensitive_data, getpass.getuser(), file_path)

                                # Update last report time to debounce
                                self.last_opened_report[file_path] = now

                        # Update last access time tracker regardless
                        self.last_access_times[file_path] = atime

                    except Exception as e:
                        # Log errors if needed
                        print(f"[ERROR] poll_access_times error on {file_path}: {e}")
                        continue
    def should_monitor(self, file_path):
        ext = os.path.splitext(file_path)[1].lower()
        return ext in self.allowed_extensions and ext not in self.excluded_extensions


    def process_event(self, file_path, action):
        print(f"DEBUG: Detected {action} on {file_path}")
        user = getpass.getuser()
        sensitive_data = []
        risk = 'Low'

        try:
            # Filter extensions
            if not self.should_monitor(file_path):
                print(f"SKIPPED: Not a monitored file type: {file_path}")
                return

            if not os.path.exists(file_path):
                self.send_event(time.strftime('%Y-%m-%d %H:%M:%S'), action, os.path.basename(file_path), risk, sensitive_data, user, file_path)
                return

            # Read file content
            ext = os.path.splitext(file_path)[1].lower()
            text = ""

            if ext == '.pdf':
                text = self.extract_text_from_pdf(file_path)
            elif ext in ['.txt', '.csv', '.json', '.xml', '.py', '.java', '.cpp']:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    text = f.read()
            '''elif ext == '.docx':
                try:
                    doc = docx.Document(file_path)
                    text = "\n".join([para.text for para in doc.paragraphs])
                except Exception as e:
                    print(f"[ERROR] Reading DOCX: {e}")
                    text = "" 
            else:
                # Other allowed but non-readable
                print(f"SKIPPED: No reader implemented for {file_path}")
                return '''

            # Hash check
            content_hash = calculate_hash(text)
            if content_hash in self.hash_to_path and self.hash_to_path[content_hash] != file_path:
                print(f"[=] File copied from {self.hash_to_path[content_hash]} to {file_path}")

            self.hash_to_path[content_hash] = file_path
            if file_path in self.last_processed_content and self.last_processed_content[file_path] == content_hash:
                self.send_event(time.strftime('%Y-%m-%d %H:%M:%S'), action, os.path.basename(file_path), risk, sensitive_data, user, file_path)
                return
            self.last_processed_content[file_path] = content_hash

            # Analyze sensitive content
            emails = email_regex.findall(text)
            ssns = ssn_regex.findall(text)
            credit_cards = credit_card_regex.findall(text)
            phones = phone_regex.findall(text)

            if emails or ssns or credit_cards or phones:
                sensitive_data.extend(emails + ssns + credit_cards + phones)
                # Set risk level: High if SSN or Credit Card detected
                if ssns or credit_cards:
                    risk = 'High'
                else:
                    risk = 'Medium'

            if any(word in os.path.basename(file_path).lower() for word in risk_keywords):
                risk = 'High'

            self.send_event(time.strftime('%Y-%m-%d %H:%M:%S'), action, os.path.basename(file_path), risk, sensitive_data, user, file_path)

        except Exception as e:
            print(f"[ERROR] Processing file {file_path}: {e}")
            self.send_event(time.strftime('%Y-%m-%d %H:%M:%S'), action, os.path.basename(file_path), risk, sensitive_data, user, file_path)
    def extract_text_from_pdf(self, pdf_path):
        text = ""
        try:
            with fitz.open(pdf_path) as pdf_document:
                for page in pdf_document:
                    text += page.get_text()
        except Exception as e:
            print(f"[ERROR] Extracting PDF text from {pdf_path}: {e}")
        return text

    def send_event(self, timestamp, action, filename, risk, sensitive_data, user, full_path):
        print(f"DEBUG: Sending event: {timestamp}, {action}, {filename}, {risk}, {user}")
        self.gui_callback(timestamp, action, filename, risk, sensitive_data, user, full_path)

class FileMonitorApp:
    def __init__(self, root, path_to_monitor):
        self.root = root
        self.root.title("Real-Time Sensitive File Monitor")
        self.running = False
        self.path_to_monitor = path_to_monitor

        self.all_events = []

        # ✅ Add these lines before threads or handlers
        self.risk_counter = Counter()
        self.action_counter = Counter()

        self.setup_ui()

        self.event_handler = SensitiveHandler(self.add_event)
        self.observer = Observer()
        self.setup_column_sorting()
        
    def setup_ui(self):
        top_frame = tk.Frame(self.root)
        top_frame.pack(pady=5, fill='x')

        self.toggle_button = ttk.Button(top_frame, text="Start Monitoring", command=self.toggle_monitoring)
        self.toggle_button.pack(side='left', padx=5)

        export_btn = ttk.Button(top_frame, text="Export Logs", command=self.export_logs)
        export_btn.pack(side='left', padx=5)

        # ✅ Directory selection button
        dir_btn = ttk.Button(top_frame, text="Select Directory", command=self.select_directory)
        dir_btn.pack(side='left', padx=5)

        tk.Label(top_frame, text="Search: ").pack(side='left')
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(top_frame, textvariable=self.search_var)
        search_entry.pack(side='left')
        search_entry.bind('<KeyRelease>', self.filter_events)

        # ✅ Scrollable Treeview Frame
        tree_frame = tk.Frame(self.root)
        tree_frame.pack(padx=10, pady=5, fill='both', expand=True)

        tree_scroll_y = ttk.Scrollbar(tree_frame, orient="vertical")
        tree_scroll_y.pack(side="right", fill="y")

        tree_scroll_x = ttk.Scrollbar(tree_frame, orient="horizontal")
        tree_scroll_x.pack(side="bottom", fill="x")

        columns = ('Time', 'Action', 'Filename', 'Risk', 'User')
        self.tree = ttk.Treeview(
            tree_frame, columns=columns, show='headings', height=20,
            yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set
        )

        for col in columns:
            self.tree.heading(col, text=col)
            width = 100 if col != 'Filename' else 250
            self.tree.column(col, width=width)
        self.tree.pack(fill='both', expand=True)
    
        tree_scroll_y.config(command=self.tree.yview)
        tree_scroll_x.config(command=self.tree.xview)

        self.tree.tag_configure('High', background='red', foreground='white')
        self.tree.tag_configure('Medium', background='orange')

        self.tree.bind('<Double-1>', self.show_event_details)

        # === Scrollable Chart Frame (both horizontal & vertical) ===
        chart_container = tk.Frame(self.root)
        chart_container.pack(padx=10, pady=5, fill='both', expand=True)

        chart_canvas = tk.Canvas(chart_container, bd=2, relief=tk.SUNKEN)
        chart_canvas.pack(side='left', fill='both', expand=True)

        # Scrollbars
        y_scroll = ttk.Scrollbar(chart_container, orient='vertical', command=chart_canvas.yview)
        y_scroll.pack(side='right', fill='y')

        chart_canvas.configure(yscrollcommand=y_scroll.set)

        # Frame inside the canvas for charts
        self.chart_frame = tk.Frame(chart_canvas)
        chart_window = chart_canvas.create_window((0, 0), window=self.chart_frame, anchor='nw')
        self.chart_frame.bind("<Configure>", lambda e: chart_canvas.configure(scrollregion=chart_canvas.bbox("all")))
        chart_canvas.bind("<Configure>", self.on_canvas_resize)

        # Automatically update scroll region
    def update_scroll_region(self, event):
        event.widget.configure(scrollregion=event.widget.bbox("all"))

              # Dynamically resize the charts when the canvas size changes
    def on_canvas_resize(self, event):
        canvas_width = event.width
        canvas_height = event.height
        self.redraw_charts(canvas_width, canvas_height)


    def select_directory(self):
        path = filedialog.askdirectory()
        if path:
            self.path_to_monitor = path
            print(f"[INFO] Now monitoring: {path}")
            if self.running:
                self.toggle_monitoring()  # Stop
                self.toggle_monitoring()  # Restart with new path


    def add_event(self, timestamp, action, filename, risk, sensitive_data, user, full_path):
        self.all_events.append((timestamp, action, filename, risk, user, sensitive_data, full_path))
    
        self.risk_counter[risk] += 1
        self.action_counter[action] += 1

        self.root.after(0, self._add_event_to_tree, timestamp, action, filename, risk, user)
        self.root.after(0, self.update_charts)

    def _add_event_to_tree(self, timestamp, action, filename, risk, user):
        row_id = self.tree.insert('', 'end', values=(timestamp, action, filename, risk, user))
        if risk in ('High', 'Medium'):
            self.tree.item(row_id, tags=(risk,))

    def toggle_monitoring(self):
        if not self.running:
            self.start_monitoring()
        else:
            self.stop_monitoring()

    def start_monitoring(self):
        self.running = True
        self.toggle_button.config(text="Pause Monitoring")
        self.observer.schedule(self.event_handler, self.path_to_monitor, recursive=True)
        threading.Thread(target=self.observer.start, daemon=True).start()
        threading.Thread(target=self.event_handler.poll_access_times, daemon=True).start()
        threading.Thread(target=self.event_handler.cleanup_open_files, daemon=True).start()


    def stop_monitoring(self):
        self.running = False
        self.toggle_button.config(text="Start Monitoring")
        self.observer.stop()
        self.observer.join()
        self.observer = Observer()
    def setup_column_sorting(self):
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col, command=lambda _col=col: self.sort_column(_col, False))

    def sort_column(self, col, reverse):
        l = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
    
        try:
            # Try to sort as date or number if possible
            if col == "DateTime":
                l.sort(key=lambda t: datetime.strptime(t[0], "%Y-%m-%d %H:%M:%S"), reverse=reverse)
            elif col == "Risk":
                risk_priority = {"High": 3, "Medium": 2, "Low": 1}
                l.sort(key=lambda t: risk_priority.get(t[0], 0), reverse=reverse)
            else:
                l.sort(reverse=reverse)
        except Exception as e:
            print(f"[!] Sorting failed for {col}: {e}")
            l.sort(reverse=reverse)

        # Rearranging items in sorted positions
        for index, (val, k) in enumerate(l):
            self.tree.move(k, '', index)

        # Toggle sort order on next click
        self.tree.heading(col, command=lambda: self.sort_column(col, not reverse))
    def update_charts(self):
        # Clear previous charts
        for widget in self.chart_frame.winfo_children():
            widget.destroy()

        fig, axs = plt.subplots(1, 2, figsize=(8, 4))

        # Pie chart for risk
        risks = ['High', 'Medium', 'Low']
        risk_values = [self.risk_counter.get(r, 0) for r in risks]
        axs[0].pie(risk_values, labels=risks, autopct='%1.1f%%', colors=['#1f77b4', '#ff7f0e', '#2ca02c'])
        axs[0].set_title('Risk Distribution')

        # Bar chart for actions
        actions = list(self.action_counter.keys())
        values = [self.action_counter[a] for a in actions]
        axs[1].bar(actions, values, color='skyblue')
        axs[1].set_title('Action Frequency')
        axs[1].set_ylabel('Count')

        canvas = FigureCanvasTkAgg(fig, master=self.chart_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        plt.close(fig)  # Prevent memory warning
    def export_logs(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("PDF files", "*.pdf")],
            title="Save Logs As"
        )

        if not file_path:
            return

        try:
            if file_path.endswith(".csv"):
                with open(file_path, mode='w', newline='', encoding='utf-8') as file:
                    writer = csv.writer(file)
                    writer.writerow(["Time", "Action", "Filename", "Risk", "User"])
                    for row in self.tree.get_children():
                        writer.writerow(self.tree.item(row)['values'])

            else:
                buffer = io.BytesIO()
                doc = SimpleDocTemplate(file_path, pagesize=letter)
                elements = []
                styles = getSampleStyleSheet()

                # Title
                elements.append(Paragraph("Real-Time File Monitoring Report", styles['Title']))
                elements.append(Spacer(1, 12))

                # Chart image
                fig, axs = plt.subplots(1, 2, figsize=(8, 3))
                axs[0].bar(self.risk_counter.keys(), self.risk_counter.values(), color=['red', 'orange', 'green'])
                axs[0].set_title("Risk Level Distribution")
                axs[1].pie(self.action_counter.values(), labels=self.action_counter.keys(), autopct='%1.1f%%')
                axs[1].set_title("Action Distribution")
                plt.tight_layout()

                chart_img = io.BytesIO()
                plt.savefig(chart_img, format='PNG')
                chart_img.seek(0)
                elements.append(Image(chart_img, width=400, height=200))
                elements.append(Spacer(1, 12))
                plt.close()

                    # Styled table
                wrap_style = ParagraphStyle(name='WrapStyle', fontSize=8)

                # ✅ Build full table data before creating the table
                table_data = [[
                    Paragraph("Time", wrap_style),
                    Paragraph("Action", wrap_style),
                    Paragraph("Filename", wrap_style),
                    Paragraph("Risk", wrap_style),
                    Paragraph("User", wrap_style)
                ]]

                for event in self.all_events:
                    table_data.append([
                        Paragraph(str(event[0]), wrap_style),
                        Paragraph(str(event[1]), wrap_style),
                        Paragraph(str(event[2]), wrap_style),
                        Paragraph(str(event[3]), wrap_style),
                        Paragraph(str(event[4]), wrap_style),
                    ])

                # ✅ Now create table after adding rows
                table = Table(table_data, colWidths=[80, 60, 200, 50, 80])

                # Table styles
                style = TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                    ('GRID', (0, 0), (-1, -1), 0.25, colors.black)
                ])

            # Row coloring based on risk
                for i, event in enumerate(self.all_events, start=1):  # start=1 because header is row 0
                    if event[3] == 'High':
                        style.add('BACKGROUND', (0, i), (-1, i), colors.red)
                        style.add('TEXTCOLOR', (0, i), (-1, i), colors.whitesmoke)
                    elif event[3] == 'Medium':
                        style.add('BACKGROUND', (0, i), (-1, i), colors.orange)
                    else:
                        style.add('BACKGROUND', (0, i), (-1, i), colors.whitesmoke)

                table.setStyle(style)
                elements.append(table)

                doc.build(elements)
            messagebox.showinfo("Export Successful", f"Logs exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export logs:\n{e}")
    def filter_events(self, event):
        keyword = self.search_var.get().lower()
        for item in self.tree.get_children():
            self.tree.delete(item)
        for evt in self.all_events:
            if any(keyword in str(val).lower() for val in evt[:5]):
                self._add_event_to_tree(*evt[:5])

    def show_event_details(self, event):
        item_id = self.tree.focus()
        if not item_id:
            return
        values = self.tree.item(item_id)['values']
        timestamp, action, filename, risk, user = values
        for evt in self.all_events:
            if evt[:5] == (timestamp, action, filename, risk, user):
                sensitive_data, full_path = evt[5], evt[6]
                break
        else:
            return

        detail_win = tk.Toplevel(self.root)
        detail_win.title("Event Details")

        tk.Label(detail_win, text=f"Full Path: {full_path}").pack(anchor='w', padx=10, pady=5)
        tk.Label(detail_win, text=f"Risk Level: {risk}").pack(anchor='w', padx=10)
        tk.Label(detail_win, text="Sensitive Data:").pack(anchor='w', padx=10)

        text_widget = tk.Text(detail_win, height=10, width=80)
        text_widget.pack(padx=10, pady=5)
        text_widget.insert('1.0', '\n'.join(str(item) for item in sensitive_data))
        text_widget.config(state='disabled')  # Make it read-only

    def redraw_charts(self, width=800, height=400):
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

        # Clear existing charts
        for widget in self.chart_frame.winfo_children():
            widget.destroy()

        # Calculate dynamic size
        fig_width = max(6, width / 100)
        fig_height = max(3, height / 100)

        fig, axs = plt.subplots(1, 2, figsize=(fig_width, fig_height))

        # Example dummy data plots — replace with your actual chart logic
        axs[0].bar(self.risk_counter.keys(), self.risk_counter.values(), color='crimson')
        axs[0].set_title('Risk Level Distribution')

        axs[1].pie(self.action_counter.values(), labels=self.action_counter.keys(), autopct='%1.1f%%')
        axs[1].set_title('Action Types')

        fig.tight_layout()

        chart_canvas = FigureCanvasTkAgg(fig, master=self.chart_frame)
        chart_canvas.draw()
        chart_canvas.get_tk_widget().pack(fill='both', expand=True)

        plt.close(fig)  # Prevent memory leaks 


    def on_close(self):
        if self.running:
            self.stop_monitoring()
        self.root.destroy()
        plt.close('all')
    
if __name__ == "__main__":
    path = r"E:\\project"
    root = tk.Tk()
    app = FileMonitorApp(root, path)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
