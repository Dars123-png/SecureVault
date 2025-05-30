import tkinter as tk
from tkinter import messagebox, ttk, Toplevel
from clipboardmonitor import DLPDashboard
from fmapp import FileMonitorApp
from usbmoni import USBMonitorDashboard
from mail import create_dashboard

class MainDashboard(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Main Dashboard")
        self.geometry("420x380")  # Adjusted for more buttons
        self.configure(bg="#f4f6f8")

        label = tk.Label(self, text="Select Dashboard to Open", font=("Segoe UI", 14), bg="#f4f6f8")
        label.pack(pady=20)

        btn_frame = tk.Frame(self, bg="#f4f6f8")
        btn_frame.pack(pady=10)

        buttons = [
            ("Open ClipBoard Monitor Dashboard", self.open_dlp_dashboard),
            ("Open File Monitor Dashboard", self.open_file_monitor),
            ("Open USB Monitor Dashboard", self.open_usb_monitor),
            ("Open Email Monitoring Dashboard", self.start_email_monitoring),
            #("View Activity Logs", self.open_log_viewer),
            #("Check Alert Thresholds", self.show_threshold_alerts)
        ]

        for text, cmd in buttons:
            btn = tk.Button(btn_frame, text=text, font=("Segoe UI", 12),
                            bg="#007ACC", fg="white", width=28, command=cmd)
            btn.pack(pady=5)

    def open_dlp_dashboard(self):
        try:
            DLPDashboard()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open DLP Dashboard:\n{e}")

    def open_file_monitor(self):
        try:
            fm_win = tk.Toplevel(self)
            path_to_monitor = r"."
            FileMonitorApp(fm_win, path_to_monitor)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open File Monitor Dashboard:\n{e}")

    def open_usb_monitor(self):
        try:
            usb_win = tk.Toplevel(self)
            usb_app = USBMonitorDashboard()
            usb_app.master = usb_win
            usb_app.mainloop()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open USB Monitor Dashboard:\n{e}")

    def start_email_monitoring(self):
        try:
            create_dashboard()
            messagebox.showinfo("Monitoring", "Email monitoring started.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start email monitoring:\n{e}")


def main():
    root = MainDashboard()
    root.mainloop()

if __name__ == "__main__":
    main()
