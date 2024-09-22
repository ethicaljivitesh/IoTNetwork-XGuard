import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import shodan
import csv

# Define your Shodan API key
API_KEY = "<Enter your SHodan API Here>"
shodan_client = shodan.Shodan(API_KEY)

# Main Application Class
class ShodanSearchApp:
    def __init__(self, root):
        self.root = root
        self.root.title("IoT Network-X Guard")
        self.root.geometry("900x600")

        # Set red/gray theme colors
        self.bg_color = "#2c2c2c"
        self.button_color = "#ff4500"
        self.text_color = "#ffffff"
        self.entry_bg_color = "#ffffff"
        self.entry_fg_color = "#000000"

        self.root.config(bg=self.bg_color)
        self.root.resizable(True, True)

        # Style Configuration
        style = ttk.Style()
        style.configure("TLabel", background=self.bg_color, foreground=self.text_color, font=("Helvetica", 12))
        style.configure("TButton", background=self.button_color, font=("Helvetica", 12))

        # Animation Effect for Buttons
        def on_enter(e):
            e.widget.config(background='#ff6347')
        def on_leave(e):
            e.widget.config(background=self.button_color)

        # API Key Management
        self.api_key_label = ttk.Label(root, text="Shodan API Key:")
        self.api_key_label.pack(pady=10)
        self.api_key_entry = tk.Entry(root, width=50, bg=self.entry_bg_color, fg=self.entry_fg_color)
        self.api_key_entry.insert(0, API_KEY)
        self.api_key_entry.pack(pady=5)

        # Search Input Field
        self.search_label = ttk.Label(root, text="Enter Search Query:")
        self.search_label.pack(pady=10)
        self.search_entry = tk.Entry(root, width=50, bg=self.entry_bg_color, fg=self.entry_fg_color)
        self.search_entry.pack(pady=5)

        # Search Button
        self.search_button = tk.Button(root, text="Search", bg=self.button_color, fg=self.text_color, font=("Helvetica", 12), command=self.perform_search)
        self.search_button.pack(pady=10)
        self.search_button.bind("<Enter>", on_enter)
        self.search_button.bind("<Leave>", on_leave)

        # Frame for Buttons
        self.button_frame = tk.Frame(root, bg=self.bg_color)
        self.button_frame.pack(pady=10)

        # New Buttons
        self.show_iot_button = tk.Button(self.button_frame, text="Show All Public IoT Systems", bg=self.button_color, fg=self.text_color, font=("Helvetica", 12), command=self.show_iot_popup)
        self.show_iot_button.grid(row=0, column=0, padx=5)
        self.show_iot_button.bind("<Enter>", on_enter)
        self.show_iot_button.bind("<Leave>", on_leave)

        self.monitor_iot_button = tk.Button(self.button_frame, text="Live IoT System Monitoring", bg=self.button_color, fg=self.text_color, font=("Helvetica", 12), command=self.monitor_iot_systems)
        self.monitor_iot_button.grid(row=0, column=1, padx=5)
        self.monitor_iot_button.bind("<Enter>", on_enter)
        self.monitor_iot_button.bind("<Leave>", on_leave)

        self.vulnerability_button = tk.Button(self.button_frame, text="Vulnerability Detection & Exploit Lookup", bg=self.button_color, fg=self.text_color, font=("Helvetica", 12), command=self.perform_vulnerability_lookup)
        self.vulnerability_button.grid(row=0, column=2, padx=5)
        self.vulnerability_button.bind("<Enter>", on_enter)
        self.vulnerability_button.bind("<Leave>", on_leave)

        self.historical_data_button = tk.Button(self.button_frame, text="Historical Data Lookup", bg=self.button_color, fg=self.text_color, font=("Helvetica", 12), command=self.perform_historical_lookup)
        self.historical_data_button.grid(row=0, column=3, padx=5)
        self.historical_data_button.bind("<Enter>", on_enter)
        self.historical_data_button.bind("<Leave>", on_leave)

        # Frame to hold the result area and make it responsive
        self.result_frame = tk.Frame(root, bg=self.bg_color)
        self.result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Result Display Area
        self.result_area = tk.Text(self.result_frame, bg="#3b3b3b", fg=self.text_color, font=("Helvetica", 10))
        self.result_area.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        # Scrollbar for the result area
        self.scrollbar = tk.Scrollbar(self.result_frame, command=self.result_area.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.result_area.config(yscrollcommand=self.scrollbar.set)

        # Export Button
        self.export_button = tk.Button(root, text="Export Results", bg=self.button_color, fg=self.text_color, font=("Helvetica", 12), command=self.export_results)
        self.export_button.pack(pady=10)
        self.export_button.bind("<Enter>", on_enter)
        self.export_button.bind("<Leave>", on_leave)

    def perform_search(self):
        query = self.search_entry.get()
        api_key = self.api_key_entry.get()

        try:
            shodan_client = shodan.Shodan(api_key)
            results = shodan_client.search(query)
            self.display_results(results)
        except shodan.APIError as e:
            messagebox.showerror("Error", str(e))

    def display_results(self, results):
        self.result_area.delete('1.0', tk.END)
        for result in results['matches']:
            ip_str = result['ip_str']
            org = result.get('org', 'Unknown Organization')
            data = result['data']
            self.result_area.insert(tk.END, f"IP: {ip_str}\nOrg: {org}\nData: {data}\n{'-'*50}\n")

    def show_iot_popup(self):
        new_window = tk.Toplevel(self.root)
        new_window.title("Public IoT Systems")
        new_window.geometry("900x600")

        result_frame_popup = tk.Frame(new_window, bg=self.bg_color)
        result_frame_popup.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        result_area_popup = tk.Text(result_frame_popup, bg="#3b3b3b", fg=self.text_color, font=("Helvetica", 10))
        result_area_popup.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        scrollbar_popup = tk.Scrollbar(result_frame_popup, command=result_area_popup.yview)
        scrollbar_popup.pack(side=tk.RIGHT, fill=tk.Y)
        result_area_popup.config(yscrollcommand=scrollbar_popup.set)

        try:
            iot_query = "port:554"
            results = shodan_client.search(iot_query)
            for result in results['matches']:
                ip_str = result['ip_str']
                org = result.get('org', 'Unknown Organization')
                data = result['data']
                result_area_popup.insert(tk.END, f"IP: {ip_str}\nOrg: {org}\nData: {data}\n{'-'*50}\n")

        except shodan.APIError as e:
            messagebox.showerror("Error", str(e))

    def monitor_iot_systems(self):
        monitor_window = tk.Toplevel(self.root)
        monitor_window.title("Live IoT System Monitoring")
        monitor_window.geometry("900x600")

        result_frame_monitor = tk.Frame(monitor_window, bg=self.bg_color)
        result_frame_monitor.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        result_area_monitor = tk.Text(result_frame_monitor, bg="#3b3b3b", fg=self.text_color, font=("Helvetica", 10))
        result_area_monitor.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        scrollbar_monitor = tk.Scrollbar(result_frame_monitor, command=result_area_monitor.yview)
        scrollbar_monitor.pack(side=tk.RIGHT, fill=tk.Y)
        result_area_monitor.config(yscrollcommand=scrollbar_monitor.set)

        def update_monitor():
            if not monitor_window.winfo_exists():
                return
            
            try:
                iot_query = "port:554"
                results = shodan_client.search(iot_query)
                result_area_monitor.delete('1.0', tk.END)
                for result in results['matches']:
                    ip_str = result['ip_str']
                    org = result.get('org', 'Unknown Organization')
                    data = result['data']
                    result_area_monitor.insert(tk.END, f"IP: {ip_str}\nOrg: {org}\nData: {data}\n{'-'*50}\n")
                self.root.after(60000, update_monitor)  # Update every 60 seconds
            except shodan.APIError as e:
                messagebox.showerror("Error", str(e))

        update_monitor()

    def perform_vulnerability_lookup(self):
        query = self.search_entry.get()
        try:
            results = shodan_client.search(query)
            details_window = tk.Toplevel(self.root)
            details_window.title("Vulnerability Lookup")
            details_window.geometry("900x600")

            result_frame_details = tk.Frame(details_window, bg=self.bg_color)
            result_frame_details.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            result_area_details = tk.Text(result_frame_details, bg="#3b3b3b", fg=self.text_color, font=("Helvetica", 10))
            result_area_details.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

            scrollbar_details = tk.Scrollbar(result_frame_details, command=result_area_details.yview)
            scrollbar_details.pack(side=tk.RIGHT, fill=tk.Y)
            result_area_details.config(yscrollcommand=scrollbar_details.set)

            ip = results['ip_str']
            org = results.get('org', 'Unknown Organization')
            data = results['data']
            result_area_details.insert(tk.END, f"IP: {ip}\nOrg: {org}\nData: {data}\n{'-'*50}\n")

        except shodan.APIError as e:
            messagebox.showerror("Error", str(e))

    def perform_historical_lookup(self):
        query = self.search_entry.get()
        try:
            results = shodan_client.search(query)
            details_window = tk.Toplevel(self.root)
            details_window.title("Historical Data Lookup")
            details_window.geometry("900x600")

            result_frame_details = tk.Frame(details_window, bg=self.bg_color)
            result_frame_details.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            result_area_details = tk.Text(result_frame_details, bg="#3b3b3b", fg=self.text_color, font=("Helvetica", 10))
            result_area_details.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

            scrollbar_details = tk.Scrollbar(result_frame_details, command=result_area_details.yview)
            scrollbar_details.pack(side=tk.RIGHT, fill=tk.Y)
            result_area_details.config(yscrollcommand=scrollbar_details.set)

            for result in results['matches']:
                ip_str = result['ip_str']
                org = result.get('org', 'Unknown Organization')
                data = result['data']
                result_area_details.insert(tk.END, f"IP: {ip_str}\nOrg: {org}\nData: {data}\n{'-'*50}\n")

        except shodan.APIError as e:
            messagebox.showerror("Error", str(e))

    def export_results(self):
        file_type = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if not file_type:
            return
        
        content = self.result_area.get('1.0', tk.END).strip()
        
        if not content:
            messagebox.showwarning("Warning", "No data available to export.")
            return
        
        try:
            if file_type.endswith(".csv"):
                with open(file_type, 'w', newline='', encoding='utf-8') as file:
                    writer = csv.writer(file)
                    writer.writerow(["IP", "Organization", "Data"])
                    lines = content.split('\n')
                    for i in range(0, len(lines), 3):
                        ip_line = lines[i].replace("IP: ", "")
                        org_line = lines[i+1].replace("Org: ", "")
                        data_line = lines[i+2].replace("Data: ", "")
                        writer.writerow([ip_line, org_line, data_line])
                messagebox.showinfo("Success", "Results exported to CSV successfully.")
                
            else:
                with open(file_type, 'w', encoding='utf-8') as file:
                    file.write(content)
                messagebox.showinfo("Success", "Results exported to text file successfully.")
        
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while exporting results: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = ShodanSearchApp(root)
    root.mainloop()
