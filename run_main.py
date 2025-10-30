import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import json
import ipaddress
import os
import paramiko
import csv
from datetime import datetime
from pathlib import Path

# Configuration - These will be set via dialog if not configured
FTP_SERVER_IP = None
FTP_USERNAME = None
FTP_PASSWORD = None

# Default values
DEFAULT_HOSTNAME = "default_host"
DEFAULT_VLAN_ID = "0"
DEFAULT_VLAN_NAME = "default_vlan"
DEFAULT_LOCATION = "default_location"

class TemplateManager:
    def __init__(self, template_dir="templates"):
        self.template_dir = Path(template_dir)
        self.template_dir.mkdir(exist_ok=True)
    
    def load_template(self, template_name):
        """Load template from file"""
        template_file = self.template_dir / f"{template_name}.j2"
        if template_file.exists():
            with open(template_file, 'r') as f:
                return f.read()
        else:
            raise FileNotFoundError(f"Template {template_name} not found at {template_file}")
    
    def get_available_templates(self):
        """Get list of available templates"""
        templates = []
        for file in self.template_dir.glob("*.j2"):
            templates.append(file.stem)
        return sorted(templates)

class NetworkConfig:
    def __init__(self, config_dir="config"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)
        self.config_file = self.config_dir / "network_config.json"
        self.load_config()
    
    def load_config(self):
        """Load network configuration from JSON file"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    self.config = json.load(f)
                print(f"Loaded network configuration from {self.config_file}")
            except json.JSONDecodeError as e:
                messagebox.showerror("Config Error", f"Invalid JSON in config file: {e}")
                self._create_default_config()
        else:
            self._create_default_config()
    
    def _create_default_config(self):
        """Create default network configuration"""
        # Just create a basic structure, user should populate the actual config file
        self.config = {
            "aruba-sw": {
                "network_address": "172.22.27.0",
                "subnet_mask": "255.255.255.0",
                "gateway": "172.17.27.254",
                "hosts_range": ["172.22.27.1", "172.22.27.253"],
                "data_vlan": {
                    "id": "100",
                    "name": "Data_VLAN"
                },
                "profiles": {
                    "av": {},
                    "standard": {}
                }
            }
        }
        self.save_config()
        print(f"Created basic network configuration at {self.config_file}")
        print("Please populate the network_config.json file with your network details and profiles")
    
    def save_config(self):
        """Save network configuration to JSON file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            print(f"Saved network configuration to {self.config_file}")
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def get_network_names(self):
        """Get list of available network names"""
        return list(self.config.keys())
    
    def calculate_gateway(self, management_ip):
        """Calculate gateway IP based on management IP"""
        try:
            ip = ipaddress.IPv4Address(management_ip)
            
            # Check which network the IP belongs to
            for network_name, network_config in self.config.items():
                try:
                    network = ipaddress.IPv4Network(
                        f"{network_config['network_address']}/{network_config['subnet_mask']}", 
                        strict=False
                    )
                    if ip in network:
                        print(f"IP {management_ip} belongs to network {network_name}, gateway: {network_config['gateway']}")
                        return network_config['gateway']
                except Exception as e:
                    print(f"Error processing network {network_name}: {e}")
                    continue
            
            # If no match found, use default gateway calculation (.254)
            network = ipaddress.IPv4Network(f"{management_ip}/24", strict=False)
            default_gateway = str(network.network_address + 254)
            print(f"No matching network found for {management_ip}, using default gateway: {default_gateway}")
            return default_gateway
            
        except Exception as e:
            print(f"Error calculating gateway: {e}")
            return "0.0.0.0"
    
    def get_profile_vlans(self, management_ip, profile_type):
        """Get the VLANs for the specified profile type based on management IP location"""
        try:
            ip = ipaddress.IPv4Address(management_ip)
            
            # Check which network the IP belongs to
            for network_name, network_config in self.config.items():
                try:
                    network = ipaddress.IPv4Network(
                        f"{network_config['network_address']}/{network_config['subnet_mask']}", 
                        strict=False
                    )
                    if ip in network:
                        if 'profiles' in network_config and profile_type in network_config['profiles']:
                            print(f"Found {profile_type} profile VLANs for network {network_name}: {network_config['profiles'][profile_type]}")
                            return network_config['profiles'][profile_type]
                        else:
                            print(f"No {profile_type} profile found for network {network_name}")
                            return {}
                except Exception as e:
                    print(f"Error processing network {network_name}: {e}")
                    continue
            
            print(f"No matching network found for {management_ip}")
            return {}
            
        except Exception as e:
            print(f"Error getting profile VLANs: {e}")
            return {}
    
    def get_data_vlan_info(self, management_ip):
        """Get data VLAN ID and name based on management IP location"""
        try:
            ip = ipaddress.IPv4Address(management_ip)
            
            # Check which network the IP belongs to
            for network_name, network_config in self.config.items():
                try:
                    network = ipaddress.IPv4Network(
                        f"{network_config['network_address']}/{network_config['subnet_mask']}", 
                        strict=False
                    )
                    if ip in network:
                        if 'data_vlan' in network_config:
                            return network_config['data_vlan']['id'], network_config['data_vlan']['name']
                        else:
                            print(f"No data_vlan found for network {network_name}")
                            return DEFAULT_VLAN_ID, DEFAULT_VLAN_NAME
                except Exception as e:
                    print(f"Error processing network {network_name}: {e}")
                    continue
            
            print(f"No matching network found for {management_ip}")
            return DEFAULT_VLAN_ID, DEFAULT_VLAN_NAME
            
        except Exception as e:
            print(f"Error getting data VLAN info: {e}")
            return DEFAULT_VLAN_ID, DEFAULT_VLAN_NAME
    
    def generate_hostname(self, management_ip, template_type):
        """Generate hostname based on management IP and template type"""
        try:
            ip = ipaddress.IPv4Address(management_ip)
            octets = str(ip).split('.')
            
            if template_type == "aruba-4100":
                return f"ae4100i-{octets[1]}-{octets[2]}-{octets[3]}"
            elif template_type == "aruba-6300":
                return f"ae6300M-{octets[1]}-{octets[2]}-{octets[3]}"
            else:
                return f"{template_type}-{octets[1]}-{octets[2]}-{octets[3]}"
                
        except Exception as e:
            print(f"Error generating hostname: {e}")
            return DEFAULT_HOSTNAME

class SFTPUploader:
    def __init__(self):
        self.authenticated = False
        self.ftp_server_ip = None
        self.ftp_username = None
        self.ftp_password = None
        
    def authenticate(self, server_ip, username, password):
        """Authenticate with SFTP server"""
        self.ftp_server_ip = server_ip
        self.ftp_username = username
        self.ftp_password = password
        self.authenticated = True
        print(f"SFTP authenticated for server: {server_ip}, username: {username}")
        
    def upload_with_sftp(self, local_file: str, remote_file: str) -> bool:
        """Upload file to SFTP server"""
        if not self.authenticated:
            print("Cannot upload - not authenticated")
            return False
            
        if not self.ftp_server_ip or not self.ftp_username or not self.ftp_password:
            print("SFTP credentials not set")
            return False
            
        print(f"Starting SFTP upload to {self.ftp_server_ip}")
        
        try:
            transport = paramiko.Transport((self.ftp_server_ip, 22))
            transport.connect(username=self.ftp_username, password=self.ftp_password)
            sftp = paramiko.SFTPClient.from_transport(transport)
            
            remote_directory = "ztp"
            
            # Try to create remote directory if it doesn't exist
            try:
                sftp.mkdir(remote_directory)
            except IOError:
                # Directory likely already exists
                pass
                
            remote_path = f"{remote_directory}/{remote_file}"
            
            sftp.put(local_file, remote_path)
            sftp.close()
            transport.close()
            
            print(f"Uploaded {local_file} to {self.ftp_server_ip} as {remote_path}")
            return True
            
        except Exception as e:
            print(f"SFTP upload failed: {e}")
            return False

class SFTPLoginDialog(simpledialog.Dialog):
    def __init__(self, parent, title="SFTP Login"):
        self.server_ip = None
        self.username = None
        self.password = None
        super().__init__(parent, title)
        
    def body(self, master):
        ttk.Label(master, text="SFTP Server:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.server_entry = ttk.Entry(master, width=30)
        self.server_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        
        ttk.Label(master, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.user_entry = ttk.Entry(master, width=30)
        self.user_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        
        ttk.Label(master, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.pass_entry = ttk.Entry(master, width=30, show="*")
        self.pass_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5, padx=5)
        
        # Set focus to server entry
        self.server_entry.focus_set()
        
        return self.server_entry  # initial focus
    
    def apply(self):
        self.server_ip = self.server_entry.get().strip()
        self.username = self.user_entry.get().strip()
        self.password = self.pass_entry.get().strip()

class SwitchConfigGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("Aruba Switch Configuration Generator")
        self.root.geometry("600x750")
        
        # Initialize managers
        self.template_manager = TemplateManager()
        self.network_config = NetworkConfig()
        self.sftp_uploader = SFTPUploader()
        
        # Create output directory
        self.output_dir = Path("generated_configs")
        self.output_dir.mkdir(exist_ok=True)
        
        self.create_widgets()
        
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, text="Aruba Switch Configuration Generator", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Template Selection
        ttk.Label(main_frame, text="Switch Template:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.template_var = tk.StringVar()
        
        # Get available templates
        templates = self.template_manager.get_available_templates()
        if not templates:
            messagebox.showwarning("No Templates", "No template files found in templates folder!")
            templates = ["aruba-4100", "aruba-6300"]  # Fallback
        
        template_combo = ttk.Combobox(main_frame, textvariable=self.template_var, 
                                     values=templates, state="readonly")
        template_combo.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5)
        template_combo.set(templates[0])  # Set first template as default
        
        # Profile Selection
        ttk.Label(main_frame, text="Profile:").grid(row=2, column=0, sticky=tk.W, pady=5)
        profile_frame = ttk.Frame(main_frame)
        profile_frame.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5)
        
        self.profile_var = tk.StringVar(value="standard")
        self.standard_check = ttk.Checkbutton(profile_frame, text="Standard", 
                                            variable=self.profile_var, 
                                            onvalue="standard", offvalue="")
        self.standard_check.pack(side=tk.LEFT, padx=(0, 10))
        
        self.av_check = ttk.Checkbutton(profile_frame, text="AV", 
                                      variable=self.profile_var,
                                      onvalue="av", offvalue="")
        self.av_check.pack(side=tk.LEFT)
        
        # Management IP (Required) - MOVED BEFORE HOSTNAME
        ttk.Label(main_frame, text="Management IP *:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.management_ip_var = tk.StringVar()
        management_ip_entry = ttk.Entry(main_frame, textvariable=self.management_ip_var)
        management_ip_entry.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=5)
        # Bind auto-fill to management IP changes
        management_ip_entry.bind('<FocusOut>', self.auto_fill_fields)
        
        # Hostname
        ttk.Label(main_frame, text="Hostname:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.hostname_var = tk.StringVar()
        hostname_entry = ttk.Entry(main_frame, textvariable=self.hostname_var)
        hostname_entry.grid(row=4, column=1, sticky=(tk.W, tk.E), pady=5)
        
        # Location
        ttk.Label(main_frame, text="Location:").grid(row=5, column=0, sticky=tk.W, pady=5)
        self.location_var = tk.StringVar()
        location_entry = ttk.Entry(main_frame, textvariable=self.location_var)
        location_entry.grid(row=5, column=1, sticky=(tk.W, tk.E), pady=5)
        # Add placeholder text
        location_entry.insert(0, DEFAULT_LOCATION)
        
        # Data VLAN ID
        ttk.Label(main_frame, text="Data VLAN ID:").grid(row=6, column=0, sticky=tk.W, pady=5)
        self.data_vlan_id_var = tk.StringVar()
        data_vlan_id_entry = ttk.Entry(main_frame, textvariable=self.data_vlan_id_var)
        data_vlan_id_entry.grid(row=6, column=1, sticky=(tk.W, tk.E), pady=5)
        
        # Data VLAN Name
        ttk.Label(main_frame, text="Data VLAN Name:").grid(row=7, column=0, sticky=tk.W, pady=5)
        self.data_vlan_name_var = tk.StringVar()
        data_vlan_name_entry = ttk.Entry(main_frame, textvariable=self.data_vlan_name_var)
        data_vlan_name_entry.grid(row=7, column=1, sticky=(tk.W, tk.E), pady=5)
        
        # MAC Address (Required)
        ttk.Label(main_frame, text="MAC Address *:").grid(row=8, column=0, sticky=tk.W, pady=5)
        self.mac_address_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.mac_address_var).grid(row=8, column=1, sticky=(tk.W, tk.E), pady=5)
        
        # Serial Number (Required)
        ttk.Label(main_frame, text="Serial Number *:").grid(row=9, column=0, sticky=tk.W, pady=5)
        self.serial_number_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.serial_number_var).grid(row=9, column=1, sticky=(tk.W, tk.E), pady=5)
        
        # Upload option
        self.upload_var = tk.BooleanVar()
        upload_check = ttk.Checkbutton(main_frame, text="Upload to SFTP server", 
                                      variable=self.upload_var,
                                      command=self.on_upload_toggle)
        upload_check.grid(row=10, column=0, columnspan=2, pady=10)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=11, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Generate Configuration", 
                  command=self.generate_config).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Clear All", 
                  command=self.clear_all).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Exit", 
                  command=self.root.quit).pack(side=tk.LEFT, padx=5)
        
        # Required fields note
        required_note = ttk.Label(main_frame, text="* Required fields", 
                                 font=("Arial", 9, "italic"), foreground="red")
        required_note.grid(row=12, column=0, columnspan=2, pady=(5, 0))
        
        # Output text area
        ttk.Label(main_frame, text="Output:").grid(row=13, column=0, sticky=tk.W, pady=(20, 5))
        
        self.output_text = tk.Text(main_frame, height=15, width=70)
        self.output_text.grid(row=14, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Scrollbar for output text
        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.output_text.yview)
        scrollbar.grid(row=14, column=2, sticky=(tk.N, tk.S))
        self.output_text.configure(yscrollcommand=scrollbar.set)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.grid(row=15, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(5, 0))
        
        # Configure grid weights
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(14, weight=1)
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
    
    def auto_fill_fields(self, event=None):
        """Auto-fill hostname and data VLAN fields based on management IP"""
        management_ip = self.management_ip_var.get().strip()
        
        if not management_ip:
            return
        
        try:
            # Validate IP address
            ipaddress.IPv4Address(management_ip)
            
            # Generate hostname
            template_type = self.template_var.get()
            hostname = self.network_config.generate_hostname(management_ip, template_type)
            self.hostname_var.set(hostname)
            
            # Get data VLAN info
            data_vlan_id, data_vlan_name = self.network_config.get_data_vlan_info(management_ip)
            self.data_vlan_id_var.set(data_vlan_id)
            self.data_vlan_name_var.set(data_vlan_name)
            
        except ipaddress.AddressValueError:
            # Invalid IP, do nothing
            pass
        except Exception as e:
            print(f"Error auto-filling fields: {str(e)}")
    
    def on_upload_toggle(self):
        """Handle upload checkbox toggle"""
        if self.upload_var.get() and not self.sftp_uploader.authenticated:
            self.configure_sftp()
    
    def configure_sftp(self):
        """Configure SFTP credentials"""
        dialog = SFTPLoginDialog(self.root)
        
        if dialog.server_ip and dialog.username and dialog.password:
            self.sftp_uploader.authenticate(dialog.server_ip, dialog.username, dialog.password)
            messagebox.showinfo("SFTP Configuration", "SFTP credentials configured successfully!")
        else:
            self.upload_var.set(False)
            messagebox.showwarning("SFTP Configuration", "SFTP configuration was cancelled.")
    
    def generate_profile_vlan_config(self, management_ip, profile_type):
        """Generate VLAN configuration blocks for the selected profile"""
        profile_vlans = self.network_config.get_profile_vlans(management_ip, profile_type)
        vlan_config = ""
        
        if profile_vlans:
            for vlan_id, vlan_name in profile_vlans.items():
                vlan_config += f"vlan {vlan_id}\n"
                vlan_config += f"   name {vlan_name}\n"
                vlan_config += "!\n"
        
        return vlan_config
    
    def generate_aruba_central_json(self, hostname, management_ip, data_vlan_id, data_vlan_name, 
                                  location, gateway, mac_address, serial_number, profile_type):
        """Generate JSON file for Aruba Central"""
        central_data = {
            serial_number: {
                "_sys_data_vlan_id": data_vlan_id,
                "_sys_data_vlan_name": data_vlan_name,
                "_sys_gateway": gateway,
                "_sys_hostname": hostname,
                "_sys_lan_mac": mac_address,
                "_sys_location": location,
                "_sys_mgnt_ip": management_ip,
                "_sys_serial": serial_number
            }
        }
        
        # Add profile-specific VLANs
        profile_vlans = self.network_config.get_profile_vlans(management_ip, profile_type)
        print(f"Profile VLANs for {profile_type}: {profile_vlans}")  # Debug print
        
        if profile_vlans:
            for vlan_id, vlan_name in profile_vlans.items():
                central_data[serial_number][f"_sys_{vlan_id}_vlan_name"] = vlan_name
            print(f"Added {len(profile_vlans)} profile VLANs to JSON")  # Debug print
        else:
            print(f"No profile VLANs found for {profile_type} profile")  # Debug print
        
        return central_data
    
    def save_csv_file(self, central_json, output_path):
        """Save CSV version of the JSON data"""
        try:
            with open(output_path, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                
                # Write header
                writer.writerow(['Variable', 'Value'])
                
                # Write data rows
                for serial_number, data in central_json.items():
                    for key, value in data.items():
                        writer.writerow([key, value])
                        
            print(f"CSV file saved: {output_path}")
        except Exception as e:
            print(f"Error saving CSV file: {e}")
    
    def generate_config(self):
        """Generate configuration based on user input"""
        try:
            # Validate required fields
            if not all([
                self.management_ip_var.get(),
                self.mac_address_var.get(),
                self.serial_number_var.get()
            ]):
                messagebox.showerror("Error", "Please fill in all required fields (*)")
                return
            
            # Validate IP address
            try:
                ipaddress.IPv4Address(self.management_ip_var.get())
            except ipaddress.AddressValueError:
                messagebox.showerror("Error", "Invalid Management IP address")
                return
            
            # Validate profile selection
            if not self.profile_var.get():
                messagebox.showerror("Error", "Please select a profile (Standard or AV)")
                return
            
            # Check SFTP authentication if upload is selected
            if self.upload_var.get() and not self.sftp_uploader.authenticated:
                if not messagebox.askyesno("SFTP Not Configured", 
                                         "SFTP is not configured. Would you like to configure it now?"):
                    self.upload_var.set(False)
                else:
                    self.configure_sftp()
                    if not self.sftp_uploader.authenticated:
                        self.upload_var.set(False)
                        messagebox.showwarning("SFTP Required", 
                                            "Upload cancelled. Configuration will be generated locally only.")
            
            self.status_var.set("Loading template...")
            self.root.update()
            
            # Load template
            template_content = self.template_manager.load_template(self.template_var.get())
            
            self.status_var.set("Calculating gateway...")
            self.root.update()
            
            # Calculate gateway
            gateway = self.network_config.calculate_gateway(self.management_ip_var.get())
            
            self.status_var.set("Generating configuration...")
            self.root.update()
            
            # Use default values for empty optional fields
            hostname = self.hostname_var.get() or DEFAULT_HOSTNAME
            data_vlan_id = self.data_vlan_id_var.get() or DEFAULT_VLAN_ID
            data_vlan_name = self.data_vlan_name_var.get() or DEFAULT_VLAN_NAME
            location = self.location_var.get() or DEFAULT_LOCATION
            mac_address = self.mac_address_var.get()
            serial_number = self.serial_number_var.get()
            management_ip = self.management_ip_var.get()
            profile_type = self.profile_var.get()
            
            # Generate profile VLAN configuration
            profile_vlan_config = self.generate_profile_vlan_config(management_ip, profile_type)
            
            # Replace variables in template
            config = template_content.replace("{{hostname}}", hostname)
            config = config.replace("{{management_ip}}", management_ip)
            config = config.replace("{{data_vlan_id}}", data_vlan_id)
            config = config.replace("{{data_vlan_name}}", data_vlan_name)
            config = config.replace("{{snmp_location}}", location)
            config = config.replace("{{gateway}}", gateway)
            
            # Insert profile VLANs into the configuration
            # Find the position to insert VLANs (after existing VLAN definitions)
            if "{{profile_vlans}}" in template_content:
                config = config.replace("{{profile_vlans}}", profile_vlan_config)
            else:
                # If no placeholder, insert after the data VLAN definition
                vlan_insert_position = config.find(f"vlan {data_vlan_id}")
                if vlan_insert_position != -1:
                    # Find the end of the data VLAN block
                    end_of_data_vlan = config.find("!", vlan_insert_position)
                    if end_of_data_vlan != -1:
                        # Insert profile VLANs after the data VLAN
                        config = config[:end_of_data_vlan + 1] + "\n" + profile_vlan_config + config[end_of_data_vlan + 1:]
            
            # Generate fixed filenames (overwrite each time)
            config_file_path = self.output_dir / "config.cfg"
            json_file_path = self.output_dir / "variables.json"
            csv_file_path = self.output_dir / "variables.csv"
            
            # Save configuration to file (overwrite)
            with open(config_file_path, 'w') as f:
                f.write(config)
            
            # Generate Aruba Central JSON
            central_json = self.generate_aruba_central_json(
                hostname, management_ip, data_vlan_id, data_vlan_name, 
                location, gateway, mac_address, serial_number, profile_type
            )
            
            # Save Aruba Central JSON file (overwrite)
            with open(json_file_path, 'w') as f:
                json.dump(central_json, f, indent=2)
            
            # Save CSV file (overwrite)
            self.save_csv_file(central_json, csv_file_path)
            
            # Display configuration in output text
            self.output_text.delete(1.0, tk.END)
            output_content = f"=== SWITCH CONFIGURATION ===\n{config}\n\n"
            output_content += f"=== ARUBA CENTRAL JSON ({profile_type.upper()} PROFILE) ===\n{json.dumps(central_json, indent=2)}"
            self.output_text.insert(1.0, output_content)
            
            # Upload to SFTP if selected and authenticated
            if self.upload_var.get() and self.sftp_uploader.authenticated:
                self.status_var.set("Uploading to SFTP...")
                self.root.update()
                
                # Use MAC address as remote filename for config
                remote_filename = f"{mac_address.replace(':', '').replace('-', '').lower()}.cfg"
                
                if self.sftp_uploader.upload_with_sftp(str(config_file_path), remote_filename):
                    messagebox.showinfo("Success", 
                                      f"Configuration generated and uploaded successfully!\n\n"
                                      f"Profile: {profile_type.upper()}\n\n"
                                      f"Local files (overwritten):\n"
                                      f"- {config_file_path}\n"
                                      f"- {json_file_path}\n"
                                      f"- {csv_file_path}\n\n"
                                      f"Remote file: {remote_filename}")
                    self.status_var.set("Upload successful!")
                else:
                    messagebox.showwarning("Upload Failed", 
                                         f"Configuration generated but upload failed!\n\n"
                                         f"Profile: {profile_type.upper()}\n\n"
                                         f"Local files (overwritten):\n"
                                         f"- {config_file_path}\n"
                                         f"- {json_file_path}\n"
                                         f"- {csv_file_path}")
                    self.status_var.set("Upload failed!")
            else:
                messagebox.showinfo("Success", 
                                  f"Configuration generated successfully!\n\n"
                                  f"Profile: {profile_type.upper()}\n\n"
                                  f"Files created (overwritten):\n"
                                  f"- {config_file_path}\n"
                                  f"- {json_file_path}\n"
                                  f"- {csv_file_path}")
                self.status_var.set("Configuration generated!")
                
        except FileNotFoundError as e:
            messagebox.showerror("Template Error", f"Template file not found: {e}")
            self.status_var.set("Error: Template not found")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
            self.status_var.set("Error occurred")
    
    def clear_all(self):
        """Clear all input fields"""
        self.hostname_var.set("")
        self.management_ip_var.set("")
        self.location_var.set("")
        self.data_vlan_id_var.set("")
        self.data_vlan_name_var.set("")
        self.mac_address_var.set("")
        self.serial_number_var.set("")
        self.profile_var.set("standard")  # Reset to standard profile
        self.output_text.delete(1.0, tk.END)
        self.upload_var.set(False)
        self.status_var.set("Ready")

def main():
    root = tk.Tk()
    app = SwitchConfigGenerator(root)
    root.mainloop()

if __name__ == "__main__":
    main()