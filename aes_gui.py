import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import mysql.connector
from mysql.connector import errorcode
import bcrypt
import os
import shutil
import subprocess
import platform
import time
from datetime import datetime

# --- MySQL Database Configuration ---
DB_CONFIG = {
    'host': '127.0.0.1',
    'user': 'root', 
    'password': '',
    'database': 'secure_share_db_v3' # Ensure this DB exists or user has create privileges
}

# --- Configurable Path for code.sh ---
CODE_SH_SCRIPT_PATH = "./code.sh" # UPDATE AS NEEDED


def find_bash_on_windows():
    common_paths = [
        os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "Git", "usr", "bin", "bash.exe"),
        os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "Git", "bin", "bash.exe"),
        os.path.join(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"), "Git", "usr", "bin", "bash.exe"),
        os.path.join(os.environ.get("ProgramW6432", "C:\\Program Files"), "Git", "usr", "bin", "bash.exe"), # For 64-bit git on 64-bit python
        os.path.join(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"), "Git", "bin", "bash.exe"),
    ]
    for path in common_paths:
        if os.path.exists(path): return path
    # Fallback to hoping 'bash' is in PATH if common locations not found
    # This is important, otherwise it returns 'bash' even if a path was found above.
    # Only return 'bash' if NO common path was valid.
    # Correction: The original logic would return "bash" if os.environ.get("ProgramFiles") was None.
    
    # Try checking PATH directly via shutil.which
    bash_from_path = shutil.which("bash")
    if bash_from_path:
        return bash_from_path
        
    # If still not found, return "bash" and let Popen try to find it via PATH
    return "bash"


# --- Database Setup (MySQL - V3 Schema) ---
def init_db():
    try:
        # Connect without specifying a database first to try and create it
        cnx = mysql.connector.connect(host=DB_CONFIG['host'], user=DB_CONFIG['user'], password=DB_CONFIG['password'])
        cursor = cnx.cursor()
        db_name = DB_CONFIG['database']
        try:
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_name} DEFAULT CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_ci'")
            print(f"Database '{db_name}' ensured.")
        except mysql.connector.Error as err:
            # If DB creation fails but DB exists (e.g. insufficient privileges), proceed.
            if err.errno != errorcode.ER_DB_CREATE_EXISTS:
                 print(f"Failed creating database '{db_name}': {err}")
                 exit(1) # Exit if it's a different error like access denied to create

        cursor.execute(f"USE {db_name}") # Select the database
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255) UNIQUE NOT NULL, 
                password_hash VARCHAR(255) NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_files (
                id INT AUTO_INCREMENT PRIMARY KEY, 
                owner_user_id INT NOT NULL,
                original_filename VARCHAR(255) NOT NULL,
                encrypted_filename VARCHAR(255) NOT NULL,
                encrypted_filepath VARCHAR(1024) NOT NULL, 
                filesize BIGINT, 
                upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (owner_user_id) REFERENCES users (id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;''')
            
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_shares (
                id INT AUTO_INCREMENT PRIMARY KEY, 
                file_id INT NOT NULL,
                sharer_user_id INT NOT NULL,
                shared_with_user_id INT NOT NULL,
                permissions VARCHAR(50) DEFAULT 'view',
                file_encryption_password_mock TEXT, 
                share_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (file_id) REFERENCES user_files (id) ON DELETE CASCADE,
                FOREIGN KEY (sharer_user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (shared_with_user_id) REFERENCES users (id) ON DELETE CASCADE,
                UNIQUE KEY unique_share (file_id, shared_with_user_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;''')
        cnx.commit()
        print(f"Database '{db_name}' tables V3 checked/created.")
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR: print("MySQL Access denied: Check username/password for MySQL server connection.")
        elif err.errno == errorcode.ER_BAD_DB_ERROR: print(f"MySQL Database '{DB_CONFIG['database']}' problem or does not exist and could not be created.")
        else: print(f"MySQL Error in init_db: {err}")
        exit(1) # Exit if DB setup fails critically
    finally:
        if 'cnx' in locals() and cnx.is_connected(): cursor.close(); cnx.close()

# --- User Authentication Logic ---
def hash_password(password): return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
def check_password(password, hashed_pw_bytes): return bcrypt.checkpw(password.encode('utf-8'), hashed_pw_bytes)

def register_user(username, password):
    if not username or not password: return False, "Username/password empty."
    hashed_pw_bytes = hash_password(password)    
    cnx = None
    try:
        cnx = mysql.connector.connect(**DB_CONFIG)
        cursor = cnx.cursor()
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, hashed_pw_bytes.decode('utf-8')))
        cnx.commit()
        user_files_dir = os.path.join("user_data", username, "files")
        os.makedirs(user_files_dir, exist_ok=True)
        return True, "Registration successful!"
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_DUP_ENTRY: return False, "Username already taken."
        else: print(f"MySQL Error in register_user: {err}"); return False, f"DB error: {err}"
    finally:
        if cnx and cnx.is_connected(): cursor.close(); cnx.close()

def login_user(username, password):
    if not username or not password: return False, "Username/password empty.", None
    cnx = None
    try:
        cnx = mysql.connector.connect(**DB_CONFIG)
        cursor = cnx.cursor()
        cursor.execute("SELECT id, password_hash FROM users WHERE username = %s", (username,))
        result = cursor.fetchone()
        if result:
            user_id, hashed_pw_str_from_db = result
            if check_password(password, hashed_pw_str_from_db.encode('utf-8')):
                return True, "Login successful!", user_id
            else: return False, "Invalid password.", None
        else: return False, "Username not found.", None
    except mysql.connector.Error as err: print(f"MySQL Error in login_user: {err}"); return False, f"DB error: {err}", None
    finally:
        if cnx and cnx.is_connected(): cursor.close(); cnx.close()

# --- File Operations & Encryption/Decryption using code.sh ---
def run_encryption_script(mode, input_file, output_file, password):
    script_path_abs = os.path.abspath(CODE_SH_SCRIPT_PATH)
    if not os.path.exists(script_path_abs):
        return False, f"Encryption script not found at specified path: {script_path_abs}", ""
    
    current_os = platform.system()
    if not os.access(script_path_abs, os.X_OK) and current_os != "Windows":
        try: os.chmod(script_path_abs, 0o755)
        except Exception as e: return False, f"Script not executable and chmod failed: {e}", ""

    cmd_prefix = []
    if current_os == "Windows":
        bash_executable = find_bash_on_windows()
        if not os.path.exists(bash_executable) and bash_executable == "bash":
            return False, "bash.exe not found in PATH or common Git locations. Please install Git for Windows and ensure bash is in PATH.", ""
        cmd_prefix = [bash_executable]
    
    abs_input_file = os.path.abspath(input_file)
    abs_output_file = os.path.abspath(output_file)

    bash_input_file = abs_input_file
    bash_output_file = abs_output_file

    if current_os == "Windows":
        drive_letter_input, path_without_drive_input = os.path.splitdrive(abs_input_file)
        if drive_letter_input:
             bash_input_file = "/" + drive_letter_input.lower().replace(":", "") + path_without_drive_input.replace(os.sep, "/")
        else: bash_input_file = abs_input_file.replace(os.sep, "/")
        drive_letter_output, path_without_drive_output = os.path.splitdrive(abs_output_file)
        if drive_letter_output:
            bash_output_file = "/" + drive_letter_output.lower().replace(":", "") + path_without_drive_output.replace(os.sep, "/")
        else: bash_output_file = abs_output_file.replace(os.sep, "/")
    
    # Command now includes mode, input file, and output file as arguments
    command = cmd_prefix + [
        script_path_abs,
        'e' if mode == 'encrypt' else 'd', # Mode as argument 1
        bash_input_file,                   # Input file as argument 2
        bash_output_file                   # Output file as argument 3
    ]
    
    # Password(s) are still sent via stdin
    password_input_str = f"{password}\n"
    if mode == 'encrypt':
        password_input_str += f"{password}\n" # Confirm password

    try:
        startupinfo = None; creation_flags = 0
        if current_os == "Windows":
            startupinfo = subprocess.STARTUPINFO(); startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW; startupinfo.wShowWindow = subprocess.SW_HIDE
            creation_flags = subprocess.CREATE_NO_WINDOW

        process = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, startupinfo=startupinfo, cwd=os.path.dirname(script_path_abs),
            creationflags=creation_flags
        )
        # Send passwords to stdin
        stdout_data, stderr_data = process.communicate(password_input_str, timeout=60)

        if process.returncode == 0:
            return True, f"File {mode}ed successfully.", stdout_data.strip()
        else:
            err_msg = f"Script error (code {process.returncode}).\n"
            # Include the full command that was attempted
            err_msg += f"Attempted to run: {' '.join(command)}\n" 
            # Note: For passwords in stdin, they won't appear in 'command' above
            err_msg += f"Bash Input File (Arg): {bash_input_file}\nBash Output File (Arg): {bash_output_file}\n"
            if stdout_data: err_msg += f"STDOUT: {stdout_data.strip()}\n"
            if stderr_data: err_msg += f"STDERR: {stderr_data.strip()}"
            return False, err_msg.strip(), stderr_data.strip()
    except subprocess.TimeoutExpired: return False, "Script execution timed out.", ""
    except FileNotFoundError as e: 
        return False, f"Command execution failed: {e}. Ensure bash (if on Windows) is in PATH or `find_bash_on_windows` works, and script path is correct. Tried: {' '.join(command)}", ""
    except Exception as e: return False, f"Unexpected error running script: {e}. Tried: {' '.join(command)}", ""

# --- Main Application Class ---
class SecureShareApp(tk.Tk):
    COLOR_BACKGROUND = "#0D1B2A"; COLOR_BACKGROUND_LIGHTER = "#1B263B"; COLOR_FOREGROUND = "#E0E1DD"
    COLOR_ACCENT = "#56CFE1"; COLOR_ACCENT_DARKER = "#48B5C4"; COLOR_ENTRY_BG = "#2A3947"
    COLOR_ENTRY_FG = COLOR_ACCENT; COLOR_BUTTON_BG = "#4A5B6F"; COLOR_BUTTON_FG = COLOR_FOREGROUND
    COLOR_BUTTON_ACTIVE_BG = "#6D839D"; COLOR_PRIMARY_ACTION_BG = COLOR_ACCENT
    COLOR_PRIMARY_ACTION_FG = "#070A0E"; COLOR_PRIMARY_ACTION_HOVER_BG = COLOR_ACCENT_DARKER
    COLOR_DISABLED_FG = "#778DA9"; COLOR_BORDER = "#415A77"
    TAG_COLORS = {"normal": COLOR_FOREGROUND, "error": "#FF6B6B", "success": "#70E094", "info": COLOR_ACCENT, "warning": "#FFB4A2"}
    FONT_PRIMARY = ("Consolas", 12); FONT_HEADER = ("Consolas", 24, "bold"); FONT_SUB_HEADER = ("Consolas", 16, "bold")
    FONT_BUTTON = ("Consolas", 12, "bold"); FONT_SMALL = ("Consolas", 10)

    def __init__(self):
        super().__init__()
        self.title("SecureShare Client (V3.1 - Polling)") # Updated title
        self.geometry("600x450")
        self.configure(bg=self.COLOR_BACKGROUND)
        self.resizable(False, False)
        
        self.poll_job = None # CRITICAL: Initialize poll_job attribute HERE
        
        self.current_user_id = None
        self.current_user_username = None
        self._setup_styles()
        self.container = tk.Frame(self, bg=self.COLOR_BACKGROUND)
        self.container.pack(side="top", fill="both", expand=True)
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)
        self.frames = {}
        self._create_auth_view("Login")
        self._create_auth_view("Register")
        self._create_main_app_view()
        
        self.show_frame("LoginView") # This will call stop_polling_shared_files
        self.center_window()
        self.POLL_INTERVAL = 30000 # milliseconds (e.g., 30 seconds)


    def _setup_styles(self):
        self.style = ttk.Style(self); self.style.theme_use('clam')
        self.style.configure("TButton", background=self.COLOR_BUTTON_BG, foreground=self.COLOR_BUTTON_FG,font=self.FONT_PRIMARY, relief="flat", padding=(10, 6),borderwidth=1, bordercolor=self.COLOR_BORDER, focuscolor=self.COLOR_ACCENT_DARKER)
        self.style.map("TButton", background=[('active', self.COLOR_BUTTON_ACTIVE_BG), ('pressed', self.COLOR_ACCENT_DARKER)],bordercolor=[('active', self.COLOR_ACCENT), ('focus', self.COLOR_ACCENT)])
        self.style.configure("Treeview", background=self.COLOR_ENTRY_BG, foreground=self.COLOR_FOREGROUND,fieldbackground=self.COLOR_ENTRY_BG, font=self.FONT_PRIMARY, rowheight=28)
        self.style.map("Treeview", background=[('selected', self.COLOR_ACCENT_DARKER)],foreground=[('selected', self.COLOR_PRIMARY_ACTION_FG)])
        self.style.configure("Treeview.Heading", background=self.COLOR_BUTTON_BG, foreground=self.COLOR_FOREGROUND,font=self.FONT_BUTTON, relief="flat", padding=5)
        self.style.map("Treeview.Heading", background=[('active', self.COLOR_BUTTON_ACTIVE_BG)])
        self.style.configure("Vertical.TScrollbar", gripcount=0, background=self.COLOR_BUTTON_BG,darkcolor=self.COLOR_BACKGROUND_LIGHTER, lightcolor=self.COLOR_BACKGROUND_LIGHTER,troughcolor=self.COLOR_BACKGROUND, bordercolor=self.COLOR_BORDER,arrowcolor=self.COLOR_ACCENT, relief='flat')
        self.style.map("Vertical.TScrollbar", background=[('active',self.COLOR_BUTTON_ACTIVE_BG)],arrowcolor=[('pressed',self.COLOR_ACCENT_DARKER)])

    def center_window(self, width=None, height=None):
        self.update_idletasks(); w = width if width else self.winfo_width(); h = height if height else self.winfo_height()
        sw = self.winfo_screenwidth(); sh = self.winfo_screenheight(); x = max(0,(sw//2)-(w//2)); y = max(0,(sh//2)-(h//2))
        if w > 0 and h > 0: self.geometry(f'{w}x{h}+{x}+{y}')

    def start_polling_shared_files(self):
        if self.current_user_id and self.frames["MainAppView"].winfo_viewable(): # Only poll if main view is active
            # print(f"[{datetime.now().strftime('%H:%M:%S')}] Polling for shared files...")
            self.frames["MainAppView"].load_user_files()
            if hasattr(self, 'poll_job') and self.poll_job is not None: # Cancel previous if any (though should be one)
                self.after_cancel(self.poll_job)
            self.poll_job = self.after(self.POLL_INTERVAL, self.start_polling_shared_files)

    def stop_polling_shared_files(self):
        if hasattr(self, 'poll_job') and self.poll_job is not None:
            try:
                self.after_cancel(self.poll_job)
                # print("Polling job cancelled.")
            except tk.TclError: # Might happen if job id is invalid or already processed
                # print(f"Note: TclError while cancelling poll_job (ID: {self.poll_job}).")
                pass # Ignore error if job can't be cancelled
            finally:
                self.poll_job = None
        # else:
            # print("Polling was already stopped or poll_job not initialized.")
    
    def show_frame(self, page_name_key):
        frame = self.frames[page_name_key]; frame.tkraise()
        if page_name_key == "MainAppView":
            self.geometry("1100x750"); self.resizable(True, True); self.center_window(1100, 750)
            if hasattr(frame, 'load_user_files'): frame.load_user_files()
            self.start_polling_shared_files()
        else: 
            self.stop_polling_shared_files()
            self.geometry("600x450"); self.resizable(False, False); self.center_window(600,450)

    def _create_input_field(self, parent, text, show_char=None, is_confirm=False):
        f = tk.Frame(parent,bg=self.COLOR_BACKGROUND); tk.Label(f,text=text,bg=self.COLOR_BACKGROUND,fg=self.COLOR_FOREGROUND,font=self.FONT_PRIMARY,width=18,anchor='w').pack(side="left",padx=(0,10))
        v = tk.StringVar(); e = tk.Entry(f,textvariable=v,bg=self.COLOR_ENTRY_BG,fg=self.COLOR_ENTRY_FG,insertbackground=self.COLOR_ACCENT,font=self.FONT_PRIMARY,relief='flat',show=show_char,borderwidth=2,highlightthickness=0)
        e.pack(side="left",fill="x",expand=True); return f, v, e

    def _create_auth_view(self, mode="Login"):
        k = f"{mode}View"; f = tk.Frame(self.container,bg=self.COLOR_BACKGROUND); self.frames[k]=f; f.grid(row=0,column=0,sticky="nsew")
        cf = tk.Frame(f,bg=self.COLOR_BACKGROUND); cf.place(relx=0.5,rely=0.5,anchor="center")
        h_txt = "SecureShare Login" if mode == "Login" else "Create Account"; tk.Label(cf,text=h_txt,font=self.FONT_HEADER,bg=self.COLOR_BACKGROUND,fg=self.COLOR_ACCENT).pack(pady=(0,30))
        f.auth_vars = {}; uf,uv,_=self._create_input_field(cf,"Username:");uf.pack(pady=8,fill="x",padx=20);f.auth_vars["username"]=uv
        pf,pv,_=self._create_input_field(cf,"Password:",show_char='●');pf.pack(pady=8,fill="x",padx=20);f.auth_vars["password"]=pv
        if mode=="Register": cpf,cpv,_=self._create_input_field(cf,"Confirm Password:",show_char='●');cpf.pack(pady=8,fill="x",padx=20);f.auth_vars["confirm_password"]=cpv
        el=tk.Label(cf,text="",font=self.FONT_SMALL,bg=self.COLOR_BACKGROUND,fg=self.TAG_COLORS["error"],wraplength=350);el.pack(pady=(5,10));f.auth_vars["error_label"]=el
        bs={"font":self.FONT_BUTTON,"relief":'flat',"borderwidth":0,"width":20,"pady":8}
        pbs={**bs,"bg":self.COLOR_PRIMARY_ACTION_BG,"fg":self.COLOR_PRIMARY_ACTION_FG,"activebackground":self.COLOR_PRIMARY_ACTION_HOVER_BG,"activeforeground":self.COLOR_PRIMARY_ACTION_FG}
        sbs={**bs,"bg":self.COLOR_BUTTON_BG,"fg":self.COLOR_BUTTON_FG,"activebackground":self.COLOR_BUTTON_ACTIVE_BG}
        if mode=="Login": tk.Button(cf,text="Login",command=self._handle_login,**pbs).pack(pady=(10,5)); tk.Button(cf,text="Create Account",command=lambda:self.show_frame("RegisterView"),**sbs).pack(pady=5)
        else: tk.Button(cf,text="Register",command=self._handle_register,**pbs).pack(pady=(10,5)); tk.Button(cf,text="Back to Login",command=lambda:self.show_frame("LoginView"),**sbs).pack(pady=5)

    def _handle_login(self):
        lf=self.frames["LoginView"]; u=lf.auth_vars["username"].get(); p=lf.auth_vars["password"].get(); el=lf.auth_vars["error_label"]
        s,m,uid=login_user(u,p)
        if s: el.config(text=m,fg=self.TAG_COLORS["success"]); self.current_user_id=uid; self.current_user_username=u; self.after(1000,lambda:self.show_frame("MainAppView"))
        else: el.config(text=m,fg=self.TAG_COLORS["error"])
        lf.auth_vars["password"].set("")

    def _handle_register(self):
        rf=self.frames["RegisterView"]; u=rf.auth_vars["username"].get(); p=rf.auth_vars["password"].get(); cp=rf.auth_vars["confirm_password"].get(); el=rf.auth_vars["error_label"]
        if not u.strip()or not p:el.config(text="Username/password empty.",fg=self.TAG_COLORS["error"]);return
        if p!=cp:el.config(text="Passwords do not match.",fg=self.TAG_COLORS["error"]);return
        if len(p)<8:el.config(text="Password at least 8 chars.",fg=self.TAG_COLORS["error"]);return
        s,m=register_user(u,p)
        if s:el.config(text=m,fg=self.TAG_COLORS["success"]);self.after(1500,lambda:self.show_frame("LoginView"))
        else:el.config(text=m,fg=self.TAG_COLORS["error"])
        rf.auth_vars["password"].set("");rf.auth_vars["confirm_password"].set("")
        
    def _create_main_app_view(self):
        frame = tk.Frame(self.container, bg=self.COLOR_BACKGROUND)
        self.frames["MainAppView"] = frame
        frame.grid(row=0, column=0, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1); frame.grid_rowconfigure(2, weight=1)
        header_area = tk.Frame(frame, bg=self.COLOR_BACKGROUND_LIGHTER, padx=10, pady=10)
        header_area.grid(row=0, column=0, columnspan=2, sticky="ew"); header_area.grid_columnconfigure(0, weight=1)
        tk.Label(header_area, text="SecureShare - File Manager", font=self.FONT_HEADER, bg=self.COLOR_BACKGROUND_LIGHTER, fg=self.COLOR_ACCENT).grid(row=0, column=0, sticky="w")
        self.current_user_label = tk.Label(header_area, text="User: N/A", font=self.FONT_PRIMARY, bg=self.COLOR_BACKGROUND_LIGHTER, fg=self.COLOR_FOREGROUND)
        self.current_user_label.grid(row=0, column=1, sticky="e", padx=(0, 20))
        ttk.Button(header_area, text="Logout", style="TButton", command=self._handle_logout, width=8).grid(row=0, column=2, sticky="e", padx=(0,10))
        toolbar_frame = tk.Frame(frame, bg=self.COLOR_BACKGROUND, pady=10)
        toolbar_frame.grid(row=1, column=0, columnspan=2, sticky="ew", padx=20)
        ttk.Button(toolbar_frame, text="Upload File", style="TButton", command=self._upload_file).pack(side="left", padx=5)
        ttk.Button(toolbar_frame, text="Download/Decrypt", style="TButton", command=self._download_file).pack(side="left", padx=5)
        ttk.Button(toolbar_frame, text="Delete File", style="TButton", command=self._delete_file_db).pack(side="left", padx=5)
        ttk.Button(toolbar_frame, text="Share File", style="TButton", command=self._share_file_with_user).pack(side="left", padx=5)
        ttk.Button(toolbar_frame, text="Refresh List", style="TButton", command=lambda: self.frames["MainAppView"].load_user_files()).pack(side="left", padx=5)
        file_list_frame = tk.Frame(frame, bg=self.COLOR_BACKGROUND)
        file_list_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=20, pady=(0,10))
        file_list_frame.grid_rowconfigure(0, weight=1); file_list_frame.grid_columnconfigure(0, weight=1)
        columns = ("original_name", "size", "upload_date", "owner_sharer", "type")
        self.file_tree = ttk.Treeview(file_list_frame, columns=columns, show="headings", style="Treeview", selectmode="browse")
        self.file_tree.heading("original_name", text="Filename"); self.file_tree.heading("size", text="Size", anchor="e")
        self.file_tree.heading("upload_date", text="Date", anchor="center")
        self.file_tree.heading("owner_sharer", text="Owner / Shared By", anchor="w"); self.file_tree.heading("type", text="Status", anchor="center") # Renamed for clarity
        self.file_tree.column("original_name", width=350, stretch=tk.YES); self.file_tree.column("size", width=100, stretch=tk.NO, anchor="e")
        self.file_tree.column("upload_date", width=150, stretch=tk.NO, anchor="center")
        self.file_tree.column("owner_sharer", width=200, stretch=tk.NO, anchor="w"); self.file_tree.column("type", width=100, stretch=tk.NO, anchor="center")
        self.file_tree.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(file_list_frame, orient="vertical", command=self.file_tree.yview, style="Vertical.TScrollbar")
        self.file_tree.configure(yscrollcommand=scrollbar.set); scrollbar.grid(row=0, column=1, sticky="ns")
        self.status_bar_label = tk.Label(frame, text="Status: Ready", font=self.FONT_SMALL, bg=self.COLOR_BORDER, fg=self.COLOR_FOREGROUND, anchor="w", padx=10)
        self.status_bar_label.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(5,0))
        frame.load_user_files = self._load_user_files_from_db

    def _load_user_files_from_db(self):
        if not self.current_user_id: return
        self.current_user_label.config(text=f"User: {self.current_user_username}")
        # Preserve selection if possible
        current_selection_iid = self.file_tree.focus()
        for item in self.file_tree.get_children(): self.file_tree.delete(item)
        cnx = None
        try:
            cnx = mysql.connector.connect(**DB_CONFIG)
            cursor = cnx.cursor(dictionary=True)
            owned_query = ("SELECT uf.id, uf.original_filename, uf.filesize, uf.upload_date, u_owner.username as owner_username "
                           "FROM user_files uf JOIN users u_owner ON uf.owner_user_id = u_owner.id WHERE uf.owner_user_id = %s")
            cursor.execute(owned_query, (self.current_user_id,))
            for file_data in cursor.fetchall(): self._insert_file_into_tree(file_data, "Owned", file_data['owner_username'])
            shared_query = ("SELECT fs.file_id as id, uf.original_filename, uf.filesize, uf.upload_date, u_sharer.username as sharer_username "
                            "FROM file_shares fs JOIN user_files uf ON fs.file_id = uf.id JOIN users u_sharer ON fs.sharer_user_id = u_sharer.id "
                            "WHERE fs.shared_with_user_id = %s AND fs.sharer_user_id != %s")
            cursor.execute(shared_query, (self.current_user_id, self.current_user_id))
            for file_data in cursor.fetchall(): self._insert_file_into_tree(file_data, "Shared", file_data['sharer_username'])
            if current_selection_iid and self.file_tree.exists(current_selection_iid):
                self.file_tree.focus(current_selection_iid)
                self.file_tree.selection_set(current_selection_iid)
        except mysql.connector.Error as err: self.status_bar_label.config(text=f"Status: DB Error loading files: {err}")
        finally:
            if cnx and cnx.is_connected(): cursor.close(); cnx.close()

    def _insert_file_into_tree(self, file_data, file_type, owner_sharer_username):
        db_id = file_data['id']; original_name = file_data['original_filename']; size_bytes = file_data.get('filesize', 0)
        upload_dt_obj = file_data.get('upload_date') or file_data.get('share_date')
        size_str = f"{size_bytes/(1024*1024):.1f} MB" if size_bytes and size_bytes>=1024*1024 else (f"{size_bytes/1024:.1f} KB" if size_bytes else "-")
        date_str = upload_dt_obj.strftime('%Y-%m-%d %H:%M') if isinstance(upload_dt_obj, datetime) else str(upload_dt_obj or "-")
        item_iid = str(db_id) + "_" + file_type.lower()
        self.file_tree.insert("", "end", iid=item_iid, values=(original_name, size_str, date_str, owner_sharer_username, file_type), tags=(file_type.lower(),))

    def _prompt_password(self, title="Enter Password", prompt="Password for operation:"):
        return simpledialog.askstring(title, prompt, show='●', parent=self)

    def _get_selected_file_info(self):
        selected_tree_iid = self.file_tree.focus()
        if not selected_tree_iid: messagebox.showwarning("No Selection", "Please select a file.", parent=self); return None, None
        try: db_id_str, file_type = selected_tree_iid.rsplit('_', 1); return int(db_id_str), file_type
        except ValueError: messagebox.showerror("Internal Error", "Invalid item selected.", parent=self); return None, None

    def _upload_file(self):
        if not self.current_user_id: messagebox.showerror("Error","Login required.",parent=self); return
        filepath = filedialog.askopenfilename(parent=self, title="Select file to upload")
        if not filepath: return
        orig_fn = os.path.basename(filepath); filesize = os.path.getsize(filepath)
        ts = str(int(time.time())); enc_fn_base = f"{os.path.splitext(orig_fn)[0]}_{ts}.enc"
        user_files_dir = os.path.join("user_data",self.current_user_username,"files"); enc_fp = os.path.join(user_files_dir,enc_fn_base)
        file_enc_pass = self._prompt_password(title="Set File Encryption Password",prompt="Create a password to encrypt this file:")
        if not file_enc_pass: self.status_bar_label.config(text="Status: Upload cancelled."); return
        self.status_bar_label.config(text=f"Encrypting {orig_fn}..."); self.update_idletasks()
        success, message, script_out = run_encryption_script('encrypt', filepath, enc_fp, file_enc_pass)
        if success:
            cnx = None
            try:
                cnx = mysql.connector.connect(**DB_CONFIG); cursor = cnx.cursor()
                q = ("INSERT INTO user_files (owner_user_id, original_filename, encrypted_filename, encrypted_filepath, filesize) VALUES (%s,%s,%s,%s,%s)")
                cursor.execute(q, (self.current_user_id, orig_fn, enc_fn_base, enc_fp, filesize))
                cnx.commit(); self.status_bar_label.config(text=f"'{orig_fn}' uploaded."); messagebox.showinfo("Success","File encrypted & uploaded.",parent=self); self._load_user_files_from_db()
            except mysql.connector.Error as err:
                self.status_bar_label.config(text=f"DB Error: {err}"); messagebox.showerror("DB Error",f"DB Error: {err}",parent=self)
                if os.path.exists(enc_fp): os.remove(enc_fp)
            finally:
                if cnx and cnx.is_connected(): cursor.close(); cnx.close()
        else: self.status_bar_label.config(text="Encryption failed."); messagebox.showerror("Encryption Failed",f"Failed: {message}\nDetails: {script_out}",parent=self)

# Inside the _download_file method of SecureShareApp class

    def _download_file(self):
        db_id, file_type = self._get_selected_file_info()
        if not db_id: return

        cnx = None
        try:
            cnx = mysql.connector.connect(**DB_CONFIG)
            cursor = cnx.cursor(dictionary=True)
            
            orig_fn, enc_fp_db, dec_pass = None, None, None # Initialize

            if file_type == "owned":
                cursor.execute("SELECT original_filename, encrypted_filepath FROM user_files WHERE id=%s AND owner_user_id=%s",(db_id,self.current_user_id))
                data = cursor.fetchone()
                if data: 
                    orig_fn, enc_fp_db = data['original_filename'], data['encrypted_filepath']
                    dec_pass = self._prompt_password(title="Decrypt Owned File", prompt=f"Password for '{orig_fn}':")
            elif file_type == "shared":
                cursor.execute("SELECT uf.original_filename, uf.encrypted_filepath, fs.file_encryption_password_mock FROM file_shares fs JOIN user_files uf ON fs.file_id=uf.id WHERE fs.file_id=%s AND fs.shared_with_user_id=%s",(db_id,self.current_user_id))
                data = cursor.fetchone()
                if data: 
                    orig_fn, enc_fp_db, dec_pass = data['original_filename'], data['encrypted_filepath'], data['file_encryption_password_mock']
                if not dec_pass and data: # Check if dec_pass is missing even if data was found
                    messagebox.showerror("Error","Shared file password missing. Share might be incomplete.",parent=self)
                    return # Exit early
            
            if not orig_fn: # This covers cases where data is None or orig_fn wasn't set
                messagebox.showerror("Error","File data not retrieved or access denied.",parent=self)
                return
            if not dec_pass: # If user cancelled password prompt for owned file, or if it was missing for shared
                self.status_bar_label.config(text="Status: Decryption cancelled or password unavailable.")
                return

            if not os.path.exists(enc_fp_db): 
                messagebox.showerror("File Error",f"Encrypted file missing at: {enc_fp_db}\n"
                                     "(Client needs access to owner's encrypted files path for shared items in this mock-up.)",parent=self)
                return
            
            save_loc = filedialog.asksaveasfilename(parent=self,title="Save decrypted file as...",initialfile=orig_fn)
            if not save_loc: return # User cancelled save dialog
            
            self.status_bar_label.config(text=f"Status: Decrypting {orig_fn}..."); self.update_idletasks()
            success, message, script_out = run_encryption_script('decrypt', enc_fp_db, save_loc, dec_pass)
            
            if success: 
                self.status_bar_label.config(text=f"'{orig_fn}' decrypted."); 
                messagebox.showinfo("Success",f"Decrypted & saved:\n{save_loc}",parent=self)
            else: 
                self.status_bar_label.config(text="Decryption failed.")
                messagebox.showerror("Decryption Failed",f"Failed: {message}\nDetails: {script_out}",parent=self)
                # --- Improved Cleanup ---
                if os.path.exists(save_loc):
                    try:
                        # Only remove if it's a very small file, indicating it might be an error output or incomplete
                        if os.path.getsize(save_loc) < 64: 
                            os.remove(save_loc)
                            print(f"Cleaned up potentially incomplete/error output file: {save_loc}")
                        else:
                            print(f"Warning: Decryption failed, but output file '{save_loc}' exists and is larger than threshold. Not deleting.")
                    except OSError as oe:
                        print(f"Warning: Could not cleanup/check output file '{save_loc}' after failed decryption: {oe}")
                    except Exception as e_cleanup: # Catch any other unexpected error during cleanup check
                        print(f"Warning: Unexpected error during cleanup check for '{save_loc}': {e_cleanup}")
        
        except mysql.connector.Error as err: 
            self.status_bar_label.config(text=f"DB Error: {err}"); 
            messagebox.showerror("DB Error",f"DB error: {err}",parent=self)
        finally:
            if cnx and cnx.is_connected(): cursor.close(); cnx.close()

    def _delete_file_db(self):
        db_id, file_type = self._get_selected_file_info();
        if not db_id: return
        if file_type != "owned": messagebox.showerror("Permission Denied", "Only owners can delete files.", parent=self); return
        cnx = None
        try:
            cnx = mysql.connector.connect(**DB_CONFIG); cursor = cnx.cursor()
            cursor.execute("SELECT original_filename,encrypted_filepath FROM user_files WHERE id=%s AND owner_user_id=%s",(db_id,self.current_user_id))
            info = cursor.fetchone()
            if not info: messagebox.showerror("Error", "File not found/not owned.",parent=self); return
            orig_fn, enc_fp = info
            if messagebox.askyesno("Confirm Delete", f"Delete YOUR file '{orig_fn}'?",parent=self):
                if os.path.exists(enc_fp): os.remove(enc_fp)
                cursor.execute("DELETE FROM file_shares WHERE file_id = %s", (db_id,)) # Cascade should handle this, but explicit is safer.
                cursor.execute("DELETE FROM user_files WHERE id = %s", (db_id,))
                cnx.commit(); self.status_bar_label.config(text=f"'{orig_fn}' deleted."); messagebox.showinfo("Deleted",f"'{orig_fn}' deleted.",parent=self); self._load_user_files_from_db()
            else: self.status_bar_label.config(text="Delete cancelled.")
        except mysql.connector.Error as err:
            if cnx: cnx.rollback(); self.status_bar_label.config(text=f"DB Error: {err}"); messagebox.showerror("DB Error", f"Delete error: {err}", parent=self)
        except OSError as oe: self.status_bar_label.config(text=f"File Error: {oe}"); messagebox.showerror("File Error",f"Disk delete error: {oe}",parent=self)
        finally:
            if cnx and cnx.is_connected(): cursor.close(); cnx.close()

    def _share_file_with_user(self):
        db_id, file_type = self._get_selected_file_info()
        if not db_id: return
        if file_type != "owned": messagebox.showerror("Error", "Only owners can share files.", parent=self); return
        cnx = None
        try:
            cnx = mysql.connector.connect(**DB_CONFIG); cursor = cnx.cursor(dictionary=True)
            cursor.execute("SELECT original_filename FROM user_files WHERE id=%s AND owner_user_id=%s",(db_id,self.current_user_id))
            file_info = cursor.fetchone()
            if not file_info: messagebox.showerror("Error","File not found/not owned.",parent=self); return
            orig_fn = file_info['original_filename']
            shared_user = simpledialog.askstring("Share File",f"Username to share '{orig_fn}' with:",parent=self)
            if not shared_user or shared_user == self.current_user_username: messagebox.showinfo("Share Info", "Invalid username or cannot share with self.", parent=self); return
            cursor.execute("SELECT id FROM users WHERE username = %s", (shared_user,))
            target_user = cursor.fetchone()
            if not target_user: messagebox.showwarning("User Not Found", f"User '{shared_user}' does not exist.", parent=self); return
            shared_uid = target_user['id']
            file_enc_pass_share = self._prompt_password(title="Password for Sharing",prompt=f"Enter YOUR password for '{orig_fn}' (to share with {shared_user}):")
            if not file_enc_pass_share: messagebox.showinfo("Share Cancelled", "Password not provided.", parent=self); return
            perms = simpledialog.askstring("Set Permissions",f"Permissions for {shared_user} (e.g., download):",initialvalue="download",parent=self) or "download"
            try:
                q = ("INSERT INTO file_shares (file_id,sharer_user_id,shared_with_user_id,permissions,file_encryption_password_mock) VALUES (%s,%s,%s,%s,%s)")
                cursor.execute(q, (db_id,self.current_user_id,shared_uid,perms,file_enc_pass_share))
                cnx.commit(); self.status_bar_label.config(text=f"'{orig_fn}' shared with '{shared_user}'."); messagebox.showinfo("Shared",f"'{orig_fn}' shared with '{shared_user}'.",parent=self); self._load_user_files_from_db()
            except mysql.connector.Error as err:
                if err.errno == errorcode.ER_DUP_ENTRY: messagebox.showwarning("Already Shared", f"Already shared with '{shared_user}'.",parent=self)
                else:
                    if cnx: cnx.rollback(); self.status_bar_label.config(text=f"DB Error on share: {err}"); messagebox.showerror("DB Error",f"Share DB error: {err}",parent=self)
        except mysql.connector.Error as err: self.status_bar_label.config(text=f"DB Error: {err}"); messagebox.showerror("DB Error",f"Share prep error: {err}",parent=self)
        finally:
            if cnx and cnx.is_connected(): cursor.close(); cnx.close()

    def _handle_logout(self):
        self.stop_polling_shared_files(); self.current_user_id = None; self.current_user_username = None
        lfv = self.frames["LoginView"].auth_vars; lfv["username"].set(""); lfv["password"].set(""); lfv["error_label"].config(text="")
        self.show_frame("LoginView")
        if hasattr(self, 'status_bar_label'): self.status_bar_label.config(text="Status: Logged out.")

if __name__ == "__main__":
    init_db()
    app = SecureShareApp()
    app.mainloop()