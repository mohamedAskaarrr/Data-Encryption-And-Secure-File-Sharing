import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import sqlite3
import hashlib # For basic password hashing
import os
import shutil
import subprocess
import platform
import time
from datetime import datetime
# Removed: bcrypt, paramiko

# --- SECURITY WARNING ---
SECURITY_WARNING_INSECURE_PASSWORDS = """
############################################################################
# WARNING: INSECURE PASSWORD HANDLING!                                     #
# This version uses a basic SHA256 hash with a static salt for passwords   #
# because 'bcrypt' was removed. This is NOT cryptographically secure.      #
# DO NOT USE THIS FOR REAL SENSITIVE DATA OR IN PRODUCTION ENVIRONMENTS.   #
# This is for demonstration purposes only where libraries cannot be used.  #
############################################################################
"""
print(SECURITY_WARNING_INSECURE_PASSWORDS)

# --- SQLite Database Configuration (For User Authentication) ---
DB_NAME_AUTH = "secure_share_local_auth.db"

# --- Local Storage Configuration ---
LOCAL_BASE_DATA_DIR = "secure_share_data_local" # Root for ALL user data locally
LOCAL_MY_FILES_DIR = "_my_files"
LOCAL_SHARED_WITH_ME_DIR = "_shared_with_me"
LOCAL_KEY_SUFFIX = ".keyinfo" # For storing decryption password for shared files

# --- Configurable Path for code.sh (Make sure this script exists and is executable) ---
CODE_SH_SCRIPT_PATH = "./code.sh"

# --- A hardcoded salt for password hashing (NOT SECURE FOR PRODUCTION) ---
PASSWORD_SALT = b"a_very_static_and_not_so_secret_salt" # CHANGE THIS if you use it, but still not secure

# --- find_bash_on_windows() (Less relevant now but kept for `code.sh` consistency) ---
def find_bash_on_windows():
    # ... (same as before)
    common_paths = [
        os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "Git", "usr", "bin", "bash.exe"),
        os.path.join(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"), "Git", "usr", "bin", "bash.exe"),
        shutil.which("bash")
    ]
    for path in common_paths:
        if path and os.path.exists(path): return path
    return "bash"

# --- Database Setup (SQLite - Users Table ONLY) ---
def init_auth_db():
    conn = sqlite3.connect(DB_NAME_AUTH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL -- Will store SHA256 hash
        )''')
    conn.commit()
    print(f"Authentication Database '{DB_NAME_AUTH}' checked/created.")
    conn.close()

# --- User Authentication Logic (Using hashlib.sha256 - INSECURE) ---
def hash_password_insecure(password):
    hasher = hashlib.sha256()
    hasher.update(PASSWORD_SALT)
    hasher.update(password.encode('utf-8'))
    return hasher.hexdigest()

def check_password_insecure(password, stored_hash):
    return hash_password_insecure(password) == stored_hash

def register_user(username, password):
    if not username or not password: return False, "Username/password cannot be empty."
    
    hashed_pw_str = hash_password_insecure(password)

    # Create local directories for the user
    try:
        user_base_path = os.path.join(LOCAL_BASE_DATA_DIR, username)
        user_my_files_path = os.path.join(user_base_path, LOCAL_MY_FILES_DIR)
        user_shared_path = os.path.join(user_base_path, LOCAL_SHARED_WITH_ME_DIR)
        os.makedirs(user_my_files_path, exist_ok=True)
        os.makedirs(user_shared_path, exist_ok=True)
        print(f"Local directories created for user '{username}' under '{LOCAL_BASE_DATA_DIR}'.")
    except OSError as e:
        return False, f"Failed to create local directories for user '{username}': {e}"

    # Register user in local SQLite DB
    conn = sqlite3.connect(DB_NAME_AUTH)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                       (username, hashed_pw_str))
        conn.commit()
        return True, "Registration successful! User local directories created."
    except sqlite3.IntegrityError: return False, "Username already taken."
    except Exception as e: print(f"SQLite Error in register_user: {e}"); return False, f"DB error: {e}"
    finally: conn.close()

def login_user(username, password):
    if not username or not password: return False, "Username/password cannot be empty.", None, None
    conn = sqlite3.connect(DB_NAME_AUTH)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result:
            user_id, fetched_username, stored_hash = result
            if check_password_insecure(password, stored_hash):
                return True, "Login successful!", user_id, fetched_username
            else: return False, "Invalid password.", None, None
        else: return False, "Username not found.", None, None
    except Exception as e: print(f"SQLite Error in login_user: {e}"); return False, f"DB error: {e}", None, None
    finally: conn.close()


# --- run_encryption_script (Same as before, uses local code.sh) ---
def run_encryption_script(mode, input_file, output_file, password):
    # ... (same as before, ensure CODE_SH_SCRIPT_PATH is correct and script is executable)
    script_path_abs = os.path.abspath(CODE_SH_SCRIPT_PATH)
    if not os.path.exists(script_path_abs): return False, f"Script not found: {script_path_abs}", ""
    current_os = platform.system()
    if not os.access(script_path_abs, os.X_OK) and current_os != "Windows":
        try: os.chmod(script_path_abs, 0o755)
        except Exception as e: return False, f"Script chmod failed: {e}", ""

    cmd_prefix = [find_bash_on_windows()] if current_os == "Windows" else []
    abs_input_file = os.path.abspath(input_file); abs_output_file = os.path.abspath(output_file)
    bash_input_file = abs_input_file; bash_output_file = abs_output_file
    if current_os == "Windows":
        drive, path_no_drive = os.path.splitdrive(abs_input_file); bash_input_file = ("/" + drive.lower().replace(":", "") + path_no_drive.replace(os.sep, "/")) if drive else abs_input_file.replace(os.sep, "/")
        drive, path_no_drive = os.path.splitdrive(abs_output_file); bash_output_file = ("/" + drive.lower().replace(":", "") + path_no_drive.replace(os.sep, "/")) if drive else abs_output_file.replace(os.sep, "/")
    command = cmd_prefix + [script_path_abs, 'e' if mode == 'encrypt' else 'd', bash_input_file, bash_output_file]
    password_input_str = f"{password}\n" + (f"{password}\n" if mode == 'encrypt' else "")
    try:
        startupinfo = None; creation_flags = 0
        if current_os == "Windows": startupinfo = subprocess.STARTUPINFO(); startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW; startupinfo.wShowWindow = subprocess.SW_HIDE; creation_flags = subprocess.CREATE_NO_WINDOW
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, startupinfo=startupinfo, cwd=os.path.dirname(script_path_abs), creationflags=creation_flags)
        stdout_data, stderr_data = process.communicate(password_input_str, timeout=60)
        if process.returncode == 0: return True, f"File {mode}ed.", stdout_data.strip()
        else:
            err = f"Script err(code {process.returncode}).\nCmd: {' '.join(command)}\nIn: {bash_input_file}\nOut: {bash_output_file}\n";
            if stdout_data: err += f"STDOUT:{stdout_data.strip()}\n"
            if stderr_data: err += f"STDERR:{stderr_data.strip()}"
            return False, err.strip(), stderr_data.strip()
    except subprocess.TimeoutExpired: return False, "Script timeout.", ""
    except FileNotFoundError as e: return False, f"Exec failed: {e}. Bash/script path? Cmd: {' '.join(command)}", ""
    except Exception as e: return False, f"Script exec error: {e}. Cmd: {' '.join(command)}", ""


# --- Main Application Class ---
class SecureShareApp(tk.Tk):
    # ... (All theme and font constants remain the same) ...
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
        self.title("SecureShare Client (Local Storage Mode)") # Title changed
        self.geometry("600x450")
        self.configure(bg=self.COLOR_BACKGROUND); self.resizable(False, False)
        self.poll_job = None; self.current_user_id = None; self.current_user_username = None

        self._setup_styles()

        self.container = tk.Frame(self, bg=self.COLOR_BACKGROUND)
        self.container.pack(side="top", fill="both", expand=True)
        self.container.grid_rowconfigure(0, weight=1); self.container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        self._create_auth_view("Login")
        self._create_auth_view("Register")
        self._create_main_app_view() # Main view now uses local storage

        self.show_frame("LoginView")
        self.center_window()
        self.POLL_INTERVAL = 30000 # 30 seconds, less critical for local but kept
        self.temp_dir_base = "client_temp_files_local" # For enc/dec staging
        os.makedirs(self.temp_dir_base, exist_ok=True)
        os.makedirs(LOCAL_BASE_DATA_DIR, exist_ok=True) # Ensure base data dir exists

    def _setup_styles(self):
        # ... (same as before, using ttk styles)
        self.style = ttk.Style(self)
        self.style.theme_use('clam')
        self.style.configure("TButton", background=self.COLOR_BUTTON_BG, foreground=self.COLOR_BUTTON_FG, font=self.FONT_BUTTON, relief="flat", padding=(10,6), borderwidth=1, bordercolor=self.COLOR_BORDER, focuscolor=self.COLOR_ACCENT_DARKER)
        self.style.map("TButton", background=[('active',self.COLOR_BUTTON_ACTIVE_BG),('pressed',self.COLOR_ACCENT_DARKER)], bordercolor=[('active',self.COLOR_ACCENT),('focus',self.COLOR_ACCENT)])
        self.style.configure("Treeview", background=self.COLOR_ENTRY_BG, foreground=self.COLOR_FOREGROUND, fieldbackground=self.COLOR_ENTRY_BG, font=self.FONT_PRIMARY, rowheight=28)
        self.style.map("Treeview", background=[('selected',self.COLOR_ACCENT_DARKER)], foreground=[('selected',self.COLOR_PRIMARY_ACTION_FG)])
        self.style.configure("Treeview.Heading", background=self.COLOR_BUTTON_BG, foreground=self.COLOR_FOREGROUND, font=self.FONT_BUTTON, relief="flat", padding=5)
        self.style.map("Treeview.Heading", background=[('active',self.COLOR_BUTTON_ACTIVE_BG)])
        self.style.configure("Vertical.TScrollbar", gripcount=0, background=self.COLOR_BUTTON_BG, darkcolor=self.COLOR_BACKGROUND_LIGHTER, lightcolor=self.COLOR_BACKGROUND_LIGHTER, troughcolor=self.COLOR_BACKGROUND, bordercolor=self.COLOR_BORDER, arrowcolor=self.COLOR_ACCENT, relief='flat')
        self.style.map("Vertical.TScrollbar", background=[('active',self.COLOR_BUTTON_ACTIVE_BG)], arrowcolor=[('pressed',self.COLOR_ACCENT_DARKER)])
        self.style.configure('Link.TLabel', foreground=self.COLOR_ACCENT, font=(self.FONT_PRIMARY[0], self.FONT_PRIMARY[1], 'underline'))

    def center_window(self,width=None,height=None):
        # ... (same as before)
        self.update_idletasks();w=width if width else self.winfo_width();h=height if height else self.winfo_height();sw,sh=self.winfo_screenwidth(),self.winfo_screenheight();x,y=max(0,(sw//2)-(w//2)),max(0,(sh//2)-(h//2));self.geometry(f'{w}x{h}+{x}+{y}')

    def start_polling_local_files(self): # Renamed
        main_app_frame = self.frames.get("MainAppView")
        if self.current_user_username and main_app_frame and main_app_frame.winfo_viewable():
            if hasattr(main_app_frame, 'load_user_files_from_local'): # Method name changed
                 main_app_frame.load_user_files_from_local()
            if hasattr(self,'poll_job') and self.poll_job is not None: self.after_cancel(self.poll_job)
            self.poll_job = self.after(self.POLL_INTERVAL, self.start_polling_local_files)

    def stop_polling_local_files(self): # Renamed
        if hasattr(self,'poll_job') and self.poll_job is not None:
            try: self.after_cancel(self.poll_job)
            except tk.TclError: pass
            finally: self.poll_job = None

    def show_frame(self,page_name_key):
        # ... (logic largely same, but calls start_polling_local_files)
        frame=self.frames.get(page_name_key)
        if frame:
            frame.tkraise()
            if page_name_key=="MainAppView":
                self.geometry("1100x750");self.resizable(True,True);self.center_window(1100,750)
                if hasattr(frame,'load_user_files_from_local'): frame.load_user_files_from_local()
                self.start_polling_local_files() # Renamed
            else:
                self.stop_polling_local_files(); # Renamed
                self.geometry("600x450");self.resizable(False,False);self.center_window(600,450)
                if hasattr(frame, 'auth_vars') and 'password' in frame.auth_vars: frame.auth_vars['password'].set("")
                if hasattr(frame, 'auth_vars') and 'confirm_password' in frame.auth_vars: frame.auth_vars['confirm_password'].set("")
                if hasattr(frame, 'auth_vars') and 'error_label' in frame.auth_vars: frame.auth_vars['error_label'].config(text="")


    def _create_input_field(self,parent,text,show_char=None,is_confirm=False):
        # ... (same as before)
        f=tk.Frame(parent,bg=self.COLOR_BACKGROUND);tk.Label(f,text=text,bg=self.COLOR_BACKGROUND,fg=self.COLOR_FOREGROUND,font=self.FONT_PRIMARY,width=18,anchor='w').pack(side="left",padx=(0,10));v=tk.StringVar();e=tk.Entry(f,textvariable=v,bg=self.COLOR_ENTRY_BG,fg=self.COLOR_ENTRY_FG,insertbackground=self.COLOR_ACCENT,font=self.FONT_PRIMARY,relief='flat',show=show_char,borderwidth=2,highlightthickness=0);e.pack(side="left",fill="x",expand=True);return f,v,e

    def _create_auth_view(self, mode="Login"):
        # ... (same as before, UI unchanged)
        frame_key = f"{mode}View"
        frame = tk.Frame(self.container, bg=self.COLOR_BACKGROUND)
        self.frames[frame_key] = frame
        frame.grid(row=0, column=0, sticky="nsew")
        content_frame = tk.Frame(frame, bg=self.COLOR_BACKGROUND)
        content_frame.place(relx=0.5, rely=0.5, anchor="center")
        header_text = "SecureShare Login" if mode == "Login" else "Create SecureShare Account"
        header = tk.Label(content_frame, text=header_text, font=self.FONT_HEADER, bg=self.COLOR_BACKGROUND, fg=self.COLOR_ACCENT)
        header.pack(pady=(0, 30))
        frame.auth_vars = {}
        username_frame, username_var, _ = self._create_input_field(content_frame, "Username:")
        username_frame.pack(pady=8, fill="x", padx=20); frame.auth_vars["username"] = username_var
        password_frame, password_var, _ = self._create_input_field(content_frame, "Password:", show_char='●')
        password_frame.pack(pady=8, fill="x", padx=20); frame.auth_vars["password"] = password_var
        if mode == "Register":
            confirm_password_frame, confirm_password_var, _ = self._create_input_field(content_frame, "Confirm Password:", show_char='●')
            confirm_password_frame.pack(pady=8, fill="x", padx=20); frame.auth_vars["confirm_password"] = confirm_password_var
        error_label = tk.Label(content_frame, text="", font=self.FONT_SMALL,bg=self.COLOR_BACKGROUND, fg=self.TAG_COLORS["error"], wraplength=350)
        error_label.pack(pady=(5, 10)); frame.auth_vars["error_label"] = error_label
        button_base_config = {"font": self.FONT_BUTTON, "relief": 'flat', "borderwidth": 1, "width": 20, "pady": 8}
        primary_button_config = {**button_base_config, "bg": self.COLOR_PRIMARY_ACTION_BG, "fg": self.COLOR_PRIMARY_ACTION_FG, "activebackground": self.COLOR_PRIMARY_ACTION_HOVER_BG, "activeforeground": self.COLOR_PRIMARY_ACTION_FG}
        secondary_button_config = {**button_base_config, "bg": self.COLOR_BUTTON_BG, "fg": self.COLOR_BUTTON_FG, "activebackground": self.COLOR_BUTTON_ACTIVE_BG}
        if mode == "Login":
            tk.Button(content_frame, text="Login", command=self._handle_login, **primary_button_config).pack(pady=(10, 5))
            tk.Button(content_frame, text="Create Account", command=lambda: self.show_frame("RegisterView"), **secondary_button_config).pack(pady=5)
        else:
            tk.Button(content_frame, text="Register", command=self._handle_register, **primary_button_config).pack(pady=(10, 5))
            tk.Button(content_frame, text="Back to Login", command=lambda: self.show_frame("LoginView"), **secondary_button_config).pack(pady=5)

    def _handle_login(self):
        # ... (uses login_user which now uses insecure hashing)
        login_frame = self.frames["LoginView"]
        username = login_frame.auth_vars["username"].get()
        password = login_frame.auth_vars["password"].get()
        error_label = login_frame.auth_vars["error_label"]
        success, message, user_id, fetched_username = login_user(username, password)
        if success:
            error_label.config(text=message, fg=self.TAG_COLORS["success"])
            self.current_user_id = user_id
            self.current_user_username = fetched_username
            login_frame.auth_vars["username"].set("")
            self.after(1000, lambda: self.show_frame("MainAppView"))
        else:
            error_label.config(text=message, fg=self.TAG_COLORS["error"])
            login_frame.auth_vars["password"].set("")

    def _handle_register(self):
        # ... (uses register_user which now uses insecure hashing and local dir creation)
        register_frame = self.frames["RegisterView"]
        username = register_frame.auth_vars["username"].get()
        password = register_frame.auth_vars["password"].get()
        confirm_password = register_frame.auth_vars["confirm_password"].get()
        error_label = register_frame.auth_vars["error_label"]
        if not username.strip() or not password: error_label.config(text="Username and password cannot be empty.", fg=self.TAG_COLORS["error"]); return
        if password != confirm_password: error_label.config(text="Passwords do not match.", fg=self.TAG_COLORS["error"]); return
        if len(password) < 8: error_label.config(text="Password must be at least 8 characters.", fg=self.TAG_COLORS["error"]); return
        success, message = register_user(username, password)
        if success:
            error_label.config(text=message, fg=self.TAG_COLORS["success"])
            register_frame.auth_vars["username"].set("")
            register_frame.auth_vars["password"].set("")
            register_frame.auth_vars["confirm_password"].set("")
            self.after(1500, lambda: self.show_frame("LoginView"))
        else:
            error_label.config(text=message, fg=self.TAG_COLORS["error"])
            register_frame.auth_vars["password"].set("")
            register_frame.auth_vars["confirm_password"].set("")

    def _create_main_app_view(self):
        # ... (UI similar, but text and commands will point to local file operations)
        frame = tk.Frame(self.container,bg=self.COLOR_BACKGROUND)
        self.frames["MainAppView"]=frame
        frame.grid(row=0,column=0,sticky="nsew"); frame.grid_columnconfigure(0,weight=1); frame.grid_rowconfigure(2,weight=1)
        header_area = tk.Frame(frame,bg=self.COLOR_BACKGROUND_LIGHTER,padx=10,pady=10)
        header_area.grid(row=0,column=0,columnspan=2,sticky="ew"); header_area.grid_columnconfigure(0,weight=1)
        tk.Label(header_area,text="SecureShare (Local Data)",font=self.FONT_HEADER,bg=self.COLOR_BACKGROUND_LIGHTER,fg=self.COLOR_ACCENT).grid(row=0,column=0,sticky="w")
        self.current_user_label=tk.Label(header_area,text="User: N/A",font=self.FONT_PRIMARY,bg=self.COLOR_BACKGROUND_LIGHTER,fg=self.COLOR_FOREGROUND)
        self.current_user_label.grid(row=0,column=1,sticky="e",padx=(0,20))
        ttk.Button(header_area,text="Logout",style="TButton",command=self._handle_logout,width=8).grid(row=0,column=2,sticky="e",padx=(0,10))
        toolbar_frame = tk.Frame(frame,bg=self.COLOR_BACKGROUND,pady=10)
        toolbar_frame.grid(row=1,column=0,columnspan=2,sticky="ew",padx=20)
        ttk.Button(toolbar_frame,text="Upload Encrypted",style="TButton",command=self._upload_file_local).pack(side="left",padx=5) # Renamed
        ttk.Button(toolbar_frame,text="Download & Decrypt",style="TButton",command=self._download_file_local).pack(side="left",padx=5) # Renamed
        ttk.Button(toolbar_frame,text="Delete Local File",style="TButton",command=self._delete_file_local).pack(side="left",padx=5) # Renamed
        ttk.Button(toolbar_frame,text="Share File Locally",style="TButton",command=self._share_file_local_user).pack(side="left",padx=5) # Renamed
        ttk.Button(toolbar_frame,text="Refresh List",style="TButton",command=lambda:self.frames["MainAppView"].load_user_files_from_local()).pack(side="left",padx=5) # Renamed
        file_list_frame = tk.Frame(frame,bg=self.COLOR_BACKGROUND)
        file_list_frame.grid(row=2,column=0,columnspan=2,sticky="nsew",padx=20,pady=(0,10)); file_list_frame.grid_rowconfigure(0,weight=1); file_list_frame.grid_columnconfigure(0,weight=1)
        cols=("filename","size_approx","modified_local","owner_sharer","status_type", "local_path_hidden") # Renamed + local_path
        self.file_tree=ttk.Treeview(file_list_frame,columns=cols,show="headings",style="Treeview",selectmode="browse", displaycolumns=("filename","size_approx","modified_local","owner_sharer","status_type"))
        self.file_tree.heading("filename",text="Filename (Original)"); self.file_tree.column("filename",width=300,stretch=tk.YES)
        self.file_tree.heading("size_approx",text="Size",anchor="e"); self.file_tree.column("size_approx",width=100,stretch=tk.NO,anchor="e")
        self.file_tree.heading("modified_local",text="Date (Local Mod)",anchor="center"); self.file_tree.column("modified_local",width=180,stretch=tk.NO,anchor="center") # Renamed
        self.file_tree.heading("owner_sharer",text="Owner / Shared By",anchor="w"); self.file_tree.column("owner_sharer",width=200,stretch=tk.NO,anchor="w")
        self.file_tree.heading("status_type",text="Status",anchor="center"); self.file_tree.column("status_type",width=100,stretch=tk.NO,anchor="center")
        self.file_tree.grid(row=0,column=0,sticky="nsew");sb=ttk.Scrollbar(file_list_frame,orient="vertical",command=self.file_tree.yview,style="Vertical.TScrollbar");self.file_tree.configure(yscrollcommand=sb.set);sb.grid(row=0,column=1,sticky="ns")
        self.status_bar_label=tk.Label(frame,text="Status: Ready",font=self.FONT_SMALL,bg=self.COLOR_BORDER,fg=self.COLOR_FOREGROUND,anchor="w",padx=10)
        self.status_bar_label.grid(row=3,column=0,columnspan=2,sticky="ew",pady=(5,0))
        frame.load_user_files_from_local = self._load_user_files_from_local # New load method

    def _get_user_local_paths(self, username=None): # Renamed
        user = username if username else self.current_user_username
        if not user: return None, None, None
        user_base = os.path.join(LOCAL_BASE_DATA_DIR, user)
        my_files = os.path.join(user_base, LOCAL_MY_FILES_DIR)
        shared_with_me = os.path.join(user_base, LOCAL_SHARED_WITH_ME_DIR)
        return user_base, my_files, shared_with_me

    def _load_user_files_from_local(self): # NEW: Loads file list by scanning LOCAL directories
        if not self.current_user_username: return
        self.current_user_label.config(text=f"User: {self.current_user_username}")
        current_selection_iid = self.file_tree.focus()
        for item in self.file_tree.get_children(): self.file_tree.delete(item)

        user_base_path, my_files_path, shared_path = self._get_user_local_paths()
        os.makedirs(my_files_path, exist_ok=True) # Ensure dirs exist
        os.makedirs(shared_path, exist_ok=True)

        # Load Owned Files
        if os.path.isdir(my_files_path):
            for filename in os.listdir(my_files_path):
                if filename.startswith("enc_") and filename.endswith(".enc"):
                    full_path = os.path.join(my_files_path, filename)
                    try:
                        stat_info = os.stat(full_path)
                        parts = filename.split('_', 2)
                        original_name_with_ext = parts[2] if len(parts) > 2 else filename
                        original_name = os.path.splitext(original_name_with_ext)[0]

                        self._insert_local_file_into_tree(
                            original_name, stat_info.st_size,
                            datetime.fromtimestamp(stat_info.st_mtime),
                            full_path, "Owned", self.current_user_username
                        )
                    except OSError as e: print(f"Error stating file {full_path}: {e}")
        else: print(f"My files directory not found: {my_files_path}")


        # Load Shared Files (Files COPIED into _shared_with_me/{sharer_username}/)
        if os.path.isdir(shared_path):
            for sharer_username_dir in os.listdir(shared_path): # e.g., userA (who shared with current user)
                full_sharer_dir_path = os.path.join(shared_path, sharer_username_dir)
                if os.path.isdir(full_sharer_dir_path):
                    for shared_filename_enc in os.listdir(full_sharer_dir_path):
                        if shared_filename_enc.startswith("enc_") and shared_filename_enc.endswith(".enc"):
                            # This is a COPY of an encrypted file
                            full_shared_file_path = os.path.join(full_sharer_dir_path, shared_filename_enc)
                            try:
                                stat_info = os.stat(full_shared_file_path)
                                parts = shared_filename_enc.split('_', 2)
                                original_name_shared_ext = parts[2] if len(parts) > 2 else shared_filename_enc
                                original_name_shared = os.path.splitext(original_name_shared_ext)[0]

                                self._insert_local_file_into_tree(
                                    original_name_shared, stat_info.st_size,
                                    datetime.fromtimestamp(stat_info.st_mtime), # Mod time of the *copy*
                                    full_shared_file_path, # Path to the copied encrypted file
                                    "Shared", sharer_username_dir # Who shared it
                                )
                            except OSError as e: print(f"Error stating shared file {full_shared_file_path}: {e}")
        else: print(f"Shared directory not found: {shared_path}")


        if current_selection_iid and self.file_tree.exists(current_selection_iid):
            self.file_tree.focus(current_selection_iid); self.file_tree.selection_set(current_selection_iid)
        elif self.file_tree.get_children():
            first_item = self.file_tree.get_children()[0]
            self.file_tree.focus(first_item); self.file_tree.selection_set(first_item)

    def _insert_local_file_into_tree(self, display_filename, size_bytes, mod_time_obj, local_file_path, file_type, owner_sharer_username):
        size_str = f"{size_bytes/(1024*1024):.1f} MB" if size_bytes >=1024*1024 else (f"{size_bytes/1024:.1f} KB" if size_bytes >= 1024 else f"{size_bytes} B")
        date_str = mod_time_obj.strftime('%Y-%m-%d %H:%M') if isinstance(mod_time_obj, datetime) else "-"
        
        # Use the local_file_path for IID to ensure uniqueness within the tree for that user's view
        item_iid = local_file_path # Full path should be unique enough for tree's iid

        try:
            self.file_tree.insert("", "end", iid=item_iid,
                                  values=(display_filename, size_str, date_str, owner_sharer_username, file_type, local_file_path),
                                  tags=(file_type.lower(),))
        except tk.TclError as e: # Should be rare if local_file_path is truly unique
             print(f"Error inserting into tree (iid: {item_iid}): {e}. File: {display_filename}")


    def _get_selected_file_info_local(self): # Renamed
        selected_tree_iid = self.file_tree.focus() # IID is now the local_file_path
        if not selected_tree_iid:
            messagebox.showwarning("No Selection", "Please select a file.", parent=self)
            return None, None, None, None # display_name, local_enc_path, file_type, owner_sharer

        try:
            item_values = self.file_tree.item(selected_tree_iid, "values")
            display_name = item_values[0]
            local_enc_path = item_values[5] # This is the local_path_hidden which is the full path
            file_type = item_values[4]
            owner_sharer = item_values[3]
            return display_name, local_enc_path, file_type, owner_sharer
        except (IndexError, ValueError) as e:
            messagebox.showerror("Internal Error", f"Could not parse selected item data: {e}\nIID: {selected_tree_iid}", parent=self)
            return None, None, None, None


    def _upload_file_local(self): # Renamed and adapted
        if not self.current_user_username: messagebox.showerror("Error","Login required.",parent=self); return
        local_source_filepath = filedialog.askopenfilename(parent=self,title="Select file to encrypt & upload locally")
        if not local_source_filepath: return

        original_filename_base = os.path.basename(local_source_filepath)
        timestamp = int(time.time())
        # Encrypted filename for local storage
        encrypted_filename_for_storage = f"enc_{timestamp}_{original_filename_base}.enc"

        # Local temporary encrypted file (staging before final move)
        temp_user_upload_dir = os.path.join(self.temp_dir_base, self.current_user_username, "uploads")
        os.makedirs(temp_user_upload_dir, exist_ok=True)
        local_temp_encrypted_path = os.path.join(temp_user_upload_dir, encrypted_filename_for_storage)

        file_enc_password = self._prompt_password(title="File Encryption Password", prompt=f"Enter password to encrypt '{original_filename_base}':")
        if not file_enc_password: self.status_bar_label.config(text="Status: Upload cancelled."); return

        self.status_bar_label.config(text=f"Status: Encrypting {original_filename_base} locally..."); self.update_idletasks()
        enc_success, enc_msg, _ = run_encryption_script('encrypt', local_source_filepath, local_temp_encrypted_path, file_enc_password)

        if not enc_success:
            self.status_bar_label.config(text="Status: Local encryption failed."); messagebox.showerror("Encryption Failed", enc_msg, parent=self)
            if os.path.exists(local_temp_encrypted_path): os.remove(local_temp_encrypted_path)
            return

        # Move encrypted file to user's "my_files" directory
        _, my_files_local_path, _ = self._get_user_local_paths()
        os.makedirs(my_files_local_path, exist_ok=True) # Ensure it exists
        final_storage_path = os.path.join(my_files_local_path, encrypted_filename_for_storage)

        try:
            shutil.move(local_temp_encrypted_path, final_storage_path)
            self.status_bar_label.config(text=f"Status: '{original_filename_base}' encrypted and saved locally.")
            messagebox.showinfo("Success", "File encrypted and saved to your local storage.", parent=self)
            self._load_user_files_from_local() # Refresh list
        except Exception as e_move:
            self.status_bar_label.config(text=f"Status: Failed to save encrypted file: {e_move}"); messagebox.showerror("Save Error", f"Failed to save: {e_move}", parent=self)
            if os.path.exists(local_temp_encrypted_path): os.remove(local_temp_encrypted_path) # Clean up temp if move failed
        finally:
             # Clean up empty upload staging dir if necessary
            if os.path.exists(temp_user_upload_dir) and not os.listdir(temp_user_upload_dir):
                try: shutil.rmtree(temp_user_upload_dir)
                except OSError: pass

    def _prompt_password(self, title="Enter Password", prompt="Password:"): # Helper
        return simpledialog.askstring(title, prompt, parent=self, show='●')

    def _download_file_local(self): # Renamed and adapted
        display_filename, local_enc_path, file_type, owner_sharer_username = self._get_selected_file_info_local()
        if not local_enc_path or not os.path.exists(local_enc_path):
            messagebox.showerror("Error", "Selected file path not found or invalid.", parent=self)
            self._load_user_files_from_local() # Refresh if file is gone
            return

        # Local temporary directory for this download's decrypted output (before user saves)
        # Or rather, local_enc_path *is* the source. We decrypt from it.
        # We need a temp path for the *source* encrypted file if it's shared, to avoid issues.
        # No, local_enc_path is already the path to the encrypted file.

        decryption_password = None
        if file_type == "Owned":
            decryption_password = self._prompt_password(title="Decrypt Owned File", prompt=f"Enter password to decrypt '{display_filename}':")
        elif file_type == "Shared":
            # For shared files (which are copies), the .keyinfo is next to the copied encrypted file
            keyinfo_path = local_enc_path + LOCAL_KEY_SUFFIX # e.g., .../_shared_with_me/sharer/enc_file.enc.keyinfo
            if os.path.exists(keyinfo_path):
                try:
                    with open(keyinfo_path, 'r') as kf:
                        decryption_password = kf.read().strip()
                except IOError as e:
                    messagebox.showerror("Error", f"Could not read key information for shared file: {e}", parent=self)
            else:
                messagebox.showerror("Error", "Key information for this shared file is missing.\nIt might have been an incomplete share.", parent=self)

            if not decryption_password:
                 self.status_bar_label.config(text="Status: Shared file password not retrieved."); return

        if not decryption_password:
            self.status_bar_label.config(text="Status: Download cancelled (no password)."); return

        self.status_bar_label.config(text=f"Status: Preparing to decrypt '{display_filename}'..."); self.update_idletasks()

        save_location_decrypted = filedialog.asksaveasfilename(parent=self, title="Save decrypted file as", initialfile=display_filename)
        if not save_location_decrypted:
            self.status_bar_label.config(text="Status: Save cancelled."); return

        dec_success, dec_msg, _ = run_encryption_script('decrypt', local_enc_path, save_location_decrypted, decryption_password)

        if dec_success:
            self.status_bar_label.config(text=f"Status: '{display_filename}' successfully decrypted and saved.")
            messagebox.showinfo("Success", f"File saved to {save_location_decrypted}", parent=self)
        else:
            self.status_bar_label.config(text="Status: Decryption failed."); messagebox.showerror("Decryption Failed", dec_msg, parent=self)
            if os.path.exists(save_location_decrypted) and os.path.getsize(save_location_decrypted) == 0: # Cleanup empty file on error
                try: os.remove(save_location_decrypted)
                except OSError: pass

    def _delete_file_local(self): # Renamed and adapted
        display_filename, local_enc_path, file_type, owner_sharer = self._get_selected_file_info_local()
        if not local_enc_path: return

        # Users can delete their own files or files shared *with them* (which are copies in their space)
        confirm_msg = f"Permanently delete '{display_filename}' from your local storage?"
        if file_type == "Owned":
            confirm_msg += "\nThis will NOT affect copies already shared with other users."
        
        if not messagebox.askyesno("Confirm Delete", confirm_msg, parent=self, icon='warning'):
            self.status_bar_label.config(text="Status: Delete cancelled."); return

        self.status_bar_label.config(text=f"Status: Deleting '{display_filename}' locally..."); self.update_idletasks()
        delete_success = False
        try:
            if os.path.exists(local_enc_path):
                os.remove(local_enc_path)
                # If it was a shared file, also remove its .keyinfo file
                if file_type == "Shared":
                    keyinfo_path = local_enc_path + LOCAL_KEY_SUFFIX
                    if os.path.exists(keyinfo_path):
                        os.remove(keyinfo_path)
                delete_success = True
                self.status_bar_label.config(text=f"Status: '{display_filename}' deleted locally.")
                messagebox.showinfo("Success", "File deleted from local storage.", parent=self)
            else: # File was already gone
                self.status_bar_label.config(text=f"Status: '{display_filename}' not found, presumed deleted.")
                messagebox.showinfo("Info", "File not found (already deleted).", parent=self)
                delete_success = True
        except OSError as e_del:
            self.status_bar_label.config(text=f"Status: Local delete failed: {e_del}")
            messagebox.showerror("Delete Error", f"Could not delete file: {e_del}", parent=self)

        if delete_success:
            self._load_user_files_from_local()


    def _share_file_local_user(self): # Renamed and significantly adapted
        display_filename_owner, local_enc_path_owner, file_type_owner, _ = self._get_selected_file_info_local()
        if not local_enc_path_owner: return
        if file_type_owner != "Owned":
            messagebox.showerror("Error", "You can only share files you own.", parent=self); return

        shared_with_username = simpledialog.askstring("Share File Locally",f"Enter username to share '{display_filename_owner}' with:", parent=self)
        if not shared_with_username or not shared_with_username.strip():
            messagebox.showinfo("Share Info", "Username cannot be empty.", parent=self); return
        if shared_with_username == self.current_user_username:
             messagebox.showinfo("Share Info", "Cannot share a file with yourself.", parent=self); return


        conn_auth = sqlite3.connect(DB_NAME_AUTH)
        cur_auth = conn_auth.cursor()
        cur_auth.execute("SELECT id FROM users WHERE username = ?", (shared_with_username,))
        if not cur_auth.fetchone():
            messagebox.showwarning("User Not Found", f"User '{shared_with_username}' not found.", parent=self)
            conn_auth.close(); return
        conn_auth.close()

        file_encryption_password_for_share = self._prompt_password(
            title="Provide File Encryption Password",
            prompt=f"Enter the password YOU USED to encrypt '{display_filename_owner}'.\nThis will be stored (insecurely) for '{shared_with_username}'.")
        if not file_encryption_password_for_share:
            messagebox.showinfo("Share Cancelled", "No password provided for sharing.", parent=self); return

        self.status_bar_label.config(text=f"Status: Preparing to share '{display_filename_owner}' with '{shared_with_username}'..."); self.update_idletasks()

        try:
            # Path for the recipient's "_shared_with_me/{current_owner_username}" directory
            _, _, recipient_shared_base_path = self._get_user_local_paths(shared_with_username)
            # Directory for this specific sharer (current user) inside recipient's shared folder
            sharer_specific_dir_in_recipient_share = os.path.join(recipient_shared_base_path, self.current_user_username)
            os.makedirs(sharer_specific_dir_in_recipient_share, exist_ok=True)

            # Filename of the encrypted file owned by current user
            encrypted_filename_on_owner = os.path.basename(local_enc_path_owner)

            # Path where the COPY of the encrypted file will be placed for the recipient
            recipient_copied_enc_file_path = os.path.join(sharer_specific_dir_in_recipient_share, encrypted_filename_on_owner)

            # 1. Copy the encrypted file to the recipient's shared area
            shutil.copy2(local_enc_path_owner, recipient_copied_enc_file_path) # copy2 preserves metadata like timestamp

            # 2. Create the .keyinfo file (INSECURE - stores password in plaintext) for the copied file
            key_info_path_for_recipient = recipient_copied_enc_file_path + LOCAL_KEY_SUFFIX
            with open(key_info_path_for_recipient, 'w') as f_key:
                f_key.write(file_encryption_password_for_share)

            self.status_bar_label.config(text=f"Status: '{display_filename_owner}' shared with '{shared_with_username}'.")
            messagebox.showinfo("Shared Locally", f"'{display_filename_owner}' successfully copied and shared with '{shared_with_username}'.\nThey will see it on their next refresh.", parent=self)

        except Exception as e_share:
            self.status_bar_label.config(text=f"Status: Local sharing failed: {e_share}")
            messagebox.showerror("Local Share Error", f"Failed to set up local share: {e_share}", parent=self)
            import traceback; traceback.print_exc()


    def _handle_logout(self):
        # ... (same as before, but calls stop_polling_local_files)
        self.stop_polling_local_files()
        self.current_user_id = None; self.current_user_username = None
        login_frame = self.frames.get("LoginView")
        if login_frame and hasattr(login_frame, 'auth_vars'):
            login_frame.auth_vars["username"].set(""); login_frame.auth_vars["password"].set("")
            login_frame.auth_vars["error_label"].config(text="")
        self.show_frame("LoginView")
        if hasattr(self,'status_bar_label'): self.status_bar_label.config(text="Status: Logged out.")


if __name__ == "__main__":
    if platform.system() != "Windows" and os.path.exists(CODE_SH_SCRIPT_PATH):
        if not os.access(CODE_SH_SCRIPT_PATH, os.X_OK):
            try: os.chmod(CODE_SH_SCRIPT_PATH, 0o755); print(f"Made '{CODE_SH_SCRIPT_PATH}' executable.")
            except Exception as e: print(f"Warning: Could not make '{CODE_SH_SCRIPT_PATH}' executable: {e}")
    elif not os.path.exists(CODE_SH_SCRIPT_PATH):
         print(f"CRITICAL ERROR: Encryption script '{CODE_SH_SCRIPT_PATH}' not found. Application will not function correctly.")
         # Consider exiting if script is essential:
         # import sys
         # sys.exit(f"Error: Missing {CODE_SH_SCRIPT_PATH}")

    init_auth_db()
    app = SecureShareApp()
    app.mainloop()