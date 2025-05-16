#!/bin/bash
set -euo pipefail 

# --- Configuration ---
DEFAULT_CIPHER="aes-256-cbc"
PBKDF2_ITERATIONS=100000
output_file_on_error=""

# --- BEGIN: Define paths to utilities ---
# Assume standard utilities are in the same directory as bash.exe or a known relative path.
# Get the directory of the bash interpreter itself
BASH_DIR=$(dirname "$(command -v bash)") # This might give /usr/bin if bash is in path as seen by bash
GIT_USR_BIN=""

# Attempt to find the Git usr/bin directory more reliably
# This is a heuristic; a more robust method might be needed if Git is installed in a non-standard location
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || -n "$WINDIR" ]]; then
    # Try to find a common Git installation path.
    # This might need adjustment based on typical Git for Windows install locations.
    potential_git_paths=(
        "$(command -v git | sed 's|/cmd/git.exe$|/usr/bin|;s|/mingw64/bin/git.exe$|/mingw64/bin|')" # From git itself
        "/c/Program Files/Git/usr/bin"  # Common path in Git Bash
        "/usr/bin"                      # Sometimes usr/bin is in the path directly for MSYS2 components
    )
    for p_path in "${potential_git_paths[@]}"; do
        if [ -d "$p_path" ]; then
            GIT_USR_BIN="$p_path"
            break
        fi
    done
    # If still not found, and BASH_DIR seems like /usr/bin, use that.
    if [ -z "$GIT_USR_BIN" ] && [[ "$BASH_DIR" == "/usr/bin" || "$BASH_DIR" == "/bin" ]]; then
        GIT_USR_BIN="$BASH_DIR"
    fi
    # If after all attempts GIT_USR_BIN is empty, we might have issues.
    # As a last resort, just use the command name and hope it's in PATH
    if [ -z "$GIT_USR_BIN" ]; then
        echo "Warning (code.sh): Could not reliably determine GIT_USR_BIN. Relying on PATH for grep/dirname." >&2
        GREP_CMD="grep"
        DIRNAME_CMD="dirname"
    else
        GREP_CMD="$GIT_USR_BIN/grep"
        DIRNAME_CMD="$GIT_USR_BIN/dirname"
        echo "Debug (code.sh): Using GREP_CMD: $GREP_CMD" >&2
        echo "Debug (code.sh): Using DIRNAME_CMD: $DIRNAME_CMD" >&2

        # Verify they exist
        if [ ! -x "$GREP_CMD" ]; then
            echo "Warning (code.sh): Determined GREP_CMD '$GREP_CMD' not found or not executable. Falling back to 'grep'." >&2
            GREP_CMD="grep"
        fi
        if [ ! -x "$DIRNAME_CMD" ]; then
            echo "Warning (code.sh): Determined DIRNAME_CMD '$DIRNAME_CMD' not found or not executable. Falling back to 'dirname'." >&2
            DIRNAME_CMD="dirname"
        fi
    fi
else
    # For non-Windows (Linux, macOS), assume they are in PATH
    GREP_CMD="grep"
    DIRNAME_CMD="dirname"
fi
# --- END: Define paths to utilities ---


# --- Helper Functions ---
cleanup() {
    # ... (cleanup function remains the same)
    unset SCRIPT_ENCRYPTION_PASSWORD; unset password; unset password_confirm
    if [ -n "$1" ]; then echo "Error (code.sh): $1" >&2; fi
    if [ -n "$2" ] && [ "$2" -ne 0 ] && [ -n "$output_file_on_error" ] && [ -f "$output_file_on_error" ]; then
        local size_bytes; size_bytes=$(wc -c < "$output_file_on_error" 2>/dev/null | awk '{print $1}' 2>/dev/null) || size_bytes=0
        if [ "$size_bytes" -lt 64 ]; then rm -f "$output_file_on_error"; echo "Cleaned up output: '$output_file_on_error'." >&2
        else echo "Warning (code.sh): Output '$output_file_on_error' might be corrupted." >&2; fi
    fi; exit "${2:-0}"
}

# --- Pre-flight Checks ---
if ! command -v openssl &> /dev/null; then cleanup "OpenSSL is not installed." 1; fi

# --- Main Script Logic (arguments $1=mode, $2=input, $3=output) ---
# ... (Argument parsing and input file validation from previous version) ...
if [ "$#" -lt 3 ]; then cleanup "Usage: $0 <e|d> <input> <output>" 1; fi
script_mode_choice="$1"; raw_input_file_arg="$2"; raw_output_file_arg="$3"
input_file_to_test="$raw_input_file_arg"; output_file_to_use="$raw_output_file_arg"; output_file_on_error="$output_file_to_use"
echo "Debug (code.sh): Mode: [$script_mode_choice], Input: [$input_file_to_test], Output: [$output_file_to_use]" >&2
case "$script_mode_choice" in [Ee]*) mode="encrypt";; [Dd]*) mode="decrypt";; *) cleanup "Invalid mode: '$script_mode_choice'." 1;; esac
if [ -z "$input_file_to_test" ]; then cleanup "Input file empty." 1; fi
if [ ! -f "$input_file_to_test" ]; then cleanup "Input '$input_file_to_test' not found/regular file." 1; fi # Already PASSED
if [ ! -r "$input_file_to_test" ]; then cleanup "Input '$input_file_to_test' not readable." 1; fi
echo "Debug (code.sh): File tests PASSED for '$input_file_to_test'." >&2
if [ -z "$output_file_to_use" ]; then cleanup "Output file empty." 1; fi

# Passwords from stdin (same)
read -r -s SCRIPT_ENCRYPTION_PASSWORD; if [ -z "$SCRIPT_ENCRYPTION_PASSWORD" ]; then cleanup "Password empty." 1; fi
if [ "$mode" == "encrypt" ]; then read -r -s password_confirm; if [ "$SCRIPT_ENCRYPTION_PASSWORD" != "$password_confirm" ]; then cleanup "Passwords mismatch." 1; fi; unset password_confirm; fi
export SCRIPT_ENCRYPTION_PASSWORD

# Determine if OpenSSL supports PBKDF2 and -iter, using $GREP_CMD
use_pbkdf2_iter_opts=false
# Using $GREP_CMD variable now
if openssl enc "-$DEFAULT_CIPHER" -help 2>&1 | "$GREP_CMD" -q -- "-pbkdf2" && \
   openssl enc "-$DEFAULT_CIPHER" -help 2>&1 | "$GREP_CMD" -q -- "-iter"; then
    use_pbkdf2_iter_opts=true
    echo "Debug (code.sh): PBKDF2 and -iter options will be used." >&2
else
    echo "Warning (code.sh): OpenSSL version might not support -pbkdf2 and -iter (or $GREP_CMD failed). Using default KDF." >&2
fi

# Perform Encryption or Decryption
openssl_cmd_base=(openssl enc "-$DEFAULT_CIPHER")
openssl_cmd_key_opts=("-pass" "env:SCRIPT_ENCRYPTION_PASSWORD")
if $use_pbkdf2_iter_opts; then openssl_cmd_key_opts+=("-pbkdf2" "-iter" "$PBKDF2_ITERATIONS"); fi

# Using $DIRNAME_CMD variable now
output_dir_to_use=$("$DIRNAME_CMD" "$output_file_to_use")
if [ ! -d "$output_dir_to_use" ]; then
    mkdir -p "$output_dir_to_use" || cleanup "Could not create output directory '$output_dir_to_use'." 1
fi

echo "Debug (code.sh): Running OpenSSL. Mode: $mode. Input: $input_file_to_test. Output: $output_file_to_use" >&2
if [ "$mode" == "encrypt" ]; then
    "${openssl_cmd_base[@]}" -salt "${openssl_cmd_key_opts[@]}" -in "$input_file_to_test" -out "$output_file_to_use"
    rc=$?
else # decrypt
    "${openssl_cmd_base[@]}" -d "${openssl_cmd_key_opts[@]}" -in "$input_file_to_test" -out "$output_file_to_use"
    rc=$?
fi
action_past_tense="${mode}ed"

if [ $rc -eq 0 ]; then
    echo "File '$raw_input_file_arg' successfully $action_past_tense to '$raw_output_file_arg'."
    cleanup "" 0 
else
    cleanup "OpenSSL command failed to $mode '$raw_input_file_arg'. Exit code: $rc" "$rc" "$output_file_on_error"
fi