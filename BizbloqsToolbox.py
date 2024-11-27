import os
import hashlib
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from difflib import Differ
import pandas as pd


def hash_file(file_path):
    """Generate a hash for the content of a file."""
    hasher = hashlib.md5()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

def find_duplicates(folder_path):
    """Find duplicate files in the folder based on content."""
    file_hashes = {}
    duplicates = []

    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = hash_file(file_path)

            if file_hash in file_hashes:
                duplicates.append((file, file_path, file_hashes[file_hash]))
            else:
                file_hashes[file_hash] = file_path

    return duplicates

def select_folder():
    """Open folder dialog to select a folder."""
    folder_path = filedialog.askdirectory(title="Select Folder")
    if folder_path:
        folder_path_entry.delete(0, tk.END)  # Clear the entry field
        folder_path_entry.insert(0, folder_path)  # Set the selected folder path

def clear_results():
    """Clear the results table and text box."""
    for row in result_table.get_children():
        result_table.delete(row)
    result_summary.delete(1.0, tk.END)

def export_to_excel():
    """Export the duplicate results to an Excel file."""
    if not result_table.get_children():
        messagebox.showerror("Error", "No results to export.")
        return

    # Prepare data for export
    data = []
    for row in result_table.get_children():
        values = result_table.item(row, "values")
        data.append(values)

    # Create a DataFrame
    df = pd.DataFrame(data, columns=["File Name", "Duplicate File Path", "Original File Path"])

    # Ask the user for a save location
    file_path = filedialog.asksaveasfilename(
        defaultextension=".xlsx",
        filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")],
        title="Save as Excel File"
    )
    if file_path:
        try:
            df.to_excel(file_path, index=False)
            messagebox.showinfo("Export Complete", f"Results successfully exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export results: {e}")

def run_check():
    """Run the duplicate file check."""
    folder_path = folder_path_entry.get().strip()

    if not folder_path or not os.path.isdir(folder_path):
        messagebox.showerror("Error", "Please enter a valid folder path.")
        return

    # Clear the results
    clear_results()

    duplicates = find_duplicates(folder_path)

    if duplicates:
        for dup in duplicates:
            file_name = dup[0]
            duplicate_path = dup[1]
            original_path = dup[2]
            # Add to table
            result_table.insert("", "end", values=(file_name, duplicate_path, original_path))
            # Add to summary
            result_summary.insert(tk.END, f"'{file_name}' is a duplicate of:\n- {original_path}\n\n")
        messagebox.showinfo("Scan Complete", "Duplicate file scan is complete! Check the results.")
    else:
        result_summary.insert(tk.END, "No duplicate files found.\n")
        messagebox.showinfo("No Duplicates", "No duplicate files found.")

    # Insert the red-colored text at the end of the summary
    result_summary.insert(tk.END, "\nThis is a prototype. If you encounter any issues or bugs, please contact: \n")
    result_summary.insert(tk.END, "Harvey@bizbloqs.com\n", "red")

    # Configure the tag to use red color
    result_summary.tag_configure("red", foreground="red")

def toggle_theme():
    """Switch between light and dark mode across all tabs."""
    global dark_mode
    dark_mode = not dark_mode

    if dark_mode:
        # Dark Mode Styles
        root.configure(bg="#1e1e1e")
        style.configure("TFrame", background="#1e1e1e")
        style.configure("TLabel", background="#1e1e1e", foreground="#ffffff")
        style.configure("TButton", background="#444444", foreground="#ffffff")
        style.configure("Treeview", background="#2d2d2d", foreground="#ffffff", fieldbackground="#2d2d2d")
        
        toggle_button.configure(text="Switch to Light Mode", bg="#444444", fg="#ffffff")

        # Update all widgets in the notebook
        for tab in notebook.winfo_children():
            for widget in tab.winfo_children():
                if isinstance(widget, tk.Label):
                    widget.configure(bg="#1e1e1e", fg="#ffffff")
                elif isinstance(widget, tk.Entry):
                    widget.configure(bg="#2d2d2d", fg="#ffffff", insertbackground="#ffffff")
                elif isinstance(widget, tk.Text):
                    widget.configure(bg="#2d2d2d", fg="#ffffff", insertbackground="#ffffff")
                elif isinstance(widget, ttk.Treeview):
                    widget.configure(style="Treeview")
                elif isinstance(widget, tk.Button):
                    widget.configure(bg="#444444", fg="#ffffff")
        
        # Update Expected and Actual boxes specifically
        expected_text.configure(bg="#2d2d2d", fg="#ffffff", insertbackground="#ffffff")
        actual_text.configure(bg="#2d2d2d", fg="#ffffff", insertbackground="#ffffff")

    else:
        # Light Mode Styles
        root.configure(bg="#f9f9f9")
        style.configure("TFrame", background="#f9f9f9")
        style.configure("TLabel", background="#f9f9f9", foreground="#000000")
        style.configure("TButton", background="#e0e0e0", foreground="#000000")
        style.configure("Treeview", background="#ffffff", foreground="#000000", fieldbackground="#ffffff")
        
        toggle_button.configure(text="Switch to Dark Mode", bg="#e0e0e0", fg="#000000")

        # Update all widgets in the notebook
        for tab in notebook.winfo_children():
            for widget in tab.winfo_children():
                if isinstance(widget, tk.Label):
                    widget.configure(bg="#f9f9f9", fg="#000000")
                elif isinstance(widget, tk.Entry):
                    widget.configure(bg="#ffffff", fg="#000000", insertbackground="#000000")
                elif isinstance(widget, tk.Text):
                    widget.configure(bg="#ffffff", fg="#000000", insertbackground="#000000")
                elif isinstance(widget, ttk.Treeview):
                    widget.configure(style="Treeview")
                elif isinstance(widget, tk.Button):
                    widget.configure(bg="#e0e0e0", fg="#000000")
        
        # Update Expected and Actual boxes specifically
        expected_text.configure(bg="#ffffff", fg="#000000", insertbackground="#000000")
        actual_text.configure(bg="#ffffff", fg="#000000", insertbackground="#000000")

def highlight_differences(expected_text, actual_text, diff):
    """Highlight differences in the text boxes."""
    expected_text.tag_configure('diff', background='red')
    actual_text.tag_configure('diff', background='green')

    expected_text.tag_remove('diff', '1.0', 'end')
    actual_text.tag_remove('diff', '1.0', 'end')

    expected_idx = 1.0
    actual_idx = 1.0

    for line in diff:
        if line.startswith('- '):
            expected_text.insert(f'{expected_idx}', line[2:] + '\n', 'diff')
            expected_idx += 1
        elif line.startswith('+ '):
            actual_text.insert(f'{actual_idx}', line[2:] + '\n', 'diff')
            actual_idx += 1
        elif line.startswith('  '):
            expected_text.insert(f'{expected_idx}', line[2:] + '\n')
            actual_text.insert(f'{actual_idx}', line[2:] + '\n')
            expected_idx += 1
            actual_idx += 1

# Ensure the same approach is used for index management
def extract_and_compare():
    """Extract and compare the Expected and Actual values from the text."""
    input_text = input_text_box.get("1.0", tk.END).strip()

    try:
        expected = input_text.split('Expected:<')[1].split('>.')[0]
        actual = input_text.split('Actual:<')[1].split('>.')[0]

        expected_lines = expected.splitlines()
        actual_lines = actual.splitlines()

        expected_text.delete(1.0, tk.END)
        actual_text.delete(1.0, tk.END)

        differ = Differ()
        diff = list(differ.compare(expected_lines, actual_lines))

        highlight_differences(expected_text, actual_text, diff)

        # Show the comparison view
        show_comparison_view()

    except IndexError:
        messagebox.showerror("Error", "Unable to extract Expected and Actual values. Ensure the input format is correct.")

def show_comparison_view():
    """Switch to the comparison view."""
    # Hide the input text box and compare button
    input_text_label.pack_forget()
    input_text_box.pack_forget()
    compare_btn.pack_forget()

    # Show the results frame and clear button
    results_frame.pack(pady=5, padx=10, fill="both", expand=True)
    clear_all_btn.pack(pady=10)

def reset_to_initial_view():
    """Reset to the initial input view."""
    # Clear all text boxes
    expected_text.delete(1.0, tk.END)
    actual_text.delete(1.0, tk.END)
    input_text_box.delete(1.0, tk.END)

    # Hide the results frame and clear button
    results_frame.pack_forget()
    clear_all_btn.pack_forget()

    # Show the input text box and compare button
    input_text_label.pack(pady=5, anchor="w", padx=10)
    input_text_box.pack(pady=5, padx=10, fill="both", expand=True)
    compare_btn.pack(pady=10)


# GUI setup
root = tk.Tk()
root.title("Bizbloqs Toolbox v1.0")
root.geometry("1200x800")
root.resizable(True, True)

# Default theme (Light Mode)
dark_mode = False

# Style for Treeview
style = ttk.Style()
style.theme_use("clam")  # Modern theme

# Add a notebook widget to manage tabs
notebook = ttk.Notebook(root)
notebook.pack(pady=10, padx=10, fill="both", expand=True)

# Duplicate Finder tab
duplicate_frame = ttk.Frame(notebook)
notebook.add(duplicate_frame, text="Duplicate Finder")

# Folder Path Entry
folder_path_label = tk.Label(duplicate_frame, text="Folder Path:", font=("Arial", 12), anchor="w")
folder_path_label.pack(pady=5, anchor="w", padx=10)

folder_path_entry = tk.Entry(duplicate_frame, width=80, font=("Arial", 12))
folder_path_entry.pack(pady=5, padx=10)

# Select Folder Button
folder_btn = tk.Button(duplicate_frame, text="Browse", command=select_folder, width=15, font=("Arial", 10))
folder_btn.pack(pady=5)

# Run Check Button
check_btn = tk.Button(duplicate_frame, text="Check for Duplicates", command=run_check, width=20, font=("Arial", 12))
check_btn.pack(pady=10)

# Toggle Theme Button
toggle_button = tk.Button(duplicate_frame, text="Switch to Dark Mode", command=toggle_theme, width=20, font=("Arial", 12))
toggle_button.pack(pady=10)

# Results Table with Scrollbars
columns = ("File Name", "Duplicate File Path", "Original File Path")
result_frame = ttk.Frame(duplicate_frame)
result_frame.pack(pady=10, padx=10, fill="both", expand=True)

result_table = ttk.Treeview(result_frame, columns=columns, show="headings", height=10)

# Define column headings
result_table.heading("File Name", text="File Name")
result_table.heading("Duplicate File Path", text="Duplicate File Path")
result_table.heading("Original File Path", text="Original File Path")

# Set column widths
result_table.column("File Name", width=200, anchor="w")
result_table.column("Duplicate File Path", width=400, anchor="w")
result_table.column("Original File Path", width=400, anchor="w")

# Scrollbars
table_scroll_y = ttk.Scrollbar(result_frame, orient="vertical", command=result_table.yview)
table_scroll_x = ttk.Scrollbar(result_frame, orient="horizontal", command=result_table.xview)
result_table.configure(yscroll=table_scroll_y.set, xscroll=table_scroll_x.set)

result_table.grid(row=0, column=0, sticky="nsew")
table_scroll_y.grid(row=0, column=1, sticky="ns")
table_scroll_x.grid(row=1, column=0, sticky="ew")

result_frame.grid_columnconfigure(0, weight=1)
result_frame.grid_rowconfigure(0, weight=1)

# Summary Text Box
summary_label = tk.Label(duplicate_frame, text="Summary of Results:", font=("Arial", 12), anchor="w")
summary_label.pack(pady=5, anchor="w", padx=10)

result_summary = tk.Text(duplicate_frame, wrap=tk.WORD, font=("Arial", 10), height=10)
result_summary.pack(pady=5, padx=10, fill="both", expand=True)

#Export as Excel
export_btn = tk.Button(duplicate_frame, text="Export as Excel", command=export_to_excel, width=15, font=("Arial", 10))
export_btn.pack(pady=10)

# Clear Results Button
clear_btn = tk.Button(duplicate_frame, text="Clear Results", command=clear_results, width=15, font=("Arial", 10))
clear_btn.pack(pady=10)

# Add new tab for the difference checker
diff_checker_frame = ttk.Frame(notebook)
notebook.add(diff_checker_frame, text="Expected VS Actual Checker")

# Input Text Box
input_text_label = tk.Label(diff_checker_frame, text="Paste the test failing message here:", font=("Arial", 12), anchor="w")
input_text_label.pack(pady=5, anchor="w", padx=10)

input_text_box = tk.Text(diff_checker_frame, wrap=tk.WORD, font=("Arial", 10), height=10)
input_text_box.pack(pady=5, padx=10, fill="both", expand=True)
input_text_box.configure(maxundo=-1, undo=True)

# Extract and Compare Button
compare_btn = tk.Button(diff_checker_frame, text="Compare", command=extract_and_compare, width=20, font=("Arial", 12))
compare_btn.pack(pady=10)

# Results Frame for side-by-side comparison
results_frame = tk.Frame(diff_checker_frame)
results_frame.pack(pady=5, padx=10, fill="both", expand=True)

# Add "Clear All" button, initially hidden
clear_all_btn = tk.Button(diff_checker_frame, text="Clear All", command=reset_to_initial_view, width=20, font=("Arial", 12))

# Hide results frame initially
results_frame.pack_forget()
clear_all_btn.pack_forget()

# Shared Vertical Scrollbar
scrollbar = tk.Scrollbar(results_frame, orient="vertical")

# Expected Text Box
expected_label = tk.Label(results_frame, text="Expected:", font=("Arial", 12), anchor="w")
expected_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

expected_text = tk.Text(results_frame, wrap=tk.WORD, font=("Arial", 10), height=20, width=50, yscrollcommand=scrollbar.set)
expected_text.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
expected_text.configure(maxundo=-1, undo=True)

# Actual Text Box
actual_label = tk.Label(results_frame, text="Actual:", font=("Arial", 12), anchor="w")
actual_label.grid(row=0, column=1, padx=5, pady=5, sticky="w")

actual_text = tk.Text(results_frame, wrap=tk.WORD, font=("Arial", 10), height=20, width=50, yscrollcommand=scrollbar.set)
actual_text.grid(row=1, column=1, padx=5, pady=5, sticky="nsew")
actual_text.configure(maxundo=-1, undo=True)

# Configure shared scrollbar
scrollbar.config(command=lambda *args: (expected_text.yview(*args), actual_text.yview(*args)))
scrollbar.grid(row=1, column=2, sticky="ns")

# Synchronize scrolling
def sync_scroll(*args):
    expected_text.yview_moveto(args[0])
    actual_text.yview_moveto(args[0])

expected_text.configure(yscrollcommand=sync_scroll)
actual_text.configure(yscrollcommand=sync_scroll)

# Make the frame responsive
results_frame.grid_columnconfigure(0, weight=1)
results_frame.grid_columnconfigure(1, weight=1)
results_frame.grid_rowconfigure(1, weight=1)


# Initial Light Mode Styles
toggle_theme()

# Run the GUI loop
root.mainloop()