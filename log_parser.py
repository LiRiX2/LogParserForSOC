import pandas as pd
import re
import os
from datetime import datetime, timezone  # Keep timezone here, it's used in parse_flexible_datetime

# Fügen Sie dieses Dictionary mit Event-ID-Beschreibungen hinzu.
EVENT_ID_DESCRIPTIONS = {
    '1': 'Process Creation (Sysmon) - A process has been created. Use this to find suspicious executables.',
    '3': 'Network Connection (Sysmon) - A network connection was initiated. Crucial for C2 and data exfiltration.',
    '11': 'File Creation (Sysmon) - A file was created on the system. Useful for finding malicious downloads or tools.',
    '12': 'Registry Object Created/Deleted (Sysmon) - A registry key or value was created or deleted.',
    '13': 'Registry Value Set (Sysmon) - A value in a registry key was modified. Crucial for persistence tracking (e.g., Run keys).',
    '4624': 'Successful Logon (Windows Security) - A user successfully logged on to the system. Look for suspicious logon types.',
    '4625': 'Failed Logon (Windows Security) - A logon attempt failed. Important for detecting brute-force attacks.',
    '4688': 'Process Creation (Windows Security Audit) - Logs process creation with command line arguments. A key log for forensics.',
    '4720': 'User Account Created (Windows Security) - A new user account was created. Highly suspicious if unauthorized.',
    '4732': 'Member Added to a Local Group (Windows Security) - A user was added to a local group (e.g., Administrators).',
    '5145': 'Share Accessed (Windows Security) - A file share was accessed. Useful for tracking lateral movement.'
}


def parse_flexible_datetime(datetime_str: str):  # Removed preferred_format_str parameter
    """
    Attempts to parse a datetime string using multiple common formats, assuming UTC.

    Args:
        datetime_str (str): The datetime string to parse.

    Returns:
        datetime: A timezone-aware datetime object in UTC, or None if parsing fails.
    """
    # Define common datetime formats (including dot-separated for Europe)
    # Ensure formats are exhaustive and handle potential variations
    formats = [
        '%Y-%m-%d %H:%M:%S',  # YYYY-MM-DD HH:MM:SS (e.g., 2025-06-30 09:00:00)
        '%d.%m.%Y %H:%M:%S',  # DD.MM.YYYY HH:MM:SS (e.g., 30.06.2025 09:00:00)
        '%Y-%m-%d %H:%M',  # YYYY-MM-DD HH:MM
        '%d.%m.%Y %H:%M',  # DD.MM.YYYY HH:MM
        '%Y-%m-%d',  # YYYY-MM-DD (assume midnight UTC)
        '%d.%m.%Y'  # DD.MM.YYYY (assume midnight UTC)
    ]

    for fmt in formats:
        try:
            # Parse the string without timezone first
            dt_obj = datetime.strptime(datetime_str, fmt)
            # Make it timezone-aware (UTC)
            return dt_obj.replace(tzinfo=timezone.utc)
        except ValueError:
            continue  # Try the next format if this one fails

    return None  # Return None if no format matched


def parse_logs(log_file_path: str, filters: dict, time_field: str = 'UtcTime'):
    """
    Parses a log file (CSV or JSON format) and filters the data based on specified criteria.

    Args:
        log_file_path (str): The path to the log file (e.g., 'siem_logs.csv', 'api_logs.json').
        filters (dict): A dictionary where keys are column names (e.g., 'Image', 'DestinationIP')
                        and values are the strings or regular expressions to search for.
        time_field (str): The name of the column containing the timestamp (default is 'UtcTime').

    Returns:
        pd.DataFrame: A DataFrame containing the filtered logs.
                      Returns None if the file is not found or is empty.
    """
    if not os.path.exists(log_file_path):
        print(f"Error: The file '{log_file_path}' was not found.")
        return None

    print(f"Loading log file from: {log_file_path}")

    file_extension = os.path.splitext(log_file_path)[1].lower()

    try:
        if file_extension == '.csv':
            df = pd.read_csv(log_file_path, on_bad_lines='skip', encoding='utf-8')
        elif file_extension == '.json':
            # For JSON, we use orient='records' because our dummy data is a list of objects.
            df = pd.read_json(log_file_path, orient='records', encoding='utf-8')
        else:
            print(f"Error: Unsupported file format '{file_extension}'. Only .csv and .json are supported.")
            return None
    except Exception as e:
        print(f"Error reading the file: {e}")
        return None

    if df.empty:
        print("The DataFrame is empty. No data to process.")
        return df

    # --- Convert time_field to datetime objects ---
    if time_field in df.columns:
        try:
            # Ensure UTC timezone awareness. Use errors='coerce' to turn unparseable dates into NaT.
            df[time_field] = pd.to_datetime(df[time_field], errors='coerce', utc=True)
            # Drop rows where datetime conversion failed (NaT values)
            df.dropna(subset=[time_field], inplace=True)
            if df.empty:
                print(f"Warning: No valid timestamps found in the '{time_field}' column after conversion.")
                return df
        except Exception as e:
            print(f"Error converting '{time_field}' column to datetime: {e}")
            return None
    else:
        print(
            f"Warning: Time field '{time_field}' not found in the log file. Cannot perform time-based sorting or filtering.")

    filtered_df = df.copy()

    # Track if any filter was successfully applied.
    filter_applied_count = 0

    # Apply each filter dynamically.
    for column, value in filters.items():
        if column in filtered_df.columns:
            # We convert the column to string type to handle different data types.
            filtered_df = filtered_df[
                filtered_df[column].astype(str).str.contains(value, case=False, na=False, regex=True)]
            filter_applied_count += 1
        else:
            print(f"Warning: The column '{column}' does not exist in the log file. Skipping this filter.")

    # --- New Logic to prevent misleading results ---
    # If no filters were applied, return an empty DataFrame and a clear message.
    if filter_applied_count == 0 and filters:  # Only warn if filters were actually provided
        print("\nNo filters could be applied because none of the specified columns were found.")
        print("Please check the column names in your log file.")
        return pd.DataFrame()

    if time_field in filtered_df.columns:
        filtered_df = filtered_df.sort_values(by=time_field)

    filtered_df = filtered_df.reset_index(drop=True)

    if filtered_df.empty:
        print("\nNo matching logs were found with the given filters.")
    else:
        print(f"\nSuccessfully found {len(filtered_df)} matching log entries.")

    return filtered_df


def export_to_json(data_frame, file_name):
    """
    Exports a pandas DataFrame to a JSON file.

    Args:
        data_frame (pd.DataFrame): The DataFrame to export.
        file_name (str): The name of the output JSON file.
    """
    if data_frame is None or data_frame.empty:
        print("No data to export.")
        return

    try:
        # Orient='records' exports each row as a separate JSON object in a list.
        # indent=4 makes the JSON file human-readable.
        data_frame.to_json(file_name, orient='records', indent=4)
        print(f"Successfully exported {len(data_frame)} records to '{file_name}'.")
    except Exception as e:
        print(f"Error exporting data to JSON: {e}")


# --- Helper functions for specific use cases ---

def get_user_sid(log_file_path: str, username: str):
    """
    Finds the SID for a given username in Windows Event Logs.
    """
    print(f"\n" + "=" * 60 + "\n")
    print(f"--- Searching for the SID of user '{username}' ---")
    sid_filter = {
        'EventID': '4624',
        'TargetUsername': username
    }
    user_logons = parse_logs(log_file_path, sid_filter)

    if user_logons is not None and not user_logons.empty:
        if 'TargetUserSid' in user_logons.columns:
            unique_sids = user_logons['TargetUserSid'].drop_duplicates().tolist()
            print(f"Found the following SIDs for user '{username}':")
            for sid in unique_sids:
                print(f"  - {sid}")
            return user_logons
        else:
            print("Error: 'TargetUserSid' column not found in the log file.")
            return None
    else:
        print(f"No successful logon events found for user '{username}'.")
        return None


def find_rdp_logon(log_file_path: str, username: str, source_ip: str = None):
    """
    Finds a successful RDP logon event for a user.
    """
    print(f"\n" + "=" * 60 + "\n")
    print(f"--- Searching for RDP logon for user '{username}' ---")
    rdp_filter = {
        'EventID': '4624',
        'LogonType': '3',
        'TargetUsername': username
    }
    if source_ip:
        rdp_filter['SourceIp'] = source_ip
        print(f"  ...from source IP: {source_ip}")

    rdp_logons = parse_logs(log_file_path, rdp_filter)

    if rdp_logons is not None and not rdp_logons.empty:
        print("\nFound the following RDP logon events:")
        if all(col in rdp_logons.columns for col in ['UtcTime', 'TargetUsername', 'SourceIp']):
            print(rdp_logons[['UtcTime', 'TargetUsername', 'SourceIp']])
        else:
            print("Required columns (UtcTime, TargetUsername, SourceIp) not found in the results.")
        return rdp_logons
    else:
        print(f"No RDP logon events found for user '{username}' (LogonType 3, EventID 4624).")
        return None


def correlate_processes(log_file_path: str, parent_identifier: str, is_id: bool = False):
    """
    Correlates events by finding all child processes started by a specified parent process.

    Args:
        log_file_path (str): Path to the log file.
        parent_identifier (str): The name (Image) or ProcessId of the parent process.
        is_id (bool): If True, treats parent_identifier as a ProcessId, otherwise as an Image name.

    Returns:
        pd.DataFrame: A DataFrame with all events started by the parent process.
    """
    print(f"\n" + "=" * 60 + "\n")
    if is_id:
        print(f"--- Searching for child processes of ParentProcessId '{parent_identifier}' ---")
        filter_column = 'ParentProcessId'
    else:
        print(f"--- Searching for child processes of Übergeordneter Prozessname (Image) '{parent_identifier}' ---")
        filter_column = 'ParentImage'

    # Use the existing parser to filter based on the parent.
    process_filter = {filter_column: parent_identifier}

    child_processes = parse_logs(log_file_path, process_filter)

    if child_processes is not None and not child_processes.empty:
        print("\nFound the following child processes:")
        # We display the most relevant columns for process correlation.
        if all(col in child_processes.columns for col in
               ['UtcTime', 'Image', 'CommandLine', 'ProcessId', 'ParentImage']):
            # Rename columns for clear output
            print(child_processes.rename(
                columns={'Image': 'Prozessname (Image)', 'ParentImage': 'Übergeordneter Prozess'})[
                      ['UtcTime', 'Prozessname (Image)', 'CommandLine', 'ProcessId', 'Übergeordneter Prozess']])
        else:
            print("Required columns (Image, CommandLine, ProcessId, ParentImage) not found in the results.")
        return child_processes
    else:
        print(f"No child processes found for '{parent_identifier}'.")
        return None


def filter_by_time_range(log_file_path: str, time_field: str = 'UtcTime'):
    """
    Filters logs by a specified time range (start and end UtcTime).

    Args:
        log_file_path (str): The path to the log file.
        time_field (str): The name of the column containing the timestamp.

    Returns:
        pd.DataFrame: A DataFrame filtered by the specified time range.
    """
    print("\n" + "=" * 60 + "\n")
    print("--- Filtering logs by time range ---")

    # First, load the entire log file (without content filters, only for time).
    # We pass an empty filter dict so parse_logs loads everything and converts timestamps.
    df = parse_logs(log_file_path, filters={}, time_field=time_field)

    if df is None or df.empty:
        return pd.DataFrame()  # Return empty if no data or error during initial load.

    if time_field not in df.columns or not pd.api.types.is_datetime64_any_dtype(df[time_field]):
        print(f"Error: Time field '{time_field}' not found or not in datetime format. Cannot filter by time.")
        return pd.DataFrame()

    print(f"\nCurrent earliest log entry: {df[time_field].min()}")
    print(f"Current latest log entry: {df[time_field].max()}")

    while True:
        # Reverted prompt to only suggest ISO, but parse_flexible_datetime still handles both.
        start_time_str = input("Enter start time (YYYY-MM-DD HH:MM:SS or just date) or 'back' to return: ")
        if start_time_str.lower() == 'back':
            return pd.DataFrame()

        end_time_str = input("Enter end time (YYYY-MM-DD HH:MM:SS or just date) or 'back' to return: ")
        if end_time_str.lower() == 'back':
            return pd.DataFrame()

        # parse_flexible_datetime still attempts to parse both ISO and EU formats.
        start_time = parse_flexible_datetime(start_time_str)  # Removed preferred_format_str
        end_time = parse_flexible_datetime(end_time_str)  # Removed preferred_format_str

        if start_time is None or end_time is None:
            # Corrected prompt to reflect current format options more accurately based on parse_flexible_datetime
            print(
                f"Invalid time format. Please use one of the following: YYYY-MM-DD HH:MM:SS, DD.MM.YYYY HH:MM:SS, or just date.")
            continue

        if start_time >= end_time:
            print("Error: Start time must be before end time. Please try again.")
            continue

        break  # Exit loop if times are valid

    # Apply the time filter
    filtered_by_time = df[(df[time_field] >= start_time) & (df[time_field] <= end_time)].copy()

    if filtered_by_time.empty:
        print(f"\nNo logs found within the time range {start_time} to {end_time}.")
    else:
        print(f"\nSuccessfully found {len(filtered_by_time)} logs within the time range:")
        # Display the relevant information for the time filter.
        # Ensure 'Image' is renamed if it exists in the filtered_by_time DataFrame
        if 'Image' in filtered_by_time.columns:
            print(filtered_by_time.rename(columns={'Image': 'Prozessname (Image)'}))
        else:
            print(filtered_by_time)

    return filtered_by_time


# --- Hauptlogik für die interaktive Benutzereingabe ---
if __name__ == "__main__":
    # --- Dummy-Dateien zur Demonstration erstellen ---
    print("Creating dummy log files for demonstration purposes...")

    # Dummy data for Windows Security Logs (for SID and RDP)
    dummy_security_data = {
        'UtcTime': ['2025-06-30T09:00:00Z', '2025-06-30T09:01:00Z', '2025-06-30T09:02:00Z', '2025-06-30T09:05:00Z',
                    '2025-06-30T15:30:00Z'],
        'EventID': [4624, 4624, 4625, 4624, 4624],
        'TargetUsername': ['admin', 'Florence', 'Florence', 'admin', 'Florence'],
        'TargetUserSid': ['S-1-5-21-123-456-789-1001', 'S-1-5-21-123-456-789-1005', 'S-1-5-21-123-456-789-1005',
                          'S-1-5-21-123-456-789-1001', 'S-1-5-21-123-456-789-1005'],
        'LogonType': [2, 3, 3, 2, 3],  # 2 = interactive, 3 = network
        'SourceIp': ['192.168.1.1', '10.0.0.10', '10.0.0.0', '192.168.1.1', '10.0.0.50']
    }
    dummy_security_df = pd.DataFrame(dummy_security_data)
    dummy_security_df.to_csv('windows_security_logs_interactive.csv', index=False)

    # Dummy data for Sysmon/Registry Logs (for persistence and file creation)
    dummy_sysmon_data = {
        'UtcTime': ['2025-06-30T11:00:00Z', '2025-06-30T11:00:05Z', '2025-06-30T11:01:00Z', '2025-06-30T11:15:00Z',
                    '2025-06-30T11:16:00Z', '2025-06-30T11:17:00Z'],
        'EventType': ['ProcessCreate', 'RegistryEvent', 'FileCreate', 'FileCreate', 'ProcessCreate',
                      'NetworkConnection'],
        'EventID': ['1', '13', '11', '1', '1', '3'],  # Added EventID column for consistency
        'Image': ['powershell.exe', 'reg.exe', 'chrome.exe', 'cmd.exe', 'malicious_script.exe', 'malware.exe'],
        'CommandLine': ['powershell.exe -e...', 'reg.exe add HKCU\\...\\Run /v ...', '',
                        'copy C:\\temp\\* C:\\Users\\Florence\\AppData\\Local\\Temp\\Staging',
                        'malicious_script.exe -c', ''],
        'RegistryKey': ['', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\malware_app', '', '', '', ''],
        'FilePath': ['', '', 'C:\\Users\\Florence\\Downloads\\invoice.exe',
                     'C:\\Users\\Florence\\AppData\\Local\\Temp\\Staging', 'C:\\temp\\malicious_script.exe', ''],
        'ProcessId': ['1234', '5678', '9101', '1213', '1415', '1617'],  # New column
        'ParentImage': ['explorer.exe', 'powershell.exe', 'svchost.exe', 'powershell.exe', 'cmd.exe',
                        'malicious_script.exe'],  # New column
        'ParentProcessId': ['999', '1234', '888', '1234', '1213', '1415']  # New column
    }
    dummy_sysmon_df = pd.DataFrame(dummy_sysmon_data)
    dummy_sysmon_df.to_csv('sysmon_logs_interactive.csv', index=False)

    # Dummy data for JSON logs
    dummy_json_data = [
        {"UtcTime": "2025-06-30T10:00:00Z", "EventID": 1, "Image": "calc.exe", "CommandLine": "calc.exe",
         "User": "admin", "SourceIp": "192.168.1.1"},
        {"UtcTime": "2025-06-30T10:01:00Z", "EventID": 3, "Image": "powershell.exe", "DestinationIP": "1.2.3.4",
         "User": "florence", "DestinationPort": 443},
        {"UtcTime": "2025-06-30T10:02:00Z", "EventID": 1, "Image": "bad_process.exe",
         "CommandLine": "bad_process.exe --hidden", "User": "florence", "ParentImage": "chrome.exe",
         "SourceIp": "10.0.0.1"},
        {"UtcTime": "2025-06-30T10:03:00Z", "EventID": 4624, "TargetUsername": "Florence", "LogonType": 2,
         "User": "florence", "SourceIp": "192.168.1.5"}
    ]
    dummy_json_df = pd.DataFrame(dummy_json_data)
    dummy_json_df.to_json('sample_logs.json', orient='records', indent=4)  # Save as JSON

    print(
        "Dummy log files ('windows_security_logs_interactive.csv', 'sysmon_logs_interactive.csv', 'sample_logs.json') created.\n" + "=" * 60 + "\n")

    # --- Interaktive Eingabe vom Benutzer ---
    print("Welcome to the Interactive Log Analyzer.")
    log_file_path_input = input(
        "Please enter the full path to the log file (e.g., windows_security_logs_interactive.csv): ")

    # Check if the user entered a path.
    if not log_file_path_input:
        print("No file path entered. Exiting.")
        exit()

    # --- Main menu loop ---
    while True:
        print("\n" + "=" * 60 + "\n")
        print(f"Currently analyzing: {log_file_path_input}\n")

        print("Please select a query to run:")
        print("1. Find events by ID or type (e.g., EventID 4624, EventType ProcessCreate).")
        print("2. Correlate processes by parent (e.g., find all children of powershell.exe).")
        print("3. Find SID for a user.")
        print("4. Find RDP logon events for a user.")
        print("5. Search for malicious outbound traffic.")
        print("6. Find a suspicious downloaded file.")
        print("7. Find persistence via registry key.")
        print("8. Find a staging folder.")
        print("9. Filter logs by time range.")
        print("10. Change log file.")
        # print("11. Set preferred date/time format for input.") # Removed this option and its logic
        print("11. Exit.")  # This is now option 11 again

        choice = input("Enter your choice (1-11): ")  # Updated choice range

        results = None  # Initialize results variable

        if choice == '1':
            # Find events by ID or type with suggestions.
            print("\n--- Select an event type to search for: ---")
            print(f"a. Process Creation (Sysmon Event ID 1): {EVENT_ID_DESCRIPTIONS['1']}")
            print(f"b. Network Connection (Sysmon Event ID 3): {EVENT_ID_DESCRIPTIONS['3']}")
            print(f"c. Successful Logon (Windows Event ID 4624): {EVENT_ID_DESCRIPTIONS['4624']}")
            print(f"d. Failed Logon (Windows Event ID 4625): {EVENT_ID_DESCRIPTIONS['4625']}")
            print(f"e. Registry Value Set (Sysmon Event ID 13): {EVENT_ID_DESCRIPTIONS['13']}")
            print(f"f. File Creation (Sysmon Event ID 11): {EVENT_ID_DESCRIPTIONS['11']}")
            print("g. Custom Search (Enter column and value manually)")

            sub_choice = input("Enter your choice (a-g): ")

            dynamic_filter = {}
            column_name = ''
            value_to_find = ''

            if sub_choice.lower() == 'a':
                column_name = 'EventID'
                value_to_find = '1'
                print(f"\nSearching for: {EVENT_ID_DESCRIPTIONS['1']}...")
            elif sub_choice.lower() == 'b':
                column_name = 'EventID'
                value_to_find = '3'
                print(f"\nSearching for: {EVENT_ID_DESCRIPTIONS['3']}...")
            elif sub_choice.lower() == 'c':
                column_name = 'EventID'
                value_to_find = '4624'
                print(f"\nSearching for: {EVENT_ID_DESCRIPTIONS['4624']}...")
            elif sub_choice.lower() == 'd':
                column_name = 'EventID'
                value_to_find = '4625'
                print(f"\nSearching for: {EVENT_ID_DESCRIPTIONS['4625']}...")
            elif sub_choice.lower() == 'e':
                column_name = 'EventID'
                value_to_find = '13'
                print(f"\nSearching for: {EVENT_ID_DESCRIPTIONS['13']}...")
            elif sub_choice.lower() == 'f':
                column_name = 'EventID'
                value_to_find = '11'
                print(f"\nSearching for: {EVENT_ID_DESCRIPTIONS['11']}...")
            elif sub_choice.lower() == 'g':
                column_name = input("Enter the column name to filter (e.g., 'EventID' or 'EventType'): ")
                value_to_find = input(f"Enter the value to search for in '{column_name}': ")
            else:
                print("Invalid sub-choice. Returning to main menu.")
                continue

            if column_name and value_to_find:
                dynamic_filter = {column_name: value_to_find}
                results = parse_logs(log_file_path_input, dynamic_filter)
                if results is not None and not results.empty:
                    # Rename columns for clear output where 'Image' might appear
                    if 'Image' in results.columns:
                        print(results.rename(columns={'Image': 'Prozessname (Image)'}))
                    else:
                        print(results)
            else:
                continue  # Go back to the main menu if no filter was created.
        elif choice == '2':
            # Correlate processes by parent
            parent_type = input("Search by parent Process Name (e.g., powershell.exe) (i) or ProcessId (p)? (i/p): ")
            if parent_type.lower() == 'i':
                parent_image = input("Enter the parent Process Name: ")
                results = correlate_processes(log_file_path_input, parent_image, is_id=False)
            elif parent_type.lower() == 'p':
                parent_pid = input("Enter the parent ProcessId: ")
                results = correlate_processes(log_file_path_input, parent_pid, is_id=True)
            else:
                print("Invalid choice. Returning to main menu.")
                continue
        elif choice == '3':
            # Shifted from 2
            username_to_find = input("Enter the username to search for (e.g., 'Florence'): ")
            results = get_user_sid(log_file_path_input, username_to_find)
        elif choice == '4':
            # Shifted from 3
            username_to_find = input("Enter the username to search for RDP logons: ")
            source_ip_to_find = input("Enter the source IP (optional, press Enter to skip): ")
            results = find_rdp_logon(log_file_path_input, username_to_find,
                                     source_ip_to_find if source_ip_to_find else None)
        elif choice == '5':
            # Shifted from 4
            ip_to_find = input("Enter the malicious destination IP: ")
            image_to_find = input("Enter the process name (e.g., powershell.exe, optional): ")
            malicious_traffic_filter = {'DestinationIP': ip_to_find}
            if image_to_find:
                malicious_traffic_filter['Image'] = image_to_find
            results = parse_logs(log_file_path_input, malicious_traffic_filter)
            if results is not None and not results.empty:
                print(results.rename(columns={'Image': 'Prozessname (Image)'}))
        elif choice == '6':
            # Shifted from 5
            file_filter = {'FilePath': '.*Downloads.*\\.(?:exe|zip|docm|js)$',
                           'Image': '.*(?:chrome|firefox|edge)\.exe'}
            print("Searching for suspicious downloads in the 'Downloads' folder...")
            results = parse_logs(log_file_path_input, file_filter)
            if results is not None and not results.empty:
                print(results.rename(columns={'Image': 'Prozessname (Image)'})[
                          ['UtcTime', 'Prozessname (Image)', 'FilePath']])
        elif choice == '7':
            # Shifted from 6
            persistence_filter = {
                'EventType': 'RegistryEvent',
                'RegistryKey': '.*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run.*'
            }
            print("Searching for persistence via common registry run keys...")
            results = parse_logs(log_file_path_input, persistence_filter)
            if results is not None and not results.empty:
                print(results.rename(columns={'Image': 'Prozessname (Image)'}))
        elif choice == '8':
            # Shifted from 7
            staging_folder_filter = {
                'FilePath': r'.*\\AppData\\Local\\Temp\\(?!Microsoft|Google|Mozilla|.*Cache|.*Temp).*',
                'EventType': 'FileCreate|ProcessCreate|FileRename'
            }
            print("Searching for unexpected staging folders in AppData\\Local\\Temp...")
            results = parse_logs(log_file_path_input, staging_folder_filter)
            if results is not None and not results.empty:
                print(results.rename(columns={'Image': 'Prozessname (Image)'}))
        elif choice == '9':
            # Filter by time range
            results = filter_by_time_range(log_file_path_input)
            if results is not None and not results.empty:
                pass  # Already printed, no further action needed here
            else:
                continue
        elif choice == '10':
            # Shifted from 8
            new_file_path = input("Please enter the new file path: ")
            if new_file_path:
                log_file_path_input = new_file_path
                print(f"File has been changed to: {log_file_path_input}")
            else:
                print("No new file path entered. Continuing with the current file.")
            continue  # Skip the export prompt and go back to the menu loop.
        elif choice == '11':  # This is now EXIT again
            # Shifted from 9
            print("Exiting the Log Analyzer. Goodbye!")
            break  # This breaks out of the `while True` loop and ends the script.
        else:
            print("Invalid choice. Please enter a number from 1 to 11.")
            continue  # Go back to the menu loop.

        # --- Ask to export results after a query is run successfully (except for time filter and file change) ---
        # Only ask for export if a DataFrame 'results' was populated by the query
        if results is not None and not results.empty:
            # Check if this choice was an option that implicitly prints results or doesn't produce results for export.
            # Options 9 (time filter), 10 (change file) are handled separately.
            if choice not in ['9', '10']:
                export_choice = input("\nDo you want to export these results to a JSON file? (y/n): ")
                if export_choice.lower() == 'y':
                    query_name = "query_" + choice
                    output_file_name = f"{query_name}_report.json"
                    export_to_json(results, output_file_name)

        # Add a separator for better readability.
        print("\n" + "=" * 60 + "\n")