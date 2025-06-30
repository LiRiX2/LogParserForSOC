Here's your updated `README.md` with the cool icons and the author field. This will definitely make your project stand out\!

-----

# LogParserForSOC

An interactive Python-based log parser designed for Security Operations Center (SOC) analysts to efficiently analyze CSV and JSON log files. This tool allows for filtering logs by specific events, performing process correlations, and exporting results for further investigation.

-----

## ✨ Features

  * **Multi-Format Log Support:** Loads and parses `.csv` and `.json` log files.
  * **Interactive Menu:** User-friendly console interface that guides you through various analysis options.
  * **Flexible Event Search:**
      * Search for events based on **Event IDs** (e.g., Windows Security Events) or **Event Types** (e.g., Sysmon Events).
      * Pre-defined queries for common forensic events (process creation, network connections, logons, registry changes, file creation) with integrated descriptions.
  * **Process Correlation:** Trace **parent-child relationships** of processes to reconstruct execution chains (e.g., identifying which process launched another).
  * **Time Range Filtering:** Narrows down analysis to a specific date and time range, with flexible input supporting both ISO standard (`YYYY-MM-DD HH:MM:SS`) and European format (`DD.MM.YYYY HH:MM:SS`).
  * **Staging Folder Detection:** A specific query to identify suspicious temporary folders often used for data exfiltration.
  * **Results Export:** Exports filtered log entries as readable JSON files for documentation or further analysis in other tools.
  * **Dynamic File Switching:** Allows changing the log file being analyzed during runtime without needing to restart the script.

-----

## Installation & Setup

1.  **Install Python:** Make sure you have [Python 3.x](https://www.python.org/downloads/) installed on your system.
2.  **Install Dependencies:** Open your terminal or command prompt and install the required Python libraries:
    ```bash
    pip install pandas
    ```

-----

## Usage

1.  **Clone or Download the Project:**
    If you've cloned or downloaded the project from GitHub, navigate to the project's root directory in your terminal.

2.  **Run the Script:**
    Execute the main script:

    ```bash
    python log_parser.py
    ```

    *(Ensure you use the actual name of your Python file if it's different, e.g., `log_analyzer.py`)*

3.  **Load Log File:**
    Upon startup, you'll be prompted to enter the **full path** to your log file (CSV or JSON).

      * For the dummy data the script generates itself:
          * `C:\Users\Analyse\PycharmProjects\Logparser\windows_security_logs_interactive.csv`
          * `C:\Users\Analyse\PycharmProjects\Logparser\sysmon_logs_interactive.csv`
          * `C:\Users\Analyse\PycharmProjects\Logparser\sample_logs.json`

4.  **Menu Interaction:**
    Select one of the displayed options to perform an analysis. The script will guide you through the necessary inputs.

5.  **Date Formats for Time Filtering:**
    When using time range filtering (Option 9), the script accepts flexible date input formats:

      * `YYYY-MM-DD HH:MM:SS` (e.g., `2025-06-30 09:00:00`)
      * `DD.MM.YYYY HH:MM:SS` (e.g., `30.06.2025 09:00:00`)
      * Dates only (`YYYY-MM-DD` or `DD.MM.YYYY`) are also recognized and default to midnight UTC.

6.  **Export Results:**
    After a successful query, you'll be asked if you want to export the results to a JSON file. This file will be saved in the script's directory.

-----

## 🧪 Testing

To test the full capabilities of the analyzer, you can create sample `.eml` files (though the current log parser doesn't directly process `.eml`, this section provides good general testing advice for related tools):

  * **Download an original email:** Most email clients allow you to "Show Original" or "Download Original" of an email, saving it as a `.eml` file.
  * **Craft a test email:**
      * **For HTML analysis:** Send yourself an email via Gmail/Outlook.com with deliberately crafted HTML links (e.g., `<a>` tags where the displayed text differs from the actual `href` URL, or `<img>` tags with suspicious `src`). Then download its original `.eml`.
      * **For attachment analysis:** Attach a dummy `test.txt`, a renamed `dummy.exe` (a text file renamed to `.exe`), and a macro-enabled Office document (`.docm` or `.xlsm`) containing a safe test macro (e.g., a simple `MsgBox` in `Sub AutoOpen()` or `Sub Workbook_Open()`). Send it to yourself and download the original `.eml`.

-----

## 💡 Future Enhancements

Here are some ideas to further enhance this log parser:

  * ### 📊 **Advanced Visualizations**

      * Integrate libraries like `matplotlib` or `seaborn` to create dynamic charts.
      * Visualize event timelines, top N IPs/processes, or connection patterns for quicker insights.

  * ### 🗺️ **GeoIP Lookups**

      * Add a feature to resolve source/destination IP addresses to country names.
      * This could use free APIs (like `ip-api.com`) or local GeoIP databases (like `MaxMind GeoLite2`).

  * ### 🔗 **Full Kill Chain Reconstruction**

      * Extend process correlation to build a complete graphical representation of an attack chain, showing all processes, network connections, and file/registry modifications linked to an initial event.

  * ### 🔔 **Rule-Based Alerting (Simple)**

      * Implement a simple rule engine where users can define patterns (e.g., "powershell.exe with base64 in command line") and the parser can highlight these automatically.

  * ### 📦 **More Log Formats (EVTX, Syslog)**

      * Expand parsing capabilities to include native Windows Event Log (`.evtx`) files using libraries like `python-evtx` or `evtx_parser`.
      * Add support for standard Syslog messages, common in network devices.

  * ### 🚀 **Performance Optimization**

      * For very large log files (multiple GBs), implement "chunking" (reading the file in smaller parts) to reduce memory consumption.

-----

### Author

Tobias Kastenhuber/LiRiX2

-----
