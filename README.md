LogParserForSOC
An interactive Python-based log parser designed for Security Operations Center (SOC) analysts to efficiently analyze CSV and JSON log files. This tool allows for filtering logs by specific events, performing process correlations, and exporting results for further investigation.

Features
Multi-Format Log Support: Loads and parses .csv and .json log files.

Interactive Menu: User-friendly console interface that guides you through various analysis options.

Flexible Event Search:

Search for events based on Event IDs (e.g., Windows Security Events) or Event Types (e.g., Sysmon Events).

Pre-defined queries for common forensic events (process creation, network connections, logons, registry changes, file creation) with integrated descriptions.

Process Correlation: Trace parent-child relationships of processes to reconstruct execution chains (e.g., identifying which process launched another).

Time Range Filtering: Narrows down analysis to a specific date and time range, with flexible input supporting both ISO standard (YYYY-MM-DD HH:MM:SS) and European format (DD.MM.YYYY HH:MM:SS).

Staging Folder Detection: A specific query to identify suspicious temporary folders often used for data exfiltration.

Results Export: Exports filtered log entries as readable JSON files for documentation or further analysis in other tools.

Dynamic File Switching: Allows changing the log file being analyzed during runtime without needing to restart the script.

Installation & Setup
Install Python: Make sure you have Python 3.x installed on your system.

Install Dependencies: Open your terminal or command prompt and install the required Python libraries:

Bash

pip install pandas
Usage
Clone or Download the Project:
If you've cloned or downloaded the project from GitHub, navigate to the project's root directory in your terminal.

Run the Script:
Execute the main script:

Bash

python log_parser.py
(Ensure you use the actual name of your Python file if it's different, e.g., log_analyzer.py)

Load Log File:
Upon startup, you'll be prompted to enter the full path to your log file (CSV or JSON).

For the dummy data the script generates itself:

C:\Users\Analyse\PycharmProjects\Logparser\windows_security_logs_interactive.csv

C:\Users\Analyse\PycharmProjects\Logparser\sysmon_logs_interactive.csv

C:\Users\Analyse\PycharmProjects\Logparser\sample_logs.json

Menu Interaction:
Select one of the displayed options to perform an analysis. The script will guide you through the necessary inputs.

Date Formats for Time Filtering:
When using time range filtering (Option 9), the script accepts flexible date input formats:

YYYY-MM-DD HH:MM:SS (e.g., 2025-06-30 09:00:00)

DD.MM.YYYY HH:MM:SS (e.g., 30.06.2025 09:00:00)

Dates only (YYYY-MM-DD or DD.MM.YYYY) are also recognized and default to midnight UTC.

Export Results:
After a successful query, you'll be asked if you want to export the results to a JSON file. This file will be saved in the script's directory.

Example Data
The script automatically generates three dummy log files in the same directory upon its first run to demonstrate its functionalities:

windows_security_logs_interactive.csv

sysmon_logs_interactive.csv

sample_logs.json

Contribution
Ideas and improvements are welcome! If you'd like to add new features or fix bugs, feel free to submit a pull request or open an issue on GitHub.

✍️ Author
Tobias Kastenhuber / LiRiX2

📄 License
This project is licensed under the MIT License - see the LICENSE file for details (you can create this file separately on GitHub or in your project root).
