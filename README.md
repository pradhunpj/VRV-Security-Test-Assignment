# VRV Security Test Assignment

This repository contains the solution to the **VRV Security Test Assignment**, aimed at analyzing and extracting valuable insights from log files. The project demonstrates the use of Python for log parsing, focusing on identifying requests per IP and detecting suspicious activity related to failed login attempts.

## Project Overview

The key functionality of this project includes:
1. **Log File Parsing**: The script processes log files to extract IP addresses, endpoints, and status codes.
2. **Request Count per IP**: It aggregates the total number of requests made by each IP address.
3. **Failed Login Detection**: The program identifies failed login attempts based on HTTP status codes (401) or specific error messages like "Invalid credentials."
4. **Suspicious Activity Detection**: It flags IP addresses with failed login attempts exceeding a configurable threshold (default: 10 attempts).
5. **CSV Report Generation**: The results are saved in a CSV file, which includes:
    - Requests per IP address.
    - Most accessed endpoints.
    - Failed login attempts for each IP address.
    - Suspicious activity detected for IPs exceeding the threshold.

## Technologies Used
- **Python**: The main programming language used for log parsing and analysis.
- **Regular Expressions (Regex)**: Utilized for extracting relevant data from the log lines.
- **CSV**: Used for saving and exporting the analysis results in a structured format.

## Features
- Configurable threshold for failed login attempts.
- Detailed analysis and reporting of suspicious activity.
- Clean and readable output, both in the console and in the exported CSV file.

## How to Run
1. Clone this repository to your local machine.
2. Replace `sample.log` with the actual log file you want to analyze.
3. Run the Python script to analyze the log file and generate the report.
