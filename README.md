# Log Analysis Script

## Overview  
This project is a Python-based log analysis tool designed to process web server logs, extract key insights, and identify potential security threats. It demonstrates skills in file handling, data analysis, and cybersecurity.

## Features  
1. **Requests Per IP Address**  
   - Counts the number of requests made by each IP address.
   - Displays results in descending order of request counts.

2. **Most Frequently Accessed Endpoint**  
   - Identifies the most accessed endpoint (URL or resource path).
   - Displays the endpoint and the total number of accesses.

3. **Suspicious Activity Detection**  
   - Detects potential brute-force login attempts by analyzing failed login attempts (HTTP 401).
   - Flags IP addresses exceeding a configurable threshold (default: 10 attempts).

4. **Output and CSV Generation**  
   - Displays results in the terminal in a clear format.
   - Saves results to a CSV file named `log_analysis_results.csv`.

## Usage  
1. Clone the repository:  
   ```bash
  [ git clone https://github.com/PAVITRA1919/Log_Analysis.git ]
