# Malicious Content Detector

A Python application to scan static log or packet data files for malicious words or patterns. Supports initial threat detection use cases in cybersecurity, with potential for real-time network monitoring integration.

## Features

- Scan log files for malicious content patterns.
- Customizable pattern definitions.
- Detailed threat reporting with line numbers.
- Support for regex patterns.
- Case-insensitive matching.
- Command-line interface.

## Installation

1. Clone or download this repository
2. Ensure you have Python 3.6+ installed
3. No additional dependencies required

## Usage

### Basic Usage

```bash
python detector.py <log_file>
```

Example:
```bash
python detector.py sample_logs.txt
```

### Custom Patterns File

```bash
python detector.py <log_file> <patterns_file>
```

Example:
```bash
python detector.py sample_logs.txt custom_patterns.txt
```

### Pattern File Format

The patterns file should contain one regex pattern per line. Lines starting with `#` are treated as comments and ignored.

Example patterns.txt:
```
# SQL Injection patterns
SELECT\s+\*\s+FROM
UNION\s+SELECT
DROP\s+TABLE

# XSS patterns
<script
javascript:
eval\s*$$
```

## How It Works

The detector scans through the provided log file line by line, checking each line against a set of predefined malicious patterns. When a match is found, it reports:

- Line number where threat was found
- The content of the line
- The pattern that matched

## Extending Patterns

To add new malicious patterns:

1. Edit the `malicious_patterns.txt` file
2. Add one regex pattern per line
3. Use Python regex syntax
4. Comments start with `#`

## Example Output

```
Found 2 potential threats:
  Line 15: 192.168.1.100 - - [20/May/2023:10:05:23 +0000] "GET /login.php?user=admin&pass=<script>alert('xss')</script> HTTP/1.1" 200 1234
    Matched pattern: <script

  Line 23: 192.168.1.105 - - [20/May/2023:10:12:45 +0000] "POST /admin.php HTTP/1.1" "uname -a; cat /etc/passwd"
    Matched pattern: cat\s+/etc/passwd
```

## Integration

This tool can be integrated into:

- SIEM systems for log analysis
- Network monitoring solutions
- Automated threat detection pipelines
- Real-time network traffic analysis (with modifications)

## Future Enhancements

- Real-time network packet monitoring
- Machine learning-based anomaly detection
- Integration with threat intelligence feeds
- JSON output format for easier integration
- Multi-threaded scanning for large files
- Web interface for easier management

## Contributing

Feel free to fork this project and submit pull requests with improvements or additional features.

## License

This project is open-source and available under the MIT License.

