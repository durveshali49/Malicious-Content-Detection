import re
import sys
from typing import List, Dict

class MaliciousContentDetector:
    def __init__(self, patterns_file: str = "malicious_patterns.txt"):
        """
        Initialize the detector with malicious patterns.
        
        Args:
            patterns_file: Path to file containing malicious patterns (one per line)
        """
        self.patterns = self._load_patterns(patterns_file)
    
    def _load_patterns(self, patterns_file: str) -> List[re.Pattern]:
        """
        Load malicious patterns from file.
        
        Args:
            patterns_file: Path to patterns file
            
        Returns:
            List of compiled regex patterns
        """
        patterns = []
        try:
            with open(patterns_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):  # Skip empty lines and comments
                        # Compile as regex pattern
                        patterns.append(re.compile(line, re.IGNORECASE))
        except FileNotFoundError:
            print(f"Warning: Patterns file '{patterns_file}' not found. Using default patterns.")
            # Default patterns if file not found
            default_patterns = [
                r"SELECT\s+\*\s+FROM",  # SQL injection
                r"UNION\s+SELECT",      # SQL injection
                r"DROP\s+TABLE",        # SQL injection
                r"<script>",            # XSS
                r"javascript:",         # XSS
                r"eval\s*\(",           # Malicious JavaScript
                r"base64_decode",       # PHP encoded payloads
                r"cmd\.exe",            # Windows command injection
                r"system\s*\(",         # Command injection
                r"exec\s*\(",           # Command execution
                r"passwd",              # Sensitive file access
                r"shadow",              # Sensitive file access
                r"\.exe",               # Executable files
                r"\.bat",               # Batch files
                r"\.scr",               # Screen saver files (often malicious)
                r"wget\s+",             # File download attempts
                r"curl\s+",             # File download attempts
            ]
            patterns = [re.compile(pattern, re.IGNORECASE) for pattern in default_patterns]
        
        return patterns
    
    def scan_file(self, log_file: str) -> List[Dict]:
        """
        Scan a log file for malicious content.
        
        Args:
            log_file: Path to log file to scan
            
        Returns:
            List of detected threats with details
        """
        threats = []
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    for pattern in self.patterns:
                        if pattern.search(line):
                            threats.append({
                                'line_number': line_num,
                                'content': line,
                                'pattern': pattern.pattern
                            })
        except FileNotFoundError:
            print(f"Error: File '{log_file}' not found.")
            sys.exit(1)
        except Exception as e:
            print(f"Error reading file: {e}")
            sys.exit(1)
        
        return threats
    
    def scan_content(self, content: str) -> List[Dict]:
        """
        Scan content directly for malicious patterns.
        
        Args:
            content: Text content to scan
            
        Returns:
            List of detected threats with details
        """
        threats = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            for pattern in self.patterns:
                if pattern.search(line):
                    threats.append({
                        'line_number': line_num,
                        'content': line,
                        'pattern': pattern.pattern
                    })
        
        return threats

def main():
    """
    Main function to run the malicious content detector.
    """
    if len(sys.argv) < 2:
        print("Usage: python detector.py <log_file>")
        print("   or: python detector.py <log_file> <patterns_file>")
        sys.exit(1)
    
    log_file = sys.argv[1]
    patterns_file = sys.argv[2] if len(sys.argv) > 2 else "malicious_patterns.txt"
    
    # Initialize detector
    detector = MaliciousContentDetector(patterns_file)
    
    # Scan file
    threats = detector.scan_file(log_file)
    
    # Display results
    if threats:
        print(f"Found {len(threats)} potential threats:")
        for threat in threats:
            print(f"  Line {threat['line_number']}: {threat['content']}")
            print(f"    Matched pattern: {threat['pattern']}")
            print()
    else:
        print("No threats detected.")

if __name__ == "__main__":
    main()
