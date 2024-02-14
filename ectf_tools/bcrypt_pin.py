# hash_pin.py
import re
from bcrypt import hashpw, gensalt

def hash_pin_in_file(file_path):
    with open(file_path, 'r+') as file:
        content = file.read()
        # Regex to find the pin in the file. Adjust the pattern to match exactly how the pin is defined
        pin_pattern = re.compile(r'#define PIN "(\d{6})"')
        match = pin_pattern.search(content)
        if match:
            pin = match.group(1).encode('utf-8')
            hashed_pin = hashpw(pin, gensalt()).decode('utf-8')
            # Replace the pin with its bcrypt hash
            content = pin_pattern.sub(f'#define PIN "{hashed_pin}"', content)
            file.seek(0)
            file.write(content)
            file.truncate()

if __name__ == '__main__':
    import sys
    hash_pin_in_file(sys.argv[1])