import re
from bcrypt import hashpw, gensalt

def hash_pin_in_file(file_path):
    with open(file_path, 'r+') as file:
        content = file.read()
        # Regex to find the pin in the file
        pin_pattern = re.compile(r'#define AP_PIN "(\d{6})"')
        match = pin_pattern.search(content)
        if match:
            pin = match.group(1).encode('utf-8')
            hashed_pin = hashpw(pin, gensalt()).decode('utf-8')
            # Replace the pin with its bcrypt hash
            content = pin_pattern.sub(f'#define AP_PIN "{hashed_pin}"', content)

        # Regex to find the token in the file
        token_pattern = re.compile(r'#define AP_TOKEN "(\w+)"')
        match = token_pattern.search(content)
        if match:
            token = match.group(1).encode('utf-8')
            hashed_token = hashpw(token, gensalt()).decode('utf-8')
            # Replace the token with its bcrypt hash
            content = token_pattern.sub(f'#define AP_TOKEN "{hashed_token}"', content)

        file.seek(0)
        file.write(content)
        file.truncate()

if __name__ == '__main__':
    import sys
    hash_pin_in_file(sys.argv[1])