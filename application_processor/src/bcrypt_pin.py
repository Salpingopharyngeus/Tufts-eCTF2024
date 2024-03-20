import re
import os
from bcrypt import hashpw, gensalt

def hash_pin_in_file(file_path):

    
    # Expand the '~' to the user's home directory
    expanded_file_path = os.path.expanduser(file_path)
    with open(expanded_file_path, 'r+') as file:
        print(f'Hashing pin and token in {file_path}')
        content = file.read()
        # Regex to find the pin in the file
        pin_pattern = re.compile(r'#define AP_PIN "(\w+)"')
        match = pin_pattern.search(content)
        if match:
            pin = match.group(1).encode('utf-8')
            hashed_pin = hashpw(pin, gensalt(6)).decode('utf-8')
            # Replace the pin with its bcrypt hash
            content = pin_pattern.sub(f'#define AP_PIN "{hashed_pin}"', content)

        # Regex to find the token in the file
        token_pattern = re.compile(r'#define AP_TOKEN "(\w+)"')
        match = token_pattern.search(content)
        if match:
            token = match.group(1).encode('utf-8')
            hashed_token = hashpw(token, gensalt(6)).decode('utf-8')
            # Replace the token with its bcrypt hash
            content = token_pattern.sub(f'#define AP_TOKEN "{hashed_token}"', content)

        file.seek(0)
        file.write(content)
        file.truncate()
        print('Done')

if __name__ == '__main__':
    import sys
    hash_pin_in_file(sys.argv[1])
