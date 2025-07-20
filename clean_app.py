#!/usr/bin/env python3

# Clean null bytes from files
files_to_clean = ['app.py', 'modules1/social_media_analyzer.py']

for filename in files_to_clean:
    try:
        with open(filename, 'rb') as f:
            content = f.read()

        # Remove null bytes
        clean_content = content.replace(b'\x00', b'')

        # Write cleaned content back to file
        with open(filename, 'wb') as f:
            f.write(clean_content)

        print(f'Cleaned {filename}')
        print(f'Original size: {len(content)} bytes')
        print(f'Cleaned size: {len(clean_content)} bytes')
        print(f'Null bytes removed: {len(content) - len(clean_content)}')
        print('---')
    except Exception as e:
        print(f'Error cleaning {filename}: {e}') 