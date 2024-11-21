from string import ascii_letters, digits

def custom_quote(string, safe='/'):
    """URL编码实现"""
    safe_chars = ascii_letters + digits + safe
    encoded = ''
    for char in string:
        if char in safe_chars:
            encoded += char
        else:
            encoded += f'%{ord(char):02X}'
    return encoded

if __name__ == '__main__':
    print(custom_quote("Hello World"))