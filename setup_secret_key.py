"""
Script to generate a secure Flask secret key
Run this script to generate a secure secret key for your Flask application
"""
import secrets

def generate_secret_key():
    """Generate a secure random secret key"""
    key = secrets.token_hex(32)
    print("=" * 60)
    print("Generated Flask Secret Key:")
    print("=" * 60)
    print(key)
    print("=" * 60)
    print("\nTo use this key:")
    print("1. Windows (PowerShell):")
    print(f'   $env:FLASK_SECRET_KEY="{key}"')
    print("\n2. Windows (Command Prompt):")
    print(f'   set FLASK_SECRET_KEY={key}')
    print("\n3. Linux/Mac:")
    print(f'   export FLASK_SECRET_KEY="{key}"')
    print("\n4. Or add to .env file:")
    print(f'   FLASK_SECRET_KEY={key}')
    print("=" * 60)
    return key

if __name__ == "__main__":
    generate_secret_key()

