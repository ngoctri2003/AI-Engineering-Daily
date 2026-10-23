"""Make the AUTH_USERS and AUTH_SECRET values for the manual send page login.

    python tools/hash_password.py tri.ung@dssolution.jp quyen.hoang@dssolution.jp

Passwords are typed without echo (never put them on the command line) and only their PBKDF2 hashes are printed.
Paste the two printed lines into the Vercel project environment variables, then redeploy. Do not commit them.
"""
import getpass
import json
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import auth  # noqa: E402


def main(emails):
    if not emails:
        sys.exit(__doc__)
    users = {}
    for email in emails:
        email = email.strip().lower()
        if "@" not in email or len(email) > auth.MAX_FIELD:
            sys.exit(f"Not an email address: {email}")
        password = getpass.getpass(f"Password for {email}: ")
        if not password or len(password) > auth.MAX_FIELD:
            sys.exit(f"The password must be 1 to {auth.MAX_FIELD} characters")
        if password != getpass.getpass("Type it again: "):
            sys.exit("The two entries differ, nothing was made")
        if len(password) < 12:
            print(f"Warning: the password for {email} is short; use at least 12 characters for a shared web page.",
                  file=sys.stderr)
        users[email] = auth.hash_password(password)
    print()
    print("AUTH_USERS=" + json.dumps(users, separators=(",", ":")))
    print("AUTH_SECRET=" + secrets.token_urlsafe(48))
    print("\nA new AUTH_SECRET signs every session; changing it later signs everyone out.", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1:])
