"""
make_small.py — Extract first N passwords from rockyou.txt for testing
Usage: python make_small.py
Creates: small.txt (500 common passwords)
"""

N = 500

with open("rockyou.txt", encoding="latin-1") as f_in, \
     open("small.txt", "w") as f_out:
    for i, line in enumerate(f_in):
        if i >= N:
            break
        f_out.write(line)

print(f"Created small.txt with {N} passwords")
