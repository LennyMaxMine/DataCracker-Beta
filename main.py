import subprocess

data = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles']).decode(
    'utf-8', errors='backslashreplace').split('\n')
profiles = [i.split(':')[1][1:-1] for i in data if 'All User Profile' in i]

for profile in profiles:
    try:
        results = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', profile, 'key=clear']).decode(
            'utf-8', errors='backslashreplace').split('\n')
        passwords = [b.split(':')[1][1:-1]
                     for b in results if 'Key Content' in b]
        password = passwords[0] if passwords else ''
        print("{:<30}|  {:<}".format(profile, password))
    except subprocess.CalledProcessError:
        print("{:<30}|  {:<}".format(profile, 'ENCODING ERROR'))

input('')
