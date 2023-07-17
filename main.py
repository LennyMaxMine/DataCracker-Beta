import subprocess


print("Started")

profiles = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', 'key=clear']).decode(
    'utf-8', errors='backslashreplace').split('\n')

print("Check One")

for profile in profiles:
    profile_parts = profile.split(':')

    if len(profile_parts) > 1:
        profile_name = profile_parts[1].strip()
    else:
        None

password_info = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', f'name={profile_name}', 'key=clear']).decode(
    'utf-8', errors='backslashreplace').split('\n')

password = ''
for line in password_info:
    if "Key Content" in line:
        line_parts = line.split(':')
        if len(line_parts) > 1:
            password = line_parts[1].strip()
            break
        else:

print("{:<30}|  {:<}".format(profile_name, password))


print("Check Two")

# except:
#    print("Failed")

#
#    for profile in profiles:
#        try:
#            if 'Profil für alle Benutzer' in profile:
#                profile_name = profile.split(':')[1].strip()
#                print(profile_name)
#                password_info = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', f'name={profile_name}', 'key=clear']).decode(
#                    'utf-8', errors='backslashreplace').split('\n')
#                password = [line.split(':')[1].strip(
#                ) for line in password_info if "Key Content" in line][0]
#                print("{:<30}|  {:<}".format(profile_name, password))
#        except IndexError:
#            print("{:<30}|  {:<}".format(profile_name, "No Password Found"))
#        except subprocess.CalledProcessError:
#            print("{:<30}|  {:<}".format(profile_name, "Encoding Error"))
#
#    print("Check Two")
# except Exception as e:
#    print("An error occurred:", str(e))


#    print("Check Two")
# except Exception as e:
#    print("An error occurred:", str(e))


#                passwords = [b.split(':')[1][1:-1]
#                         for b in results if 'Key Content' in b]
#            password = passwords[0] if passwords else ''
#            print("{:<30}|  {:<}".format(profile, password))
#        except subprocess.CalledProcessError:
#            print("{:<30}|  {:<}".format(profile, 'ENCODING ERROR'))
#        except IndexError:
#            print("{:<30}|  {:<}".format(profile, 'No Password Found'))
