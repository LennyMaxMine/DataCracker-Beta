import subprocess

print("Started")
failed = 0

profiles = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', 'key=clear']).decode(
    'cp850', errors='backslashreplace').split('\n')

for profile in profiles:
    profile_parts = profile.split(':')

    if len(profile_parts) > 1:
        profile_name = profile_parts[1].strip()
    else:
        profile_name = None
    # print(f"Profile Name: {profile_name}")

    if profile_name is not None and profile_name != "":
        password_info = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', f'name={profile_name}', 'key=clear']).decode(
            'cp850', errors='backslashreplace').split('\n')

        password = ''
        for line in password_info:
            # print(line)
            if "Schlüsselinhalt" in line:
                # print(line)
                line_parts = line.split(':')
                if len(line_parts) > 1:
                    password = line_parts[1].strip()
                else:
                    password = "Password not found."
            else:
                failed += 1
                None

        if password:
            print("{:<30}|  {:<}".format(profile_name, password))
        else:
            print("{:<30}|  {:<}".format(profile_name, "Password not found."))

print("Failed times", int(failed))


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
