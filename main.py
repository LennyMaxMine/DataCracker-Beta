import subprocess
from datetime import datetime
print("Started")

current_time = datetime.now()
formatted_time = current_time.strftime("%d-%m-%Y--%H;%M;%S")  # 24-hour format
# print(formatted_time)

failed = 0

profiles = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', 'key=clear']).decode(
    'cp850', errors='backslashreplace').split('\n')

output_data = []
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
                    output_data.append((profile_name, password, failed))
                else:
                    password = "Password not found."
            else:
                failed += 1
                None

    with open(f'{formatted_time}.txt', 'w') as f:
        f.write("Time on Input: " + formatted_time + "\n")

        for data in output_data:
            profile_name, password, failed = data
            f.write("SSID: {:<30} | Password: {:<50} | Failed Times: {:<}\n".format(
                profile_name, password, failed))

        f.write("\nFailed times in total: {}\n".format(failed))
        f.close()

print("Failed times in total: ", failed)
