# Make a '.env' file and set value to file:
# API_KEY=<YOUR_API_HERE>
# and .gitignore for .env file, heres example:
#
# .env
#
# and all :3

import virustotal_python
from pprint import pprint
from base64 import urlsafe_b64encode
import os
from dotenv import load_dotenv

load_dotenv()

M1 = r"""
  /$$$$$$  /$$   /$$ /$$    /$$
 /$$__  $$| $$$ | $$| $$   | $$
| $$  \ $$| $$$$| $$| $$   | $$
| $$  | $$| $$ $$ $$|  $$ / $$/
| $$  | $$| $$  $$$$ \  $$ $$/ 
| $$  | $$| $$\  $$$  \  $$$/  
|  $$$$$$/| $$ \  $$   \  $/   
 \______/ |__/  \__/    \_/                       
        File/Site Checker

    [1] Check Site
    [2] Check File
    [3] Get Info About File (SHA-256, SHA-1, MD-5)
    [4] Get Info About Domain
    
    [0] Exit
"""

def main():
    while True:
        print(M1)
        menu = input("[qemu-gadalka@gadalka ONV]$ ").strip()

        match menu:
            case "1":  # URL Check
                url = input("URL: ").strip()
                with virustotal_python.Virustotal(API_KEY) as vtotal:
                    resp = vtotal.request("urls", data={"url": url}, method="POST")
                    url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
                    report = vtotal.request(f"urls/{url_id}")
                    pprint(report.data)

            case "2":  # File Check
                FILE_PATH = input("FilePath: ").strip()
                with open(os.path.abspath(FILE_PATH), "rb") as f:
                    files = {"file": (os.path.basename(FILE_PATH), f)}
                    with virustotal_python.Virustotal(API_KEY) as vtotal:
                        resp = vtotal.request("files", files=files, method="POST")
                        pprint(resp.json())

            case "3":  # File SUM Check
                FILE_ID = input("SUM: ").strip()
                with virustotal_python.Virustotal(API_KEY) as vtotal:
                    resp = vtotal.request(f"files/{FILE_ID}")
                    pprint(resp.data)

            case "4":  # Domain Info
                domain = input("Domain: ").strip()
                with virustotal_python.Virustotal(API_KEY) as vtotal:
                    resp = vtotal.request(f"domains/{domain}")
                    pprint(resp.data)

            case "0":  # Exit
                print("Goodbye!")
                break

            case _:
                print("Invalid option, try again.")

if __name__ == "__main__":
    API_KEY = os.getenv('API_KEY')
    if not API_KEY:
        print("FATAL: API key not found in .env file")
        exit(1)

    try:
        main()
    except FileNotFoundError:
        print("File not found, Try without '~'")
    except virustotal_python.VirustotalError as e:
        print("VT Error:", e)
    except KeyboardInterrupt:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("Goodbye!")
