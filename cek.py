import openpyxl
import requests
import time

# VirusTotal API Key
API_KEY = 'xxxxxxx'  # Ganti pake API Virustotal 

# URL Endpoint VT
VT_URL = 'https://www.virustotal.com/api/v3/ip_addresses/'

# Load Excel file
file_path = 'D:\Source IP Malicious 14 Juni 2025.xlsx'  # Pastikan file py sama excell ada di path yang sama
wb = openpyxl.load_workbook(file_path)
sheet = wb.active

# Tambahkan kolom hasil jika belum ada
if sheet['B1'].value != 'VirusTotal Status':
    sheet['B1'] = 'VirusTotal Status'

# Ini loop untuk mengecek IP satu per satu
for row in range(2, sheet.max_row + 1):
    ip = sheet[f'A{row}'].value
    if not ip:
        continue

    print(f'Checking {ip}...')
    try:
        headers = {"x-apikey": API_KEY}
        response = requests.get(VT_URL + ip, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)

            status = 'malicious' if malicious > 0 or suspicious > 0 else 'clean'
        else:
            status = f'Error {response.status_code}'

    except Exception as e:
        status = f'Error: {str(e)}'

    sheet[f'B{row}'] = status
    time.sleep(16)  # Hindari rate limit (untuk public API)

# Simpan hasil ke file baru
output_file = 'D:\Hasil 1.xlsx' # ini diatur aja buat outputnya
wb.save(output_file)
print(f'Result saved to {output_file}')
