# Aircraft Maintenance Work Sheet System

Sistem manajemen maintenance work sheet untuk aircraft dengan tracking real-time dan role-based access control.

## 🚀 Fitur Utama

- **Role-Based Access Control**: 5 role berbeda dengan permission yang spesifik
- **Real-time Tracking**: Monitor progress maintenance secara real-time
- **Responsive Design**: Optimized untuk semua device (mobile, tablet, desktop)
- **Digital Signatures**: Sistem tanda tangan digital untuk approval
- **Audit Trail**: Tracking semua aktivitas user

## 👥 User Roles

| Role | NIK | Password | Deskripsi |
|------|-----|----------|-----------|
| **Admin (A)** | 001 | 123 | Membuat MWS dan Prepared By |
| **Mechanic (U1)** | 002 | 123 | Mengisi MAN, Hours, TECH dan tanggal |
| **Quality Inspector (U2)** | 003 | 123 | Inspeksi setiap langkah kerja |
| **Quality CUDR (U3)** | 004 | 123 | Verified By |
| **Super Admin (S.A)** | 005 | 123 | Approved By dan kontrol penuh |

## 🛠️ Instalasi & Menjalankan

### Windows
```bash
# Install dependencies
pip install -r requirements.txt

# Jalankan aplikasi
start.bat
```

### Linux/Mac
```bash
# Install dependencies
pip3 install -r requirements.txt

# Jalankan aplikasi
./start.sh
```

### Manual
```bash
python run_app.py
```

## 🌐 Akses Aplikasi

Setelah menjalankan aplikasi, buka browser dan akses:
- **URL**: http://localhost:5000
- **Login**: Gunakan NIK dan password dari tabel di atas

## 📱 Responsive Design

Aplikasi ini fully responsive dan optimized untuk:
- 📱 **Mobile**: iPhone, Android (320px+)
- 📱 **Tablet**: iPad, Android Tablet (768px+)
- 💻 **Desktop**: Laptop, PC (1024px+)
- 🖥️ **Large Screen**: Monitor besar (1440px+)

## 🔐 Keamanan

- Session-based authentication
- Password hashing (SHA-256)
- Role-based authorization
- Input validation & sanitization
- CSRF protection ready

## 📊 Workflow

1. **Admin** membuat MWS baru
2. **Admin** assign part ke **Mechanic**
3. **Mechanic** mengerjakan steps dan update progress
4. **Quality Inspector** melakukan inspeksi
5. **Quality CUDR** melakukan verifikasi
6. **Admin** memberikan prepared by signature
7. **Super Admin** memberikan final approval

## 🗂️ Struktur File

```
project/
├── app.py                 # Main Flask application
├── run_app.py            # Application runner
├── requirements.txt      # Python dependencies
├── start.bat            # Windows startup script
├── start.sh             # Linux/Mac startup script
├── templates/           # HTML templates
│   ├── shared/         # Shared templates
│   ├── admin/          # Admin templates
│   ├── mechanic/       # Mechanic templates
│   ├── auth/           # Authentication templates
│   └── mws/            # MWS detail templates
├── worksheet_data.json  # Data storage (auto-generated)
└── users_data.json     # User data (auto-generated)
```

## 🔧 Konfigurasi

File konfigurasi akan dibuat otomatis saat pertama kali menjalankan aplikasi:
- `worksheet_data.json`: Data MWS dan parts
- `users_data.json`: Data user dan credentials

## 📝 Changelog

### v1.0.0
- ✅ Sistem role-based authentication
- ✅ Responsive design untuk semua device
- ✅ Real-time tracking progress
- ✅ Digital signature system
- ✅ Audit trail dan logging
- ✅ Mobile-first design approach

## 🆘 Troubleshooting

### Port sudah digunakan
```bash
# Ganti port di run_app.py line terakhir
app.run(debug=True, host='0.0.0.0', port=5001)  # Ganti ke port lain
```

### Permission Error (Linux/Mac)
```bash
chmod +x start.sh
```

### Python tidak ditemukan
- Windows: Install Python dari python.org
- Linux: `sudo apt install python3 python3-pip`
- Mac: `brew install python3`

## 📞 Support

Jika mengalami masalah, pastikan:
1. Python 3.7+ terinstall
2. Semua dependencies terinstall (`pip install -r requirements.txt`)
3. Port 5000 tidak digunakan aplikasi lain
4. Firewall tidak memblokir aplikasi

---

**© 2025 Aircraft Maintenance Work Sheet System**