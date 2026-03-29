# NetGuard Quick Reference

## 🚀 How to Run the Project

### Method 1: Quick Start Script (Easiest)
```batch
# Double-click this file:
START.bat

OR in PowerShell:
.\START.ps1
```

### Method 2: Manual Command Line
```bash
# Navigate to project
cd c:\Users\ktkrr\Music\NetGuard

# Activate environment
.\netguard_env\Scripts\Activate.ps1

# Start server
python manage.py runserver 8000
```

### Method 3: From VS Code
- Terminal → New Terminal
- Run: `.\START.ps1`

---

## 🌐 Access the Application

**Local Development:**
- Login Page: `http://localhost:8000/login/`
- Dashboard: `http://localhost:8000/` (after login)

---

## 👥 User Flow

```
Start
  ↓
Visit http://localhost:8000/login/
  ↓
┌─────────────────────────────┐
│  1. First Time?             │
│     Click "Create Account"  │
│     → Register Page         │
│     → Enter Username/Pw     │
│     → Auto-login            │
└─────────────────────────────┘
  ↓
┌─────────────────────────────┐
│  2. Returning User?         │
│     Enter Username/Pw       │
│     → Dashboard             │
└─────────────────────────────┘
  ↓
Dashboard
  • See "User Pill" (top-right)
  • Click "Logout" to exit
  • Back to Login Page
```

---

## 🎨 Design Features

### Login/Register Pages
- ✅ Light, modern color palette (white/blue/green)
- ✅ Smooth animations on floating logo
- ✅ Gradient blue buttons with hover effects
- ✅ Clean, spacious layout
- ✅ Responsive on mobile

### Dashboard
- ✅ Light background with card-based layout
- ✅ User profile pill in header
- ✅ Network scan panels (2x2 grid)
- ✅ Device discovery cards
- ✅ Threat analysis with color-coded badges
- ✅ AI chat integration

---

## 🔐 Security & Authentication

### Password Storage
- ✅ Django hashes all passwords automatically
- ✅ PBKDF2 algorithm (industry standard)
- ✅ Stored in SQLite database
- ✅ Never stored in plaintext

### Login Protection
- ✅ @login_required decorator on dashboard
- ✅ Session management
- ✅ CSRF token on all forms
- ✅ Secure logout clears sessions

---

## 📊 Database

### Current: SQLite (Development)
- File: `db.sqlite3`
- User table: Stores username + hashed password
- Migrations: `scanner/migrations/`

### For Production: PostgreSQL
```python
# Update settings.py
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'netguard',
        'USER': 'postgres',
        'PASSWORD': 'your-password',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}
```

---

## 🚢 Deployment (Get a Live URL)

### Simplest (Heroku):
```bash
heroku create myapp
git push heroku main
# URL: https://myapp.herokuapp.com/login/
```

### Recommended (Railway.app):
1. Go to https://railway.app
2. Sign up with GitHub
3. Deploy repo
4. Add PostgreSQL
5. Get live URL instantly

### Full Guide:
See `SETUP_AND_DEPLOYMENT.md` for all options:
- Heroku
- PythonAnywhere
- DigitalOcean
- Railway
- AWS
- Google Cloud

---

## ⚡ Useful Commands

```bash
# Start development server
python manage.py runserver 8000

# Create new superuser (admin)
python manage.py createsuperuser

# Reset database
rm db.sqlite3
python manage.py migrate

# View Django admin
http://localhost:8000/admin/

# Check for errors
python manage.py check

# Create migrations
python manage.py makemigrations

# Apply migrations
python manage.py migrate

# Clear cache
python manage.py clearmaigrationtable
```

---

## 🎯 Project Structure

```
NetGuard/
├── scanner/                          # Main app
│   ├── templates/scanner/
│   │   ├── login.html               # ✅ NEW: Light UI login
│   │   ├── register.html            # ✅ NEW: Light UI register
│   │   └── index.html               # Dashboard
│   ├── static/scanner/
│   │   ├── style.css                # ✅ NEW: Light theme CSS
│   │   └── main.js
│   ├── views.py                     # ✅ Auth views included
│   ├── urls.py                      # ✅ Auth routes included
│   └── models.py
├── netguard_core/
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── db.sqlite3                       # Database with users
├── START.bat                        # ✅ NEW: Quick start
├── START.ps1                        # ✅ NEW: PowerShell start
├── SETUP_AND_DEPLOYMENT.md          # ✅ NEW: Full guide
└── requirements.txt                 # Dependencies
```

---

## ✅ Verification Checklist

- [x] Login page displays (light theme)
- [x] Register page displays (light theme)
- [x] Can create new user account
- [x] Can login with credentials
- [x] Password is hashed in database
- [x] Dashboard shows after login
- [x] User pill shows username
- [x] Logout button works
- [x] Redirects to login when not authenticated
- [x] Colors are light, not dark
- [x] Mobile responsive

---

## 🐛 If Something Breaks

1. **"Login page blank?"**
   - Stop server: Ctrl+C
   - Run: `python manage.py check`
   - Restart: `python manage.py runserver`

2. **"Database errors?"**
   - Delete `db.sqlite3`
   - Run: `python manage.py migrate`

3. **"Static files not loading?"**
   - Run: `python manage.py collectstatic --noinput`

4. **"CSRF token invalid?"**
   - Clear browser cache
   - Restart server

5. **"500 error on login?"**
   - Check `settings.py` ALLOWED_HOSTS
   - Check form field names match views.py

---

## 📞 Support Files

- **Setup Guide**: `SETUP_AND_DEPLOYMENT.md`
- **Deployment Help**: See "Deployment Options" section
- **Django Docs**: https://docs.djangoproject.com
- **Common Issues**: See troubleshooting section in guide

---

## 🎉 You're Ready!

1. Run: `.\START.ps1`
2. Open: `http://localhost:8000/login/`
3. Create account
4. Explore dashboard
5. Deploy to production with one click!

Questions? Check SETUP_AND_DEPLOYMENT.md for detailed instructions.
