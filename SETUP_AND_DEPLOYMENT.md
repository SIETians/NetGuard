# NetGuard Setup & Deployment Guide

## Project Structure & How It Works

```
Login Page (Light Modern UI) 
    ↓
    └─→ Sign Up for New Users
    └─→ Existing Users Sign In
    ↓
Django Authentication (Password Hashing + Database Storage)
    ↓
NetGuard Dashboard (Light Modern UI with Network Scanning)
    └─→ Network Discovery (ARP Scan)
    └─→ Port Scanning
    └─→ AI-Powered Threat Analysis
    └─→ User Profile & Logout
```

---

## Running The Project Locally

### Quick Start (5 Minutes)

1. **Open Terminal in Project Folder**
   ```bash
   cd c:\Users\ktkrr\Music\NetGuard
   ```

2. **Activate Virtual Environment**
   ```bash
   .\netguard_env\Scripts\Activate.ps1
   ```

3. **Run Django Development Server**
   ```bash
   python manage.py runserver 8000
   ```

4. **Open Browser**
   - Go to: `http://localhost:8000/login/`
   - Sign up for a new account OR login with existing credentials
   - Password is securely hashed in SQLite database

### User Flow

**First Time Users:**
1. Click "Create Account" on Login Page
2. Enter Username & Password (min 8 characters)
3. Password automatically hashed & stored in database
4. Redirected to Dashboard

**Returning Users:**
1. Enter Username & Password
2. Django authenticates against hashed password in database
3. Redirected to Dashboard
4. View "User Pill" in top-right (shows username + logout)

---

## Application Architecture

### Components

| Component | File Location | Purpose |
|-----------|---------------|---------|
| Login Form | `scanner/templates/scanner/login.html` | User authentication portal |
| Register Form | `scanner/templates/scanner/register.html` | New user account creation |
| Dashboard | `scanner/templates/scanner/index.html` | Main app interface |
| Backend Auth | `scanner/views.py` | Django login/register/logout handlers |
| Styling | `scanner/static/scanner/style.css` | Light modern UI theme |
| Database | `db.sqlite3` | Stores user accounts (hashed passwords) |

### Authentication Flow

1. **User Registration** (register_view)
   - Username checked for duplicates
   - Password validated (min 8 chars)
   - User.objects.create_user() - hashes password automatically
   - Redirects to Dashboard after success

2. **User Login** (login_view)
   - Django authenticate() checks hashed password
   - Session created if valid
   - Auth required for Dashboard (@login_required decorator)

3. **Logout** (logout_view)
   - Session cleared
   - Redirects to Login page

---

## Deployment Options

### Option 1: Heroku (Easiest for Beginners)

**Step 1: Install Heroku CLI**
- Download: https://devcenter.heroku.com/articles/heroku-cli
- Install and verify: `heroku --version`

**Step 2: Create Heroku Account**
- Go to: https://www.heroku.com/
- Sign up (free tier available)

**Step 3: Login to Heroku**
```bash
heroku login
```

**Step 4: Create Procfile**
Create a file named `Procfile` in project root:
```
web: python manage.py migrate && gunicorn netguard_core.wsgi
```

**Step 5: Create requirements.txt**
```bash
pip freeze > requirements.txt
```

**Step 6: Deploy**
```bash
heroku create netguard-yourname
git init
git add .
git commit -m "Initial deployment"
git push heroku main
```

**Your App URL:** `https://netguard-yourname.herokuapp.com/login/`

---

### Option 2: PythonAnywhere (Recommended for Django)

**Step 1: Create Account**
- Go to: https://www.pythonanywhere.com
- Sign up (free tier: 512MB storage)

**Step 2: Upload Code**
- Use Git to clone your repo OR upload ZIP file
- Access via web console on PythonAnywhere

**Step 3: Create Web App**
- Web tab → Add new web app
- Choose Python 3.9+
- Choose Django framework
- Set source code location

**Step 4: Configure Settings**
- ALLOWED_HOSTS in settings.py:
  ```python
  ALLOWED_HOSTS = ['yourusername.pythonanywhere.com']
  ```

**Step 5: Create Database**
```bash
python manage.py migrate
```

**Your App URL:** `https://yourusername.pythonanywhere.com/login/`

---

### Option 3: DigitalOcean (Best Performance)

**Step 1: Create Droplet**
- Go to: https://www.digitalocean.com
- Create Ubuntu 22.04 Droplet ($4-6/month)

**Step 2: SSH into Server**
```bash
ssh root@your_droplet_ip
```

**Step 3: Install Dependencies**
```bash
apt update && apt install python3-pip python3-venv nginx gunicorn
```

**Step 4: Clone Project**
```bash
git clone <your-repo-url>
cd NetGuard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
```

**Step 5: Configure Gunicorn**
Create `/etc/systemd/system/netguard.service`:
```ini
[Unit]
Description=NetGuard Django App
After=network.target

[Service]
User=root
WorkingDirectory=/root/NetGuard
ExecStart=/root/NetGuard/venv/bin/gunicorn --bind 127.0.0.1:8000 netguard_core.wsgi

[Install]
WantedBy=multi-user.target
```

**Step 6: Configure Nginx**
Create `/etc/nginx/sites-available/netguard`:
```nginx
server {
    listen 80;
    server_name your_domain_or_ip;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

**Step 7: Enable & Start**
```bash
systemctl start netguard
systemctl enable netguard
```

**Your App URL:** `http://your_droplet_ip/login/`

---

### Option 4: Railway.app (Simple & Fast)

**Step 1: Sign Up**
- Go to: https://railway.app
- Sign up with GitHub

**Step 2: Create Project**
- New Project → GitHub Repo → Authorize
- Select NetGuard repository

**Step 3: Add PostgreSQL**
- Add a new service → PostgreSQL database
- Railway auto-connects to your app

**Step 4: Set Environment Variables**
In Railway Dashboard:
```
DATABASE_URL=postgresql://...
DEBUG=False
ALLOWED_HOSTS=*.railway.app
SECRET_KEY=your-secret-key
```

**Step 5: Deploy**
- Push to main branch
- Railway auto-deploys

**Your App URL:** `https://netguard-xxx.railway.app/login/`

---

## Important Pre-Deployment Checklist

### 1. Security Settings
```python
# settings.py
DEBUG = False  # Never True in production
ALLOWED_HOSTS = ['yourdomain.com', 'www.yourdomain.com']
SECRET_KEY = 'generate-a-strong-key'  # Use environment variable
```

### 2. Database
```python
# PostgreSQL is recommended for production (not SQLite)
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

### 3. Static Files
```python
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATIC_URL = '/static/'
```

### 4. Environment Variables
Create `.env` file (never commit to Git):
```
DJANGO_SECRET_KEY=your-secret-key
DEBUG=False
ALLOWED_HOSTS=yourdomain.com
GROQ_API_KEY=your-groq-key
DATABASE_URL=postgresql://user:password@host:port/dbname
```

### 5. Requirements.txt
```bash
pip freeze > requirements.txt
```

Contents should include:
```
Django==4.2.7
gunicorn
psycopg2-binary  # For PostgreSQL
python-dotenv
groq
```

---

## Fresh Database & Testing

### Reset Database
```bash
# Delete old database
rm db.sqlite3

# Create migrations
python manage.py makemigrations

# Apply migrations
python manage.py migrate

# Create superuser (optional)
python manage.py createsuperuser
```

### Create Test User
1. Go to `/register/`
2. Username: `testuser`
3. Password: `TestPassword123`
4. Click "Create Account"

### Login & Test
1. Go to `/login/`
2. Enter credentials
3. Should be redirected to Dashboard
4. See username in top-right corner
5. Click "Logout" to test session clearing

---

## Troubleshooting

### "Login Not Working" - Common Issues

**Issue 1: CSRF Token Error**
- Solution: Make sure `{% csrf_token %}` is in form
- ✅ Already included in both login.html & register.html

**Issue 2: Password Hashing Not Working**
- Solution: Use User.objects.create_user() NOT create()
- ✅ Already implemented in views.py

**Issue 3: Redirect Loop**
- Solution: Check @login_required decorator
- ✅ Already applied to index view

**Issue 4: Database Not Found**
- Solution: Run `python manage.py migrate`
- Creates db.sqlite3 with proper tables

**Issue 5: Static Files Not Loading**
- Local: Run `python manage.py collectstatic`
- Production: Set STATIC_ROOT/STATIC_URL correctly

---

## Performance Tips

1. **Use PostgreSQL** instead of SQLite for production
2. **Enable HTTPS** on all deployments (free with Let's Encrypt)
3. **Add Caching** for network scan results
4. **Use Redis** for session management
5. **Monitor** with Sentry or New Relic

---

## Support & Next Steps

1. ✅ Login/Register working with hashed passwords
2. ✅ Dashboard accessible after authentication
3. ✅ Modern light UI design
4. 🎯 Deploy to production using one of options above
5. 🎯 Add custom domain with DNS configuration
6. 🎯 Enable HTTPS/SSL certificate

Get your site live in < 1 hour! 🚀
