"""
Django settings for netguard_core project.
"""

from pathlib import Path
import os

# ─── Optional .env loader ──────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
try:
    from dotenv import load_dotenv
    # override=True ensures .env beats any stale environment variables
    load_dotenv(BASE_DIR / '.env', override=True)
except ImportError:
    # python-dotenv not installed; environment variables should be set elsewhere
    pass


# ─── Security ─────────────────────────────────────────────────────────────────
SECRET_KEY = os.getenv('DJANGO_SECRET_KEY', 'CHANGE-ME-in-production')
DEBUG = os.getenv('DEBUG', 'False') == 'True'
ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')

CSRF_COOKIE_SECURE = False
CSRF_COOKIE_HTTPONLY = False
CSRF_TRUSTED_ORIGINS = ['http://localhost:8000', 'http://127.0.0.1:8000']


# ─── Application definition ───────────────────────────────────────────────────
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'scanner',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'netguard_core.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        # Add project-level templates dir so login.html is found
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'netguard_core.wsgi.application'


# ─── Database ─────────────────────────────────────────────────────────────────
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# ─── Password validation ──────────────────────────────────────────────────────
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]


# ─── Internationalisation ─────────────────────────────────────────────────────
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True


# ─── Static files ─────────────────────────────────────────────────────────────
STATIC_URL = 'static/'
STATICFILES_DIRS = [BASE_DIR / 'scanner' / 'static']


# ─── Auth redirects ───────────────────────────────────────────────────────────
# Where @login_required sends unauthenticated users
LOGIN_URL = '/login/'
# Where Django redirects after a successful login (your dashboard)
LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/login/'


# ─── Startup environment validator ─────────────────────────────────────────────
import sys as _sys

_REQUIRED_ENV = {
    'GROQ_API_KEY': (
        'Get a free key at https://console.groq.com/keys  '
        'then add:  GROQ_API_KEY=gsk_...  to your .env'
    ),
    'DJANGO_SECRET_KEY': (
        'Generate one with:  '
        'python -c "from django.core.management.utils import get_random_secret_key; '
        'print(get_random_secret_key())"'
    ),
    'NETGUARD_ENCRYPTION_KEY': (
        'Generate one with:  '
        'python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
    ),
}

# Skip validation during management commands that don't need the full stack
_MGMT_CMDS = {'migrate', 'makemigrations', 'collectstatic', 'createsuperuser', 'shell'}
_is_mgmt   = any(cmd in _sys.argv for cmd in _MGMT_CMDS)

_missing = [k for k in _REQUIRED_ENV if not os.getenv(k, '').strip()]
if _missing and not _is_mgmt:
    _sep = '=' * 70
    print(f'\n{_sep}', file=_sys.stderr)
    print('⛔  NetGuard — missing .env variables (server may behave incorrectly):', file=_sys.stderr)
    for _key in _missing:
        print(f'    ✗  {_key}', file=_sys.stderr)
        print(f'       {_REQUIRED_ENV[_key]}', file=_sys.stderr)
    print(_sep + '\n', file=_sys.stderr)