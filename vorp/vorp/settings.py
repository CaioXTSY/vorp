import os
from pathlib import Path
from dotenv import load_dotenv

# Define o diretório base do projeto
BASE_DIR = Path(__file__).resolve().parent.parent

# Carrega variáveis de ambiente do arquivo .env
load_dotenv(os.path.join(BASE_DIR, '.env'))

# Chave secreta e Debug
SECRET_KEY = os.getenv('SECRET_KEY', 'sua-chave-secreta')
DEBUG = True

ALLOWED_HOSTS = ['*']  # ajuste conforme necessário em produção

# Installed Apps: Django nativo, módulo de banco e apps funcionais
INSTALLED_APPS = [
    # Apps nativos do Django
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Módulo único para banco de dados (contém todos os models)
    'db',

    # Apps funcionais (sem models próprios)
    'accounts',
    'notes',
    'core',
]

# Configuração do Middleware
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# Configuração das URLs
ROOT_URLCONF = 'vorp.urls'

# Configuração dos Templates
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],  # Pasta(s) de templates globais (se necessário)
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',  # necessário para usar request nas templates
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

# Configuração do WSGI
# ATENÇÃO: Altere para 'vorp.wsgi.application'
WSGI_APPLICATION = 'vorp.wsgi.application'

# Configuração do Banco de Dados (SQLite neste exemplo)
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'vorp.db',
    }
}

# Validações de senha (pode ajustar conforme necessário)
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Usando o modelo de usuário customizado que está no app "db"
AUTH_USER_MODEL = 'db.User'

# Internacionalização
LANGUAGE_CODE = 'pt-br'
TIME_ZONE = 'America/Sao_Paulo'
USE_I18N = True
USE_L10N = True
USE_TZ = True

# Configuração de Arquivos Estáticos e Mídia
STATIC_URL = '/static/'
# STATIC_ROOT não será usado para servir arquivos estáticos em desenvolvimento
STATIC_ROOT = BASE_DIR / 'staticfiles'

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Definição do campo automático padrão para modelos
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Configuração de E-mail
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = os.getenv('MAIL_USERNAME')
EMAIL_HOST_PASSWORD = os.getenv('MAIL_PASSWORD')
DEFAULT_FROM_EMAIL = ('VORP', EMAIL_HOST_USER)

# Configurações de Login/Logout
LOGIN_URL = '/accounts/login/'
LOGIN_REDIRECT_URL = '/notes/'
LOGOUT_REDIRECT_URL = '/accounts/login/'
