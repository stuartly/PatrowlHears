from datetime import timedelta
from celery.schedules import crontab
import os

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get('SECRET_KEY', '&-e9z@w=gerd+_k1)rj2#ri2_cswyp_cg5zj-g!-fo(3vx9l33x')
CSRF_COOKIE_SECURE = True
CSRF_USE_SESSIONS = True
#SESSION_COOKIE_SECURE = True # Only if HTTPS is enabled
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_NAME = 'patrowl-hears'
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_HSTS_PRELOAD = True
SECURE_HSTS_SECONDS = 3600  # 1 hour (for testing only, otherwise, set 31536000)
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_SSL_REDIRECT = False  # Dev/test environment
# SECURE_SSL_REDIRECT = True # Production environment, if HTTPS is enabled
SECURE_SSL_REDIRECT = os.environ.get('SECURE_SSL_REDIRECT', '').lower() in ['true', '1', 'yes', 'y', 'on']  # Production environment, if HTTPS is enabled
# X_FRAME_OPTIONS = 'DENY'
USE_X_FORWARDED_HOST = os.environ.get('USE_X_FORWARDED_HOST', 'true').lower() in ['true', '1', 'yes', 'y', 'on']
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get('APP_DEBUG', 'false').lower() in ['true', '1', 'yes', 'on', 'y']
# DEBUG = os.environ.get('DEBUG', True)

ALLOWED_HOSTS = ['*']

PROXIES = {
    "http": os.environ.get('PATROWLHEARS_PROXY_HTTP', None),
    "https": os.environ.get('PATROWLHEARS_PROXY_HTTPS', None)
}

BASE_URL = os.environ.get('BASE_URL', "http://localhost:8080")

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    # 'rest_framework_filters',
    'rest_framework.authtoken',
    'drf_yasg',
    'corsheaders',
    'django_filters',
    'simple_history',
    'django_celery_beat',
    'django_celery_results',
    'organizations',
    'annoying',

    'users',
    'custusers',
    'cves',
    'monitored_assets',
    'vulns',
    'vpratings',
    'alerts',
    'search',
    'data',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'simple_history.middleware.HistoryRequestMiddleware',
]

SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'
SESSION_COOKIE_HTTPONLY = True

if DEBUG is True:
    INSTALLED_APPS += ['debug_toolbar']
    MIDDLEWARE += ['debug_toolbar.middleware.DebugToolbarMiddleware']
    DEBUG_TOOLBAR_CONFIG = {
        "SHOW_TOOLBAR_CALLBACK": lambda request: True,
    }


LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'console': {
            'format': '%(name)-12s %(levelname)-8s %(message)s'
        },
        'file': {
            'format': '%(asctime)s %(name)-12s %(levelname)-8s %(message)s'
        }
    },
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': 'var/log/django-debug.log',
            'formatter': 'file'
        },
        'console': {
            # 'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'console'
        }
    },
    'loggers': {
        'django': {
            'handlers': ['file', 'console'],
            'level': os.getenv('DJANGO_LOG_LEVEL', 'INFO'),
            'propagate': True,
        },
    },
}

DEFAULT_AUTO_FIELD='django.db.models.AutoField' 

# APPEND_SLASH = False

AUTH_USER_MODEL = 'custusers.User'
INVITATION_BACKEND = 'users.backends.CustomInvitations'
REGISTRATION_BACKEND = 'users.backends.CustomRegistrations'

AUTHENTICATION_BACKENDS = [
    'users.backends.EmailOrUsernameModelBackend',
    'django.contrib.auth.backends.ModelBackend',
]

LOGIN_URL = '/admin/login/'

ROOT_URLCONF = 'backend_app.urls'

FRONTEND_DIR = os.path.join(BASE_DIR, '../frontend')
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, "static"),
    os.path.join(FRONTEND_DIR, 'dist/static'),
]

MEDIA_ROOT = 'media'
MEDIA_URL = '/media/'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            os.path.join(FRONTEND_DIR, 'dist'),
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
            'libraries': {
                'patrowl_tags': 'templatetags.common_tags',
            }
        },
    },
]

TEMPLATE_CONTEXT_PROCESSORS = (
    "common.context_processors.site",
 )

WSGI_APPLICATION = 'backend_app.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('POSTGRES_DBNAME', 'patrowlhears_db'),
        'USER': os.environ.get('POSTGRES_USER', 'patrowlhears'),
        'PASSWORD': os.environ.get('POSTGRES_PASSWORD', 'patrowlhears_pw'),
        'HOST': os.environ.get('POSTGRES_HOST', 'localhost'),
        'PORT': os.environ.get('POSTGRES_PORT', ''),
    },
    'mongodb': {
        'HOST': os.environ.get('CVESEARCH_MONGODB_HOST', 'localhost'),
        'PORT': os.environ.get('CVESEARCH_MONGODB_PORT', 27017),
    }
}

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

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Europe/Paris'
USE_I18N = True
USE_L10N = True
USE_TZ = False


REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.BasicAuthentication',
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.TokenAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_FILTER_BACKENDS': (
        # 'rest_framework_filters.backends.RestFrameworkFilterBackend',
        'django_filters.rest_framework.DjangoFilterBackend',
      ),
    'DEFAULT_SCHEMA_CLASS': 'rest_framework.schemas.coreapi.AutoSchema',
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.LimitOffsetPagination',
    'PAGE_SIZE': 20,
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.UserRateThrottle',
        'users.throttling.CustomUserRateThrottle'
    ],
    'DEFAULT_THROTTLE_RATES': {
        'user': '5/second',
        'custom': '200/day'
    }
}

SWAGGER_SETTINGS = {
    'SECURITY_DEFINITIONS': {
        'api_key': {
            'type': 'apiKey',
            'in': 'header',
            'name': 'Authorization'
        }
    },
    'USE_SESSION_AUTH': True,
    'JSON_EDITOR': True,
}

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
    }
}

CORS_ORIGIN_ALLOW_ALL = True
# CORS_ORIGIN_WHITELIST = (
#     'http://localhost:8080',
# )
# CORS_ALLOW_HEADERS = [
#     'accept',
#     'accept-encoding',
#     'authorization',
#     'content-type',
#     'dnt',
#     'origin',
#     'user-agent',
#     'x-csrftoken',
#     'x-requested-with',
# ]
CORS_ALLOW_CREDENTIALS = True

SIMPLE_JWT = {
    # 'ACCESS_TOKEN_LIFETIME': timedelta(minutes=5),
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=80000),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'ROTATE_REFRESH_TOKENS': False,
    'BLACKLIST_AFTER_ROTATION': True,

    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'VERIFYING_KEY': None,
    'AUDIENCE': None,
    'ISSUER': None,

    'AUTH_HEADER_TYPES': ('Bearer', 'JWT',),
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',

    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',

    'JTI_CLAIM': 'jti',

    'SLIDING_TOKEN_REFRESH_EXP_CLAIM': 'refresh_exp',
    'SLIDING_TOKEN_LIFETIME': timedelta(minutes=5),
    'SLIDING_TOKEN_REFRESH_LIFETIME': timedelta(days=1),
}

LOGIN_REQUIRED_URLS = (
    r'/(.*)$',
)
LOGIN_REQUIRED_URLS_EXCEPTIONS = (
    r'/auth-jwt/(.*)$',
    r'/login(.*)$',
    r'/logout(.*)$',
    r'/static/(.*)$',
    # r'/(.*)/api/v1/(.*)$',
    r'/(.*)/api/(.*)$',
    r'/users/activate(.*)$',
)


RABBIT_HOSTNAME = os.environ.get('RABBITMQ_HOSTNAME', 'localhost:5672')

if RABBIT_HOSTNAME.startswith('tcp://'):
    RABBIT_HOSTNAME = RABBIT_HOSTNAME.split('//')[1]

BROKER_URL = os.environ.get('BROKER_URL', '')
if BROKER_URL == "":
    BROKER_URL = 'amqp://{user}:{password}@{hostname}/{vhost}/'.format(
        user=os.environ.get('RABBIT_ENV_USER', 'guest'),
        password=os.environ.get('RABBIT_ENV_RABBITMQ_PASS', 'guest'),
        hostname=RABBIT_HOSTNAME,
        vhost=os.environ.get('RABBIT_ENV_VHOST', ''))

# BROKER_HEARTBEAT = '?heartbeat=30'
# if not BROKER_URL.endswith(BROKER_HEARTBEAT):
#     BROKER_URL += BROKER_HEARTBEAT

# BROKER_POOL_LIMIT = None
BROKER_HEARTBEAT = None
BROKER_POOL_LIMIT = 1
BROKER_CONNECTION_TIMEOUT = 30

# CELERY
# CELERY_RESULT_BACKEND = 'rpc://'
CELERY_RESULT_BACKEND = 'django-db'
# CELERY_RESULT_PERSISTENT = True
CELERY_RESULT_PERSISTENT = False
CELERY_ACCEPT_CONTENT = ['application/json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = os.environ.get('PATROWL_TZ', 'Europe/Paris')
CELERY_IGNORE_RESULT = True
CELERY_TASK_IGNORE_RESULT = True
# CELERY_TASK_RESULT_EXPIRES = 300
CELERY_ACKS_LATE = True

# Hears data sync modes:
#   - 'master': sync data from CVE-SEARCH and VIA4CVE
#   - 'slave': sync data from another Hears instance using APIs
HEARS_DATASYNC_MODE =  os.environ.get('HEARS_DATASYNC_MODE', 'master')
# Force mode status 'master' by default
if HEARS_DATASYNC_MODE not in ['master', 'slave']:
    HEARS_DATASYNC_MODE = 'master'

if HEARS_DATASYNC_MODE == 'master':
    CELERY_BEAT_SCHEDULE = {
        # 'refresh_vulns_scores': {
        #     'task': 'vulns.tasks.refresh_vulns_score_task',
        #     'schedule': timedelta(days=1)
        # },
        # Alerting by mail
        'alert_monitored_products_daily': {
            'task': 'vulns.tasks.email_daily_report_task',
            'schedule': crontab(minute=0, hour=0)
        },
        'alert_monitored_products_weekly': {
            'task': 'vulns.tasks.email_weekly_report_task',
            'schedule': crontab(day_of_week='monday')
        },
        'alert_monitored_products_monthly': {
            'task': 'vulns.tasks.email_monthly_report_task',
            'schedule': crontab(0, 0, day_of_month='1')
        },
    }
else:
    CELERY_BEAT_SCHEDULE = {
        # 'datasync_models': {
        #     'task': 'data.tasks.run_datasync_models_task',
        #     'schedule': crontab(hour="*/4")
        # },
    }

LIMIT_MAX_USERS = 0
LIMIT_MAX_MONITORED = 0
LIMIT_MAX_ORG_CONTACTS = 0
RESTRICTED_MODE = os.environ.get('RESTRICTED_MODE', '').lower() in ['true', '1', 'yes', 'on', 'y']

# Email settings
EMAIL_USE_TLS = os.environ.get('EMAIL_USE_TLS', 'true').lower() in ['true', '1', 'yes', 'on', 'y']
EMAIL_HOST = os.environ.get('EMAIL_HOST', 'xxxxx')
EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER', 'alerts@xxxx.fr')
EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD', 'xxxxxx')
EMAIL_PORT = os.environ.get('EMAIL_PORT', 587)
EMAIL_RCPT_USER = os.environ.get('EMAIL_RCPT_USER', 'xxxxxx')
DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', 'xxxx@xxx.io')

# Others
CVESEARCH_URL = os.environ.get('CVESEARCH_URL', 'http://localhost:5000')

# Slack
ALERTING_SLACK_APITOKEN = os.environ.get('ALERTING_SLACK_APITOKEN', '')

# Twitter
TWITTER_ENABLED = os.environ.get('TWITTER_ENABLED', False)
TWITTER_CONSUMER_KEY = os.environ.get('TWITTER_CONSUMER_KEY', '')
TWITTER_CONSUMER_SECRET = os.environ.get('TWITTER_CONSUMER_SECRET', '')
TWITTER_ACCESS_TOKEN_KEY = os.environ.get('TWITTER_ACCESS_TOKEN_KEY', '')
TWITTER_ACCESS_TOKEN_SECRET = os.environ.get('TWITTER_ACCESS_TOKEN_SECRET', '')

# Data Sync options
HEARS_DATASYNC_URL = os.environ.get('HEARS_DATASYNC_URL', "http://localhost:3333")
HEARS_DATASYNC_AUTHTOKEN = os.environ.get('HEARS_DATASYNC_AUTHTOKEN', "774c5c9d7908a6d970be392cf54b20ddca1d0319")
HEARS_DATASYNC_FREQUENCY = os.environ.get('HEARS_DATASYNC_FREQUENCY', "hourly")     # 'weekly', 'daily', 'hourly', 'minutely'
HEARS_DATASYNC_ENABLED = os.environ.get('HEARS_DATASYNC_ENABLED', 'true').lower() in ['true', '1', 'yes', 'on', 'y']
HEARS_DATASYNC_BASEDATE = os.environ.get('HEARS_DATASYNC_BASEDATE', '2020-01-01')
HEARS_DATASYNC_SSLVERIFY = os.environ.get('HEARS_DATASYNC_SSLVERIFY', 'false').lower() in ['true', '1', 'yes', 'on', 'y']
HEARS_DATASYNC_TIMEOUT = os.environ.get('HEARS_DATASYNC_TIMEOUT', None)
HEARS_DATASYNC_CHUNKSIZE = int(os.environ.get('HEARS_DATASYNC_CHUNKSIZE', 100))

## Pro edition - Load extra settings
PRO_EDITION = os.environ.get('PRO_EDITION', '').lower() in ['true', '1', 'yes', 'y', 'on']
if PRO_EDITION is True and os.path.isdir('pro'):
    try:
        from pro.settings import *
        INSTALLED_APPS += PRO_INSTALLED_APPS
        MIDDLEWARE += PRO_MIDDLEWARE
        AUTHENTICATION_BACKENDS += PRO_AUTHENTICATION_BACKENDS
        L_LRUE = list(LOGIN_REQUIRED_URLS_EXCEPTIONS)
        L_LRUE.append(PRO_LOGIN_REQUIRED_URLS_EXCEPTIONS)
        LOGIN_REQUIRED_URLS_EXCEPTIONS = tuple(L_LRUE)

    except ImportError:
        print("ERROR: Unable to load PRO modules")
