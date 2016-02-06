from os import environ, path
from dotenv import load_dotenv

class ConfigError(Exception):
    pass

def require(key):
    if key not in environ:
        raise ConfigError('Required config missing: {}'.format(key))
    return environ.get(key)

dotenv_path = path.join(path.dirname(__file__), '.env')
load_dotenv(dotenv_path)

STOMP_BROKER_URI = require('STOMP_BROKER_URI')
STOMP_QUEUE = require('STOMP_QUEUE')
STOMP_USERNAME = require('STOMP_USERNAME')
STOMP_PASSWORD = require('STOMP_PASSWORD')
