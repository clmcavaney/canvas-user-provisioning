#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import os
import sys
import argparse
from canvas_api import Canvas
import string
import random
import secrets
import json
import logging

_version = 0.4

class usersFilter(logging.Filter):
    def filter(self, record):
        return record.getMessage().startswith('user created')


# lifted from https://gist.github.com/asfaltboy/79a02a2b9871501af5f00c95daaeb6e7
class EmailType(object):
    """
    Supports checking email agains different patterns. The current available patterns is:
    RFC5322 (http://www.ietf.org/rfc/rfc5322.txt)
    """

    # slightly modified 20221108 to include an apostrophe which is allowed according to RFC3696 (https://www.rfc-editor.org/rfc/rfc3696)
    patterns = {
        'RFC5322': re.compile(r"^[a-zA-Z0-9'_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"),
    }

    def __init__(self, pattern):
        if pattern not in self.patterns:
            raise KeyError('{} is not a supported email pattern, choose from:'
                           ' {}'.format(pattern, ','.join(self.patterns)))
        self._rules = pattern
        self._pattern = self.patterns[pattern]

    def __call__(self, value):
        if not self._pattern.match(value):
            raise argparse.ArgumentTypeError(
                "'{}' is not a valid email - does not match {} rules".format(value, self._rules))
        return value


# creates a fairly random password of 10 characters
def generate_password():
    _num_chars = 10

    alphabet = string.ascii_letters + string.digits
    while True:
        password = ''.join(secrets.SystemRandom().choice(alphabet) for c in range(_num_chars))
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and sum(c.isdigit() for c in password) >= 3):
            break

    return password


if 'CANVAS_ACCESS_TOKEN' not in os.environ:
    print('Can\'t find Canvas Access Token in your environment.  Make sure that an environment variable "CANVAS_ACCESS_TOKEN" is set.')
    sys.exit(1)

# parse arguments
parser = argparse.ArgumentParser(description='Create a user in an instance.  If the user login is using Canvas authentication then a random generated password will be created and logged.  Output of each run is stored in a "data-output" directory from where this code is run.', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('--version', action='version', version='%(prog)s {}'.format(_version))
parser.add_argument('-d', '--debug', dest='debug', action='store_true', help='Turn on debugging')
parser.add_argument('-p', '--use-prod', dest='use_prod', action='store_true', help='By default the script will run against the beta environment.  This flag changes the behaviour to the prod environment for both source and destination.')
parser.add_argument('-l', '--live', dest='live_mode', action='store_true', default=False, help='Run in live mode (default is to not make changes - aka "dry run")')
parser.add_argument('-a', '--auth', dest='auth_type', choices=['canvas','saml'], default='canvas', help='Authentication type.  For "saml" no password will be generated as it isn\'t required.')
parser.add_argument(dest='fn', type=str, help='First name')
parser.add_argument(dest='ln', type=str, help='Last name')
parser.add_argument(dest='email', type=EmailType('RFC5322'), help='email address')
parser.add_argument(dest='subdomain', type=str, help='Canvas subdomain (i.e. sandbox - "christopher", or customer - "qed", or special - "queensland.security", basically anything prior to ".instructure.com")')
parser.add_argument('--login-id', dest='login_id', type=str, help='Specify an explicit login_id for the user, otherwise the detauls is a randomly generated one')
parser.add_argument('--sis-user-id', dest='sis_user_id', type=str, help='Specify an explicit SIS user_id for the user, otherwise the detauls is a randomly generated one')
parser.add_argument('--sortable-name', dest='sortable_name', type=str, help='Specify a "sortable name" for the user.  Default "<last name>, <first name>"')

args = parser.parse_args()

debug = args.debug
environment = 'beta'
if args.use_prod is True:
    environment = ''
live_mode = args.live_mode

print('debug == {}'.format(debug))
print(args.__dict__)
for key in args.__dict__:
    print('args.{} == {}'.format(key, args.__dict__[key]))

_inst_sub_domain = ('.' + environment if environment == 'beta' else '')
print('_inst_sub_domain == "{}"'.format(_inst_sub_domain))


data_output_location = 'data-output'
_full_data_output_location = os.path.join(os.path.dirname(os.path.realpath(__file__)),data_output_location)
_subdomain_path = os.path.join(_full_data_output_location, '{}{}'.format(args.subdomain, _inst_sub_domain))
if not os.path.exists(_subdomain_path):
    os.makedirs(_subdomain_path)

logger = logging.getLogger('load-user-with-pwd')
logger.setLevel(logging.DEBUG)
logger.propagate = False

# console handler
ch = logging.StreamHandler()
ch.setFormatter(logging.Formatter('%(asctime)s: %(levelname)s: [%(name)s.%(funcName)s:%(lineno)d]: %(message)s'))
logger.addHandler(ch)

# create a file handler for the subdomain specified, that way each time the script is run details will be logged
lf = os.path.join(_subdomain_path, 'users.log')
fh = logging.FileHandler(lf)
fh.setFormatter(logging.Formatter('%(asctime)s: %(message)s'))
fh.addFilter(usersFilter())
logger.addHandler(fh)


_canvas_instance_tpl = '{}{}.instructure.com'
# substitute in the subdomain and .beta (or not)
_instance = _canvas_instance_tpl.format(args.subdomain, _inst_sub_domain)

logger.info('Connecting to {}'.format(_instance))

c = Canvas(_instance, log_level='debug', CANVAS_ACCESS_TOKEN=os.getenv('CANVAS_ACCESS_TOKEN'))

# generate a random: unique_id, sis_user_id
_code = ''.join(random.choice(string.ascii_letters) for c in range(8)) + ''.join(random.choice(string.digits) for d in range(2))

if args.login_id is None:
    _login_id = _code
else:
    _login_id = args.login_id
if args.sis_user_id is None:
    _sis_user_id = _code
else:
    _sis_user_id = args.sis_user_id
if args.sortable_name is None:
    _sortable_name = args.ln + ', ' + args.fn
else:
    _sortable_name = args.sortable_name

payload = {
    'user[name]': args.fn + ' ' + args.ln,
    'user[sortable_name]': _sortable_name,
    'user[skip_registration]': 'true',
    'pseudonym[send_confirmation]': 'false',
    'pseudonym[unique_id]': _login_id,
    'pseudonym[sis_user_id]': _sis_user_id,
    'pseudonym[authentication_provider_id]': args.auth_type,
    'communication_channel[skip_confirmation]': 'true',
    'communication_channel[type]': 'email',
    'communication_channel[address]': args.email,
    'enable_sis_reactivation':'true'
}

_password = None
if args.auth_type == 'canvas':
    _password = generate_password()
    payload['pseudonym[password]'] = _password


if args.live_mode is True:
    #resp = c.accounts('self').users.post(data={}, http_headers={}, do_json=False, **{'params': payload})
    resp = c.accounts('self').users.post(**{'params': payload})
    if resp.status_code == 200:
        print('User successfully created')
        print('password:{}'.format(_password))
        logger.info('user created - F:{} L:{} LID:{} SID:{} PWD:{} E:{} SN:"{}"'.format(args.fn, args.ln, _login_id, _sis_user_id, _password, args.email, _sortable_name))
    else:
        print('An error occured creting the user')
        print(resp.text)
        print(resp.json())
else:
    print('**NOT LIVE**: would have created user with this payload:\n{}'.format(json.dumps(payload, indent=2)))
    print('**NOT LIVE**: password would have been: {}'.format(_password))
    logger.info('user created - **NOT LIVE** - F:{} L:{} LID:{} SID:{} PWD:{} E:{} SN:"{}"'.format(args.fn, args.ln, _login_id, _code, _password, args.email, _sortable_name))


# vim:expandtab ts=4 sw=4
# END OF FILE
