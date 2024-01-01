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
import art
import uuid

_version = 0.6


# filter used for logging only users created to the log file
class usersFilter(logging.Filter):
    def filter(self, record):
        _msg = record.getMessage()
        return _msg.startswith('user created') or _msg.startswith('login created')


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


# ensure the domain does not include '.instructure.com' - or just truncate that if supplied
def canvas_subdomain(subdomain):
    _sd = re.sub(r'([A-Za-z0-9.]+).instructure.com', r'\1', subdomain)
    return _sd


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
parser.add_argument(dest='subdomain', type=canvas_subdomain, help='Canvas subdomain (i.e. sandbox - "christopher", or customer - "qed", or special - "queensland.security", basically anything prior to ".instructure.com")')
parser.add_argument('--login-id', dest='login_id', type=str, help='Specify an explicit login_id for the user, otherwise the default is a randomly generated one')
parser.add_argument('--sis-user-id', dest='sis_user_id', type=str, help='Specify an explicit SIS user_id for the user, otherwise the default is a randomly generated one')
parser.add_argument('--sortable-name', dest='sortable_name', type=str, help='Specify a "sortable name" for the user.  Default "<last name>, <first name>"')
parser.add_argument('--primary-login', dest='primary_login', type=canvas_subdomain, help='If specified, should be the domain of a primary instance of a Canvas consortia.  A login (aka pseudonym) will be created on this instance for the user.')
parser.add_argument('--integration-id', dest='integration_id', type=str, help='Specify an explicit integration_id for the user.  If specified with no value, then a value (i.e. UUID) will be generated.  If not specified, no value will be supplied with the user.', default='not-specified', nargs='?')

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
art.tprint(environment if environment == 'beta' else 'prod')


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

c = Canvas(_instance, log_level='debug' if args.debug is True else 'info', CANVAS_ACCESS_TOKEN=os.getenv('CANVAS_ACCESS_TOKEN'))

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

_integration_id = args.integration_id
# parameter specified, but no value
if args.integration_id is None:
    # do UUID stuff here
    _integration_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, _login_id))
    payload['pseudonym[integration_id]'] = _integration_id
elif args.integration_id != 'not-specified':
    # take what was specified
    payload['pseudonym[integration_id]'] = _integration_id


_canvas_user_id = '<FAKE USER ID - NOT LIVE>'
if args.live_mode is True:
    #resp = c.accounts('self').users.post(data={}, http_headers={}, do_json=False, **{'params': payload})
    resp = c.accounts('self').users.post(**{'params': payload})
    if resp.status_code == 200:
        print('User successfully created')
        print('password:{}'.format(_password))
        _canvas_user_id = resp.json()['id']
        logger.info('user created - SD:{} F:{} L:{} LID:{} SID:{} PWD:{} E:{} SN:"{}" CID:{}'.format(args.subdomain, args.fn, args.ln, _login_id, _sis_user_id, _password, args.email, _sortable_name, _canvas_user_id))
    else:
        print('An error occurred creting the user')
        print(resp.text)
        print(resp.json())
else:
    print('**NOT LIVE**: would have created user with this payload:\n{}'.format(json.dumps(payload, indent=2)))
    print('**NOT LIVE**: password would have been: {}'.format(_password))
    logger.info('user created - **NOT LIVE** - SD:{} F:{} L:{} LID:{} SID:{} PWD:{} E:{} SN:"{}" CID:{}'.format(args.subdomain, args.fn, args.ln, _login_id, _sis_user_id, _password, args.email, _sortable_name, _canvas_user_id))


# If the primary_login parameter has been specified, act on that here
# Need to get the shard ID of the specific child instance
if args.primary_login is not None:
    # instance of the "primary" of the consortia
    _instance = _canvas_instance_tpl.format(args.primary_login, _inst_sub_domain)
    logger.info('Connecting to {}'.format(_instance))
    c = Canvas(_instance, log_level='debug' if args.debug is True else 'info', CANVAS_ACCESS_TOKEN=os.getenv('CANVAS_ACCESS_TOKEN'))

    if args.live_mode is True:
        print('Searching for shard of the child instance where the user record was created')
        # NOTE: Some Canvas environments (e.g. syd-security), the canvas_account_id will not be '1', but something else
        # There currently isn't a consortia setup there, so not too much of an issue
        resp = c.accounts(1).root_accounts.get(http_headers={'Accept':'application/json+canvas-string-ids'})
        if resp.status_code == 200:
            # Find the relevant root_account (aka instance) via a generator expression of a generator expression
            # Looks crazy but there can be multiple domains for an instance, so need to search all for the one we are looking for
            root_account_details = next((root_account for root_account in resp.json() if next((domain for domain in root_account['domains'] if domain['host'] == _canvas_instance_tpl.format(args.subdomain, '')), None) is not None), None)
            # Extract the 'id' for the relevant instance
            root_account_id = root_account_details['id']
            print('Found root account ID "{}"'.format(root_account_id))
            # Strip off the 0's to the end
            # e.g. 201330000000000001 --> group 1 "20133", group 2 "1"
            matches = re.match(r"^([0-9]{5})0+([1-9])$", root_account_id)
            shard_id = None
            if matches is None:
                print('Error, shard ID couldn\'t be found')
                sys.exit(2)
            else:
                shard_id = matches.group(1)
        else:
            print('An error occured finding the instance shard')
            print(resp.text)
            print(resp.json())
            sys.exit(2)
    else:
        shard_id = '<FAKE SHARD ID - NOT LIVE>'


    full_canvas_user_id = f'{shard_id}~{_canvas_user_id}'
    payload = {
        'user[id]': full_canvas_user_id,
        'login[unique_id]': _login_id,
        'login[sis_user_id]': _sis_user_id,
    }
    if args.auth_type == 'canvas':
        payload['login[password]'] = _password
    if args.integration_id is None or args.integration_id != 'not-specified':
        payload['login[integration_id]'] = _integration_id

    if args.live_mode is True:
        resp = c.accounts('self').logins.post(params=payload)
        if resp.status_code == 200:
            print('Login successfully created')
            logger.info('login created - PSD:{} LID:{} SID:{} CID:{}'.format(args.primary_login, _login_id, _sis_user_id, full_canvas_user_id))
        else:
            print('An error occurred creating the user')
            print(resp.text)
            print(resp.json())
    else:
        print('**NOT LIVE**: would have created a login on the primary ({}) with this payload:\n{}'.format(args.primary_login, json.dumps(payload, indent=2)))
        logger.info('login created - **NOT LIVE** - PSD:{} LID:{} SID:{} CID:{}'.format(args.primary_login, _login_id, _sis_user_id, full_canvas_user_id))


# vim:expandtab ts=4 sw=4
# END OF FILE
