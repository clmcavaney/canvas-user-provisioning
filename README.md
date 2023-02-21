# Introduction

Provision a user in a Canvas instance, similar to a SIS import, but from the CLI

## Usage

You will need a Canvas API bearer token to use this script.  That token will need to be contained in an environment variable called `CANVAS_ACCESS_TOKEN`.


```
usage: load-user-with-pwd.py [-h] [--version] [-d] [-p] [-l] [-a {canvas,saml}] [--login-id LOGIN_ID]
                             [--sis-user-id SIS_USER_ID] [--sortable-name SORTABLE_NAME]
                             fn ln email subdomain

Create a user in an instance. If the user login is using Canvas authentication then a random generated password will be
created and logged.

positional arguments:
  fn                    First name
  ln                    Last name
  email                 email address
  subdomain             Canvas subdomain (i.e. sandbox - "christopher", or customer - "qed", or special -
                        "queensland.security", basically anything prior to ".instructure.com")

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -d, --debug           Turn on debugging (default: False)
  -p, --use-prod        By default the script will run against the beta environment. This flag changes the behaviour to the
                        prod environment for both source and destination. (default: False)
  -l, --live            Run in live mode (default is to not make changes - aka "dry run") (default: False)
  -a {canvas,saml}, --auth {canvas,saml}
                        Authentication type. For "saml" no password will be generated as it isn't required. (default:
                        canvas)
  --login-id LOGIN_ID   Specify an explicit login_id for the user, otherwise the detauls is a randomly generated one
                        (default: None)
  --sis-user-id SIS_USER_ID
                        Specify an explicit SIS user_id for the user, otherwise the detauls is a randomly generated one
                        (default: None)
  --sortable-name SORTABLE_NAME
                        Specify a "sortable name" for the user. Default "<last name>, <first name>" (default: None)
```

# Installation

Install the appropriate libraries

```
pip install --requirement requirements.txt
```
