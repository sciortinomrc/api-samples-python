#!/usr/bin/env python2.7

import argparse
from collections import namedtuple
import logging
import os
import requests
import sys
import httplib
import json

API_TOKEN_ENVVAR = 'METERIAN_API_TOKEN'

TIMEOUT = namedtuple('literal', 'text status_code')(text='{"status":"timeout"}', status_code=999)

DATABASES = [ 'all', 'php', 'nvd', 'gha', 'nvd-me', 'nvd-raw']


class HelpingParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write('error: %s\n' % message)
        self.print_help()
        sys.stderr.write('\n')
        sys.exit(-1)


def _logHttpRequests():
    httplib.HTTPConnection.debuglevel = 1

    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True

    logging.debug('Full debug log for HTTP requests enabled')

def _parseArgs():
    parser = HelpingParser()

    parser.add_argument('db', help='The name of the databse you want to enquiry\n (i.e. nvd) %s' % DATABASES);
    parser.add_argument('vuln', help='The unique identifier of the vulnerability\n (i.e. CVE-2020-9483)');

    token = os.environ[API_TOKEN_ENVVAR] if API_TOKEN_ENVVAR in os.environ else None
    parser.add_argument(
        '-t',
        '--token',
        metavar='API-TOKEN',
        default=token,
        help=(
            'Allows you to specify the API token to use directly on the command line. '
            'You can create your token with a bootstrap+ plan at https://meterian.com/account/#tokens'
        )
    )

    parser.add_argument(
        '-l',
        '--log',
        default='warning',
        metavar='LOGLEVEL',
        help='Sets the logging level (default is warning)'
    )

    return parser.parse_args()


def _initLogging(args):
    levels = {
        'critical': logging.CRITICAL,
        'error': logging.ERROR,
        'warn': logging.WARNING,
        'warning': logging.WARNING,
        'info': logging.INFO,
        'debug': logging.DEBUG
    }
    level = levels.get(args.log.lower())
    if level is None:
        raise ValueError('Invalid log level requested - must be in '+levels.keys());

    logging.basicConfig(level=level)
    logging.basicConfig(format='%(time)s-%(levelname)s-%(message)s')

    if level == logging.DEBUG:
        _logHttpRequests()
    else:
        logging.getLogger('requests').setLevel(logging.WARNING)

    logging.debug('Logging initiated')


def _loadVulnerability(args):

    url = 'https://www.meterian.com/api/v1/vulns/%s/%s' % (args.db, args.vuln)
    logging.debug('Loading vulnerability info from url [%s]...', url)

    try:
        result = requests.get(url, timeout=30, headers={'Authorization':'Token %s' % args.token})
        logging.info('Result %s' % result.text )
    except:
        result = TIMEOUT

    if result.status_code == 404:
        print 'No matching vulnerability was found'
        return None
    elif result.status_code != 200:
        print 'Unable to successfully contact the meterian server: %s' % str(result)
        return None
    else:
        return json.loads(result.text)



#
# CLI entry point
#

if __name__ == '__main__':

    args = _parseArgs()
    _initLogging(args)

    if not args.db in DATABASES:
        sys.stderr.write('invalid database: %s\n' % args.db);
        sys.stderr.write('available databases: %s\n' % str(DATABASES));
        sys.stderr.write('\n')
        sys.exit(-1)

    token = args.token
    if token == None:
        sys.stderr.write('No API token found.\nPlease specify it using the "%s" environment variable or use --token on the command line' % API_TOKEN_ENVVAR);
        sys.stderr.write('\n')
        sys.exit(-1)

    print 'Fetching information for vulnerability "%s" from the "%s" database...' % (args.vuln, args.db)
    vuln = _loadVulnerability(args)

    if vuln != None:
        if str(args.db) == "nvd-me" or str(args.db) == "nvd-raw":
            print
            print(json.dumps(vuln, indent=4, sort_keys=True))
        else:
            print '- id:   ' + vuln["id"]
            print '  - library:'
            print '    language: ' + vuln["library"]["language"]
            print '    name: ' + vuln["library"]["name"]
            print '  version range: ' + vuln["versionRange"]
            print '  severity: ' + vuln["severity"]

            if len(vuln["links"]) > 0:
                print '  - links: '
                for link in vuln["links"]:
                    if link["url"].startswith("http"):
                        print '    ' + link["url"]

            print '  source: ' + vuln["source"]
            print '  type: ' + vuln["type"]
            print '  cwe: ' + vuln["cwe"]
            print '  cvss: ' + str(vuln["cvss"])
            print '  active: ' + str(vuln["active"])

            if len(vuln["fixedVersions"]) > 0:
                print '  - fixed versions: '
                for fixedVer in vuln["fixedVersions"]:
                    print '    ' + fixedVer

            print '  description: ' + vuln["description"]