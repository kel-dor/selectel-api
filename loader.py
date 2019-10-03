# Interact with the Selectel Cloud API.
#
# Usage: docker run --env-file env.list -i -v [local directory]:/selectel/shared \
#        [container name] [-c [file1 [file2 ...]]] [-d [file1 [file2 ...]]] \
#        [-g [dir]] [--ls [dir]] [-r [file1 [file2 ...]]] [-t dir] \
#        [-u [file1 [file2 ...]]] [-e] [-f] [-h] [-i] [-m] [-q] [-s] [-z]

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import magic
import requests
import shlex
import sys
import shutil


class Session:

    def __init__(self, login_data, auth_url, api_url, storage_url):
        self.session = requests.Session()
        self.login_data = login_data
        self.auth_url = auth_url
        self.api_url = api_url
        self.storage_url = storage_url
        self.container = None
        self.token = None
        self.token_expires_in = None

    # Static helper methods

    @staticmethod
    def get_md5_hash(path):
        """Create md5 hash based on the contents of the given file."""
        hasher = hashlib.md5()
        with open(path, 'rb') as f:
            hasher.update(f.read())
            return hasher.hexdigest()

    @staticmethod
    def get_mime_type(path):
        """Determine the type of the file and form the Content-Type header."""
        mime = magic.Magic(mime=True)
        return mime.from_file(path)

    @staticmethod
    def get_timestamp(from_when, how_many_seconds=0):
        """Calculate the timestamp for X-Delete-At and similar headers."""
        return int(datetime.timestamp(from_when)) + how_many_seconds

    @staticmethod
    def utc_to_local(utc_dt_string):
        """Convert UTC to local time."""
        utc_dt = datetime.strptime(utc_dt_string, '%Y-%m-%dT%H:%M:%S.%f')
        local_dt = utc_dt.replace(tzinfo=timezone.utc).astimezone(tz=None)
        return local_dt.strftime('%a, %d %b %Y %H:%M:%S %Z')

    # Decorators

    def check_token(decorated):
        """Check whether the authentication token has expired or not."""

        def checker(self, *args, **kwargs):
            if self.token_expires_in < datetime.now():
                self.get_auth_token()
            return decorated(self, *args, **kwargs)
        return checker

    # Other helpers

    def ask_to_retry(self, msg, *args, **kwargs):
        """Ask for extra user prompt in case of some error."""
        retry = input(msg + 'Proceed? y/n ').lower()
        if retry == 'y' or retry == 'yes':
            command = input()
            return self.parser.parse_known_args(shlex.split(command))
        else:
            raise SystemExit

    def get_remote_path(self, path='', base_url='', container=''):
        """Form the remote path"""
        if not base_url:
            base_url = self.api_url

        if container:
            # Switch to this container
            self.container = container
        elif container == None or self.container == None:
            # Case 1: the container parameter is set to None (we want to see
            # the containers list before selecting the container to work with).
            # Case 2: the self.container was not set at the start
            print('\nPlease select the container to work with.')
            self.switch_to_another_container()
            container = self.container
        else:
            container = self.container
        return os.path.join(base_url, container, path)

    # User input parsers

    def init_argument_parser(self, args_to_parse=None):
        """Set up the parser for command line arguments."""
        self.parser = argparse.ArgumentParser(add_help=False)

        # Add options with parameters required
        self.parser.add_argument('-c', '--check', nargs='*',
                                 help='check if the file is in the container',
                                 metavar=('file1', 'file2'))
        self.parser.add_argument('-d', '--download', nargs='*',
                                 help='download files',
                                 metavar=('file1', 'file2'))
        self.parser.add_argument('-g', '--get-list', nargs='?', const=True,
                                 help='get the list of files in the ' +
                                 'container or in the given directory',
                                 metavar='dir')
        self.parser.add_argument('--ls', nargs='?', const=True,
                                 help='get the list of files in the ' +
                                 'local storage or in the given directory',
                                 metavar='dir')
        self.parser.add_argument('-r', '--remove', nargs='*',
                                 help='remove files',
                                 metavar=('file1', 'file2'))
        self.parser.add_argument('-t', '--to-dir',
                                 help='create a local directory to download ' +
                                 'file into it or create a remote directory ' +
                                 'to upload file',
                                 metavar='dir')
        self.parser.add_argument('-u', '--upload', nargs='*',
                                 help='upload files',
                                 metavar=('file1', 'file2'))
        # Add flags
        self.parser.add_argument('-e', '--extract', action='store_true',
                                 help='upload and extract the .tar, .tar.gz ' +
                                      'or .gzip archive into the container')
        self.parser.add_argument('-f', '--force', action='store_true',
                                 help='force upload files')
        self.parser.add_argument('-h', '--help', action='help',
                                 default=argparse.SUPPRESS,
                                 help='show this help message')
        self.parser.add_argument('-i', '--interactive', action='store_true',
                                 help='enter interactive mode to run ' +
                                 'multiple commands')
        self.parser.add_argument('-m', '--minimize', action='store_true',
                                 help='hide the subdirectories contents')
        self.parser.add_argument('-s', '--switch', action='store_true',
                                 help='switch to another container')
        self.parser.add_argument('-q', '--quit', action='store_true',
                                 help='leave interactive mode and exit')
        self.parser.add_argument('-z', '--zip', action='store_true',
                                 help='download file/directory as an archive')
        if not args_to_parse:
            print('The script was run with no arguments and did nothing.')
            print('Please take a look at the help message:\n')
            self.parser.print_help()
            raise SystemExit

    def handle_user_commands(self, command=None):
        """Parse user input and pass settings to the command handlers."""

        if command:
            args, unknown = self.parser.parse_known_args(shlex.split(command))
        else:
            args, unknown = self.parser.parse_known_args()
        if unknown:
            args, unknown = self.ask_to_retry('Unknown option' +
                                              's' * (len(unknown) > 1) +
                                              ': ' + ' '.join(unknown) + '. ')

        args_dict = vars(args)  # convert argparse.Namespace object into a dict
        handlers_map = {
            'check':        self.check_if_exists,
            'download':     self.download_files,
            'get_list':     self.get_files_list,
            'interactive':  self.enter_interactive_mode,
            'ls':           self.get_local_files_list,
            'quit':         self.quit_interactive_mode,
            'remove':       self.remove_files,
            'switch':       self.switch_to_another_container,
            'upload':       self.upload_files,
        }

        settings = {
            'extract':      None,               # a flag for upload handler
            'force':        None,               # a flag for upload_handler
            'minimize':     None,               # a flag for get_list handler
            'to_dir':       None,               # requires directory name
            'zip':          None,               # a flag for download handler
        }

        handlers = []
        if not self.token:
            handlers.append((self.get_auth_token, []))    # authenticate first
        run_interactive = False

        for option, params in args_dict.items():
            if params:
                handler = handlers_map.get(option)
                if handler:
                    if option == 'interactive':
                        run_interactive = True
                        interactive_mode_handler = handler
                    else:
                        handlers.append((handler, params))
                else:
                    # If there is no special handler function for the option,
                    # then add it to settings
                    settings[option] = params

        # Run all handlers from the queue
        for (handler, params) in handlers:
            if params is True:
                # Pass only values that are explicitly set, don't pass True
                params = []
            elif isinstance(params, str):
                # Pass a string as a single item inside the list (otherwise
                # it is passed as a list of chars)
                params = [params]
            handler(*params, **settings)
            print('')

        # Run interactive mode only after calling other handlers
        if run_interactive:
            interactive_mode_handler()

    # Authentication handler

    def get_auth_token(self, *args, **kwargs):
        """Send the login data to the API and get an authentication token."""

        print('Getting authentication token... ', end='')
        resp = self.session.post(self.auth_url, headers=login_data)
        if resp.status_code == 204:
            self.token = resp.headers.get('X-Auth-Token')
            exp = int(resp.headers.get('X-Expire-Auth-Token'))
            # Update the session's headers to contain the token
            self.session.headers.update({'X-Auth-Token': self.token})
            # Save the expiry timestamp for the check_token function
            self.token_expires_in = datetime.now() + timedelta(seconds=exp)
            print('Done', end='')
        else:
            print('Failed with code {}'.format(resp.status_code))
            if resp.status_code == 403:
                print('Please check your credentials')
            raise SystemExit

    # User command handler functions
    @check_token
    def enter_interactive_mode(self, *args, **kwargs):
        """Allow user to run multiple commands."""
        print('\nYou are in the interactive mode. Print --help for more info.')
        self.switch_to_another_container()
        while True:
            try:
                command = input('')
                self.handle_user_commands(command=command)
            except SystemExit:
                # Disable exiting after printing the help message
                if command not in ['--help', '-h']:
                    sys.exit()

    def quit_interactive_mode(self, *args, **kwargs):
        """Exit from the interactive mode."""
        raise SystemExit

    @check_token
    def check_if_exists(self, *args, **kwargs):
        """Try to find the given pattern within names or extensions of
           files in the container.
        """
        # Update the list of files
        files_list = []
        files_list = self.get_files_list(silent=True)

        for pattern in args:
            print('\nChecking pattern {}... '.format(pattern), end='')
            # Find all files
            dirs_found, files_found = set(), []
            for elem in files_list:
                name = elem['name']
                fname = os.path.basename(name)
                parent_dirs = os.path.dirname(name).split('/')
                extension = os.path.splitext(name)[1]
                if pattern == name or pattern == fname or pattern == extension:
                    files_found.append(elem)
                elif pattern in parent_dirs:
                    path = ''
                    for dname in parent_dirs:
                        path += dname + '/'
                        if dname == pattern:
                            break
                    dirs_found.add(path)

            if not files_found and not dirs_found:
                print('Not found')

            if files_found:
                n = len(files_found)
                print('Found {} file'.format(n) + 's' * (n > 1))

                for elem in files_found:
                    print('\nPath:\t\t{}'.format(
                        self.get_remote_path(elem['name'], self.storage_url)
                    ))
                    print('Etag:\t\t{}'.format(elem['hash']))
                    print('Size:\t\t{}'.format(elem['bytes']))
                    print('Type:\t\t{}'.format(elem['content_type']))
                    print('Modified:\t{}'.format(
                        self.utc_to_local(elem['last_modified'])
                    ))
                print()

            if dirs_found:
                n = len(dirs_found)
                print('Found {} director'.format(n) +
                      ('ies' if n > 1 else 'y'))
                # Since we are unable to get info about directories from the
                # API, we only show their paths
                for elem in dirs_found:
                    path = self.get_remote_path(elem)
                    print('\nPath:\t\t{}'.format(path))

    @check_token
    def download_files(self, *args, **kwargs):
        """Download files from the container."""

        for fname in args:
            # # Allow downloading as zip
            # headers = {'X-Container-Meta-Allow-ZipDownload': 'true'}
            # headers.update(self.session.headers)
            # resp = self.session.put(self.get_remote_path(), headers=headers)

            # Handle both cases: short relative path, e.g. copied from the
            # files list, and long absolute path, e. g. from the http headers
            print('Downloading {}'.format(fname), end='')
            if fname.startswith(self.api_url):
                path = fname
            else:
                path = self.get_remote_path(fname)

            # Download the remote directory as a zip archive if needed
            params = {}
            if kwargs.get('zip'):
                print(' as a zip archive', end='')
                fname = os.path.splitext(fname)[0] + '.zip'
                params.update({'download-all-as-zip': ''})
            print('... ', end='')

            # Send GET request
            resp = self.session.get(path, params=params)

            # Create a local directory if needed
            lpath = kwargs.get('to_dir')
            if lpath:
                if not os.path.exists(lpath):
                    os.makedirs(lpath)
                fname = os.path.join(lpath, fname)

            if resp.status_code == 200:
                print('Done')
                with open(fname, 'wb') as f:
                    f.write(resp.content)
            else:
                print('Failed with code {}'.format(str(resp.status_code)))

    @check_token
    def switch_to_another_container(self, *args, **kwargs):
        print('Getting containers list... ')
        resp = self.session.get(self.api_url)
        if resp.status_code == 200:
            print(resp.text)
            containers_list = resp.text.split()
            container = input('Select the container: ')
            if container not in containers_list and not self.container:
                print('Please enter the correct container name.')
                self.switch_to_another_container()
            elif container:
                self.container = container
                print('Working container: {}. Use -s to switch to another.'.format(container))
            else:
                print('Container was not switch. Working container: {}.'.format(self.container))
        else:
            print('Failed with code {}'.format(resp.status_code))
            sys.exit()


    @check_token
    def get_files_list(self, *args, **kwargs):
        """Get list of files present in the container."""
        files_list = []

        # If some directory name is specified, load only its contents
        if args:
            dname = args[0]
        else:
            dname = ''

        # The API can not send us more than 10000 filenames at once, so
        # if there are more files in the directory, we need to request the
        # list in parts within this loop (and we need the marker to do it)
        marker = ''
        while True:
            url = self.get_remote_path()
            print('Getting files list... ', end='')
            params = {
                'format':       'json',
                'marker':       marker,
                'prefix':       dname,
            }

            # By default the script gets a list of all files, including the
            # contents of all subdirectories. If the flag is set, only the
            # subdirectories' names are shown
            if kwargs.get('minimize'):
                params.update({'delimiter': '/'})
            resp = self.session.get(url, params=params)
            if resp.status_code == 200:
                print('Done')
                # Save all the json metadata
                files_list.extend(json.loads(resp.text))

                # Print the list (if the --get-list option was explicitly set
                # by the user)
                if not kwargs.get('silent'):
                    for elem in files_list:
                        if elem.get('name'):
                            print(elem['name'])
                        elif elem.get('subdir'):
                            print(elem['subdir'])
                        else:
                            print('debug: ', elem)

                if len(resp.text) != 10000:
                    return files_list
                else:
                    # Send request for the next chunk of data starting
                    # from the new marker
                    marker = files_list[-1]['name']
            else:
                print('Failed with code {}'.format(resp.status_code))
                return []

    def get_local_files_list(self, *args, **kwargs):
        """Print a list of files, just like the ls command."""
        if args:
            dname = args[0]
            lpath = os.path.abspath(dname)
        else:
            lpath = os.getcwd()

        if os.path.exists(lpath) and os.path.isdir(lpath):
            local_files_list = sorted(os.listdir(lpath))
            for name in local_files_list:
                print(name)
        else:
            print('Directory {} not found. '.format(dname))

    @check_token
    def remove_files(self, *args, **kwargs):
        """Delete files from the container."""
        files_list = self.get_files_list(silent=True)
        for name in args:
            if name.endswith('/'):
                # Delete all files from the given directory
                for elem in files_list:
                    fname = elem['name']
                    if fname.startswith(name):
                        print('\rDeleting {}... '.format(fname), end='')
                        rpath = self.get_remote_path(fname)
                        resp = self.session.delete(rpath)
                        if resp.status_code == 204:
                            print('Done')
                        else:
                            print('Failed with code {}'.format(
                                resp.status_code))
            else:
                # Delete the single file
                print('Deleting {}... '.format(name), end='')
                rpath = self.get_remote_path(name)
                resp = self.session.delete(rpath)
                if resp.status_code == 204:
                    print('Done')
                else:
                    print('Failed with code {}'.format(resp.status_code))

    @check_token
    def upload_files(self, *args, **kwargs):
        """Upload files to the container."""
        for lpath in args:
            print('Trying to upload file {}... '.format(lpath), end='')
            # Check local path
            if not os.path.exists(lpath):
                print('File not found')
            else:
                print('File found', end='')
                if os.path.isdir(lpath):
                    # Upload the contents of the given directory
                    print(' and is a directory')
                    for name in os.listdir(lpath):
                        self.upload_files(os.path.join(lpath, name), **kwargs,
                                          p_dir=os.path.basename(lpath))
                else:
                    # Upload the given file
                    print('')
                    fname = os.path.basename(lpath)
                    extension = os.path.splitext(lpath)[1]
                    ftype = self.get_mime_type(lpath)

                    # Add some remote directory name to the path
                    to_dir = kwargs['to_dir'] if kwargs.get('to_dir') else ''
                    parent_dir = kwargs['p_dir'] if kwargs.get('p_dir') else ''
                    dname = os.path.join(to_dir, parent_dir)

                    # Check if the file exists in the container
                    files_list = self.get_files_list(silent=True)
                    if kwargs.get('newname'):       # if you need to rename the
                        fname = kwargs['newname']   # file before uploading
                    fname = os.path.join(dname, fname)
                    rpath = self.get_remote_path(fname)
                    file_not_found = True

                    is_an_archive = extension in ['.tar', '.gzip', '.tar.gz']
                    force = True if kwargs.get('force') else False

                    if not is_an_archive and not force:
                        for elem in files_list:
                            if elem['name'] == fname:
                                print('The file already exists:')
                                print(self.get_remote_path(elem['name'],
                                                           self.storage_url))
                                # Hash is compared with etag only if the file
                                # with the same name was found in the cloud
                                fhash = self.get_md5_hash(lpath)
                                if elem.get('hash') and elem['hash'] == fhash:
                                    ans = input("You are trying to upload " +
                                                "the unchanged file.\n" +
                                                "Proceed? y/n ")
                                    if ans not in ['y', 'yes']:
                                        file_not_found = False
                                else:
                                    rename = input('Do you want to use ' +
                                                   'another name? y/n ')
                                    if rename.lower() in ['y', 'yes']:
                                        newname = input('Enter: ')
                                        self.upload_files(lpath, **kwargs,
                                                          newname=newname)
                                    file_not_found = False

                    # Upload the file
                    if file_not_found:
                        print('Uploading file {}... '.format(fname), end='')
                        headers = {'Content-type': ftype, 'Slug': fname}
                        params = {}

                        # Extract archive if needed
                        if (kwargs.get('extract') and is_an_archive):
                            params.update({'extract-archive': extension})
                            rpath = os.path.splitext(rpath)[0] + '/'

                        # Send PUT request
                        headers.update(self.session.headers)
                        resp = self.session.put(rpath, data=open(lpath, 'rb'),
                                                headers=headers, params=params)
                        if resp.status_code == 201:
                            print('Done')
                            print(self.get_remote_path(fname,
                                                       self.storage_url))
                        else:
                            print('Failed with code {}'.format(resp.status_code))


if __name__ == '__main__':

    login = os.environ['LOGIN']
    password = os.environ['PASSWORD']
    storage = os.environ['STORAGE']

    auth_url = 'https://auth.selcdn.ru/'
    api_url = 'https://api.selcdn.ru/v1/SEL_{}'.format(login)
    storage_url = 'https://{}.selcdn.ru/'.format(storage)
    login_data = {'X-Auth-User': login, 'X-Auth-Key': password}

    s = Session(login_data, auth_url, api_url, storage_url)
    s.init_argument_parser(sys.argv[1:])
    s.handle_user_commands()
