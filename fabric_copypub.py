from __future__ import with_statement
from paramiko import Transport
from socket import getdefaulttimeout, setdefaulttimeout

from fabric.api import run, env

import getpass
import gnupg
import os
import re


class PromptUserException(Exception):
    """ Make sure we are catching what we want """
    pass

env.abort_exception = PromptUserException
env.abort_on_prompts = True # (--abort_on_prompts)

passwords_input_file='passwords.gpg'
passwords_output_file='passwords.txt'

userlogin='root'
sshport='22'

def if_host_offline_ignore(fn):
    """Return the wrapped function to check for host aliveness"""
    def wrapped():
      original_timeout = getdefaulttimeout()
      setdefaulttimeout(3)
      try:
          Transport((env.host, int(env.port)))
          return fn()
      except:
          print "The following host appears to be offline: " + env.host
      setdefaulttimeout(original_timeout)
    return wrapped

def decrypt_get_passwords(passwords_file=passwords_output_file):
    gpg = gnupg.GPG(gnupghome=os.path.expanduser('~/.gnupg'))
    ask_pass = getpass.getpass("Decrypt passwords.gpg: ")

    with open(passwords_input_file, 'rb') as f:
      status = gpg.decrypt_file(f, passphrase=ask_pass, output=passwords_output_file)

    print status.status
    print status.stderr

    passwords = [line.rstrip('\n') for line in open(passwords_output_file)]
    os.remove(passwords_output_file)

    stack_passwords = {}

    for line in passwords:
      stack_pass = line.split(":")
      stack_passwords[stack_pass[0]] = stack_pass[1]

    return stack_passwords

def host_format_full(fqdn):
    """ Format the fqdn to the expected Fabric format user@fqdn:port  """
    return "%s@%s:%s" % (userlogin, fqdn, sshport)

def set_env_passwords(stack_passwords):
    
    stacks = stack_passwords.keys()

    for host in env.hosts:
      found = False
      for stack in stacks:
        if re.search((r"%s" % stack), host, re.M|re.I):
          found = True
          env.passwords[host] = stack_passwords[stack]
      if not found:
          env.passwords[host] = 'default'

def set_host(host_name):
    env.hosts = [host_format_full(host_name)]
    set_env_passwords(decrypt_get_passwords())

def set_hosts(filename="hosts.txt"):
    """Set hosts environment from a file and properly format it according
    to the user@host:port fabric convention

    Fill the passwords environment dictionary with the matched passwords from
    the encrypted stacks password file.
    """
    env.hosts = [host_format_full(line.rstrip('\n')) for line in open(filename)]

    set_env_passwords(decrypt_get_passwords())

default_passwords = ['default1', 'default2', 'default3']

def get_new_password(current_password):
    """ Return next pasword for retry, None if no other password is available """
    if current_password in default_passwords:
        if default_passwords.index(current_password) + 1 <= len(default_passwords) - 1:
            return default_passwords[default_passwords.index(current_password) + 1]
        else:
            return None
    else:
        return default_passwords[0]

@if_host_offline_ignore
def hostname_f():
    run('hostname -f')

@if_host_offline_ignore
def copy_pub(pubkeyfile='~/.ssh/id_rsa.pub'):

    pubkey = open(os.path.expanduser(pubkeyfile)).read()

    current_password = True
    first_command_run = False
    while current_password is not None:
        try:
            hostname_f()
            current_password = None
            first_command_run = True
        except PromptUserException:
            print 'Trying another default password!'
            host = host_format_full(env.host) 
            current_password = get_new_password(env.passwords[host]) 
            env.passwords[host] = current_password
    
    if current_password is None and not first_command_run:
        print "Failed all tries with known passwords. Aborting."
        raise SystemExit

    # Check if authorized keys exists and create it if that's not the case
    size_before = run('[[ -e .ssh/authorized_keys ]] && stat --printf="%s" /root/.ssh/authorized_keys || (touch /root/.ssh/authorized_keys && echo 0)')

    echo_cmd = "echo %s >> /root/.ssh/authorized_keys" % (pubkey)
    run(echo_cmd)
    run('sort -u -o /root/.ssh/authorized_keys /root/.ssh/authorized_keys')

    size_after = run('stat --printf="%s" /root/.ssh/authorized_keys')

    if size_after == size_before:
      run('echo "File unchanged."')
    else:
      run('echo "File changed!"')

