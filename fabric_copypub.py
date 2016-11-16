from __future__ import with_statement
from paramiko import Transport
from socket import getdefaulttimeout, setdefaulttimeout

from fabric.api import run, env

import getpass
import gnupg
import os
import re


passwords_txt='passwords.txt'

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

def decrypt_get_passwords(passwords_file=passwords_txt):
    gpg = gnupg.GPG(gnupghome='/home/SCIS-TAAARFR4/.gnupg')
    ask_pass = getpass.getpass("Decrypt passwords.gpg: ")

    with open('passwords.gpg', 'rb') as f:
      status = gpg.decrypt_file(f, passphrase=ask_pass, output=passwords_txt)

    print status.status
    print status.stderr

    passwords = [line.rstrip('\n') for line in open(passwords_txt)]
    os.remove(passwords_txt)

    stack_passwords = {}

    for line in passwords:
      stack_pass = line.split(":")
      stack_passwords[stack_pass[0]] = stack_pass[1]

    return stack_passwords

def set_env_passwords(stack_passwords):

    stacks = stack_passwords.keys()

    for host in env.hosts:
      host = ("%s:22" % host)
      found = False
      for stack in stacks:
        if re.search((r"%s" % stack), host, re.M|re.I):
          found = True
          env.passwords[host] = stack_passwords[stack]
      if not found:
          env.passwords[host] = 'default'

def set_host(host_name):
    env.hosts = [ "root@%s" % host_name ]

    set_env_passwords(decrypt_get_passwords())

def set_hosts(filename="hosts.txt"):
    """Set hosts environment from a file and properly format it according
    to the user@host:port fabric convention

    Fill the passwords environment dictionary with the matched passwords from
    the encrypted stacks password file.
    """
    env.hosts = [("root@%s" % line.rstrip('\n')) for line in open(filename)]

    set_env_passwords(decrypt_get_passwords())

@if_host_offline_ignore
def hostname_f():
    run('hostname -f')

@if_host_offline_ignore
def copy_pub(pubkey):

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

