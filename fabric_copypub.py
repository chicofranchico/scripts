from __future__ import with_statement
from paramiko import Transport
from socket import getdefaulttimeout, setdefaulttimeout

from fabric.api import run, env, cd, settings

import distutils
import getpass
import gnupg
import os
import re
import sys


class PromptUserException(Exception):
  """ Make sure we are catching what we want """
  pass

env.abort_exception = PromptUserException
env.abort_on_prompts = True # (--abort_on_prompts)

passwords_input_file  = os.path.expanduser('~/passwords.gpg')
passwords_output_file = os.path.expanduser('~/passwords.txt')

userlogin = 'root'
sshport = '22'

gnupg_home=os.path.expanduser('~/.gnupg')

proto = "https://"
repo_url = "github.com" # CHANGEME

########################
### HELPER FUNCTIONS ###
########################

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

def host_format_full(fqdn):
  """ Format the fqdn to the expected Fabric format user@fqdn:port  """
  return "%s@%s:%s" % (userlogin, fqdn, sshport)

def decrypt_get_passwords():
  """
  Decrypt passwords file where each line is of the type "system:password"
  Return it as a dictionary
  :return: dictionary containing password entries for each system
  """
  gpg = gnupg.GPG(gnupghome=gnupg_home, use_agent=True)

  with open(passwords_input_file, 'rb') as f:
    status = gpg.decrypt_file(f, output=passwords_output_file)
    print status.status

  passwords = [line.rstrip('\n') for line in open(passwords_output_file)]
  os.remove(passwords_output_file)

  system_passwords = {}

  for line in passwords:
    system_pass = line.split(":")
    system_passwords[system_pass[0]] = system_pass[1]

  return system_passwords

default_passwords = ['default1', 'default2', 'default3']

def get_new_password(current_password):
  """
  Return next password from a list of known default passwords for retry, None if no other password is available
  :param current_password: last password used
  :return: string: next password from the default_passwords
  """
  if current_password in default_passwords:
    if default_passwords.index(current_password) + 1 <= len(default_passwords) - 1:
      return default_passwords[default_passwords.index(current_password) + 1]
    else:
      return None
  else:
    return default_passwords[0]

##############################
### FABRIC SET ENVIRONMENT ###
##############################

def set_env_passwords(system_passwords):
  """
  Fabric specific function to set the environment password for each host @see env.passwords
  :param system_passwords: dictionary with matching system per password
  """
  stacks = system_passwords.keys()

  for host in env.hosts:
    found = False
    for stack in stacks:
      if re.search((r"%s" % stack), host, re.M|re.I):
        found = True
        env.passwords[host] = system_passwords[stack]
    if not found:
      env.passwords[host] = 'bladetest'


def set_host(host_name, set_password="True"):
  """
  Fabric specific function to set the environment for a single host
  :param host_name: the hostname
  :param set_password: Fill the
  :return:
  """
  env.hosts = [host_format_full(host_name)]
  if bool(distutils.util.strtobool(set_password)):
    set_env_passwords(decrypt_get_passwords())


def set_hosts(file_name, set_password="True"):
  """
  Fabric specific function to set hosts environment from a file and properly
  format it according to the user@host:port fabric convention

  :param set_password: Fill the passwords environment dictionary with the matched
                       passwords from the encrypted stacks password file.
  """
  env.hosts = [host_format_full(line.rstrip('\n')) for line in open(file_name)]

  if bool(distutils.util.strtobool(set_password)):
    set_env_passwords(decrypt_get_passwords())

########################
### REMOTE FUNCTIONS ###
########################

def hostname_f():
  """
  Run this as a first test to see if we can connect to the host
  :return:
  """
  run('hostname -f')

@if_host_offline_ignore
def copy_pub(pubkeyfile=os.path.expanduser('~/.ssh/id_rsa.pub')):
  """
  Copy a public key to (a) host(s)
  :param pubkeyfile: path to the public key file. Defaults to your home local id_rsa.pub file
  """

  pubkey = open(pubkeyfile).read().rstrip('\n')

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

  # Check if authorized keys exists and create it if that's not the case. Return 0 so that fabric doesn't fail
  size_before = run('[[ -e .ssh/authorized_keys ]] && stat --printf="%s" /root/.ssh/authorized_keys || (touch /root/.ssh/authorized_keys && echo 0)')

  echo_cmd = "echo \"%s\" >> /root/.ssh/authorized_keys" % (pubkey)
  run(echo_cmd)

  # prevent duplicate keys
  run('sort -u -o /root/.ssh/authorized_keys /root/.ssh/authorized_keys')

  size_after = run('stat --printf="%s" /root/.ssh/authorized_keys')

  if size_after == size_before:
    run('echo "File unchanged."')
  else:
    run('echo "File changed!"')

#####################
### GIT FUNCTIONS ###
#####################

_git_pass = 'password'

def input_git_password(username):
  global _git_pass
  _git_pass = getpass.getpass("git pull password for %s: " % username)

def pull_hieradata(username):
  """
  Specify the username.gpg file on the home directory with your GIT password as a single line
  :param username: string
  :return:
  """
  global _git_pass

  if username == "":
    print "Username for gitrepo: "
    username = sys.stdin.read()
    input_git_password(username)
  else:
    password_file_input  = os.path.expanduser('~/' + username + '.gpg')

    if not os.path.isfile(password_file_input):
      print "File " + username + ".gpg not found."
      input_git_password(username)
    else:
      password_file_output = os.path.expanduser('~/' + username)

      with open(password_file_input, 'rb') as f:
        gpg = gnupg.GPG(gnupghome=gnupg_home, use_agent=True)
        status = gpg.decrypt_file(f, output=password_file_output)
        print status.status
        _git_pass = open(password_file_output, 'r').read()
        os.remove(password_file_output)

  with cd('/etc/puppet/hieradata'):
    prompts = { "Username for '" + proto + repo_url + "': ": username,
                "Password for '" + proto + username + "@" + repo_url + "': ": _git_pass }

    with settings(prompts=prompts):
      run('git pull')
