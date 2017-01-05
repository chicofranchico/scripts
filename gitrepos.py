#!/bin/env python

import argparse, os, sys, requests
from git import Repo, GitCommandError

from requests.packages.urllib3.exceptions import InsecureRequestWarning


def main():
  parser = argparse.ArgumentParser(description='Recursively clones/pulls gitlab repositories')
  parser.add_argument('-u', '--url', required=True,
                help='gitlab URL')
  parser.add_argument('-t', '--private-token', required=True,
                help='private token generated in gitlab')
  parser.add_argument('-o', '--output-dir', required=True,
                help='a directory where the repositories are stored')
  parser.add_argument('-n', '--no-ssl-verify', action='store_false',
                dest='ssl_verify',
                help='do not verify SSL certificates (dangerous)')
  args = parser.parse_args(sys.argv[1:])

  url = args.url + '/api/v3/'
  tok = 'private_token=' + args.private_token

  requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
  response = requests.get(url + 'groups?per_page=100&' + tok, verify=args.ssl_verify)

  data = response.json()

  for group in data:
    group_id = group.get('id', None)

    print 'Group projects: ' + group.get('name', None)

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    response = requests.get(url + 'groups/' + str(group_id) + '/?' + tok, verify=args.ssl_verify)

    data_groups = response.json()

    for project in data_groups['projects']:
      http_url = project['http_url_to_repo']
      project_name = http_url.rsplit('/',1)[-1].rsplit('.',1)[0]
      print '	' + project_name,

      repo_dir = args.output_dir + '/' + http_url.rsplit('/',1)[0].rsplit('/',1)[-1] + '/' + project_name
      if os.path.exists(repo_dir):
        repo = Repo(repo_dir)
        try:
          repo.remotes.origin.pull()
          print '		[Pull OK]'
        except GitCommandError as e:
          print '		[Git Command Error (%s)]' % e.status
      else:
        Repo.clone_from(http_url, repo_dir)
        print '		[Clone OK]'

if __name__ == '__main__':
  main()
