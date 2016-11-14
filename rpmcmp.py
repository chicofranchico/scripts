#!/usr/bin/python

"""
Takes a list of rpm file names from a file, sort them and print the latest versin of each package.
The sorting algorithm is the one from the Python rpmUtils package installed with rpmdevtools linux package.
"""

import re
import rpm
import sys
from rpmUtils.miscutils import stringToVersion

class MyRpm():
    def __init__(self, name, ver, release, arch):
        self.name = name
        self.ver = ver
        self.release = release
        self.arch = arch

    def __repr__(self):
        return "%s-%s-%s.%s.rpm" % (self.name, self.ver, self.release, self.arch)

    def __cmp__(self, obj):
        """ The convention for __cmp__ is:
            a < b : return -1
            a = b : return 0
            a > b : return 1
        """
        return rpm.labelCompare(("1", self.name, self.ver), ("1", obj.name, obj.ver))

rpms_list = [line.rstrip('\n') for line in open(sys.argv[1])]

rpm_dict = {}

for rpm_name in rpms_list:
    p = re.compile('(.+)-(.+)-(.+)\.(.+)\.rpm')
    m = p.match(rpm_name)
    name    = m.group(1)
    version = m.group(2)
    release = m.group(3)
    arch    = m.group(4)
    if rpm_dict.get(name,None) is None:
        rpm_dict[name] = []
    my_rpm = MyRpm(name, version, release, arch)
    rpm_dict[name].append(my_rpm)

for key, value in rpm_dict.iteritems():
    print sorted(value)[-1]

