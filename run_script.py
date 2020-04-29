# -*- coding: utf-8 -*-
# **********************************************************************;
# Project           : bCIRT
# License           : GPL-3.0
# Program name      : tasks/scriptmanager/run_script.py
# Author            : Balazs Lendvay
# Date created      : 2019.07.27
# Purpose           : Script manager script to run commands/scripts file for the bCIRT
# Revision History  : v1
# Date        Author      Ref    Description
# 2019.07.29  Lendvay     1      Initial file
# 2019.08.12  Lendvay     2      commented out the debug prints
# **********************************************************************;
# https://www.daniweb.com/programming/software-development/code/257449/a-command-class-to-run-shell-commands
# https://pymotw.com/2/argparse/
from subprocess import Popen, PIPE, STDOUT
import sys

class run_script_class(object):
    """
    Run a python script and capture its output string, error string and exit status
    input: interpreter, command, argument="", timeout=300
    output:

    """
    def __init__(self, interpreter, command, argument=None, timeout=None):
        self.commandline = str(interpreter)
        if command != "None":
            self.commandline = self.commandline + " " + str(command)
            # print(self.commandline)
        if argument != "None" and argument != "":
            self.commandline = self.commandline + " " + str(argument)
            # print(self.commandline)
        self.command = self.commandline.split()
        self.timeout = None
        if timeout:
            self.timeout = timeout

    def runscript(self, atofile=False, afilepath=None):
        """
        runs a script using the given parameters
        :input: command, timeout
        :return: {{"command:": X, "status": S, "error": E, "output": O, "PID": P}}
        """
        try:
            process = Popen(self.command, universal_newlines=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT)
            pid = process.pid
            if self.timeout:
                process.wait(self.timeout)
            self.output, self.error = process.communicate()
            self.status = process.returncode
            # self.exitstatus = process.poll()
        except Exception as e:
            return {"command": self.command, "status": "1", "error": "1", "output": str(e)}
        if self.error == None:
            if atofile and afilepath:
                outfile = open(afilepath, 'w')
                for line in self.output:
                    sys.stdout.write(line)
                    outfile.write(line)
                outfile.close()
            return {"command": self.command, "status": self.status, "error": "0", "output": self.output, "pid": pid}
        else:
            return {"command": self.command, "status": self.status, "error": self.error, "output": self.output, "pid": pid}

    def runcmd(self):
        """
        runs a script using the given parameters
        :input: command, timeout
        :return: {{"command:": X, "status": S, "error": E, "output": O, "PID": P}}
        """
        try:
            process = Popen(self.commandline, shell=True, universal_newlines=True, stdout=PIPE, stderr=STDOUT)
            pid = process.pid
            process.wait(self.timeout)
            self.output, self.error = process.communicate()
            self.status = process.returncode
            # self.exitstatus = process.poll()
        except Exception as e:
            return {"command": self.command, "status": "1", "error": "1", "output": str(e)}
        if self.error == None:
            return {"command": self.command, "status": self.status, "error": "0", "output": self.output, "pid": pid}
        else:
            return {"command": self.command, "status": self.status, "error": self.error, "output": self.output, "pid": pid}

# output_dict = run_script_class(interpreter='/usr/bin/file', command='/tmp/bCIRT_memimage_analyser/exports/*').runcmd()
# output_list = output_dict['output'].split('\n')
# for outitem in output_list:
#     if outitem.startswith('None:'):
#         print("[i] Skipping None")
#     elif outitem:
#         filename, filetype = outitem.split(':')
#         filetype = filetype.strip(' ')
#         md5hash = run_script_class(interpreter='/usr/bin/md5sum',
#                                    command=filename).runcmd()
#         filemd5 = md5hash['output'].split(' ', maxsplit=1)[0]
#         sha256hash = run_script_class(interpreter='/usr/bin/md5sum',
#                                    command=filename).runcmd()
#         filesha256 = sha256hash['output'].split(' ', maxsplit=1)[0]
#         outvalue = "%s|%s|%s|%s" % (filemd5, filesha256,filename, filetype)
#         print(outvalue)
#     else:
#         pass