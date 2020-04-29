#!/usr/bin/env python
# -*- coding: utf-8 -*-

#example:
# python bcirt_volatility_collect.py --memfile /tmp/memfile.raw --id IR_111 --profile Win10x64_17134
import subprocess
from sqlite_manager import SQLITE_manager
from bcirt_volatility_init import VolatilityCollectInit
from argparse import ArgumentParser
import os
import sys
from subprocess import Popen, PIPE, STDOUT
from run_script import run_script_class

class VolatilityCheckExecute():

    analysis_dict = {
        'res_processcheck1': '''
        SELECT *
        FROM processcheck1
        JOIN psscan ON lower(psscan.name)=lower(processcheck1.process)
        WHERE processcheck1.enabled=True
        ''',
        'ISSUE_processcheck1_singletoncheck': '''
        SELECT *
        FROM(
            SELECT process,count() as itemcount
            FROM res_processcheck1
            WHERE singleton=True
            GROUP BY process)
        WHERE itemcount>1
        ''',
        'ISSUE_processcheck2_hiddenprocesscheck': '''
            SELECT * 
            FROM psscan
            LEFT JOIN pslist ON psscan.pid = pslist.pid 
            WHERE pslist.id IS NULL
            ''',
        'ISSUE_processcheck3a_wrongparentcheckname': '''
        SELECT res_processcheck1.Name, res_processcheck1.parent,res_processcheck1.PID, res_processcheck1.PPID,PSScan.*
            FROM res_processcheck1
            LEFT JOIN PSScan ON lower(res_processcheck1.parent)=lower(PSScan.Name)
            WHERE lower(PSScan.PID)<>lower(res_processcheck1.PPID)
        ''',
        'ISSUE_processcheck3b_wrongparentcheckpid': '''
        SELECT res_processcheck1.Name, res_processcheck1.parent,res_processcheck1.PID, res_processcheck1.PPID,PSScan.*
            FROM res_processcheck1
            LEFT JOIN PSScan ON lower(res_processcheck1.PPID)=lower(PSScan.PID)
            WHERE lower(PSScan.Name)<>lower(res_processcheck1.parent)
        ''',
        'ISSUE_processcheck4_wincorewrongpath': '''
        SELECT res_processcheck1.process, res_processcheck1.PID, res_processcheck1.path, PSTree.*
            FROM res_processcheck1
            LEFT JOIN pstree ON lower(res_processcheck1.process) = lower(pstree.Name)
            WHERE lower(res_processcheck1.path)<>lower(PSTree.Path)
        ''',
        'MANUAL_processcheck5_starttimes': '''
        SELECT process,PID,PPID,"Offset(P)",starttime, "Time Created", "Time Exited"
            FROM res_processcheck1
            WHERE starttime<>'any'
            ORDER by "Time Created"
        ''',
        'MANUAL_processcheck6_windowscore': '''
        SELECT *
            FROM PSTree
            WHERE Name like '%system%' OR
            Name like '%wininit%' OR
            Name like '%lsass%' OR
            Name like '%lsaiso%' OR
            Name like '%lsm%' OR
            Name like '%services%' OR
            Name like '%sms%' OR
            Name like '%taskhost%' OR
            Name like '%winlogon%' OR
            Name like '%eixplore%' OR
            Name like '%explorer%' OR
            Name like '%svchost%' OR
            Name like '%csrss%'
        ''',
        'MANUAL_processcheck7a_windowsnotcore': '''
        SELECT *
            FROM PSTree
            WHERE not (Name like '%system%' OR
            Name like '%wininit%' OR
            Name like '%lsass%' OR
            Name like '%lsaiso%' OR
            Name like '%lsm%' OR
            Name like '%services%' OR
            Name like '%sms%' OR
            Name like '%taskhost%' OR
            Name like '%winlogon%' OR
            Name like '%eixplore%' OR
            Name like '%explorer%' OR
            Name like '%svchost%' OR
            Name like '%csrss%')
            ORDER BY Name
        ''',
        'MANUAL_processcheck7b_windowsnotcorecount': '''
        SELECT Name,count(*) AS Occured
            FROM PSScan
            WHERE not (Name like '%system%' OR
            Name like '%wininit%' OR
            Name like '%lsass%' OR
            Name like '%lsaiso%' OR
            Name like '%lsm%' OR
            Name like '%services%' OR
            Name like '%sms%' OR
            Name like '%taskhost%' OR
            Name like '%winlogon%' OR
            Name like '%eixplore%' OR
            Name like '%explorer%' OR
            Name like '%svchost%' OR
            Name like '%csrss%')
            GROUP BY NAME
            ORDER BY Occured
        ''',
        'MANUAL_processcheck8_psxviewunlinked': '''
        SELECT *
            FROM PSXview
            WHERE pslist='False' and
            (psscan<>'False' OR
            thrdproc<>'False' OR
            pspcid<>'False' OR
            csrss<>'False' OR
            session<>'False' OR
            deskthrd<>'False')
        '''
    }

    def __init__(self):
        pass

    def myintro(self, pshow=False):
        if pshow:
            print('''
#######################################################
bCIRT memory analysis with volatility v2 and python2
Balazs Lendvay 2020
#######################################################
Requires volatility 2.6.1+ to be configured
#######################################################
#######################################################
            ''')
        else:
            pass

def build_parser():
    parser = ArgumentParser(description='Start bCIRT Volatility Analyzer component.',
                            usage='bcirt_volatility_analyze [options]')
    parser.add_argument("--memfile", required=True, action='store', type=str,
                        help="*Memory file full path")
    parser.add_argument("--id", required=True, action='store', type=str,
                        help="*Investigation name or evidence ID")
    parser.add_argument("--profile", required=True, action='store', type=str,
                        help="*Memory image profile e.g. Win10x64_17134")
    parser.add_argument("--workdir",required=False, action='store', type=str,
                        help="Output directory path, default: /tmp/bCIRT_memimage_analyser")
    parser.add_argument("--pythonpath", required=False, action='store', type=str,
                        help="Path to Python2, default: /usr/bin/python2")
    parser.add_argument("--volpath", required=False, action='store', type=str,
                        help="Volatility path, de3fault: /usr/bin/vol.py")
    args = vars(parser.parse_args())
    return args

def main():
    VolatilityCheckExecute().myintro(pshow=True)

    MYVOLPATH = '/usr/bin/vol.py'
    MYPYTHONPATH = '/usr/bin/python2'
    MYWORKDIR = '/tmp/bCIRT_memimage_analyser'
    args = build_parser()

    if not args['memfile']:
        print("[x] Missing memfile parameter --memfile <FULL PATH TO FILE>")
        exit(1)
    elif not args['id']:
        print("[x] Missing ID parameter --id <Investsigation ID>")
        exit(1)
    elif not args['profile']:
        print("[x] Missing Profile parameter --profile <Profile like Win10x64_17134>")
        exit(1)
    else:
        pass
    if args['volpath']:
        MYVOLPATH = args['volpath']
    if not os.path.exists(MYVOLPATH):
        print("[x] Cannot find volatility at %s!" % MYVOLPATH)
        exit(1)
    if args['pythonpath']:
        MYPYTHONPATH = args['pythonpath']
    if not os.path.exists(MYPYTHONPATH):
        print("[x] Cannot find Python at %s!" % MYPYTHONPATH)
        exit(1)

    if args['workdir']:
        MYWORKDIR = args['workdir']


    mymemfile = args['memfile']
    if not os.path.exists(mymemfile):
        print("[x] Cannot read the memory file!")
        exit(1)
    myid = args['id']
    myprofile = args['profile']

    myresultdir = os.path.join(MYWORKDIR, "results")
    myexportdir = os.path.join(MYWORKDIR, "exports")
    try:
        if not os.path.exists(MYWORKDIR):
            os.makedirs(MYWORKDIR, exist_ok=True)
    except:
        print("[x] Cannot create output directory!")
        exit(1)
    try:
        os.makedirs(myresultdir, exist_ok=True)
    except:
        print("[x] Cannot create results folder!")
        exit(1)
    try:
        os.makedirs(myexportdir, exist_ok=True)
    except:
        print("[x] Cannot create exports folder!")
        exit(1)

    # Generate testing database if not existing already
    mycheckdb = "%s.db" % myid
    # this would be the current dir:
    # mycheckpath=os.path.join(os.path.dirname(__file__), mycheckdb)
    mycheckpath = os.path.join(MYWORKDIR, mycheckdb)

    db_is_new = not os.path.exists(mycheckpath)
    if db_is_new:
        print('[+] New database %s' % mycheckpath)
        VolatilityCollectInit(pPATH=mycheckpath).db_init()
    else:
        print('[i] Existing database, skipping initialization %s' % mycheckpath)

    myconn = SQLITE_manager(pPATH=mycheckpath).db_connect()
    volatilitycollect_sql_list = "SELECT outtype, command, args from volatilitycollect where enabled=1"
    dbresult = SQLITE_manager(pPATH=mycheckpath).db_list_values_all(pconn=myconn, pquery=volatilitycollect_sql_list)
    checkcount = len(dbresult)
    counter = 0
    linecounter=0
    print("Running %i extracts." % checkcount)
    for oneitem in dbresult:
        linecounter = linecounter + 1
        print("%i. %s" % (linecounter, oneitem))

    for myitem in dbresult:
        thecommand = None
        counter = counter+1
        # thecommand = "/stuff/work/volatility/vol.py –-output=sqlite -–output-file=IR_111.sqlite -f /tmp/memimage.raw imageinfo"
        execretval = None
        if myitem[0] == 'sqlite':
            dbout = os.path.join(MYWORKDIR, myid+'.db')
            thecommand = "%s --output=%s --output-file=%s -f %s --profile=%s %s %s" % (
                MYVOLPATH, myitem[0], dbout, mymemfile, myprofile, myitem[1], myitem[2])
            print("[i][%i/%i] Analysing: %s ..." % (checkcount, counter, myitem[1]))
            print("[i] %s" % thecommand)
            execretval = run_script_class(interpreter=MYPYTHONPATH, command=thecommand).runscript()
        elif myitem[0] == 'file':
            # thecommand = "%s -f %s --profile=%s %s %s > %s/%s-%s.txt" % (
            #     MYVOLPATH, mymemfile, myprofile, myitem[1], myitem[2], myresultdir, myid, myitem[1])
            thecommand = "%s -f %s --profile=%s %s %s" % (
                MYVOLPATH, mymemfile, myprofile, myitem[1], myitem[2])
            print("[i][%i/%i] Analysing: %s ..." % (checkcount, counter, myitem[1]))
            print("[i] %s" % thecommand)
            execretval = run_script_class(interpreter=MYPYTHONPATH, command=thecommand).runscript(
                atofile=True,
                afilepath="%s/%s-%s.txt" % (myresultdir, myid, myitem[1]))
        elif myitem[0] == 'dump':
            thecommand = "%s -f %s --profile=%s %s %s -D %s" % (
                MYVOLPATH, mymemfile, myprofile, myitem[1], myitem[2], myexportdir)
            print("[i][%i/%i] Analysing: %s ..." % (checkcount, counter, myitem[1]))
            print("[i] %s" % thecommand)
            execretval = run_script_class(interpreter=MYPYTHONPATH, command=thecommand).runscript()

            # creating database entry for the exported items
            cmd1 = "%s/*" % myexportdir
            cmd2 = "md5sum %s/*" % myexportdir
            cmd3 = "sha1sum %s/*" % myexportdir
            cmd4 = "sha256sum %s/*" % myexportdir
            output_dict = run_script_class(interpreter='/usr/bin/file', command=cmd1).runcmd() # ['output']
            # output_dict = run_script_class(interpreter='/usr/bin/file',
            #                                command='/tmp/bCIRT_memimage_analyser/exports/*').runcmd()

            # Collecting process export hash data
            output_list = output_dict['output'].split('\n')
            for outitem in output_list:
                if outitem.startswith('None:'):
                    print("[i] Skipping None")
                elif outitem:
                    filename, filetype = outitem.split(':')
                    filetype = filetype.strip(' ')
                    md5hash = run_script_class(interpreter='/usr/bin/md5sum',
                                               command=filename).runcmd()
                    filemd5 = md5hash['output'].split(' ', maxsplit=1)[0]
                    sha256hash = run_script_class(interpreter='/usr/bin/md5sum',
                                               command=filename).runcmd()
                    filesha256 = sha256hash['output'].split(' ', maxsplit=1)[0]
                    outvalue = "%s|%s|%s|%s" % (filemd5, filesha256,filename, filetype)
                    print(outvalue)
                else:
                    pass


        # print("%s" % execretval['output'])


        ######
        # Data collection
        dbresult = SQLITE_manager(pPATH=mycheckpath).db_list_values_all(pconn=myconn, pquery=volatilitycollect_sql_list)

    # Generate tests start
    print("[i] Running analysis")

    for key, value in VolatilityCheckExecute().analysis_dict.items():
        try:
            sql_create = "CREATE TABLE %s AS %s" % (key, value)
            sql_list = value
            sqlres = SQLITE_manager(pPATH=mycheckpath).db_list_values_all(pconn=myconn, pquery=sql_list)
            if sqlres:
                SQLITE_manager(pPATH=mycheckpath).db_run_query(pconn=myconn, pquery=sql_create)
                print("[i] Analysis COMPLETED: %s" % key)
            else:
                print("[i] Analysis EMPTY: %s" % key)
        except Exception as e:
            print("[x] Error in analysis %s: %s" % (value, e))
    # Generate tests end
    SQLITE_manager(pPATH=mycheckpath).db_disconnect(pconn=myconn)
main()
print("[i] Data collection finished.")
