#!/user/bin/env python3
# -*- coding: utf-8 -*-
# example python3 bcirt_volatility_collect.py --memfile /tmp/memimage.raw --id IR_111 --profile WinXPSP3x86
# python3 bcirt_volatility_collect.py --memfile /tmp/memimage.raw --id IR_111 --profile WinXPSP3x86 --volpath=/stuff/work/volatility/vol.py
from sqlite_manager import SQLITE_manager


class VolatilityCollectInit:
    PATH = None

    volatilitycollect_list = [(False, 'Determine image information', 'Retrieve image information', 'sqlite', 'imageinfo', '-v'),
                (True, 'List running processes', 'Retrieve list of running processes', 'sqlite', 'pslist', '-v'),
                (True, 'Scan for processes', 'Retrieve list of running processes', 'sqlite', 'psscan', '-v'),
                (True, 'Scan for processes', 'Retrieve list of running processes', 'sqlite', 'cmdline', '-v'),
                (True, 'Tree list running processes', 'Retrieve list of running processes', 'sqlite', 'pstree', '-v'),
                (True, 'Tree list running processes', 'Retrieve list of running processes', 'file', 'pstree', '-v'),
                (True, 'Cross check process lists',
                 'If first column is False and any of the others is true, that needs attention', 'sqlite',
                 'psxview', '-v'),
                (False, 'List network connections', 'List network connections', 'sqlite', 'netscan', '-v'),
                (False, 'List network connections', 'List network connections', 'sqlite', 'connscan', '-v'),
                (False, 'List network connections', 'List network connections', 'sqlite', 'connections', '-v'),
                (False, 'List API hooks', 'Lists API hooks that need attention', 'sqlite', 'apihooks', '-v'),
                (False, 'Find malicious process injections', 'Find malicious process injections', 'sqlite', 'malfind',
                 '-v'),
                (False, 'Firewall status', 'Check registry key containing Windows firewall status', 'sqlite',
                 'printkey', ' -K "ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"'),
                (True, 'Export malfind items', 'Export malfind items', 'dump', 'malfind', '-v'),
                ]

    # Generate Volatilitycollect list start
    volatilitycollect_sql_create = '''
        CREATE TABLE volatilitycollect (
            id INTEGER PRIMARY KEY,
            enabled INTEGER NOT NULL DEFAULT 1,
            outtype TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            command TEXT NOT NULL,
            args TEXT NOT NULL
            )
        '''
    volatilitycollect_sql_insert = '''
        INSERT INTO volatilitycollect (enabled, title, description, outtype, command, args) 
            VALUES (?, ?, ?, ? ,?, ?)'''
    volatilitycollect_sql_list = '''SELECT outtype,command,args from volatilitycollect where enabled=1'''

    volatilitycollect_sql = [
        volatilitycollect_sql_create,
        volatilitycollect_sql_list,
        volatilitycollect_sql_insert,
        volatilitycollect_list
    ]
    # Generate Volatilitycollect list end

    processcheck1_list = [(True, 'system', None, None, 1, 'local system', 'boot'),
                         (True, 'sms.exe', 'system', 'c:\Windows\System32\smss.exe', 0, 'local system', 'boot'),
                         (True, 'wininit.exe', None, 'c:\Windows\System32\wininit.exe', 1, 'local system', 'boot'),
                         (True, 'taskhost.exe', 'services.exe', 'c:\Windows\System32\taskhost.exe', 0, 'any', 'any'),
                         (True, 'lsass.exe', 'wininit.exe', 'c:\Windows\System32\lsass.exe', 1, 'local system', 'boot'),
                         (True, 'winlogon.exe', None, 'c:\Windows\System32\winlogon.exe', 0, 'local system', 'any'),
                         (True, 'iexplore.exe', 'explorer.exe', 'c:\Program Files\Internet Explorer\iexplore.exe', 0,
                          'local users', 'any'),
                         (True, 'explorer.exe', 'userinit.exe', 'c:\Windows\explorer.exe', 0, 'local users', 'any'),
                         (True, 'lsm.exe', 'wininit.exe', 'c:\Windows\System32\lsm.exe', 1, 'local system', 'boot'),
                         (True, 'svchost.exe', 'services.exe', 'c:\Windows\System32\svchost.exe', 0, 'local system, network service, local service', 'after boot'),
                         (True, 'services.exe', 'wininit.exe', 'c:\Windows\System32\services.exe', 1, 'local system', 'boot'),
                         (True, 'csrss.exe', None, 'c:\Windows\System32\csrss.exe', 0, 'local system', 'boot'),
                         (True, 'lsaiso.exe', 'wininit.exe', 'c:\Windows\System32\lsaiso.exe', 1, 'local system', 'any'),
                         ]

    # Generate Volatility Checks list start
    processcheck1_sql_create = '''
        CREATE TABLE processcheck1 (
            id INTEGER PRIMARY KEY,
            enabled INTEGER NOT NULL DEFAULT 1,
            process TEXT NOT NULL,
            parent TEXT,
            path TEXT,
            singleton INTEGER NOT NULL DEFAULT 1,
            account TEXT NOT NULL,
            starttime TEXT NOT NULL
            )
        '''
    processcheck1_sql_insert = '''
        INSERT INTO processcheck1 (enabled, process, parent, path, singleton, account, starttime) 
            VALUES (?, ?, ?, ? ,?, ?, ?)
            '''
    processcheck1_sql_list = '''
    SELECT id, enabled, process, parent, path, singleton, account, starttime 
        FROM processcheck1 
        WHERE enabled=1
        '''

    processcheck1_sql = [
        processcheck1_sql_create,
        processcheck1_sql_list,
        processcheck1_sql_insert,
        processcheck1_list
    ]
    # Generate Volatilitycollect list end

    # (True, '', '', '', ''),
    def __init__(self, pPATH=None):
        self.PATH = pPATH
        pass

    def generate_records(self, pqueries):
        # defaults
        pmyquery_sql_create = pqueries[0]
        pmyquery_sql_list = pqueries[1]
        pmyquery_sql_insert = pqueries[2]
        volatilitycollect_list = pqueries[3]

        myconn = SQLITE_manager(pPATH=self.PATH).db_connect()
        volatilitycollect = SQLITE_manager(pPATH=self.PATH).db_create_table(
            pconn=myconn,
            pquery=pmyquery_sql_create
        )
        # listing tables
        alist = SQLITE_manager(pPATH=self.PATH).db_list_tables(
            pconn=myconn
        )

        # insert values
        for myitem in volatilitycollect_list:
            SQLITE_manager(pPATH=self.PATH).db_insert_values(
                pconn=myconn,
                pquery=pmyquery_sql_insert,
                pvalues=myitem
            )

        allvals = SQLITE_manager(pPATH=self.PATH).db_list_values_all(
            pconn=myconn,
            pquery=pmyquery_sql_list
        )

        SQLITE_manager(pPATH=self.PATH).db_disconnect(pconn=myconn)
        # print("[i] Database created: %s" % self.PATH)

        print("Functions enabled:")
        counter = 0
        for oneitem in allvals:
            counter = counter + 1
            print("%i. %s" % (counter, oneitem))

    def db_init(self):
        self.generate_records(self.volatilitycollect_sql)
        self.generate_records(self.processcheck1_sql)

def main():

    # volatilitycollect_sql = [
    #     '''
    #     CREATE TABLE volatilitycollect (
    #         id INTEGER PRIMARY KEY,
    #         enabled INTEGER NOT NULL DEFAULT 1,
    #         outtype TEXT NOT NULL,
    #         title TEXT NOT NULL,
    #         description TEXT NOT NULL,
    #         command TEXT NOT NULL,
    #         args TEXT NOT NULL
    #         )
    #     ''',
    #     "INSERT INTO volatilitycollect (enabled, title, description, outtype, command, args) "
    #      "VALUES (?, ?, ?, ? ,?, ?)",
    #     "SELECT outtype,command,args from volatilitycollect where enabled=1",
    #     [(True, 'Determine image information', 'Retrieve image information', 'sqlite', 'imageinfo', '-v'),
    #       (True, 'List running processes', 'Retrieve list of running processes', 'sqlite', 'pslist', '-v'),
    #       (False, 'Scan for processes', 'Retrieve list of running processes', 'sqlite', 'psscan', '-v'),
    #       (True, 'Tree list running processes', 'Retrieve list of running processes', 'sqlite', 'pstree', '-v'),
    #       (True, 'Tree list running processes', 'Retrieve list of running processes', 'file', 'pstree', '-v'),
    #       (False, 'Cross check process lists',
    #      'If first column is False and any of the others is true, that needs attention', 'sqlite',
    #      'psxview', '-v'),
    #       (False, 'List command line calls', 'List command line calls', 'sqlite', 'cmdline', '-v'),
    #       (False, 'List network connections', 'List network connections', 'sqlite', 'netscan', '-v'),
    #       (False, 'List network connections', 'List network connections', 'sqlite', 'connscan', '-v'),
    #       (False, 'List network connections', 'List network connections', 'sqlite', 'connections', '-v'),
    #       (False, 'List API hooks', 'Lists API hooks that need attention', 'sqlite', 'apihooks', '-v'),
    #       (False, 'Find malicious process injections', 'Find malicious process injections', 'sqlite', 'malfind', '-v'),
    #       (False, 'Firewall status', 'Check registry key containing Windows firewall status', 'sqlite',
    #        'printkey', ' -K "ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"'),
    #       ]
    # ]
    # VolatilityCollectInit().generate_records(volatilitycollect_sql)
    pass

main()
print("[i] Database generation finished.")
