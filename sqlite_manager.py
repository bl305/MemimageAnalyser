#!/user/bin/env python3
# -*- coding: utf-8 -*-

import os
import sqlite3

class SQLITE_manager():
    PATH = None

    def __init__(self, pPATH=None):
        self.PATH = pPATH
        if self.PATH is None:
            self.PATH = os.path.join(os.path.dirname(__file__), 'memimage_analyser.sqlite3')
        # db_is_new = not os.path.exists(self.PATH)
        # if db_is_new:
        #     print('New database')
        # else:
        #     print('Existing database')

    # create a default path to connect to and create (if necessary) a database
    # called 'memimage_analyseer.sqlite3' in the same directory as this script as default

    def db_connect(self, p_db_path=None):
        if p_db_path is None:
            p_db_path = self.PATH
        con = sqlite3.connect(p_db_path)
        return con

    def db_disconnect(self, pconn=None):
        mycursor = pconn.cursor()
        return mycursor.close()

    def db_create_table(self, pconn=None, pquery=None):
        sql1 = pquery
        retval = None
        mycursor = pconn.cursor()
        try:
            retval = mycursor.execute(sql1)
            pconn.commit()
        except sqlite3.OperationalError as e:
            print("[x] Table cannot be created: %s" % e)
        return retval

    def db_list_tables(self, pconn=None):
        mycursor = pconn.cursor()
        mycursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        return mycursor.fetchall()


    def db_insert_values(self, pconn=None, pquery=None, pvalues=None):
        # product_sql = "INSERT INTO products (name, price) VALUES (?, ?)"
        # >> > cur.execute(product_sql, ('book', 7.99))
        mycursor = pconn.cursor()
        retval = mycursor.execute(pquery, pvalues)
        pconn.commit()
        return retval

    def db_run_query(self, pconn=None, pquery=None):
        mycursor = pconn.cursor()
        retval = mycursor.execute(pquery)
        pconn.commit()
        return retval


    def db_list_values_all(self, pconn=None, pquery=None):
        mycursor = pconn.cursor()
        mycursor.execute(pquery)
        retval = mycursor.fetchall()
        return retval

def main():
    pass
    # # Example:
    # volatilitychecks_sql_create='''
    #     CREATE TABLE volatilitychecks (
    #         id INTEGER PRIMARY KEY,
    #         enabled INTEGER NOT NULL DEFAULT 1,
    #         title TEXT NOT NULL,
    #         description TEXT NOT NULL,
    #         command TEXT NOT NULL,
    #         args TEXT NOT NULL
    #         )
    # '''
    # myconn = SQLITE_manager().db_connect()
    # volatilitychecks = SQLITE_manager().db_create_table(pconn=myconn, pquery=volatilitychecks_sql_create)
    # print(volatilitychecks)
    # # listing tables
    # alist = SQLITE_manager().db_list_tables(pconn=myconn)
    # print(alist)
    #
    # # insert values
    # volatilitychecks_sql_insert = "INSERT INTO volatilitychecks (" \
    #                               "enabled," \
    #                               " title, " \
    #                               "description," \
    #                               " command," \
    #                               " args" \
    #                               ") VALUES (?, ?, ? ,?, ?)"
    # SQLITE_manager().db_insert_values(pconn=myconn,
    #                                   pquery=volatilitychecks_sql_insert,
    #                                   pvalues=(True, 'rule1', 'blabla', 'cmd1', 'arg1'))
    # volatilitychecks_sql_list = "SELECT * from volatilitychecks"
    # allvals = SQLITE_manager().db_list_values_all(pconn=myconn, pquery=volatilitychecks_sql_list)
    # print(allvals)
    #
    #
    # SQLITE_manager().db_disconnect(pconn=myconn)

main()

# print("[i] Program exits...bye!")