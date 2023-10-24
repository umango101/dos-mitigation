import pandas as pd
from pprint import pprint
import psycopg2
from psycopg2 import sql
from psycopg2.extensions import AsIs
from psycopg2.extras import execute_values

from psycopg2.extras import Json
from psycopg2.extensions import register_adapter
register_adapter(dict, Json)


def result_as_list(result):
    try:
        return [i[0] for i in result]
    except:
        return result


def result_as_value(result):
    try:
        return result[0][0]
    except:
        try:
            return result[0]
        except:
            return result

def parse_hostname(hostname):
    prefixes = {
        "a": "attacker",
        "c": "client",
        "s": "server",
        "r": "router",
        "sink": "sink"
    }
    hostgroup = hostname.rstrip('0123456789')
    hostnum = hostname[len(hostgroup):]
    return hostgroup, hostnum


class Connection(object):
    def __init__(self, db_name="postgres", autocommit=True):
        self.conn=psycopg2.connect(dbname=db_name)
        self.conn.set_session(autocommit=autocommit)

    
    def __enter__(self):
        return self


    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


    def close(self):
        self.conn.close()


    def autocommit(self, val):
        self.conn.set_session(autocommit=val)


    def db_name(self):
        return self.conn.get_dsn_parameters()['dbname']


    def db_query(self, query, *args):
        with self.conn.cursor() as c:
            c.execute(sql.SQL(query), *args)
            try:
                res = c.fetchall()
            except psycopg2.ProgrammingError as e:
                res = []
        return res


    def rollback(self):
        # query = "ROLLBACK"
        # _ = self._query(query)
        self.conn.rollback()


    def execute_commands(self, command_file):
        with open(command_file, 'r') as f:
            sqlFile = f.read()
            sqlCommands = sqlFile.split(';')

        with self.conn.cursor() as c:
            for command in sqlCommands:
                if command.isspace():
                    continue
                try:
                    c.execute(command)
                except Exception as e:
                    print("Command skipped: {}\n Error: {}".format(command, e))


    def table_list(self):
        query = "select relname from pg_class where relkind='r' and relname !~ '^(pg_|sql_)';"
        result = self.db_query(query)
        return result_as_list(result)


    def table_add(self, table):
        query = "CREATE TABLE {}".format(table)
        self.db_query(query)


    def table_drop(self, table):
        query = "DROP TABLE {}".format(table)
        self.db_query(query)


    def column_list(self, table):
        query = "SELECT column_name, data_type FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name = '{}'".format(table)
        return self.db_query(query)


    def describe(self):
        d = {}
        for table in self.table_list():
            d[table] = self.column_list(table)
        pprint(d)


    def list_unique(self, table, column):
        query = "SELECT DISTINCT {} from {}".format(column, table)
        return self.db_query(query)


    def value_in_column(self, table, column, value):
        query = "select exists (select 1 from {} where {} = '{}')".format(table, column, value)
        result = self.db_query(query)
        return result_as_value(result)


    def row_count(self, table):
        query = "SELECT count(*) AS exact_count FROM {}".format(table)
        result = self.db_query(query)
        return result_as_value(result)


    def row_count_where(self, table, condition):
        query = "SELECT count(*) AS exact_count FROM {} WHERE {}".format(table, condition)
        result = self.db_query(query)
        return result_as_value(result)


    def row_counts(self, table_list=[]):
        if not table_list:
            table_list = self.table_list()

        d = {}
        for table in table_list:
            d[table] = self.row_count(table)
        pprint(d)

    def row_counts_where(self, condition, table_list=[]):
        if not table_list:
            table_list = self.table_list()

        d = {}
        for table in table_list:
            d[table] = self.row_count(table)
        pprint(d)


    def insert_dict_as_row(self, table:str, d: dict):
        columns = d.keys()
        values = [d[column] for column in columns]
        query = "insert into {} (%s) values %s".format(table)
        with self.conn.cursor() as c:
            c.execute(query, (AsIs(','.join(columns)), tuple(values)))


    def insert_dicts_as_rows(self, table:str, l: list):
        columns = l[0].keys()
        query = "INSERT INTO {} ({}) VALUES %s".format(table, ','.join(columns))

        # convert projects values to list of lists
        values = [[v for v in d.values()] for d in l]
        with self.conn.cursor() as c:
            execute_values(c, query, values)

    def bulk_insert(self, table, df):
        # tuples = [tuple(x) for x in df.to_numpy()]
        # cols = ','.join(list(df.columns))
        # query  = "INSERT INTO %s(%s) VALUES %%s" % (table, cols)
        # with self.conn.cursor() as c:
        #     execute_values(c, query, tuples)
        df_columns = list(df)
        columns = ",".join(df_columns)
        values = "VALUES({})".format(",".join(["%s" for _ in df_columns])) 
        query = "INSERT INTO {} ({}) {}".format(table,columns,values)

        with self.conn.cursor() as c:
            psycopg2.extras.execute_batch(c, query, df.values)

    def nickname_id(self, table, nickname, column="nickname"):
        id = result_as_value(self.db_query("select id from {} where {}='{}'".format(table, column, nickname)))
        return id



def db_list():
    query = "SELECT datname FROM pg_database"
    with Connection() as conn:
        return conn.db_query(query)


def db_add(dbname, schema=None):
    query = "CREATE database {}".format(dbname)
    with Connection() as conn:
        _ = conn.db_query(query)

    if schema != None:
        with Connection(dbname) as conn:
            conn.execute_commands(schema)


def db_drop(dbname):
    query = "DROP database {}".format(dbname)
    with Connection() as conn:
        _ = conn.db_query(query)
