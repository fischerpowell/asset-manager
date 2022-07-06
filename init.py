import psycopg2
from psycopg2 import sql
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import configparser

#Used to initialize the PostgreSQL database


config = configparser.ConfigParser()

config.read('inventory.conf')

def create_db():

    conn = psycopg2.connect(database='postgres',
        user=config.get('postgres', 'user'),
        password=config.get('postgres', 'password'),
        host=config.get('postgres', 'host_ip'),
        port=config.get('postgres', 'host_port'))

    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)

    cursor = conn.cursor()

    cursor.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(inventory_database_name)))
    conn.commit()

def create_tables():
    conn = psycopg2.connect(database=inventory_database_name,
        user=config.get('postgres', 'user'),
        password=config.get('postgres', 'password'),
        host=config.get('postgres', 'host_ip'),
        port=config.get('postgres', 'host_port'))

    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE inventory (
    barcode INT PRIMARY KEY,
    serial TEXT,
    model TEXT,
    category TEXT,
    department TEXT,
    date_purchased DATE,
    date_retired DATE,
    last_hostname TEXT
    );''')

    cursor.execute('''CREATE TABLE transactions (
    transactionid INT PRIMARY KEY,
    barcode INT,
    inout TEXT,
    username TEXT,
    assignedto TEXT,
    hostname TEXT,
    date DATE
    );''')

    cursor.execute('''CREATE TABLE hostnames (
    hostname TEXT PRIMARY KEY,
    description TEXT,
    active BOOL
    );''')

    cursor.execute('''CREATE TABLE logs (
    username TEXT,
    actiontype TEXT,
    database TEXT,
    timestamp TIMESTAMP,
    recordcopy TEXT
    );''')

    cursor.execute('''CREATE TABLE dropdowns (
    devicetype TEXT,
    devicedepartment TEXT
    );''')

    cursor.execute('''ALTER TABLE transactions
	ADD CONSTRAINT fk_hostnames
	FOREIGN KEY (hostname)
	REFERENCES hostnames (hostname)
	ON DELETE SET NULL
    ON UPDATE CASCADE;''')

    conn.commit()

if __name__ == '__main__':
    inventory_database_name = config.get('postgres', 'database_name')
    create_db()
    create_tables()