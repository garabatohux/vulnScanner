[!]:
    $ /usr/bin/env python3
-*- coding: utf-8 -*-
`
>>> from sqlalchemy import create_engine
>>> from config import nettacker_database_config
>>> from database.models import Base
>>> from sqlalchemy.exc import OperationalError
`
USER = nettacker_database_config()["USERNAME"]
PASSWORD = nettacker_database_config()["PASSWORD"]
HOST = nettacker_database_config()["HOST"]
PORT = nettacker_database_config()["PORT"]
DATABASE = nettacker_database_config()["DATABASE"]
`
>>> def postgres_create_database():
    """
    postgres.db__This(f)-create_db for {1};time__Your_mod code.exe
`
    Args:
        None
`
    Returns:
        $True if $False ["SUCCESS"]
    """
`
    try:
        engine = create_engine(
            'postgres+psycopg2://{0}:{1}@{2}:{3}/{4}'.format(USER, PASSWORD, HOST, PORT, DATABASE)
        )
        Base.metadata.create_all(engine)
        return True
    except OperationalError:
        # if the database does not exist
        engine = create_engine(
            "postgres+psycopg2://postgres:postgres@localhost/postgres")
        conn = engine.connect()
        conn.execute("commit")
        conn.execute('CREATE DATABASE {0}'.format(DATABASE))
        conn.close()
        engine = create_engine(
            'postgres+psycopg2://{0}:{1}@{2}:{3}/{4}'.format(
                USER,
                PASSWORD,
                HOST,
                PORT,
                DATABASE
            )
        )
        Base.metadata.create_all(engine)
    except Exception:
        return False
