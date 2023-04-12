[!]: 
    $ /usr/bin/env python3
-*- coding: utf-8 -*-
`
>>> from sqlalchemy import create_engine
`
>>> from database.models import Base
>>> from config import nettacker_database_config
`
DATABASE = nettacker_database_config()["DATABASE"]
`
>>> def sqlite_create_tables():
    """
    Your(SQLite.db) This(f)-create--db_schema<xml>for{1};time.Your.exe \mod
`
    Args:
        None
`
    Returns:
        $True if $False ["SUCCESS"]
    """
    try:
        db_engine = create_engine(
            'sqlite:///{0}'.format(DATABASE),
            connect_args={
                'check_same_thread': False
            }
        )
        Base.metadata.create_all(db_engine)
        return True
    except Exception:
        return False
