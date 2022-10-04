# The Engine is the starting point for any SQLAlchemy application. 
# It’s “home base” for the actual database and its DBAPI,
# delivered to the SQLAlchemy application through a connection pool and a Dialect,
# which describes how to talk to a specific kind of database/DBAPI combination.
sqlalchemy import create_engine
from sqlalchemy.engine.base import Engine

# declarative_base() is a factory function that constructs a base class
# for declarative class definitions (which is assigned to the Base variable in your example)
# https://docs.sqlalchemy.org/en/13/orm/extensions/declarative/api.html?highlight=declarative_base#sqlalchemy.ext.declarative.declarative_base
# Construct a base class for declarative class definitions.
# 
# The new base class will be given a metaclass that produces appropriate Table objects 
# and makes the appropriate mapper() calls based on the information provided 
# declaratively in the class and any subclasses of the class.
from sqlalchemy.ext.declarative import declarative_base

# https://docs.sqlalchemy.org/en/13/orm/session_api.html#sqlalchemy.orm.session.sessionmaker
# The sessionmaker factory generates new Session objects when called, 
# creating them given the configurational arguments established here.
from sqlalchemy.orm import sessionmaker

# A path to a SQLite database.
# https://www.sqlite.org/index.html
from pacu.settings import DATABASE_CONNECTION_PATH

# https://docs.sqlalchemy.org/en/13/core/engines.html?highlight=create_engine#sqlalchemy.create_engine
# Create a new Engine instance.
engine: Engine = create_engine(DATABASE_CONNECTION_PATH)
Session: sessionmaker = sessionmaker(bind=engine)


Base = declarative_base()
