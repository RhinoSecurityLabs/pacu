from sqlalchemy import create_engine
from sqlalchemy.engine.base import Engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from pacu.settings import DATABASE_CONNECTION_PATH

engine: Engine = create_engine(DATABASE_CONNECTION_PATH)
Session: sessionmaker = sessionmaker(bind=engine)


Base = declarative_base()
