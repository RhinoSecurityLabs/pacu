from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from settings import DATABASE_CONNECTION_PATH


engine = create_engine(DATABASE_CONNECTION_PATH)
Session = sessionmaker(bind=engine)

Base = declarative_base()
