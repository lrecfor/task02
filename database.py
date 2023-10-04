from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
import config
from sqlalchemy import String, Column, Integer


engine = create_engine(config.DATABASE_URL, echo=False)

Base = declarative_base()


class Scan(Base):
    __tablename__ = "scan"
    id = Column(Integer, primary_key=True, autoincrement=True)
    host = Column(String)
    ports = Column(String)


Base.metadata.create_all(bind=engine)

Session = sessionmaker(bind=engine)
session = Session()


def add(data):
    # function for adding [data] to database
    try:
        session.add(data)
        session.commit()
    except Exception as e:
        raise
    finally:
        session.close()


def get(data):
    # function for getting data from database by [data]
    try:
        res = session.query(Scan).filter_by(username=data).first()
        return res
    except Exception as e:
        raise
    finally:
        session.close()
