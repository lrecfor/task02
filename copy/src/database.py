"""Module providing functions for working with a database."""

from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy import String, Column, Integer, create_engine
import config
from utils import InsertDatabaseErrorException

engine = create_engine(config.DATABASE_URL, echo=False)

Base = declarative_base()


class Hosts(Base):
    """Class representing hosts table."""

    __tablename__ = "hosts"
    host_id = Column(
            Integer,
            primary_key=True,
            autoincrement=True)
    ip_address = Column(String)


class Ports(Base):
    """Class representing ports table."""

    __tablename__ = "ports"
    port_id = Column(
            Integer,
            primary_key=True,
            autoincrement=True)
    host_id = Column(Integer)
    port_number = Column(Integer)
    status = Column(String)


Base.metadata.create_all(bind=engine)

Session = sessionmaker(bind=engine)
session = Session()


def add(data):
    """
    Add data to database.

    :param data: Object of class of table in the database.
    :return:
    """
    session.add(data)
    session.commit()
    session.close()


def insert_ports(host, ports):
    """
    Insert result of scanning ports to database.

    :param host: IP address of host.
    :param ports: List of strings. Each string is a port and its status.
    :return:
    """
    new_host = Hosts(ip_address=host)
    session.add(new_host)
    session.commit()

    host_id = new_host.host_id
    if isinstance(ports, str):
        ports = [ports]

    for port in ports:
        try:
            session.add(Ports(
                    host_id=host_id,
                    port_number=port.split("\t\t")[0],
                    status=port.split("\t\t")[1].strip('\n')))
        except Exception as error_text:
            raise InsertDatabaseErrorException(error_text) from error_text

    session.commit()
    session.close()


def get_ports_by_host(host):
    """
    Get ports status from database by host.

    :param host: IP address of host.
    :return: List of strings. Each string is a port and its status.
    """

    host_id = session.query(Hosts).filter_by(ip_address=host).first().host_id
    res = session.query(Ports).filter_by(host_id=host_id).all()
    res = [f"{port.port_number}\t\t{port.status}" for port in res]
    session.close()
    return res
