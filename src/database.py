from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
import config
from sqlalchemy import String, Column, Integer

engine = create_engine(config.DATABASE_URL, echo=False)

Base = declarative_base()


class Hosts(Base):
    __tablename__ = "hosts"
    host_id = Column(
            Integer,
            primary_key=True,
            autoincrement=True)
    ip_address = Column(String)


class Ports(Base):
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
    try:
        session.add(data)
        session.commit()
    except Exception as e:
        raise
    finally:
        session.close()


def insert_ports(host, ports):
    """
    Insert result of scanning ports to database.

    :param host: IP address of host.
    :param ports: List of strings. Each string is a port and its status.
    :return:
    """
    try:
        new_host = Hosts(ip_address=host)
        session.add(new_host)
        session.commit()

        host_id = new_host.host_id
        if isinstance(ports, str):
            ports = [ports]

        for port in ports:
            session.add(Ports(
                    host_id=host_id,
                    port_number=port.split("\t\t")[0],
                    status=port.split("\t\t")[1].strip('\n')))

        session.commit()
    except Exception as e:
        raise
    finally:
        session.close()


def get_ports_by_host(host):
    """
    Get ports status from database by host.

    :param host: IP address of host.
    :return: List of strings. Each string is a port and its status.
    """

    try:
        host_id = session.query(Hosts).filter_by(ip_address=host).first().host_id
        res = session.query(Ports).filter_by(host_id=host_id).all()
        res = [f"{port.port_number}\t\t{port.status}" for port in res]
        return res
    except Exception as e:
        raise
    finally:
        session.close()
