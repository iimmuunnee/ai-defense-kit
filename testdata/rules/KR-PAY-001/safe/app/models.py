from sqlalchemy import Column, String
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class VirtualAccount(Base):
    __tablename__ = "virtual_accounts"
    order_id = Column(String, primary_key=True)
    transaction_key = Column(String, nullable=False)
    secret = Column(String, nullable=False)
