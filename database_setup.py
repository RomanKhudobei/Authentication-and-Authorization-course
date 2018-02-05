import os
import sys

from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine


Base = declarative_base()

class User(Base):
    __tablename__ = 'user'

    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))
    id = Column(Integer, primary_key=True)

class Restaurant(Base):
    __tablename__ = 'restaurant'

    name = Column( String(80), nullable=False )

    id = Column(Integer, primary_key=True)

    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        item = {
            'id': self.id,
            'name': self.name
        }
        return item

class MenuItem(Base):
    __tablename__ = 'menu_item'

    name = Column( String(80), nullable=False )

    id = Column(Integer, primary_key=True)

    course = Column( String(250) )

    description = Column( String(250) )

    price = Column( String(8) )

    restaurant_id = Column(Integer, ForeignKey('restaurant.id'))
    restaurant = relationship(Restaurant)

    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        item = {
            'id': self.id,
            'name': self.name,
            'price': self.price,
            'description': self.description,
            'course': self.course
        }
        return item


engine = create_engine('sqlite:///restaurantmenu_with_users.db')
Base.metadata.create_all(engine)