#!/usr/bin/python3

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from database_setup import Base, User, Category, Item

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = scoped_session(sessionmaker(bind=engine))
session = DBSession()

user = User(id=1, username='john')

session.add(user)
session.commit() 

# add categories
action = Category(id=1, name='Action')
adventure = Category(id=2, name='Adventure')
comedy = Category(id=3 ,name='Comedy')
drama = Category(id=4, name='Drama')
scifi = Category(id=5, name='Sci-Fi')
session.add(action)
session.add(adventure)
session.add(comedy)
session.add(drama)
session.add(scifi)
session.commit()


# add categories items
diehard = Item(name='Die Hard',
               description='John McClane, officer of the NYPD, tries to save '
                           'his wife Holly Gennaro and several others that '
                           'were taken hostage by German terrorist Hans Gruber'
                           ' during a Christmas party at the Nakatomi Plaza in'
                           ' Los Angeles.',
               category_id=1,
               user_id=1)
killbill = Item(name='Kill Bill Vol.1',
                description='A former assassin known as The Bride wakens from '
                            'a four-year coma. The child she carried in her '
                            'womb is gone. Now she must wreak vengeance on the'
                            ' team of assassins who betrayed her - a team she '
                            'was once part of',
                category_id=1,
                user_id=1)
speed = Item(name='Speed',
             description='A young police officer must prevent a bomb exploding'
                         ' aboard a city bus by keeping its speed above 50 '
                         'mph.',
             category_id=1,
             user_id=1)

session.add(diehard)
session.add(killbill)
session.add(speed)

jones = Item(name='Raiders of the Lost Ark',
             description='In 1936, archaeologist and adventurer Indiana Jones '
                         'is hired by the U.S. government to find the Ark of '
                         'the Covenant before Adolf Hitler\'s Nazis can obtain'
                         ' its awesome powers',
             category_id=2,
             user_id=1)
mitty = Item(name='The Secret Life of Walter',
             description='When his job along with that of his co-worker are '
                         'threatened, Walter takes action in the real world '
                         'embarking on a global journey that turns into an '
                         'adventure more extraordinary than anything he could '
                         'have ever imagined.',
             category_id=2,
             user_id=1)
robinhood = Item(name='The Adventures of Robin Hood',
                 description='Robin of Loxley, otherwise known as Robin Hood, '
                             'and his band of Merry Men protect England from '
                             'the evil machinations of Prince John while King '
                             'Richard the Lionheart is away fighting in the '
                             'Crusades',
                 category_id=2,
                 user_id=1)

session.add(jones)
session.add(mitty)
session.add(robinhood)

pineaplle = Item(name='Pineapple Express',
                 description='A process server and his marijuana dealer wind '
                             'up on the run from hitmen and a corrupt police '
                             'officer after he witnesses his dealer\'s boss '
                             'murder a competitor while trying to serve papers'
                             ' on him.',
                 category_id=3,
                 user_id=1)
airplane = Item(name='Airplane',
                description='A man afraid to fly must ensure that a plane '
                            'lands safely after the pilots become sick.',
                category_id=3,
                user_id=1)
policeacademy = Item(name='Police Academy',
                     description='A group of good-hearted, but incompetent '
                                 'misfits enter the police academy, but the '
                                 'instructors there are not going to put up '
                                 'with their pranks.',
                     category_id=3,
                     user_id=1)

session.add(pineaplle)
session.add(airplane)
session.add(policeacademy)

titanic = Item(name='Titanic',
               description='A seventeen-year-old aristocrat falls in love with'
                           ' a kind but poor artist aboard the luxurious, '
                           'ill-fated R.M.S. Titanic.',
               category_id=4,
               user_id=1)
blackswan = Item(name='Black Swan',
                 description='A committed dancer wins the lead role in a '
                             'production of Tchaikovsky\'s "Swan Lake" only to'
                             ' find herself struggling to maintain her sanity',
                 category_id=4,
                 user_id=1)
pianist = Item(name='The Pianist',
               description='A Polish Jewish musician struggles to survive the '
                           'destruction of the Warsaw ghetto of World War II',
               category_id=4,
               user_id=1)

session.add(titanic)
session.add(blackswan)
session.add(pianist)

alien = Item(name='Alien',
             description='After her last encounter, Ellen Ripley crash-lands '
                         'on Fiorina 161, a maximum security prison. When a '
                         'series of strange and deadly events occur shortly '
                         'after her arrival, Ripley realizes that she brought '
                         'along an unwelcome visitor.',
             category_id=5,
             user_id=1)
terminator = Item(name='Terminator 2: Judgment Day',
                  description='A cyborg, identical to the one who failed to '
                              'kill Sarah Connor, must now protect her teenage'
                              ' son, John Connor, from a more advanced and '
                              'powerful cyborg.',
                  category_id=5,
                  user_id=1)
matrix = Item(name='The Matrix',
              description='A computer hacker learns from mysterious rebels '
                          'about the true nature of his reality and his role '
                          'in the war against its controllers.',
              category_id=5,
              user_id=1)

session.add(alien)
session.add(terminator)
session.add(matrix)

session.commit()

categories = session.query(Category).all()
for category in categories:
    print('category_id: {}, category_name: {}'.format(category.id,
                                                      category.name))

items = session.query(Item).all()
for item in items:
    print('item_id: {}, item_name: {}, item_description: {}'
          .format(item.id, item.name, item.description))
