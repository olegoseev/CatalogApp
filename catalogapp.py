#!/usr/bin/python3

from functools import wraps
from flask import (Flask,
                   render_template,
                   flash,
                   request,
                   session as login_session,
                   make_response,
                   redirect,
                   url_for,
                   jsonify,
                   g)
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker, scoped_session
from database_setup import Base, Category, Item, User

import httplib2
import json
import requests
import random
import string

from flask_httpauth import HTTPBasicAuth

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

auth = HTTPBasicAuth()

app = Flask(__name__)

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = scoped_session(sessionmaker(bind=engine))
session = DBSession()

G_CLIENT_ID = json.loads(
    open('google_client_secret.json', 'r').read())['web']['client_id']

FB_APP_ID = json.loads(
    open('fb_client_secret.json', 'r').read())['web']['app_id']
FB_APP_SECRET = json.loads(
    open('fb_client_secret.json', 'r').read())['web']['app_secret']

APPLICATION_NAME = "CatalogApp"


@auth.verify_password
def verify_password(username_or_token, password):
    # Try to see if it's a token first
    user_id = User.verify_auth_token(username_or_token)
    if user_id:
        user = session.query(User).filter_by(id=user_id).one_or_none()
    else:
        user = session.query(User).filter_by(username=username_or_token)\
            .first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' in login_session:
            return f(*args, **kwargs)
        else:
            flash("Please login")
            return redirect('/login')
    return decorated_function


# main page
# allows to add item if user logged in
@app.route('/')
def show_catalog():
    categories = session.query(Category).all()
    items = session.query(Item).order_by(desc(Item.id)).limit(5)
    if 'username' not in login_session:
        return render_template('public_catalog.html', categories=categories,
                               items=items)
    else:
        return render_template('catalog.html', categories=categories,
                               items=items)


# show items of the specific category
# allows to add item if user logged in
@app.route('/catalog/<category>/items')
def show_category_items(category):
    categories = session.query(Category).all()
    category = session.query(Category).filter_by(name=category).one_or_none()
    items = session.query(Item).filter_by(category_id=category.id)
    if 'username' not in login_session:
        return render_template('public_category_items.html',
                               categories=categories,
                               category=category, items=items)
    else:
        return render_template('category_items.html', categories=categories,
                               category=category, items=items)


# show description of the selected item
# allows to edit/delete item if user logged in
@app.route('/catalog/<category>/<item>')
def show_item_description(category, item):
    category = session.query(Category).filter_by(name=category).one_or_none()
    item = session.query(Item).filter_by(category_id=category.id,
                                         name=item).one_or_none()
    if 'username' not in login_session:
        return render_template('public_description.html',
                               category=category, item=item)
    else:
        return render_template('item_description.html',
                               category=category, item=item)


# update selected item
@app.route('/catalog/<item_name>/edit', methods=['GET', 'POST'])
@login_required
def edit_item(item_name):
    categories = session.query(Category).all()
    item = session.query(Item).filter_by(name=item_name).one_or_none()
    user = session.query(User).filter_by(
        username=login_session['username']).one_or_none()
    print('user.id type: {}'.format(type(user.id)))
    print('item.user_id type: {}'.format(type(item.user_id)))
    if item.user_id != user.id:
        flash('User allowed to modify only own items')
        return redirect(url_for('show_catalog'))
    if request.method == 'POST':
        if request.form['title']:
            item.name = request.form['title']
        if request.form['description']:
            item.description = request.form['description']
        category_id = request.form['category_select']
        if category_id and category_id != '0':
            item.category_id = category_id
        session.add(item)
        session.commit()
        flash('Item {} updated'.format(item.name))
        return redirect(url_for('show_catalog'))
    else:
        return render_template('edit_item.html', categories=categories,
                               item=item)


# add a new item to the database
@app.route('/catalog/item/new', methods=['GET', 'POST'])
@login_required
def add_item():
    categories = session.query(Category).all()
    if request.method == 'POST':
        item = Item()
        if not request.form['title'] or not \
                request.form['description'] or \
                request.form['category_select'] == '0':
            return redirect('/catalog/item/new')
        else:
            item.name = request.form['title']
            item.description = request.form['description']
            item.category_id = request.form['category_select']
            item.user_id = login_session['username']
            session.add(item)
            session.commit()
            flash('Item {} added'.format(item.name))
        return redirect(url_for('show_catalog'))
    else:
        return render_template('add_item.html', categories=categories)


# delete item from the database
@app.route('/catalog/<item_name>/delete', methods=['GET', 'POST'])
@login_required
def delete_item(item_name):
    item = session.query(Item).filter_by(name=item_name).one_or_none()
    user = session.query(User).filter_by(
        username=login_session['username']).one_or_none()
    print('user.id type: {}'.format(type(user.id)))
    print('item.user_id type: {}'.format(type(item.user_id)))
    if item.user_id != user.id:
        flash('User allowed delete only own items')
        return redirect(url_for('show_catalog'))
    if request.method == 'POST':
        session.delete(item)
        session.commit()
        flash('Item {} deleted'.format(item.name))
        return redirect(url_for('show_catalog'))
    else:
        return render_template('delete_item.html', item=item)


# request database shapshot in JSON format
@app.route('/catalog.json')
def catalog_json():
    categories = session.query(Category).all()
    json_object = {'Category': []}
    for category in categories:
        items = session.query(Item).filter_by(category_id=category.id).all()
        i = ([i.serialize for i in items])
        json_item = {
            'id': category.id,
            'name': category.name,
            'Item': i
        }
        json_object['Category'].append(json_item)
    return jsonify(json_object)


# Show sign up form if user doesn't want to use
# any social accounts
@app.route('/user/signup', methods=['GET', 'POST'])
def user_signup():
    if request.method == 'POST':
        if request.form['username'] is None or request.form['password'] is \
                None or request.form['confirm'] is None:
            flash("Missing required information")

        username = request.form['username']
        password = request.form['password']
        password_conf = request.form['confirm']
        if password != password_conf:
            flash('Passwords do not match')
            return render_template('sign_up.html')
        if session.query(User).filter_by(
                username=username).first() is not None:
            flash("User already exists")
            return redirect(url_for('login_page'))

        user = User(username=username, picture='', email='')
        user.hash_password(password)
        session.add(user)
        session.commit()
        return redirect(url_for('login_page'))
    else:
        return render_template('sign_up.html')


# Create anti-forgery state token
@app.route('/login')
def login_page():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state, g_lient_id=G_CLIENT_ID,
                           fb_app_id=FB_APP_ID)


# login with user/password
@app.route('/userconnect', methods=['POST'])
def user_connect():
    if request.form['username'] is None or request.form['password'] is None:
        flash("Missing required information")
        return redirect(url_for('login_page'))

    username = request.form['username']
    password = request.form['password']

    if session.query(User).filter_by(username=username).first() is None:
        flash("User not found. Please sign up")
        return redirect(url_for('login_page'))

    if verify_password(username, password) is False:
        flash("Unknown user or bad password")
        return redirect(url_for('login_page'))

    user = session.query(User).filter_by(
        username=username).one_or_none()
    
    login_session['provider'] = 'username'
    login_session['username'] = username
    login_session['email'] = username
    login_session['picture'] = ""
    login_session['user_id'] = user.id
    return redirect(url_for('show_catalog'))


# login with Facebook account
@app.route('/fbconnect', methods=['POST'])
def fb_connect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data.decode()
    url = 'https://graph.facebook.com/oauth/access_token?grant_type' \
          '=fb_exchange_token&client_id={}&client_secret={}' \
          '&fb_exchange_token={}'.format(FB_APP_ID, FB_APP_SECRET,
                                         access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1].decode()

    # Use token to get user info from API
    # userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange we
        have to
        split the token first on commas and select the first index which gives
        us the key : value
        for the server access token then we split it on colons to pull out the
        actual token value
        and replace the remaining quotes with nothing so that it can be used
        directly in the graph api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token={}&fields=name,id,'\
          'email'.format(token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token={}' \
          '&redirect=0&height=200&width=200'.format(token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = get_user_id(login_session['email'])
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: ' \
              '150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;">'

    flash("Now logged in as {}".format(login_session['username']))
    return output


@app.route('/fbdisconnect')
def fb_disconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/{}/permissions?access_token={}'.format(
        facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# connect with Google account
@app.route('/gconnect', methods=['POST'])
def g_connect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
        # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('google_client_secret.json',
                                             scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

        # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={}'
           .format(access_token))

    gresp = requests.get(url=url)
    result = json.loads(gresp.text)

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

        # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

        # Verify that the access token is valid for this app.
    if result['issued_to'] != G_CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'),
            200)
        response.headers['Content-Type'] = 'application/json'
        return response

        # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    user_id = get_user_id(login_session['email'])
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: ' \
              '150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;">'
    flash("You are now logged in as {}".format(login_session['username']))
    return output


# User Helper Functions
def create_user(login_session):
    new_user = User(username=login_session['username'], email=login_session[
        'email'], picture=login_session['picture'])
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(
        email=login_session['email']).one_or_none()
    return user.id


def get_user_info(user_id):
    user = session.query(User).filter_by(id=user_id).one_or_none()
    return user


def get_user_id(email):
    try:
        user = session.query(User).filter_by(email=email).one_or_none()
        return user.id
    except:
        return None


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def g_disconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(json.dumps('Current user not connected.'),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token={}'.format(
        login_session['access_token'])
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            g_disconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fb_disconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('show_catalog'))
    else:
        flash("You were not logged in")
        return redirect(url_for('show_catalog'))


if __name__ == '__main__':
    app.secret_key = 'very_very_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000, threaded=False)
