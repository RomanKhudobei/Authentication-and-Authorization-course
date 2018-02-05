# -*- coding: utf-8 -*-

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem, User

from flask import session as login_session
import random, string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

engine = create_engine('sqlite:///restaurantmenu_with_users.db')
Base.metadata.bind = engine

DBsession = sessionmaker(bind=engine)
session = DBsession()

CLIENT_ID = json.loads( open('client_secrets.json', 'r').read() ).get('web').get('client_id')

@app.route('/login', strict_slashes=False)
def show_login():
	authenticated = is_logged(login_session)

	if authenticated:
		flash('Current user is already connected', 'info')
		return redirect( url_for('restaurants') )

	state = ''.join( random.choice(string.ascii_uppercase + string.digits) for x in xrange(32) )
	login_session['state'] = state
	return render_template('login.html', STATE=state)

@app.route('/gconnect', methods=['POST'])
def gconnect():
	# Validate state token
	if request.args.get('state') != login_session['state']:
		flash("Failed to Log In. Invalid state token - CSRF", 'danger')

		response = make_response(json.dumps('Invalid state token'), 401)
		response.headers['Content-Type'] = 'application/json'

		return response

	# Obtain authorization code
	code = request.data

	try:	# Upgrade the authorization code into a credentials object
		oauth_flow = flow_from_clientsecrets(filename='client_secrets.json', scope='', redirect_uri='postmessage')
		credentials = oauth_flow.step2_exchange(code=code)

	except FlowExchangeError:
		flash("Failed to Log In. Failed to upgrade the authorization code", 'danger')

		response = make_response(json.dumps('Failed to upgrade the authorization code'), 401)
		response.headers['Content-Type'] = 'application/json'

		return response

	# Check that the access token is valid
	access_token = credentials.access_token
	url = 'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={}'.format(access_token)

	h = httplib2.Http()
	result = json.loads( h.request(url, 'GET')[1] )

	# If there was an error in the access token info
	if result.get('error') != None:
		flash("Failed to Log In. An error occured when requesting token info", 'danger')

		response = make_response(json.dumps(result.get('error')), 500)
		response.headers['Content-Type'] = 'application/json'

		return response

	# Verify that the access token is used for the intended user
	gplus_id = credentials.id_token['sub']

	if result.get('user_id') != gplus_id:
		flash("Failed to Log In. Token's user ID doesn't match given user ID", 'danger')

		response = make_response(json.dumps("Token's user ID doesn't match given user ID."), 401)
		response.headers['Content-Type'] = 'application/json'

		return response

	# Verify that the access token is valid for this app.
	if result.get('issued_to') != CLIENT_ID:
		flash("Failed to Log In. Token's client ID doesn't match given client ID", 'danger')

		response = make_response(json.dumps("Token's client ID doesn't match given client ID."), 401)
		response.headers['Content-Type'] = 'application/json'

		return response

	stored_credentials = login_session.get('credentials')
	stored_gplus_id = login_session.get('gplus_id')
	stored_provider = login_session.get('provider')

	if stored_credentials != None and gplus_id == stored_gplus_id or stored_provider:
		# In case when gdisconnect failed for some reason, the invalid token is stored
		# And code after this if unreachable. There so, this line is update token each time user try to login
		login_session['credentials'] = credentials.to_json()	# don't touch this. It prevents sereosly bug.
		
		flash('Current user is already connected by ' + stored_provider[0].upper() + stored_provider[1:] + ' login system', 'info')

		response = make_response(json.dumps('Current user is already connected.'), 200)
		response.headers['Content-Type'] = 'application/json'

		return response

	# Store the access token in the session for later use
	login_session['provider'] = 'google'
	login_session['credentials'] = credentials.to_json()
	login_session['gplus_id'] = gplus_id

	# Get user info
	userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
	params = {
		'access_token': credentials.access_token,
		'alt': 'json'
	}

	response = requests.get(userinfo_url, params=params)
	data = json.loads(response.text)

	login_session['username'] = data.get('name').encode('utf-8')
	login_session['picture'] = data.get('picture')
	login_session['email'] = data.get('email')


	user_id = get_user_id(login_session['email'])
	if not user_id:
		user_id = create_user(login_session)

	login_session['user_id'] = user_id

	flash('Successfully logged in as ' + unicode(login_session['username'], 'utf-8') + '!', 'success')

	response = make_response(json.dumps('Successfully logged in'), 200)
	response.headers['Content-Type'] = 'application/json'

	return response

def gdisconnect():
	credentials = login_session.get('credentials')

	if credentials:
		credentials = json.loads(credentials)
	else:
		response = make_response(json.dumps('Current user not connected.'), 401)
		response.headers['Content-Type'] = 'application/json'
		flash('Current user not connected', 'info')
		return redirect( url_for('restaurants') )

	access_token = credentials.get('access_token')
	url = 'https://accounts.google.com/o/oauth2/revoke?token={}'.format(access_token)

	h = httplib2.Http()
	result = h.request(url, 'GET')

	if result[0].get('status') == '200' or json.loads(result[1]).get('error_description') == 'Token expired or revoked':
		return True
	else:
		return False


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
	if request.args.get('state') != login_session['state']:
		flash("Failed to Log In. Invalid state token - CSRF", 'danger')

		response = make_response(json.dumps('Invalid state token'), 401)
		response.headers['Content-Type'] = 'application/json'

		return response

	access_token = request.data

	fb_client_secrets = json.loads( open('fb_client_secrets.json', 'r').read() ).get('web')

	app_id = fb_client_secrets['app_id']
	app_secret = fb_client_secrets['app_secret']

	url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id={}&client_secret={}&fb_exchange_token={}'
	url = url.format(app_id, app_secret, access_token)

	h = httplib2.Http()
	result = h.request(url, 'GET')[1]

	token = result.split(',')[0].split(':')[1].replace('"', '')
	login_session['fb_access_token'] = token

	userinfo_url = 'https://graph.facebook.com/v2.8/me?access_token={}&fields=name,id,email'.format(token)
	result = h.request(userinfo_url, 'GET')[1]
	data = json.loads(result)

	fb_id = data.get('id')

	stored_fb_id = login_session.get('fb_id')
	stored_provider = login_session.get('provider')

	if stored_fb_id or stored_provider:
		flash('Current user is already connected by ' + stored_provider[0].upper() + stored_provider[1:] + ' login system', 'info')

		response = make_response(json.dumps('Current user is already connected.'), 200)
		response.headers['Content-Type'] = 'application/json'

		return response

	login_session['provider'] = 'facebook'
	login_session['username'] = data.get('name')
	login_session['email'] = data.get('email')
	login_session['fb_id'] = fb_id

	picture_request_url = 'https://graph.facebook.com/v2.8/me/picture?access_token={}&redirect=0&height=200&width=200'.format(token)
	result = h.request(picture_request_url, 'GET')[1]
	data = json.loads(result)

	login_session['picture'] = data.get('data').get('url')

	user_id = get_user_id(login_session['email'])
	if not user_id:
		user_id = create_user(login_session)

	login_session['user_id'] = user_id

	flash('Successfully logged in as ' + login_session['username'] + '!', 'success')

	response = make_response(json.dumps('Successfully logged in'), 200)
	response.headers['Content-Type'] = 'application/json'

	return response

def fbdisconnect():
	fb_id = login_session.get('fb_id')
	access_token = login_session.get('fb_access_token')

	url = 'https://graph.facebook.com/{}/permissions?access_token={}'.format(fb_id, access_token)
	h = httplib2.Http()
	result = h.request(url, 'DELETE')[1]

@app.route('/disconnect')
def disconnect():
	if 'provider' in login_session:

		if login_session['provider'] == 'google':
			if gdisconnect():
				flash('Successfully disconnected', 'success')
				del login_session['credentials']
				del login_session['gplus_id']
			else:
				flash('Failed to revoke token for given user', 'danger')
				return redirect( url_for('restaurants') )

		elif login_session['provider'] == 'facebook':
			fbdisconnect()
			del login_session['fb_id']
			del login_session['fb_access_token']
			flash('Successfully disconnected', 'success')

		del login_session['provider']
		del login_session['username']
		del login_session['email']
		del login_session['picture']
		del login_session['user_id']

	else:
		flash('You were not logged in', 'info')
	
	return redirect( url_for('restaurants') )

@app.route('/', strict_slashes=False)
@app.route('/restaurants', strict_slashes=False)
def restaurants():
	restaurants = session.query(Restaurant).all()

	return render_template('restaurants.html', restaurants=restaurants)

@app.route('/restaurants/new', methods=['GET', 'POST'], strict_slashes=False)
def create_restaurant():
	authenticated = is_logged(login_session)

	if request.method == 'POST':
		restaurant_name = request.form.get('new-restaurant-name')
		new_restaurant = Restaurant(name=restaurant_name,
									user_id=login_session.get('user_id'))

		session.add(new_restaurant)
		session.commit()

		flash('Success! New restaurant created!', 'success')

		return redirect( url_for('restaurants') )

	elif request.method == 'GET':

		if not authenticated:
			return redirect( url_for('show_login') )

		return render_template('create_restaurant.html')

@app.route('/restaurants/<int:restaurant_id>/delete', methods=['GET', 'POST'], strict_slashes=False)
def delete_restaurant(restaurant_id):
	restaurant = session.query(Restaurant).filter_by(id=restaurant_id).first()

	if request.method == 'POST':

		# deleting each menu item before deleting restaurant
		menu_items = session.query(MenuItem).filter_by(restaurant_id=restaurant.id)

		for item in menu_items:
			session.delete(item)

		session.delete(restaurant)
		session.commit()

		flash('Success! Restaurant deleted!', 'success')

		return redirect( url_for('restaurants') )

	elif request.method == 'GET':
		if not permission(login_session, restaurant):
			return redirect( url_for('restaurant_menu', restaurant_id=restaurant_id) )

		return render_template('delete_restaurant.html', restaurant=restaurant)

@app.route('/restaurants/<int:restaurant_id>/edit', methods=['GET', 'POST'], strict_slashes=False)
def edit_restaurant(restaurant_id):
	restaurant = session.query(Restaurant).filter_by(id=restaurant_id).first()

	if request.method == 'POST':

		edited_restaurant_name = request.form.get('new-restaurant-name')

		restaurant.name = edited_restaurant_name

		session.add(restaurant)
		session.commit()

		flash('Success! Restaurant edited!', 'success')

		return redirect( url_for('restaurant_menu', restaurant_id=restaurant_id) )

	elif request.method == 'GET':
		if not permission(login_session, restaurant):
			return redirect( url_for('restaurant_menu', restaurant_id=restaurant_id) )

		return render_template('edit_restaurant.html', restaurant=restaurant)

@app.route('/restaurants/<int:restaurant_id>', strict_slashes=False)
@app.route('/restaurants/<int:restaurant_id>/menu', strict_slashes=False)
def restaurant_menu(restaurant_id):
	restaurant = session.query(Restaurant).filter_by(id=restaurant_id).first()
	items = session.query(MenuItem).filter_by(restaurant_id=restaurant_id)

	creator = get_user_info(restaurant.user_id)
	if creator.id == login_session.get('user_id'):
		owner = True
	else:
		owner = False

	return render_template('menu.html', restaurant=restaurant, items=items, owner=owner)

@app.route('/restaurants/<int:restaurant_id>/menu/new', methods=['GET', 'POST'], strict_slashes=False)
def create_menu_item(restaurant_id):
	if request.method == 'POST':

		new_menu_item = MenuItem(name=request.form['new-menu-item-name'],
								 price=request.form['new-menu-item-price'],
								 description=request.form['new-menu-item-description'],
								 course=request.form['new-menu-item-type'],
								 restaurant_id=restaurant_id,
								 user_id=login_session['user_id'])

		session.add(new_menu_item)
		session.commit()

		flash('Success! New menu item created', 'success')

		return redirect( url_for('restaurant_menu', restaurant_id=restaurant_id) )

	elif request.method == 'GET':
		restaurant = session.query(Restaurant).filter_by(id=restaurant_id).first()

		if not permission(login_session, restaurant):
			return redirect( url_for('restaurant_menu', restaurant_id=restaurant_id) )

		return render_template('create_menu_item.html', restaurant_id=restaurant_id)

@app.route('/restaurants/<int:restaurant_id>/menu/<int:menu_id>/edit', methods=['GET', 'POST'], strict_slashes=False)
def edit_menu_item(restaurant_id, menu_id):
	OPTIONS = ['Appetizer', 'Entree', 'Dessert', 'Beverage']

	menu_item = session.query(MenuItem).filter_by(id=menu_id).first()

	if request.method == 'POST':

		menu_item.name = request.form.get('new-menu-item-name')
		menu_item.price = request.form.get('new-menu-item-price')
		menu_item.description = request.form.get('new-menu-item-description')
		menu_item.course = request.form.get('new-menu-item-type')

		session.add(menu_item)
		session.commit()

		flash('Success! Menu item edited', 'success')

		return redirect( url_for('restaurant_menu', restaurant_id=restaurant_id) )

	elif request.method == 'GET':
		restaurant = session.query(Restaurant).filter_by(id=restaurant_id).first()

		if not permission(login_session, restaurant):
			return redirect( url_for('restaurant_menu', restaurant_id=restaurant_id) )

		return render_template('edit_menu_item.html', restaurant_id=restaurant_id, menu_item=menu_item, options=OPTIONS)

@app.route('/restaurants/<int:restaurant_id>/menu/<int:menu_id>/delete', methods=['GET', 'POST'], strict_slashes=False)
def delete_menu_item(restaurant_id, menu_id):
	menu_item = session.query(MenuItem).filter_by(id=menu_id).first()

	if request.method == 'POST':
		session.delete(menu_item)
		session.commit()

		flash('Success! Menu item deleted', 'success')

		return redirect( url_for('restaurant_menu', restaurant_id=restaurant_id) )

	elif request.method == 'GET':
		restaurant = session.query(Restaurant).filter_by(id=restaurant_id).first()

		if not permission(login_session, restaurant):
			return redirect( url_for('restaurant_menu', restaurant_id=restaurant_id) )

		return render_template('delete_menu_item.html', restaurant_id=restaurant_id, menu_item=menu_item)

@app.route('/api', strict_slashes=False)
def api():
	return render_template('api.html')

# API

@app.route('/restaurants/<int:restaurant_id>/menu/api', strict_slashes=False)
def restaurant_menu_api(restaurant_id):
	restaurant = session.query(Restaurant).filter_by(id=restaurant_id).first()
	items = session.query(MenuItem).filter_by(restaurant_id=restaurant_id).all()

	serialized_menu_items = [item.serialize for item in items]

	data = jsonify(restaurant_name=restaurant.name, menu_items=serialized_menu_items)

	return data

@app.route('/restaurants/<int:restaurant_id>/menu/<int:menu_id>/api', strict_slashes=False)
def single_menu_item_api(restaurant_id, menu_id):
	restaurant = session.query(Restaurant).filter_by(id=restaurant_id).first()
	items = session.query(MenuItem).filter_by(id=menu_id).all()

	serialized_menu_item = [item.serialize for item in items]

	data = jsonify(restaurant_name=restaurant.name, menu_item=serialized_menu_item)

	return data

@app.route('/restaurants/api', strict_slashes=False)
def restaurants_api():
	restaurants = session.query(Restaurant).all()

	serialized_restaurants = [restaurant.serialize for restaurant in restaurants]

	data = jsonify(restaurants=serialized_restaurants)

	return data

# Functions

def create_user(login_session):
	new_user = User(name=login_session['username'],
					email=login_session['email'],
					picture=login_session['picture'])

	session.add(new_user)
	session.commit()

	user = session.query(User).filter_by(email=login_session['email']).first()

	return user.id

def get_user_info(user_id):
	user = session.query(User).filter_by(id=user_id).first()
	return user

def get_user_id(email):
	try:
		user = session.query(User).filter_by(email=email).first()
		return user.id
	except:
		return None

def is_logged(login_session):
	if login_session.get('provider'):
		return True
	return False

def permission(login_session, restaurant):
	creator = get_user_info(restaurant.user_id)
	if creator.id != login_session.get('user_id'):
		flash('Access denied', 'danger')
		return False
	return True


if __name__ == '__main__':
	app.secret_key = 'super_secret_key'
	app.debug = True
	app.run(host='0.0.0.0', port=5000)