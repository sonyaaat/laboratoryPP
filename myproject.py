import datetime

import jwt
from dotenv import load_dotenv
from flask import Flask, request
from flask_httpauth import HTTPTokenAuth
from flask_migrate import Migrate
from flask_restful import reqparse
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import argon2

app = Flask('__name__')
load_dotenv()
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Tkach2004@localhost:3306/Shop'
app.config['SQLALCHEMY_TRACK_MODIFICATION'] = False
app.config['SECRET_KEY'] = 'secret'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
auth = HTTPTokenAuth(scheme='Bearer')
usernames = []


def generate_confirmation_token(username, expiration=6000):
    reset_token = jwt.encode(
        {
            "confirm": username,
            "exp": datetime.datetime.now(tz=datetime.timezone.utc)
                   + datetime.timedelta(seconds=expiration)
        },
        app.config['SECRET_KEY'],
        algorithm="HS256"
    )
    return reset_token


def confirm(token):
    try:
        data = jwt.decode(
            token,
            app.config['SECRET_KEY'],
            leeway=datetime.timedelta(seconds=10),
            algorithms=["HS256"]
        )
    except Exception:
        return False
    if data.get('confirm') not in usernames:
        return False
    return True


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    firstName = db.Column(db.String(255), nullable=False)
    lastName = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(120), nullable=False)

    def add_to(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username=username).first()

    @classmethod
    def find_by_phone(cls, phone):
        return cls.query.filter_by(phone=phone).first()

    @classmethod
    def find_by_email(cls, email):
        return cls.query.filter_by(email=email).first()

    @classmethod
    def find_by_id(cls, id):
        return cls.query.filter_by(id=id).first()

    def __str__(self):
        return f'{self.id}, {self.username}'

    @classmethod
    def user_list(cls):
        def to_json(user):
            return {
                'id': user.id,
                'username': user.username,
                'firstName': user.firstName,
                'lastName': user.lastName,
                'email': user.email,
                'password': user.password,
                'phone': user.phone
            }

        return {'users': [to_json(user) for user in User.query.all()]}

    @staticmethod
    def generate_hash(password):
        return argon2.hash(password)

    @staticmethod
    def verify_hash(password, hash_):
        return argon2.verify(password, hash_)


@auth.get_user_roles
def get_user_roles(token):
    data = jwt.decode(
        token,
        app.config['SECRET_KEY'],
        leeway=datetime.timedelta(seconds=10),
        algorithms=["HS256"]
    )
    user = data.get('confirm')
    user_entity = User.find_by_username(user)
    return user_entity.role


@app.route('/login', methods=['POST'])
def login():
    pars = reqparse.RequestParser()
    pars.add_argument('username', help='username cannot be blank', required=True)
    pars.add_argument('password', help='password cannot be blank', required=True)

    data = pars.parse_args()
    username = data['username']
    password = data['password']
    if User.query.filter_by(username=username).first() == None:
        return {'message': 'Error'}, 500
    elif User.verify_hash(
            hash_=User.query
                    .filter_by(username=username)
                    .first()
                    .password,
            password=password
    ):
        return generate_confirmation_token(username=username)

    return {'message': 'Error'}, 500


@app.before_request
def init_usernames():
    for i in User.query.all():
        print(str(i))
        usernames.append(i.username)


@auth.verify_token
def verify_token(token):
    if confirm(token=token):
        return token


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    itemId = db.Column(db.Integer, db.ForeignKey("item.id"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    shipDate = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(120), nullable=False)
    complete = db.Column(db.Boolean, nullable=False)
    userId = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    def add_to(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def get_by_id(cls, id):
        return cls.query.filter_by(id=id).first()


class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    photoUrls = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(120), nullable=False)

    def add_to(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def get_by_id(cls, id):
        return cls.query.filter_by(id=id).first()


# @app.before_request
def create_tables():
    db.drop_all()
    db.create_all()
    db.session.commit()


@app.route('/api/v1/hello-world-26')
def hello_world():
    return "Hello World 26"


@app.route("/item", methods=['POST', 'PUT'])
@auth.login_required(role=['admin'])
def item():
    if request.method == 'POST':

        pars = reqparse.RequestParser()
        pars.add_argument('id', help='name cannot be blank', required=True)
        pars.add_argument('name', help='name cannot be blank', required=True)
        pars.add_argument('photoUrls', help='name cannot be blank', required=True)
        pars.add_argument('status', help='status cannot be blank', required=True)

        data = pars.parse_args()
        try:
            id = int(data['id'])
        except Exception:
            return {"message": "error"}, 500

        name = data['name']
        photoUrls = data['photoUrls']
        status = data['status']

        item_1 = Item(
            id=id,
            name=name,
            photoUrls=photoUrls,
            status=status
        )
        try:
            item_1.add_to()
            return {"message": "new item added"}, 200
        except Exception:
            return {"message": "error"}, 405

    elif request.method == 'PUT':

        pars = reqparse.RequestParser()
        pars.add_argument('id', help='name cannot be blank', required=True)
        pars.add_argument('name', help='name cannot be blank', required=True)
        pars.add_argument('photoUrls', help='name cannot be blank', required=True)
        pars.add_argument('status', help='status cannot be blank', required=True)

        data = pars.parse_args()
        id = int(data['id'])

        try:
            item_1 = Item.query.filter_by(id=id).update(data)
            db.session.commit()
            return {"message": "item is updated"}, 200
        except Exception:
            return {"message": "error"}, 500


@app.route('/item/<int:item_id>', methods=['GET'])
@auth.login_required(role=['user', 'admin'])
def get_item(item_id):
    try:
        item_1 = Item.get_by_id(item_id)

        return {'id': item_1.id,
                'name': item_1.name,
                'photoUrls': item_1.photoUrls,
                'status': item_1.status
                }, 200
    except Exception:
        return {'message': 'Error'}, 500


@app.route('/item/<int:item_id>', methods=['POST', 'DELETE'])
@auth.login_required(role=['admin'])
def item_by_id(item_id):
    if request.method == 'POST':

        pars = reqparse.RequestParser()
        pars.add_argument('name', help='name cannot be blank', required=True)
        pars.add_argument('status', help='status cannot be blank', required=True)

        data = pars.parse_args()
        name = data['name']
        status = data['status']

        try:
            Item.query.filter_by(id=item_id).update(data)
            db.session.commit()
            return {"message": f"item with {item_id} is up to date"}
        except Exception:
            return {"message": "Something went wrong"}, 405
        pass

        # pass

    elif request.method == 'DELETE':
        if Item.query.filter_by(id=item_id).first() == None:
            return {"message": f"Item not found"}, 404

        try:

            Item.query.filter_by(id=item_id).delete()
            db.session.commit()
            return {"message": f"item is deleted"}, 200
        except Exception:
            return {"message": f"Something went wrong"}, 500


@app.route('/store/order', methods=['POST'])
@auth.login_required(role=['user', 'admin'])
def store_order():
    pars = reqparse.RequestParser()
    pars.add_argument('id', help='id cannot be blank', required=True)
    pars.add_argument('itemId', help='name cannot be blank', required=True)
    pars.add_argument('quantity', help='name cannot be blank', required=True)
    pars.add_argument('shipDate', help='name cannot be blank', required=True)
    pars.add_argument('status', help='status cannot be blank', required=True)
    pars.add_argument('complete', help='status cannot be blank', required=True)
    pars.add_argument('userId', help='userId cannot be blank', required=True)

    data = pars.parse_args()
    try:
        id = int(data['id'])
        itemId = int(data['itemId'])
        quantity = int(data['quantity'])
        shipDate = data['shipDate']
        status = data['status']
        complete = bool(data['complete'])
        userId = int(data['userId'])
        # return {"message": "everything is good"}, 200
    except Exception:
        return {'message': 'error'}, 500

    order_1 = Order(
        id=id,
        itemId=itemId,
        quantity=quantity,
        shipDate=shipDate,
        status=status,
        complete=complete,
        userId=userId
    )

    try:
        order_1.add_to()
        return {"message": "everything is good"}, 200
    except Exception:
        return {"message": "error"}, 500


@app.route('/store/order/<int:order_id>', methods=['GET', 'DELETE'])
@auth.login_required(role=['user', 'admin'])
def store_order_by_order_id(order_id):
    if request.method == 'GET':
        try:
            order_1 = Order.get_by_id(order_id)
            return {'id': order_1.id,
                    'itemId': order_1.itemId,
                    'quantity': order_1.quantity,
                    'shipDate': order_1.shipDate,
                    'status': order_1.status,
                    'complete': order_1.complete,
                    'userId': order_1.userId}, 200
        except Exception:
            return {'message': 'error'}, 500

    elif request.method == 'DELETE':
        if Order.query.filter_by(id=order_id).first() == None:
            return {"message": f"Item not found"}, 404
        try:
            Order.query.filter_by(id=order_id).delete()
        except Exception:
            return {'message': 'error'}, 500


@app.route('/user', methods=['POST'])
def user():
    pars = reqparse.RequestParser()
    pars.add_argument('id', help='id cannot be blank', required=True)
    pars.add_argument('username', help='name cannot be blank', required=True)
    pars.add_argument('firstName', help='name cannot be blank', required=True)
    pars.add_argument('lastName', help='status cannot be blank', required=True)
    pars.add_argument('email', help='status cannot be blank', required=True)
    pars.add_argument('phone', help='userId cannot be blank', required=True)
    pars.add_argument('password', help='userId cannot be blank', required=True)

    data = pars.parse_args()
    try:
        id = int(data['id'])
        username = (data['username'])
        firstName = (data['firstName'])
        lastName = data['lastName']
        email = data['email']
        phone = (data['phone'])
        password = (data['password'])
    except Exception:
        return {'message': 'error'}, 500

    user_1 = User(
        id=id,
        username=username,
        firstName=firstName,
        lastName=lastName,
        email=email,
        phone=phone,
        password=User.generate_hash(password=password),
        role="user"
    )

    try:
        user_1.add_to()
        return {"message": "everything is good"}, 200
    except Exception:
        return {"message": "error"}, 500


@app.route('/user/<string:username>', methods=['GET'])
@auth.login_required(role=['user', 'admin'])
def getUser(username):
    try:
        user_1 = User.find_by_username(username=username)

        return {
                   "id": user_1.id,
                   "username": user_1.username,
                   "firstName": user_1.firstName,
                   "lastName": user_1.lastName,
                   "email": user_1.email,
                   "password": user_1.password,
                   "phone": user_1.phone
               }, 200
    except Exception:
        return {'message': 'Error'}, 500


@app.route('/user/<string:username>', methods=['PUT', 'DELETE'])
@auth.login_required(role=['admin'])
def user_by_nick(username):
    if request.method == 'PUT':
        pars = reqparse.RequestParser()
        pars.add_argument('id', help='id cannot be blank', required=True)
        pars.add_argument('username', help='name cannot be blank', required=True)
        pars.add_argument('firstName', help='name cannot be blank', required=True)
        pars.add_argument('lastName', help='status cannot be blank', required=True)
        pars.add_argument('email', help='status cannot be blank', required=True)
        pars.add_argument('phone', help='userId cannot be blank', required=True)
        pars.add_argument('password', help='userId cannot be blank', required=True)

        data = pars.parse_args()
        '''
        try:
            id = int(data['id'])
            username = (data['itemId'])
            firstName = (data['quantity'])
            lastName = data['shipDate']
            email = data['status']
            phone = (data['complete'])
            password = (data['userId'])
        except Exception:
            return {'message': 'error'}, 500
        '''
        try:
            User.query.filter_by(username=username).update(data)
            db.session.commit()
            return {"message": f"item with {username} is up to date"}
        except Exception:
            return {"message": "Something went wrong"}, 500
        pass

    elif request.method == 'DELETE':
        try:
            tmp = int(username)
            return {"message": "Bad request"}, 500
        except Exception:
            pass

        if User.query.filter_by(username=username).first() == None:
            return {"message": "Something went wrong"}, 404

        try:
            User.query.filter_by(username=username).delete()
            db.session.commit()
            return {"message": f"user with {username} was deleted"}, 200
        except Exception:
            return {"message": "Something went wrong"}, 500


if __name__ == '__main__':
    app.run(debug=True)
