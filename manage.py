import os
import datetime
from flask import Flask, jsonify, render_template, request
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)
from models import db, Role, User

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


app = Flask(__name__)

app.config['DEBUG'] = True
app.config['ENV'] = 'development'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR,'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'super-secret'
jwt = JWTManager(app)
db.init_app(app)

#mail = Mail(app) # Librería de Email
bcrypt= Bcrypt(app) #Encryptado de información
Migrate(app,db) # Configuración de migraciones

manager = Manager(app)
manager.add_command("db",MigrateCommand) # Comandos para generar las migrations y tables

@app.route('/')
def main():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if not username:
        return jsonify({"msg": "Missing username parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"msg":"username not found"}), 401
    
    if not bcrypt.check_password_hash(user.password, password):
        return jsonify({"msg": "Bad username or password"}), 401

    # Identity can be any data that is json serializable
    expires=datetime.timedelta(days=3)
    access_token = create_access_token(identity=user.username, expires_delta=expires)

    return jsonify({"access_token":access_token, "user":user.serialize()}), 200

@app.route('/roles', methods=['GET', 'POST'])
@app.route('/roles/<int:id>', methods=['GET', 'PUT', "DELETE"])
@jwt_required
def roles(id=None):
    if request.method =='GET':
        if id is not None:
            role = Role.query.get(id)
            if role:
                return jsonify(role.serialize()), 200
            else:
                return jsonify({"msg":"Role not found"}), 404
        else:
            roles = Role.query.all()
            roles = list(map(lambda role: role.serialize(),roles))
            return jsonify(roles), 200

    if request.method =='POST':
        name = request.json.get('name', None)
        if name is "":
            return jsonify({"msg":"name is required"}), 422
        
        role=Role()
        role.name=name

        db.session.add(role)
        db.session.commit()

        return jsonify(role.serialize()), 201

    if request.method =='PUT':

        name = request.json.get('name', None)
        if name is "":
            return jsonify({"msg":"name is required"}), 422
        
        role=Role.query.get(id)
        role.name=name
        
        db.session.commit()

        return jsonify(role.serialize()), 200

    if request.method =='DELETE':
        pass

@app.route('/users', methods=['GET', 'POST'])
@app.route('/users/<int:id>', methods=['GET', 'PUT', "DELETE"])
@jwt_required
def users(id=None):
    if request.method =='GET':
        if id is not None:
            user = User.query.get(id)
            if user:
                return jsonify(user.serialize()), 200
            else:
                return jsonify({"msg":"User not found"}), 404
        else:
            users = User.query.all()
            users = list(map(lambda user: user.serialize(),users))
            return jsonify(users), 200

    if request.method =='POST':
        name = request.json.get('name', None)
        if name is "" or name is None:
            return jsonify({"msg":"name is required"}), 422
        username = request.json.get('username', None)
        if username is "" or username is None:
            return jsonify({"msg":"username is required"}), 422

        user = User.query.filter_by(username=username).first()
        if user:
            return jsonify({"msg":"username exists"}), 422

        email = request.json.get('email', None)
        if email is "" or email is None:
            return jsonify({"msg":"email is required"}), 422

        user = User.query.filter_by(email=email).first()
        if user:
            return jsonify({"msg":"email is taken"}), 422

        password = request.json.get('password', None)
        if password is "" or password is None:
            return jsonify({"msg":"password is required"}), 422
        role_id = request.json.get('role_id', None)
        if role_id is "" or role_id is None:
            return jsonify({"msg":"role is required"}), 422

        
        user=User()
        user.name=name
        user.username=username
        user.email=email
        user.password=bcrypt.generate_password_hash(password)
        user.active=request.json.get('active', False)
        user.role_id =role_id

        db.session.add(user)
        db.session.commit()

        return jsonify(user.serialize()), 201

    if request.method =='PUT':
        pass
    if request.method =='DELETE':
        pass


if __name__=="__main__":
    manager.run()



    # EN EL FETCH POST DEBO PASAR       'Authorization': 'Bearer' + token,
    #                                   'Content_Type':'application/json'
    # EJEMPLO HECHO EN INSOMNIA