from flask import Flask, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager

app = Flask(__name__)

# tells SQLAlchemy what database to connect to   
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///project.db"
app.config['JWT_SECRET_KEY'] = "supersecret"

db = SQLAlchemy(app)
jwt = JWTManager(app)

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String(20), nullable=False)
    admin = db.Column(db.Boolean, default=False)
    todos = db.relationship('Todo', backref='user', lazy=True)

    def serialize(self):
        return {
            "id":self.id,
            "name":self.name,
            "email":self.email,
            "password":self.password,
            "admin":self.admin
        }
    
class Todo(db.Model):
    __tablename__="todo"
    id = db.Column(db.Integer, primary_key=True)
    todo = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def serialize(self):
        return {
            "id":self.id,
            'todo':self.todo,
            'user_id':self.user_id
        }
    

app.app_context().push()

# If you want to delete tables for some reasons use 'db.drop_all()' --> run the code --> again comment it out
# db.drop_all()

# 'create_all' does not update tables if they are already in the database
# If you change a model’s columns, use a migration library like 'Flask-Migrate' to generate migrations that update the database schema.
db.create_all()


###################################################
#                                                 #
#               User Routes                       #
#                                                 #
###################################################

# Get all users
# Also Protect a route with jwt_required, which will kick out requests without a valid JWT present.
@app.route('/user', methods=['GET'])
@jwt_required()
def get_all_users():
    # Access the identity of the current user with "get_jwt_identity"
    # if identity is verified the returns "identity" else
    # Case 1: Did not provide authorization in header at all
        # Responds with 401 UNAUTHORIZED status code and {"msg":{"No Authorization Header"}}
    # Case 2: Token is timed out
        # Responds with 401 UNAUTHORIZED status code and {"msg": "Token has expired"}
    # Case 3: Wront token value
        # Responds with 422 UNPROCESSABILITY ENTITY status code and {"msg":"Signature verification failed"}

    current_user = get_jwt_identity() 

    data = User.query.all()
    users = [user.serialize() for user in data]
    return jsonify(users), 200


# Get only one user
@app.route('/user/<int:user_id>', methods=['GET'])
def get_one_user(user_id):
    user = User.query.get(user_id)
    if user is None:
        return jsonify({'msg':'No user found.'}), 400
    
    return jsonify(user.serialize()), 200


# Create user
@app.route('/user', methods=['POST'])
def create_user():

    if request.is_json: 
        name = request.json['name']
        email = request.json['email']
        password = request.json['password']

        user = User(name=name, email=email, password=password)

        db.session.add(user)
        db.session.commit()

    return jsonify({'msg':'New user created.'}), 201


# Promote user to Admin
@app.route('/user/<user_id>', methods=['PUT'])
def promote_user(user_id):
    data = User.query.get(user_id)
    if data is None:
        return jsonify({'msg':'No user found.'}), 400

    
    data.admin = True
    db.session.commit()

    return jsonify(data.serialize()), 200


# Delete user
@app.route('/user/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    data = User.query.get(user_id)
    db.session.delete(data)
    db.session.commit()

    return redirect(url_for('get_all_users'))


###################################################
#                                                 #
#          User Login Route                       #
#                                                 #
###################################################

@app.route('/login', methods=['POST'])
def login():
    # access the authorization keys,values / tokens parsed
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return jsonify({'msg':'Could not verify'}), 400

    print(request.headers)

    # find genuine user
    user = User.query.filter_by(email=auth.username).first()

    if not user or (user.serialize()['password'] != auth.password) :
        return jsonify({'msg':'Could not verify'}), 400
    
    token = create_access_token(identity=user.serialize()['id'])

    return jsonify(access_token=token), 200

if __name__=='__main__':
    app.run(debug=True)

