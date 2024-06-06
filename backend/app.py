from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tution.db'
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'

db = SQLAlchemy(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)

class Class(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    standard = db.Column(db.String(50))
    branch = db.Column(db.String(50))
    chapter = db.Column(db.String(255))
    topic = db.Column(db.String(255))

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    class_id = db.Column(db.Integer, db.ForeignKey('class.id'))
    lecture_date = db.Column(db.Date)
    start_time = db.Column(db.Time)
    end_time = db.Column(db.Time)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(username=data['username'], password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'Registered successfully'})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if not user or not check_password_hash(user.password_hash, data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401
    access_token = create_access_token(identity={'username': user.username})
    return jsonify(access_token=access_token)

@app.route('/attendance', methods=['POST'])
@jwt_required()
def mark_attendance():
    data = request.get_json()
    current_user = User.query.filter_by(username=get_jwt_identity()['username']).first()
    class_info = Class.query.filter_by(standard=data['standard'], branch=data['branch'], chapter=data['chapter'], topic=data['topic']).first()
    if not class_info:
        class_info = Class(standard=data['standard'], branch=data['branch'], chapter=data['chapter'], topic=data['topic'])
        db.session.add(class_info)
        db.session.commit()
    attendance = Attendance(user_id=current_user.id, class_id=class_info.id, lecture_date=datetime.strptime(data['date'], '%Y-%m-%d').date(), start_time=datetime.strptime(data['start_time'], '%H:%M').time(), end_time=datetime.strptime(data['end_time'], '%H:%M').time())
    db.session.add(attendance)
    db.session.commit()
    return jsonify({'message': 'Attendance marked successfully'})

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
