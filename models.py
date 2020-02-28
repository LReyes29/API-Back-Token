from flask_sqlalchemy import SQLAlchemy 

db = SQLAlchemy()

class Role(db.Model):
    __tablename__="roles"
    id= db.Column(db.Integer,primary_key=True)
    name=db.Column(db.String(50),unique=True,nullable=False)

    def __repr__(self): 
        return "<Role %r>" % self.name
    
    def serialize(self):
        return{
            "id":self.id,
            "name":self.name
        }

class User(db.Model):
    __tablename__="users"
    id= db.Column(db.Integer,primary_key=True)
    name=db.Column(db.String(50),nullable=False)
    username=db.Column(db.String(100),unique=True,nullable=False)
    email=db.Column(db.String(100),unique=True,nullable=False)
    password=db.Column(db.String(100),nullable=False)
    active=db.Column(db.Boolean, default=False)
    role_id=db.Column(db.Integer,db.ForeignKey('roles.id'), nullable=False)
    role= db.relationship(Role)

    def __repr__(self): 
        return "<User %r>" % self.name
    
    def serialize(self):
        return{
            "id":self.id,
            "name":self.name,
            "username":self.username,
            "email":self.email,
            "active":self.active,
            "role":self.role.serialize()
        }

