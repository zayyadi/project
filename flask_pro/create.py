from flask import Flask
from app import *
import os 

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI']= "postgresql://postgres:polar@localhost:5432/postgres"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False

db.init_app(app)

def main():
    db.create_all()

if __name__ == "__main__":
    with app.app_context():
        main()