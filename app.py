from flask import Flask, render_template, jsonify ,  redirect, request, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, UserMixin, current_user
from flask.views import View
from flask_bcrypt import Bcrypt
import os, time, json, re, logging
import datetime

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///evildata.db'
app.config['SECRET_KEY'] = '~9yeO{EOEH=*GOzeltS{NP~QJ^=nIDDcF62me4WC'
db  = SQLAlchemy(app)
bcrypt = Bcrypt(app) 

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"




#==============================================================================================================================================================================================================================
#==================================================DATABASE============================================================================================================================================================================
#==============================================================================================================================================================================================================================


class User( db.Model, UserMixin ):
    __tablename__ = "user"
    id = db.Column( db.Integer, primary_key=True )
    username = db.Column( db.String( 80 ), unique = True, nullable = False )
    password = db.Column( db.String( 200 ), nullable = False )
    def __repr__(self):
        return '<User %r>' % self.username

   
#==============================================================================================================================================================================================================================
#==============================================================================================================================================================================================================================
#==============================================================================================================================================================================================================================


class Category( db.Model, UserMixin ):
    __tablename__ = "category"
    id = db.Column( db.Integer, primary_key=True )
    category_name = db.Column( db.String( 200 ), unique = True, nullable = False )

    def __repr__(self):
        return '<User %r>' % self.category_name

   
#==============================================================================================================================================================================================================================
#==============================================================================================================================================================================================================================
#==============================================================================================================================================================================================================================


class Task( db.Model, UserMixin ):
    __tablename__ = "task"
    id = db.Column( db.Integer, primary_key=True )
    task_title = db.Column( db.String( 200 ), unique = True, nullable = False )
    task_dis = db.Column( db.String( 10000 ), nullable = False )
    date = db.Column(db.DateTime)
    status = db.Column( db.String( 100 ),default = 'pending', nullable = False )
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    cat_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    
    def __repr__(self):
        return '<User %r>' % self.task_title


#==============================================================================================================================================================================================================================
#==============================================================================================================================================================================================================================
#==============================================================================================================================================================================================================================


@login_manager.user_loader
def load_user(user_id):    
    return User.query.session.get(User,user_id)


#==============================================================================================================================================================================================================================
#==============================================================================================================================================================================================================================
#==============================================================================================================================================================================================================================


@app.route("/login",methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password,password) :
            login_user(user)
            return redirect("/task")
        else:
            return "Invalid username or password"
    return render_template("login.html")


#==============================================================================================================================================================================================================================
#==============================================================================================================================================================================================================================
#==============================================================================================================================================================================================================================



@app.route("/signup",methods=["GET","POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        if password == confirm_password:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=username, password=hashed_password,)            
            db.session.add(new_user)
            db.session.commit()
            user = User.query.filter_by(username=username).first()
            login_user(user)
            return redirect("/task")
        else:
            return "Password does not match"
    return render_template('signup.html')


#==============================================================================================================================================================================================================================
#==============================================================================================================================================================================================================================
#==============================================================================================================================================================================================================================


@app.route("/logout",methods = ["GET"])
@login_required
def logout():
     logout_user()
     return redirect(url_for('login'))


#==============================================================================================================================================================================================================================
#==============================================================================================================================================================================================================================
#==============================================================================================================================================================================================================================

@app.route("/task",methods=["GET","POST"])
@login_required
def tasklist():
    tasks = Task.query.filter_by(user_id=current_user.id).all()
    categories = Category.query.all()
    return render_template("task.html", cat = categories, task=tasks, str=str, count=len(tasks)) #jsonify({"task":tasks})


@app.route("/addtask",methods=["POST"])
@login_required
def addtask():
    if request.method == "POST":
        cat_id = request.form.get("cat_id")
        task_title = request.form.get("task_title")
        task_dis = request.form.get("task_dis")
        date = "/".join( request.form.get("date").split("-")[::-1] )
        cat_id = Category.query.filter().first().id
        user = User.query.filter_by(username=current_user.username).first().id
        task = Task(task_title = task_title,task_dis = task_dis,date = datetime.datetime.strptime(date,r'%d/%m/%Y'),user_id = user, cat_id = cat_id)
        try:
            db.session.add(task)
            db.session.commit()
        except:
            db.session.rollback()
        return redirect('/task')
    return redirect('/task')


@app.route("/addcategory",methods=["POST","GET"])
@login_required
def addcategory():
    cat = request.form.get("cat")
    
    if request.method == "POST":
        category = Category(category_name = cat)
        db.session.add(category)
        db.session.commit()
        
    return redirect('task')

@app.route("/done/<id>")
@login_required
def done(id):
    Task.query.get(id).status = "Done"
    db.session.commit()
    return redirect('/task')

app.app_context().push()
db.create_all()

app.run(debug=False, port=5000)
