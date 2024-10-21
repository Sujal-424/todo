from flask import Flask, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///databse.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()

        if existing_user_username:
            raise ValidationError('That username already exists. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    
    submit = SubmitField('Login')

class Todo(db.Model):
    id_a = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    time_req = db.Column(db.Integer)
    priority = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('todolist'))
    return render_template('login.html', form=form)



@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/todolist')
def todolist():
    #show all todos
    todo_list= Todo.query.filter_by(user_id=current_user.id).all()
    print(todo_list)
    return render_template('todolist.html', todo_list=todo_list)

@app.route("/add", methods=["POST"])
def add():
    # add new item
    title = request.form.get("title")
    time_req = request.form.get("time_req")
    priority = request.form.get("priority")
    new_todo = Todo(title=title, time_req=time_req,priority=priority, complete=False, user_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()
    return redirect(url_for("todolist"))

@app.route("/update/<int:todo_id_a>")
def update(todo_id_a):
    # update if completed or not
    todo = Todo.query.filter_by(id_a=todo_id_a).first()
    todo.complete = not todo.complete
    db.session.commit()
    return redirect(url_for("todolist"))

@app.route("/delete/<int:todo_id_a>")
def delete(todo_id_a):
    # delete
    todo = Todo.query.filter_by(id_a=todo_id_a).first()
    db.session.delete(todo)
    db.session.commit()
    return redirect(url_for("todolist"))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        app.run(debug=True)