import os
import flask
import flask_sqlalchemy
import flask_praetorian
import flask_cors
from flask_mail import Mail, Message
from flask import render_template, request

db = flask_sqlalchemy.SQLAlchemy()
guard = flask_praetorian.Praetorian()
cors = flask_cors.CORS()


# A generic user model that might be used by an app powered by flask-praetorian
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text, unique=True)
    password = db.Column(db.Text)
    useremail = db.Column(db.Text, unique=True)
    roles = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True, server_default='true')

    @property
    def rolenames(self):
        try:
            return self.roles.split(',')
        except Exception:
            return []

    @classmethod
    def lookup(cls, username):
        return cls.query.filter_by(username=username).one_or_none()

    @classmethod
    def identify(cls, id):
        return cls.query.get(id)

    @property
    def identity(self):
        return self.id

    def is_valid(self):
        return self.is_active

# Initialize flask app for the example
app = flask.Flask(__name__, static_folder='../build', static_url_path=None)
app.debug = True
mail = Mail(app)

# main config
app.config['SECRET_KEY'] = 'my_precious'
app.config['SECURITY_PASSWORD_SALT'] = 'my_precious_two'
app.config['DEBUG'] = False
app.config['BCRYPT_LOG_ROUNDS'] = 13
app.config['WTF_CSRF_ENABLED'] = True
app.config['DEBUG_TB_ENABLED'] = False
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False

# mail settings
app.config['[MAIL_SERVER'] = 'smtp.gmail.com'
app.config['[MAIL_PORT'] = 465
app.config['[MAIL_USE_TLS'] = False
app.config['[MAIL_USE_SSL'] = True

# gmail authentication
app.config['MAIL_USERNAME'] = 'Tatyana.emails@gmail.com'
app.config['MAIL_PASSWORD'] = '123456Tatyana'

# mail accounts
app.config['MAIL_DEFAULT_SENDER'] = 'from@example.com'

app.config['SECRET_KEY'] = 'top secret'
app.config['JWT_ACCESS_LIFESPAN'] = {'hours': 1}
app.config['JWT_REFRESH_LIFESPAN'] = {'days': 30}

# Initialize the flask-praetorian instance for the app
guard.init_app(app, User)

# Initialize a local database for the example
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(os.getcwd(), 'database.db')}"
db.init_app(app)

# Initializes CORS so that the api_tool can talk to the example app
cors.init_app(app)

# Add users for the example
with app.app_context():
    db.create_all()
    if db.session.query(User).filter_by(username='Yasoob').count() < 1:
        db.session.add(User(
          username='Yasoob',
          useremail='yasoob123@gmail.com',
          password=guard.hash_password('strongpassword'),
          roles='admin'
		))
    db.session.commit()


# Set up some routes for the example
@app.route('/api/')
def home():
  	return {"Hello": "World"}, 200

messages = ['Hey', "tschua", "hallo"]

@app.route('/hallo/', methods = ['POST', 'GET'])
def hallo():
    if request.method == 'GET':
        return render_template('hello.html',messages = messages)
    if request.method == 'POST':
        form_data = request.form
        print(form_data)
        messages.append(form_data["message"])
        return render_template('hello.html',messages = messages)

@app.route('/api/login', methods=['POST'])
def login():
    """
    Logs a user in by parsing a POST request containing user credentials and
    issuing a JWT token.
    .. example::
       $ curl http://localhost:5000/api/login -X POST \
         -d '{"username":"Yasoob","password":"strongpassword"}'
    """
    req = flask.request.get_json(force=True)
    username = req.get('username', None)
    password = req.get('password', None)
    user = guard.authenticate(username, password)
    ret = {'access_token': guard.encode_jwt_token(user)}
    return ret, 200

@app.route('/api/refresh', methods=['POST'])
def refresh():
    """
    Refreshes an existing JWT by creating a new one that is a copy of the old
    except that it has a refrehsed access expiration.
    .. example::
       $ curl http://localhost:5000/refresh -X GET \
         -H "Authorization: Bearer <your_token>"
    """
    print("refresh request")
    old_token = request.get_data()
    new_token = guard.refresh_jwt_token(old_token)
    ret = {'access_token': new_token}
    return ret, 200


@app.route('/api/protected')
@flask_praetorian.auth_required
def protected():
    """
    A protected endpoint. The auth_required decorator will require a header
    containing a valid JWT
    .. example::
       $ curl http://localhost:5000/api/protected -X GET \
         -H "Authorization: Bearer <your_token>"
    """
    return {"message": f'protected endpoint (allowed user {flask_praetorian.current_user().username})'}

## TODO create a register route for new users
# accept email + username + password
# hash the password
# send a verification email for email double opt in

# connect that to a frontend login/register form

#############################
@app.route('/api/register', methods=['POST'])
def register():
    
    req = flask.request.get_json(force=True)
    useremail = req.get('useremail', None)
    username = req.get('username', None)
    password = req.get('password', None)
    # password hashen
    password_hash=guard.hash_password(password)

    if db.session.query(User).filter_by(useremail=useremail).count() < 1:
        db.session.add(User(
            username=username,
            password=password_hash,
            useremail=useremail, 
            roles='admin'
		))
        db.session.commit()
        # TODO SEND EMAIL configuration still WIP work in progress
        send_email(useremail, "Welcom to my Aplication!", "Hey" )
        ret = {'message': "Toll"}
    else:
        ret = {'message': "Du bist schon dort!"}
    return ret, 200
##############################


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    print("Hello from catch all")
    if path != "" and os.path.exists(os.path.join('..','build',path)):
        return app.send_static_file(path)
    else:
        return app.send_static_file('index.html')

def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    mail.send(msg)

# Run the example
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)