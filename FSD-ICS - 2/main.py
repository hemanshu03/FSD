from flask import Flask, render_template, request, session, redirect, url_for
from flask_socketio import join_room, leave_room, send, SocketIO, emit
import werkzeug
import random
import urllib
from pymongo import MongoClient
import os
import socket
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask_login import LoginManager, UserMixin, logout_user
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import hashlib
import secrets
import sys
import re
from string import ascii_uppercase

app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)

app.secret_key = secrets.token_hex()
socketio = SocketIO(app)

client = MongoClient("mongodb://localhost:27017/?directConnection=true")

db_log_users = client["User_login_database"]
logins_collection = db_log_users["logs"]

db = client["User_database"]
# Create a collection for users
users_collection = db["users"]

secret_key = "Chatting app only for MITWPU Students :)"

otpv = ""

session_tokens = {}
rooms = {}
room_creators = {}

class User(UserMixin):
    pass


def generate_unique_code(length):
    while True:
        code = ""
        for _ in range(length):
            code += random.choice(ascii_uppercase)

        if code not in rooms:
            break

    return code


def is_username_unique(username):
    username = hash_un(username)
    return users_collection.count_documents({"_id": username}) == 0


def is_room_unique(room):
    Database_chat_logs = client["Chat_logs"]

    chat_collection = Database_chat_logs[room]
    
    # Retrieve the existing chats from the collection
    existing_chats = chat_collection.find_one({})

    if existing_chats is None:
        return True
    else:
        return False


def is_valid_email(email):
    # Basic pattern for email validation
    email_pattern = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?$')

    # Check if the email matches the pattern
    return bool(re.match(email_pattern, email))
    

def send_otp(email):
    message = MIMEMultipart()
    sender_email = "noreply.lanchatting@gmail.com"
    app_password = "oymk pdnc gbxx wmzk"
    
    subject = "Verify your email address for LAN chatting webapp"
    otp = str(random.randint(100000, 999999))
    body = "OTP to verify your email address you just entered to create account in LAN chatting webapp is: " + otp + "\nThis OTP can be used only one time, and will be invalid after use.\n\n\nThanks for opting into our app 😊\n\nRegards,\nLAN Chat developers team."

    recipient_email = email
    message["From"] = sender_email
    message["To"] = recipient_email
    message["Subject"] = subject

    # Attach the body of the email
    message.attach(MIMEText(body, "plain"))

    # Connect to the SMTP server
    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        # Start TLS for security
        server.starttls()

        # Login with your app-specific password
        server.login(sender_email, app_password)

        # Send the email
        server.sendmail(sender_email, recipient_email, message.as_string())
    
    return otp


def is_password_strong(password):
    # Check if the password meets the complexity requirements
    if len(password) < 8:
        return False

    # Check for at least one uppercase, one lowercase, one digit, and one special character
    if not re.search(r"[A-Z]", password) or \
       not re.search(r"[a-z]", password) or \
       not re.search(r"\d", password) or \
       not re.search(r"[!@#$&*.:_-]", password):
        return False

    if re.search(r"[%^()+=`~\|/?\"':;}][{><,]", password):
        return False

    return True


def hash_un(username, salt=""):
    if salt == "":
        hashed_user = hashlib.sha256(username.encode('utf-8')).hexdigest()
    if salt != "":
        salted_hashed_username = f"{username}{salt}"
        hashed_user = hashlib.sha256(salted_hashed_username.encode('utf-8')).hexdigest()

    return hashed_user


def hash_password(username, password):
    # Combine username and secret key as the salt
    salted_string = f"{username}{secret_key}"

    # Hash the salted password using SHA-256
    hashed_password = hashlib.sha256(salted_string.encode(
        'utf-8') + password.encode('utf-8')).hexdigest()

    return hashed_password


def register_user(username, password, email, ip):
    # Hash the password with salt
    hashed_password = hash_password(username, password)
    username = hash_un(username)
    current_datetime = datetime.now()
    formatted_datetime = current_datetime.strftime("%I:%M:%S %p %d/%m/%Y")

    # Insert user information into the collection
    
    users_collection.insert_one({
        "_id": username,
        "password": hashed_password,
        "email": email,
        "created at" : formatted_datetime,
        "created by IP address" : ip
    })


def check_regis(username, password):
    hashed_password = hash_password(username, password)
    username = hash_un(username)
    document = users_collection.find_one({"_id": username})
    
    if document:
        if hashed_password in document.get('password', ''):
            return True
        else:
            return False
    else:
        return False


def captcha():
    while True:
        captcha = ""
        for _ in range(5):
            captcha += random.choice(ascii_uppercase)
        cptc = input(
            f"Captcha: {captcha}\nEnter this captcha to confirm you are not a robot: ")
        break
    if cptc == captcha:
        return True
    else:
        return False


def encrypt(text):
    key = symmetric_key
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_text = cipher.encrypt(pad(text.encode('utf-8'), AES.block_size))
    return b64encode(encrypted_text).decode('utf-8')


def decrypt(encrypted_text):
    key = symmetric_key
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_text = unpad(cipher.decrypt(b64decode(encrypted_text)), AES.block_size)
    return decrypted_text.decode('utf-8')


def logout_user(name):
    # Add code to perform logout actions if needed
    logins_collection.update_one(
        {"user": name, "Session_status": "Active"},
        {"$set": {"Session_status": "logged_out"}}
    )
    print("Logout_user was executed")


def log_logins_outs(user, status, ip="", userid="", time_="", time_o=""):
    if userid != "":
        logins_collection.update_one(
            {
                "_id": userid,
            }, 
            {
                "$set": {
                    "user": user,
                    "IP address": ip,
                    "Session_status": "Active",
                    "login_datetime": time_,
                    "logout_datetime": time_o,
                    "login_status": status,
                },
            }, upsert=True
        )
        if userid == "":
            logins_collection.update_one(
                {
                    "user": user,
                    "IP address": ip,
                    "Session_status": "Active",
                }, 
                {
                    "$set": {
                        "logout_datetime": time_o,
                        "login_status": status,
                    },
                }, upsert=True
            )
    print("logged")
    return


def authenticate_user(username, password, ip):
    # Find the user by username
    user = hash_un(username)
    user = users_collection.find_one({"_id": user})

    if user and user["password"] == hash_password(username, password):
        return True
        # Perform actions after successful authentication
    else:
        return False


def generate_session_token():
    return hashlib.sha256(os.urandom(128)).hexdigest()


def store_sids(session_id, session_info):
    session_tokens[session_id] = session_info
    #print(session_tokens)


def get_session_info(session_id):
    if session_id in session_tokens:
        return session_tokens[session_id]
    else:
        return None


def check_if_logged(user):
    #user = hash_un(user)
    document = logins_collection.find_one({"_id": user})
    status = ""
    if document:
        if status in document.get('login_status', '') == "logged_in":
            return True
        else:
            return False
    else:
        return False


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


@app.route("/", methods=["POST", "GET"])
def login():
    counterp = 3
    capf = False
    session.clear()
    if request.method == "POST":
        ip = request.remote_addr
        name = request.form.get("name")
        password = request.form.get("password")
        login = request.form.get("login", False)
        create = request.form.get("create", False)
        forgot = request.form.get("forgot", False)

        if create != False:
            return redirect(url_for("create_acc"))

        if create != False:
            return redirect(url_for("forgot"))

        if not name:
            return render_template("login.html", error="Please enter your username.", name=name)

        if login != False and not password:
            return render_template("login.html", error="Please enter your password", name=name)

        if is_username_unique(name):
            return render_template("login.html", error=f"Username '{name}' does not exit.", name=name)

        if authenticate_user(name, password, ip):
            user = User()

            current_datetime = datetime.now()
            formatted_datetime = current_datetime.strftime("%I:%M:%S %p %d/%m/%Y")

            user.id = hash_un(name, formatted_datetime)

            if user.is_authenticated:
                log_logins_outs(name, "logged_in", ip, user.id, formatted_datetime)
            else:
                sys.exit()

            return redirect(url_for("home", username=user.id))

        if not authenticate_user(name, password, ip) and capf == False and counterp > 0:
            counterp = counterp-1
            return render_template("login.html", error=f"Incorrect password. Please try again.", name=name)

        if not authenticate_user(name, password, ip) and capf == False and counterp == 0:
            capf = True
            return redirect(url_for("captcha"))

        if not authenticate_user(name, password, ip) and capf == True and counterp > 0:
            counterp = counterp-1
            return render_template("login.html", error=f"Incorrect password. Please try again.", name=name)

        if not authenticate_user(name, password, ip) and capf == True and counterp == 0:
            return redirect(url_for("cannot_enter"))

    return render_template("login.html")


@app.errorhandler(401)
def unauthorized(error):
    return redirect(url_for("login"))

@app.errorhandler(500)
def sid_error(error):
    return redirect(url_for("login"))


@app.errorhandler(werkzeug.routing.exceptions.BuildError)
def handle_missing_parameter(error):
    return redirect(url_for("login"))

@app.route("/create", methods=["POST", "GET"])
def create_acc():
    session.clear()
    if request.method == "POST":
        ip = request.remote_addr
        email = request.form.get("email")
        name = request.form.get("name")
        password = request.form.get("password")
        create = request.form.get("create", False)

        if create != False and not name:
            return render_template("create_acc.html", error="Please enter a Username")

        if create != False and not is_username_unique(name):
            return render_template("create_acc.html", error="This username is already taken. Please use something.. different🤔")

        if create != False and not password:
            return render_template("create_acc.html", error="Please enter a Password")

        if create != False and not is_password_strong(password):
            return render_template("create_acc.html", error="Your password does not meet the requirements. Please enter a strong password")

        if create != False and not email:
            return render_template("create_acc.html", error="Please enter your 'VALID' email address")

        if create != False and is_valid_email(name):
            return render_template("create_acc.html", error=f"Please enter your 'VALID' email address")

        if create != False and name and password and email and is_password_strong(password) and is_username_unique(name) and is_valid_email(email):
            otp = send_otp(email)
            #otp = '12345'

            # Store information in session
            session['email'] = email
            session['name'] = name
            session['password'] = password
            session['otp'] = otp
            session['ip'] = ip

            redirect_target = url_for("verify_otp")
            return redirect(redirect_target)
        else:
            return render_template("create_acc.html", error="Sorry.. it's on us. We have encountered some problem on the server side 😅")

    return render_template("create_acc.html")


@app.route("/verify_otp", methods=["POST", "GET"])
def verify_otp():
    if request.method == "POST":
        otpv = request.form.get("OTP")
        #otpv = hash_un(otpv)
        verify = request.form.get("verify", False)
        success ="Registration successful!\nContinue using your account by loggin in."
        fail ="Registration unsuccessful!\nTry again."
        
        if verify != False and 'otp' not in session:
            return render_template("verify_otp.html", error="Enter the OTP first.")
        
        if verify != False and 'otp' in session:
            if otpv != session['otp']:
                return render_template("verify_otp.html", error="Incorrect OTP.")
            
            if otpv == session['otp']:
                register_user(session['name'], session['password'], session['email'], session['ip'])
                if check_regis(session['name'], session['password']) == True:
                    session['rs']=success
                if check_regis(session['name'], session['password']) == False:
                    session['rs']=fail
                if check_regis(session['name'], session['password']) != True and check_regis(session['name'], session['password']) != False:
                    print(f"An unknown error occured while creating an account for user name {session['name']}.")
                return redirect(url_for("login"))
            
            return render_template("verify_otp.html", error="Enter the OTP first.")

    return render_template("verify_otp.html")


def extract_username(url):
    # Parse the URL
    parsed_url = urllib.parse.urlparse(url)

    # Extract the username from the URL path
    username = parsed_url.path.split('/')[-1]

    return username


@app.route("/home/<username>", methods=["POST", "GET"])
def home(username):
    session.clear()
    if request.method == "POST":
        if check_if_logged(username):
            name = request.form.get("alias")
            code = request.form.get("code")
            join = request.form.get("join", False)
            create = request.form.get("create", False)

            if not name:
                return render_template("home.html", error="Please enter a name.", code=code, name=name)

            if join != False and not code:
                return render_template("home.html", error="Please enter a room code.", code=code, name=name)

            room = code
            if create != False:
                room = generate_unique_code(10)

                while not is_room_unique(room):
                    room = generate_unique_code(10)

                create_room_in_db(room, name)

                rooms[room] = {"members": 0, "messages": []}
                room_creators[room] = session.get("name")

            elif code not in rooms:
                # Retrieve room information from MongoDB
                Database_chat_logs = client["Chat_logs"]
                chat_collection = Database_chat_logs[code]
                existing_chats = chat_collection.find_one({})

                if existing_chats is None or "chats" not in existing_chats:
                    return render_template("home.html", error="Room does not exist.", code=code, name=name)

                # Initialize the rooms dictionary with data from MongoDB
                rooms[code] = {"members": 0, "messages": existing_chats["chats"]}

            session["room"] = room
            session["name"] = name

            return redirect(url_for("room"))
        else:
            print("Username not found")
            emit('error', {'error': 'Unauthorized access', 'code': 401}, namespace='/')

    return render_template("home.html")


@socketio.on("delete_chatroom")
def handle_message(message):
    if message == "delete_this_chatroom":
        room = session.get("room")

        # Assuming 'rooms' is a global variable where room information is stored
        if room in rooms:
            del rooms[room]

            # Specify your MongoDB database and collection names
            chat_logs_database = client["Chat_logs"]
            chat_collection = chat_logs_database[room]

            # Drop the specified collection
            chat_collection.drop()

        return redirect(url_for("login"))


@app.route("/room")
def room():
    #if check_if_logged(username):
    room = session.get("room")
    if room is None or session.get("name") is None or room not in rooms:
        return redirect(url_for("home"))
    #else:
        #emit('error', {'error': 'Unauthorized access', 'code': 401}, namespace='/')

    return render_template("room.html", code=room, messages=rooms[room]["messages"])


def create_room_in_db(room, name):
    Database_chat_logs = client["Chat_logs"]

    chat_collection = Database_chat_logs[room]
    
    chat_collection.insert_one({
        "creater": name,
        "chats" : []
    })
    return


def save_chats(room, content):
    Database_chat_logs = client["Chat_logs"]

    chat_collection = Database_chat_logs[room]
    
    # Retrieve the existing chats from the collection
    existing_chats = chat_collection.find_one({})

    if existing_chats is None:
        existing_chats = {"chats": []}

    # Append the new chat to the list
    new_chat = {"name": content["name"], "message": content["message"]}
    existing_chats["chats"].append(new_chat)

    # Update the collection with the new chat
    chat_collection.update_one({}, {"$set": existing_chats}, upsert=True)


@socketio.on("message")
def message(data):
    room = session.get("room")
    if room not in rooms:
        return
    
    dmsg = decrypt(data)
    
    content = {
        "name": session.get("name"),
        "message": dmsg
    }
    send(content, to=room)
    rooms[room]["messages"].append(content)

    #log_file_path = os.path.join(script_dir, f"chat_log_{room}.txt")

    save_chats(room, content)
    
    #with open(log_file_path, "a", encoding='utf-8') as logf:
        #logf.write(f"\n{session.get('name')} said: {data['data']}")

    #print(f"{session.get('name')} said: {data['data']}")


@socketio.on("connect")
def connect(auth):
    room = session.get("room")
    name = session.get("name")
    
    if not room or not name:
        return
    if room not in rooms:
        leave_room(room)
        return

    join_room(room)

    # Retrieve messages from MongoDB
    Database_chat_logs = client["Chat_logs"]
    chat_collection = Database_chat_logs[room]
    existing_chats = chat_collection.find_one({})

    if existing_chats and "chats" in existing_chats:
        for chat in existing_chats["chats"]:
            send({"name": chat["name"], "message": chat["message"]}, to=room)

    content = f"{name} has entered the room"
    
    save_chats(room, {"name": "System", "message": content})
    send({"name": "System", "message": f"{name} entered the room"}, to=room)
    rooms[room]["members"] += 1


@socketio.on("disconnect")
def disconnect():
    ip = request.remote_addr
    current_datetime = datetime.now()
    formatted_datetime = current_datetime.strftime("%I:%M:%S %p %d/%m/%Y")
    room = session.get("room")
    name = session.get("name")
    leave_room(room)

    if room in rooms:
        rooms[room]["members"] -= 1

    send({"name": "System", "message": f"{name} left the room"}, to=room)
    log_logins_outs(name, "logged_out", ip)
    logout_user(name)


if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    symmetric_key = b'3bmzBA+g8S9pXq/xRtk3fQ=='
    def get_public_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            public_ip = s.getsockname()[0]
            s.close()
            return public_ip
        except Exception as e:
            print(f"Error getting public IP: {e}")
            return None
    #print(f'Server running at http://{get_public_ip()}:5000')
    socketio.run(app, debug=False, host=str(
        get_public_ip()), port=5000)
