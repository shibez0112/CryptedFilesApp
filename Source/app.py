from ctypes import addressof
from cv2 import DIST_MASK_PRECISE
from flask import Flask, render_template, flash, redirect, url_for, session, request, send_from_directory, send_file
from flask_mysqldb import MySQL,MySQLdb
from numpy import single
from wtforms import Form, StringField, PasswordField, validators
import hashlib, uuid
from functools import wraps
from werkzeug.utils import secure_filename
import os
from datetime import datetime
import zipfile
from os.path import basename
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
import base64
from Crypto.Util.Padding import pad, unpad
from hashlib import md5
import secrets
from Crypto.Cipher import PKCS1_OAEP
import rsa




BLOCK_SIZE = 32 # Bytes




app = Flask(__name__)


# Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '123456'
app.config['MYSQL_DB'] = 'cryptedapp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
# init MYSQL
mysql = MySQL(app)


#Support Functions
def derive_key_and_iv(password, salt, key_length, iv_length): #derive key and IV from password and salt.
    d = d_i = b''
    while len(d) < key_length + iv_length:
        d_i = md5(d_i + str.encode(password) + salt).digest() #obtain the md5 hash value
        d += d_i
    return d[:key_length], d[key_length:key_length+iv_length]

def encrypt(in_file, out_file, password, key_length=32):
    bs = AES.block_size #16 bytes
    salt = os.urandom(bs) #return a string of random bytes
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    out_file.write(salt)
    finished = False

    while not finished:
        chunk = in_file.read(1024 * bs) 
        if len(chunk) == 0 or len(chunk) % bs != 0:#final block/chunk is padded before encryption
            padding_length = (bs - len(chunk) % bs) or bs
            chunk += str.encode(padding_length * chr(padding_length))
            finished = True
        out_file.write(cipher.encrypt(chunk))

def decrypt(in_file, out_file, password, key_length=32):
    bs = AES.block_size
    salt = in_file.read(bs)
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    next_chunk = ''
    finished = False
    while not finished:
        chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
        if len(next_chunk) == 0:
            padding_length = chunk[-1]
            chunk = chunk[:-padding_length]
            finished = True 
        out_file.write(bytes(x for x in chunk)) 

def sign(message, key):
    return rsa.sign(message.encode('ascii'), key, 'SHA-256')

def verify(message, signature, key):
    try:
        return rsa.verify(message.encode('ascii'), signature, key,) == 'SHA-256'
    except:
        return False


# Index
@app.route('/')
def index():
    return render_template('home.html')


# About
@app.route('/about')
def about():
    return render_template('about.html')


# Register Form Class
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    email = StringField('Email', [validators.Length(min=4, max=25)])
    dob = StringField('Day of Birth', [validators.Length(min=8, max=25)])
    phone = StringField('Phone number', [validators.Length(min=9, max=25)])
    address = StringField('Address', [validators.Length(min=4, max=25)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match'),
        validators.Length(min=8, max=25)
    ])
    confirm = PasswordField('Confirm Password')

# Update Form Class
class UpdateForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    dob = StringField('Day of Birth', [validators.Length(min=8, max=25)])
    phone = StringField('Phone number', [validators.Length(min=9, max=25)])
    address = StringField('Address', [validators.Length(min=4, max=25)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match'),
        validators.Length(min=8, max=25)
    ])
    confirm = PasswordField('Confirm Password')


# User Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        dob = form.dob.data
        phone = form.phone.data
        address = form.address.data
        salt = os.urandom(32)

        password = hashlib.pbkdf2_hmac(
            'sha256', # The hash digest algorithm for HMAC
            form.password.data.encode('utf-8'), # Convert the password to bytes
            salt, # Provide the salt
            100000 # It is recommended to use at least 100,000 iterations of SHA-256 
        )

        #storage both password and salt into database to decrypt later
        storage_password = salt+password

        # Create keys
        (public_key1, private_key1) = rsa.newkeys(1024)
        public_key = public_key1.save_pkcs1('PEM')
        private_key = private_key1.save_pkcs1('PEM')

        print("Register password: ", storage_password)
        print("Register prikey: ", private_key)

        #encrypt private key by AES using password as secret key
        secret_key = hashlib.sha256(password).digest()
        raw = pad(private_key, BLOCK_SIZE)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(secret_key, AES.MODE_CBC, iv)
        encrypted = base64.b64encode(iv + cipher.encrypt(raw))

        # Create cursor
        cur = mysql.connection.cursor()
        if cur :print("Connected")
    
        # Execute query
        cur.execute("INSERT INTO users(name, email, dob, phone, address, password, public_key, private_key) VALUES(%s, %s, %s, %s, %s, %s, %s, %s)", (name, email, dob, phone, address, storage_password, public_key, encrypted))

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('You are now registered and can log in', 'success')

        return redirect(url_for('login'))
    return render_template('register.html', form=form)


# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get Form Fields
        email = request.form['email']
        password_candidate = request.form['password']

        # Create cursor
        cur = mysql.connection.cursor()

        # Get user by email
        result = cur.execute("SELECT * FROM users WHERE email = %s", [email])

        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['password']
            #get password and salt to check
            salt_from_storage = password[:32] # 32 is the length of the salt
            password_from_storage = password[32:]       
            decrypted_password = hashlib.pbkdf2_hmac('sha256',password_candidate.encode('utf-8'),salt_from_storage, 100000)
     
            # Compare Passwords
            if password_from_storage == decrypted_password:
                # Passed
                session['logged_in'] = True
                session['email'] = email

                flash('You are now logged in', 'success')
                return redirect(url_for('index'))
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error)
            # Close connection
            cur.close()
        else:
            error = 'email not found'
            return render_template('login.html', error=error)

    return render_template('login.html')


# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap


# User Update
@app.route('/update', methods=['GET', 'POST'])
@is_logged_in
def update():
    form = UpdateForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        dob = form.dob.data
        phone = form.phone.data
        address = form.address.data
        passphase = form.password.data

        # Create cursor
        cur = mysql.connection.cursor()
        # if cur :print("Connected")
    
        # Execute query
        if (str(name) != ""):
            cur.execute("UPDATE users SET name = %s WHERE email = %s",(name, session['email']))
        if (str(dob) != ""):
            cur.execute("UPDATE users SET dob = %s WHERE email = %s",(dob, session['email']))
        if (str(phone) != ""):
            cur.execute("UPDATE users SET phone = %s WHERE email = %s",(phone, session['email']))
        if (str(address) != ""):
            cur.execute("UPDATE users SET address = %s WHERE email = %s",(address, session['email']))
        if (str(passphase) != ""):
            #find user private key

            # Create cursor
            cur = mysql.connection.cursor()

            # Get user by email
            cur.execute("SELECT * FROM users WHERE email = %s", [session['email']])

            data = cur.fetchone()
            
            password = data['password']
            #get password and salt to check
            salt_from_storage = password[:32] # 32 is the length of the salt
            password_from_storage = password[32:]       

            #decrypt private key using password
            enc = data['private_key']
            secret_key = hashlib.sha256(password_from_storage).digest()
            enc = base64.b64decode(enc)
            iv = enc[:16]
            cipher = AES.new(secret_key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(enc[16:]), BLOCK_SIZE)
            # receiver_private_key = rsa.PrivateKey.load_pkcs1(decrypted)

            salt = os.urandom(32)
            password = hashlib.pbkdf2_hmac(
                'sha256', # The hash digest algorithm for HMAC
                passphase.encode('utf-8'), # Convert the password to bytes
                salt, # Provide the salt
                100000 # It is recommended to use at least 100,000 iterations of SHA-256 
            )

            #storage both password and salt into database to decrypt later
            storage_password = salt+password

            # private_key = private_key1.save_pkcs1('PEM')

            #encrypt private key by AES using password as secret key
            secret_key = hashlib.sha256(password).digest()
            raw = pad(decrypted, BLOCK_SIZE)
            iv = Random.new().read(AES.block_size)
            cipher = AES.new(secret_key, AES.MODE_CBC, iv)
            encrypted = base64.b64encode(iv + cipher.encrypt(raw))

            print("Update password: ", storage_password)
            print("Update prikey: ", decrypted)

            
            cur.execute("UPDATE users SET password = %s WHERE email = %s",(storage_password, session['email']))
            cur.execute("UPDATE users SET private_key = %s WHERE email = %s",(encrypted, session['email']))

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('Updated information!!', 'success')

        return redirect('/')
    return render_template('update.html', form=form)


# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


#Upload
@app.route('/uploadpage',methods=["POST","GET"])
@is_logged_in
def uploadpage():
    return render_template('upload.html')

#upload folder
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
  

#Upload a File
@app.route("/upload",methods=["POST","GET"])
@is_logged_in
def upload():
    if request.method == 'POST':

        #create connection with database
        cursor = mysql.connection.cursor()
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        now = datetime.now()

        #get receiver email
        email = request.form.get('username')

        #search for receiver public key
        query = "SELECT public_key FROM users WHERE email = %s"   
        cur.execute(query,[email])
        data = cur.fetchall()
        receiver_public_key_pem = ""
        for i in data:
            receiver_public_key_pem = (i['public_key'])

        #create Ksession key
        k_session = secrets.token_urlsafe()
        # print("K_session is: ",k_session )
        # print("K_session type is: ",type(k_session) )
        # print("Public key is: ", receiver_public_key_pem)

        #encrypt receiver's public key
        receiver_public_key = rsa.PublicKey.load_pkcs1(receiver_public_key_pem)
        encrypted = rsa.encrypt(k_session.encode('ascii'), receiver_public_key)
        # print("New k_session: ", encrypted)



        files = request.files.getlist('files[]')

        for file in files:
            #if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            with open(UPLOAD_FOLDER + '/' + filename, 'wb') as out_file:
                encrypt(file, out_file, k_session)

            #Add information of files into database
            cur.execute("INSERT INTO files (file_name, uploaded_on, own_by, share_to, k_sessions) VALUES (%s, %s, %s, %s, %s)",(filename, now, session['email'], email, encrypted))
            mysql.connection.commit()

        #Close connection
        cur.close()

        flash('File(s) successfully sent')    
    return redirect('/') 


#Manage
@app.route('/manage')
@is_logged_in
def manage_file():
    # Create cursor
    cur = mysql.connection.cursor()

    # Get file
    query = "SELECT file_name FROM files WHERE share_to = %s"
    param = ([session['email']])    
    result = cur.execute(query,param)

    files_list = []
    data = cur.fetchall()
    for i in data:
        files_list.append(i['file_name'])

    if len(files_list) > 0:
        return render_template('manage.html', files_list=files_list)
    else:
        msg = 'No Files Found'
        return render_template('manage.html', msg=msg)
    # Close connection
    cur.close()


#Open file 
@app.route('/uploads/<path:filename>', methods=['GET', 'POST'])
@is_logged_in
def download(filename):
    
    #find user private key

    # Create cursor
    cur = mysql.connection.cursor()

    # Get user by email
    cur.execute("SELECT * FROM users WHERE email = %s", [session['email']])

    data = cur.fetchone()
    
    password = data['password']
    #get password and salt to check
    salt_from_storage = password[:32] # 32 is the length of the salt
    password_from_storage = password[32:]       

    #decrypt private key using password
    enc = data['private_key']
    secret_key = hashlib.sha256(password_from_storage).digest()
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(enc[16:]), BLOCK_SIZE)


    cur.execute("SELECT * FROM files WHERE file_name = %s", [filename])

    data = cur.fetchone()

    k_session = (data['k_sessions'])

    # decrypt file's ksession key
    receiver_private_key = rsa.PrivateKey.load_pkcs1(decrypted)
    decrypted_session_key = rsa.decrypt(k_session, receiver_private_key).decode('ascii')


    # using decrypted session key to decrypt file and sent to user
    with open(UPLOAD_FOLDER + '/' + filename, 'rb') as in_file, open(UPLOAD_FOLDER + '/' + filename +'decrypted', 'wb') as out_file:
        decrypt(in_file, out_file, decrypted_session_key)

    uploads = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'])
    return send_from_directory(uploads, filename + 'decrypted', filename=filename, as_attachment=True)

#Sign a file

@app.route('/signpage',methods=["POST","GET"])
@is_logged_in
def signpage():
    return render_template('sign.html')

@app.route("/signfile",methods=["POST","GET"])
@is_logged_in
def signfile():
    if request.method == 'POST':

        #find user private key

        # Create cursor
        cur = mysql.connection.cursor()

        # Get user by email
        cur.execute("SELECT * FROM users WHERE email = %s", [session['email']])

        data = cur.fetchone()
        
        password = data['password']
        #get password and salt to check
        salt_from_storage = password[:32] # 32 is the length of the salt
        password_from_storage = password[32:]       

        #decrypt private key using password
        enc = data['private_key']
        secret_key = hashlib.sha256(password_from_storage).digest()
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(secret_key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(enc[16:]), BLOCK_SIZE)
        receiver_private_key = rsa.PrivateKey.load_pkcs1(decrypted)


        files = request.files.getlist('files[]')

        # open file and hash the data
        for file in files:
            filename = file.filename
            with open(UPLOAD_FOLDER + '/' + filename + '.sig', 'wb') as out_file:
                data = file.read().decode('utf-8')  # read the data
                out_file.write(sign(data, receiver_private_key)) # write data into .sig file

            uploads = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'])
            return send_from_directory(uploads, filename + '.sig', as_attachment=True)

        flash('File(s) successfully signed')    
    return redirect('/') 


#Check sign a file

@app.route('/checksignpage',methods=["POST","GET"])
@is_logged_in
def checksignpage():
    return render_template('checksign.html')

@app.route("/checksignfile",methods=["POST","GET"])
@is_logged_in
def checksignfile():
    if request.method == 'POST':

        files = request.files.getlist('files[]')

        # open file and check the data
        data = ""
        sig = ""
        for file in files:
            filename = file.filename
            if 'sig' in filename:
                sig = file.read()  # read the data
            else :
                data = file.read().decode('utf-8')
        
        # Check if there is a public key
        # Create cursor
        cur = mysql.connection.cursor()
        # Get all the public key
        cur.execute("SELECT * FROM users")

        users_data = cur.fetchall()
        
        msg = 'Cant identify the signature!!'

        for user in users_data:
            if verify(data, sig, rsa.PublicKey.load_pkcs1(user['public_key'])):
                msg = 'Signature is valid, own by ' + user['email']
                
        return render_template('checksign.html', msg=msg)




if __name__ == '__main__':
    app.secret_key='secret123'
    app.run(debug=True)
