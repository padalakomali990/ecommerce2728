import sys
sys.dont_write_bytecode = True
from flask import Flask, request, jsonify,session, url_for
#from flask_session import Session #secure session management
import re
from flask_bcrypt import Bcrypt
from otp import genotp
from utils.cmail import send_mail
from utils.stoken import endata, dndata
from mysql.connector import connection
from datetime import timedelta
from werkzeug.utils import secure_filename #for secure file handling
import os 


mydb = connection.MySQLConnection(
    user='root',
    host='localhost',
    password='Komali@123',
    db='ecommercedb'
)

app = Flask(__name__)
app.permanent_session_lifetime = timedelta(days=1)
app.secret_key = '@janu'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
#Session(app)

#upload folder configuration

BASE_DIR= os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif','webp','pdf','jfif'}
MAX_CONTENT_LENGTH = 6 * 1024 * 1024  # 6MB
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

bcrypt = Bcrypt(app)


@app.route('/api/admin/register', methods=['POST'])
def admincreate():
    try:
        data = request.get_json(silent=True)

        if not data:
            return jsonify({'status': 'failed','message': 'No input data' }), 400

        admin_name = data.get('username', '').strip()
        admin_email = data.get('useremail', '').strip()
        admin_password = data.get('userpassword', '').strip()
        admin_address = data.get('useraddress', '').strip()
        admin_phone = data.get('userphone', '').strip()
        admin_agree = data.get('useragree')

        if not admin_name:
            return jsonify({'status': 'failed','message': 'Username required'  }), 400

        email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'

        if not re.match(email_pattern, admin_email):
            return jsonify({'status': 'failed','message': 'Invalid email' }), 400
        try:
            mydb.ping(reconnect=True)
            cursor = mydb.cursor(buffered=True)
            cursor.execute('select count(*) from admindata where admin_useremail=%s', [admin_email])
            email_exists = cursor.fetchone()[0]
            if email_exists > 0:
                return jsonify({ 'status': 'failed','message': 'Email already registered'}), 400
        except Exception as e:
            print("Database Error:", str(e))
            return jsonify({ 'status': 'failed','message': 'Database error occurred'}), 500

        if len(admin_password) < 6:
            return jsonify({
                'status': 'failed',
                'message': 'Password Too Short'
            }), 400

        cursor = mydb.cursor(buffered=True)

        cursor.execute(
            'SELECT COUNT(*) FROM admindata WHERE admin_useremail=%s',
            [admin_email]
        )

        email_exists = cursor.fetchone()[0]

        if email_exists > 0:
            cursor.close()
            return jsonify({
                'status': 'failed',
                'message': 'Email already registered'
            }), 400

        hashed_password = bcrypt.generate_password_hash(
            admin_password
        ).decode('utf-8')

        gotp = genotp()

        admindata = {
            'admin_username': admin_name,
            'admin_useremail': admin_email,
            'admin_userpassword': hashed_password,
            'admin_address': admin_address,
            'admin_phone': admin_phone,
            'admin_agree': admin_agree,
            'admin_otp': gotp
        }

        subject = 'Admin Registration Verification'

        body = f'''
Hello Admin,

Your OTP is: {gotp}

This OTP is valid for 5 minutes.

BUYROUTE Team
'''

        send_mail(
            to=admin_email,
            subject=subject,
            body=body
        )

        token = endata(admindata)

        cursor.close()

        return jsonify({
            'status': 'success',
            'message': 'OTP Sent Successfully',
            'token': token
        }), 200

    except Exception as e:
        print("Register Error:", str(e))
        return jsonify({
            'status': 'failed',
            'message': str(e)
        }), 500


@app.route('/api/admin/verify-otp', methods=['POST'])
def adminotpverify():
    cursor = None

    try:
        data = request.get_json()

        if not data:
            return jsonify({
                'status': 'failed',
                'message': 'No input data'
            }), 400

        userotp = data.get('otp')
        token = data.get('token')

        if not userotp or not token:
            return jsonify({
                'status': 'failed',
                'message': 'otp and token required'
            }), 400

        try:
            admin_details = dndata(token)

            if not admin_details:
                return jsonify({
                    'status': 'failed',
                    'message': 'Invalid token data'
                }), 400

        except Exception:
            return jsonify({
                'status': 'failed',
                'message': 'Invalid or expired token'
            }), 400

        if str(userotp) != str(admin_details['admin_otp']):
            return jsonify({
                'status': 'failed',
                'message': 'Invalid OTP'
            }), 400

        mydb.ping(reconnect=True)

        cursor = mydb.cursor(buffered=True)

        cursor.execute(
            'SELECT COUNT(*) FROM admindata WHERE admin_useremail=%s',
            [admin_details['admin_useremail']]
        )

        email_exists = cursor.fetchone()[0]

        if email_exists > 0:
            return jsonify({
                'status': 'failed',
                'message': 'Email already registered'
            }), 400

        cursor.execute(
            '''
            INSERT INTO admindata
            (
                adminid,
                admin_username,
                admin_useremail,
                admin_address,
                admin_password,
                admin_phoneno,
                admin_agree
            )
            VALUES
            (
                uuid_to_bin(uuid()),
                %s,%s,%s,%s,%s,%s
            )
            ''',
            [
                admin_details['admin_username'],
                admin_details['admin_useremail'],
                admin_details['admin_address'],
                admin_details['admin_userpassword'],
                admin_details['admin_phone'],
                admin_details['admin_agree']
            ]
        )

        mydb.commit()

        return jsonify({
            'status': 'success',
            'message': 'Admin registered successfully'
        }), 200

    except Exception as e:
        mydb.rollback()
        print("Verify OTP Error:", str(e))

        return jsonify({
            'status': 'failed',
            'message': str(e)
        }), 400

    finally:
        if cursor:
            cursor.close()


@app.route('/api/admin/login', methods=['POST'])
def adminlogin():
    cursor = None

    try:
        data = request.get_json()

        if not data:
            return jsonify({
                'status': 'failed',
                'message': 'No input data'
            }), 400

        login_email = data.get('useremail','').strip()
        login_password = data.get('userpassword','').strip()

        if not login_email or not login_password:
            return jsonify({
                'status': 'failed',
                'message': 'Email and password required'
            }), 400

        mydb.ping(reconnect=True)

        cursor = mydb.cursor(buffered=True)

        cursor.execute(
            'SELECT bin_to_uuid(adminid), admin_username, admin_useremail, admin_password FROM admindata WHERE admin_useremail=%s',[login_email])

        admin_data = cursor.fetchone()

        if not admin_data:
            return jsonify({
                'status': 'failed',
                'message': 'Invalid email or password'
            }), 404

        adminid=admin_data[0]
        adminname=admin_data[1]
        adminemail=admin_data[2]
        stored_password = admin_data[3]

        if not bcrypt.check_password_hash(stored_password,login_password ):
            return jsonify({
                'status': 'failed',
                'message': 'Invalid email or password'
            }), 401
        session.permanent = True
        session['adminid'] = adminid
        session['adminemail'] = adminemail
        return jsonify({
            'status': 'success',
            'message': 'Login successful',
            'adminid': adminid,
            'adminname': adminname,
            'adminemail': adminemail
        }), 200
    except Exception as e:
        print("Login Error:", str(e))
        return jsonify({
            'status': 'failed',
            'message': str(e)
        }), 500
    finally:
        if cursor:
            cursor.close()

@app.route('/api/admin/dashboard', methods=['GET'])
def admindashboard():
    try:
        #session check
        if 'adminid' not in session:
            return jsonify({
                'status': 'failed',
                'message': 'Unauthorized access'
            }), 401
        return jsonify({
            'status': 'success',
            'message': 'Welcome to the admin dashboard'
        ,'admin':{ 'adminid': session.get('adminid'), 'adminemail': session.get('adminemail') }}
        ), 200
    except Exception as e:
        print("Dashboard Error:", str(e))
        return jsonify({
            'status': 'failed',
            'message': str(e)
        }), 500
def allowed_file(filename:str)->bool:
    return ('.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS)

@app.route('/api/admin/add-item', methods=['POST'])
def additem():
    save_path = None
    cursor = None
    try:
        if 'adminid' not in session:
            return jsonify({
                'status': 'failed',
                'message': 'Unauthorized access'
            }), 401
        item_name = request.form.get('title','').strip()
        item_description = request.form.get('Description','').strip()
        item_about = request.form.get('About_item','').strip()
        item_quantity = request.form.get('quantity','').strip()
        item_price = request.form.get('price','').strip()
        item_category = request.form.get('category','').strip()
        #form data validation
        if not item_name :
            return jsonify({
                'status': 'failed',
                'message': 'Item name required'
            }), 400
        try:
            item_quantity = int(item_quantity)
            item_price = float(item_price)
        except ValueError:
            return jsonify({
                'status': 'failed',
                'message': 'Quantity must be an integer and price must be a number'
            }), 400
        item_filedata=request.files.get('file')
        if not item_filedata:
            return jsonify({'status': 'failed','message': 'Item image required'}), 400    
        filename = item_filedata.filename
        if not allowed_file(filename):
            return jsonify({'status': 'failed','message': 'Invalid file type' }), 400
        if not item_filedata.mimetype.startswith('image/'):
            return jsonify({'status': 'failed','message': 'File must be an image' }), 400
        orig_secure= secure_filename(filename) #remove special characters and spaces
        ext=os.path.splitext(orig_secure)[1] #get file extension
        filename=genotp()+ext #generate unique filename Rw23h.ext
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename) #save file to uploads folder
        item_filedata.save(save_path) #save file to server
        #reconnect to database and insert item data
        adminid=session.get('adminid')
        mydb.ping(reconnect=True)
        cursor = mydb.cursor(buffered=True)
        cursor.execute('''INSERT INTO items
            (
                itemid,
                item_name,
                item_description,
                item_about,
                quantity,
                price,
                category,
                item_filename,
                added_by
            )
            VALUES ( uuid_to_bin(uuid()), %s,%s,%s,%s,%s,%s,%s,uuid_to_bin(%s)) ''',
            [
                item_name,
                item_description,
                item_about,
                item_quantity,
                item_price,
                item_category,
                filename,
                session.get('adminid')
            ]
        )
        mydb.commit()
        return jsonify({'status': 'success', 'message': 'Item added successfully', 'image': url_for('static', filename=f'uploads/{filename}', _external=True)}), 200
    except Exception as e:
        mydb.rollback()
        print("Add Item Error:", str(e))
        if save_path and os.path.exists(save_path):
            os.remove(save_path) #remove uploaded file if database operation fails
        return jsonify({'status': 'failed', 'message': str(e)}), 500
    finally:
        if cursor:
            cursor.close()

if __name__ == '__main__':
    app.run(debug=True)