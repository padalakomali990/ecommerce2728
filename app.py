import sys
import uuid
sys.dont_write_bytecode = True
from flask import Flask, make_response,request,redirect,url_for,jsonify,session
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
#from flask_session import Session #security layer
from flask_bcrypt import Bcrypt
import re
from otp import genotp
from utils.cmail import send_mail
from utils.stoken import endata,dndata
from mysql.connector import (connection)
from datetime import timedelta
from io import BytesIO
from reportlab.platypus import(
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph,
    Spacer
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4
from reportlab.platypus.flowables import HRFlowable
import uuid
import razorpay
client = razorpay.Client(auth=("rzp_test_SzppdEzy51SPYd", "ZXV3p1lSRtZFXpt9wXac4kI8"))

from werkzeug.utils import secure_filename #used to check secured filenames or not
from werkzeug.middleware.proxy_fix import ProxyFix
import os

mydb=connection.MySQLConnection(user='flaskuser',host='localhost',password='password',db='ecommercedb')

app = Flask(__name__)
app.wsgi_app=ProxyFix(app.wsgi_app,x_proto=1,x_host=1)
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1
)
UPLOAD_FOLDER = "static/uploads"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
ALLOWED_EXTENSIONS={"png","jpeg","jpg","gif","webp","jfif"}
MAX_CONTENT_LENGTH=6 *1024*1024 #6MB
app.config['UPLOAD_FOLDER']=UPLOAD_FOLDER

app.secret_key = "Code123"

app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "None"
app.config["SESSION_REFRESH_EACH_REQUEST"] = True

app.permanent_session_lifetime = timedelta(days=1)
app.config['PREFERED_URL_SCHEME']='https'
CORS(
    app,
    origins=[
        "http://localhost:5173",
        "https://ecommerce-admin-user-five.vercel.app"
    ],
    supports_credentials=True
)


bcrypt=Bcrypt(app)

@app.route("/")
def home():
    return "Flask Backend Running Successfully"
@app.route('/api/admin/register',methods=['POST'])
def admincreate():
    try:
        data=request.get_json()
        print(data)
        if not data:
            return jsonify({'status':'failed','message':'No input data'}),400
        admin_name=data.get('username','').strip()
        admin_email=data.get('useremail','').strip()
        admin_address=data.get('useraddress','').strip()
        admin_password=data.get('userpassword','').strip()
        admin_phone=data.get('userphone','').strip()
        admin_agree=data.get('useragree')
        #validation
        if not admin_name:
            return jsonify({'status':'failed','message':'Username required'}),400
        email_pattern=r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_pattern,admin_email):
            return jsonify({'status':'failed','message':'Invalid email'}),400
        try:
            mydb.ping(reconnect=True)
            cursor=mydb.cursor(buffered=True)
            cursor.execute('select count(*) from admindata where admin_useremail=%s',[admin_email])
            email_exists=cursor.fetchone()[0]
            if email_exists > 0:
                return jsonify({'status':'failed','message':'Email already registered'}),400
        except Exception as e:
            print(" Mysql Error",str(e))
            return jsonify({'status':'failed','message':str(e)}),500
        if len(admin_password)<6:
            return jsonify({'status':'failed','message':'password too short'}),400
        #hash value for password encryption
        hashed_password=bcrypt.generate_password_hash(admin_password).decode('utf-8')
        gotp=genotp() #generating otp
        admindata={'admin_username':admin_name,'admin_useremail':admin_email,'admin_userpassword':hashed_password,'admin_address':admin_address,'admin_agree':admin_agree,'admin_phone':admin_phone,'admin_otp':gotp}
        subject='Admin Registration Verification'
        body=f''' Hello Admin,
                  Your OTP is :{gotp}
                  This OTP is valid for 5 minutes.
                  BUYROUTE Team'''
        send_mail(to=admin_email,subject=subject,body=body)
        token=endata(admindata)
        return jsonify({'status':'success',
                        'message':'OTP sent successfully',
                        'token':token}),200
    except Exception as e:
        print('Error occurs:',str(e))
        return jsonify({'status':'failed','message':str(e)}),500
    
@app.route('/api/admin/verify-otp',methods=['POST'])
def adminotpverify():
    cursor=None
    try:
        data=request.get_json()
        if not data:
            return jsonify({'status':'failed','message':'No input data'}),400
        userotp=data.get('otp') #F6hS8j
        token=data.get('token') 
        if not userotp or not token:
            return jsonify({'status':'failed','message':'otp and token required'}),400
        #decrypt token safely
        try:
            admin_details=dndata(token) #{'admin_username':admin_name,'admin_useremail':admin_email,'admin_userpassword':hashed_password,'admin_address':admin_address,'admin_agree':admin_agree,'admin_phone':admin_phone,'admin_otp':gotp}
        except Exception as e:
            return jsonify({'status':'failed','message':'invalid or expired token'}),400
        #otp verification
        if str(userotp) != str(admin_details['admin_otp']):
            return jsonify({'status':'failed','message':'Invalid otp'}),400
        #reconnect automatically if mysql connection loast
        mydb.ping(reconnect=True)
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select count(*) from admindata where admin_useremail=%s',[admin_details['admin_useremail']])
        email_exists=cursor.fetchone()[0]
        if email_exists > 0:
            return jsonify({'status':'failed','message':'Email already registered'}),400
        cursor.execute('insert into admindata(adminid,admin_username,admin_useremail,admin_address,admin_password,admin_phoneno,admin_agree) values(uuid_to_bin(uuid()),%s,%s,%s,%s,%s,%s)',[admin_details['admin_username'],admin_details['admin_useremail'],admin_details['admin_address'],admin_details['admin_userpassword'],admin_details['admin_phone'],admin_details['admin_agree']])
        mydb.commit()
        return jsonify({'status':'success','message':'Admin Registered Successfully'}),400
    except Exception as e:
        mydb.rollback() #undo the transaction
        print(" Mysql Error",str(e))
        return jsonify({'status':'failed','message':str(e)}),500
    finally:
        if  cursor:
            cursor.close()
            
@app.route('/api/admin/login',methods=['POST'])
def adminlogin():
    cursor=None
    try:
        data=request.get_json()
        if not data:
            return jsonify({'status':'failed','message':'No input data'}),400
        login_email=data.get('email','').strip()
        login_password=data.get('password','').strip()
        if not login_email or not login_password:
            return jsonify({'status':'failed','message':'Email and password required'}),400
        #reconnect automatically if mysql connection lost
        mydb.ping(reconnect=True)
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select bin_to_uuid(adminid),admin_username,admin_useremail,admin_password from admindata where admin_useremail=%s',[login_email])
        admin_data=cursor.fetchone()
        if not admin_data:
            return jsonify({'status':'failed','message':'Invalid email'}),404
        adminid=admin_data[0]
        adminname=admin_data[1]
        adminemail=admin_data[2]
        stored_password=admin_data[3]
        
        if not bcrypt.check_password_hash(stored_password,login_password):
            return jsonify({'status':'failed','message':'Invalid password'}),401

        session.clear()
        session.permanent = True
        session['adminid'] = adminid
        session['adminemail'] = adminemail
        print("LOGIN SESSION =", dict(session))
        print("LOGIN COOKIES =", request.cookies)

        response = jsonify({
    'status':'success',
    'message':'Login successful',
    'admin':{
        'adminid':adminid,
        'adminname':adminname,
        'adminemail':adminemail
    }
})

        print("FINAL SESSION =", dict(session))
        print("FINAL RESPONSE HEADERS =", response.headers)

        return response, 200
            
    except Exception as e:
        print('Mysql Error:',str(e))
        return jsonify({'status':'failed','message':str(e)}),500
    finally:
        if cursor:
            cursor.close()
            
@app.route('/api/admin/dashboard',methods=['GET'])
def admindashboard():
    try:
        #session validation
        if 'adminid' not in session:
            return jsonify({'status':'failed','message':'pls login First'}),401
        return jsonify({'status':'success','message':'welcome Admin','admin':{'adminid':session.get('adminid'),'adminemail':session.get('adminemail')}}),200
    except Exception as e:
        print('dashboard Error:', str(e))
        return jsonify({'status':'failed','message':str(e)}),500
def allowed_file(filename:str)->bool:
    return ("." in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS) # type: ignore

@app.route('/api/admin/add-item',methods=['POST'])
def additem():
    save_path=None
    cursor=None
    print("ADD ITEM SESSION =", session)
    print("ADD ITEM COOKIES =", request.cookies)
    print("ADMINID =", session.get("adminid"))
    try:
        if 'adminid' not in session:
            return jsonify({
                'status':'failed',
                'message':'pls login first'
            }),401
        item_name=request.form.get('title','').strip()
        item_description=request.form.get('Description','').strip()
        item_about=request.form.get('About_item','').strip()
        item_quantity=request.form.get('quantity','').strip()
        item_price=request.form.get('price','').strip()
        item_category=request.form.get('category','').strip()
        #form validation
        if not item_name:
            return jsonify({'status':'failed','message':'Item title required'}),400
        try:
            item_price=float(item_price)
            item_quantity=int(item_quantity)
        except ValueError:
            return jsonify({'status':'failed','message':'Invalid price or quantity'}),400
        item_filedata=request.files.get('file')
        if not item_filedata:
            return jsonify({'status':'failed','message':'Image required'}),400
        filename=item_filedata.filename
        if not allowed_file(filename):
            return jsonify({'status':'failed','message':'Invalid file type'}),400
        if not item_filedata.mimetype.startswith('image/'):
            return jsonify({'status':'failed','message':'Invalid image'}),400
        orig_secure=secure_filename(filename) #removes extra / spaces
        ext=os.path.splitext(orig_secure)[1]
        filename=genotp()+ext #'R7hD4n.ext'
        save_path=os.path.join(app.config['UPLOAD_FOLDER'],filename) #defile imagefile path
        item_filedata.save(save_path) #stores img in savepath 
        #reconnect automatically if mysql connection lost
        adminid=session.get('adminid')
        mydb.ping(reconnect=True)
        cursor=mydb.cursor(buffered=True)
        cursor.execute('''insert into items(itemid,item_name,item_description,item_about,quantity,price,category,item_filename,added_by) values(uuid_to_bin(uuid()),%s,%s,%s,%s,%s,%s,%s,uuid_to_bin(%s))''',[item_name,item_description,item_about,item_quantity,item_price,item_category,filename,adminid])
        mydb.commit()
        return jsonify({'status':'success','message':'Item Added Successfully','image':url_for('static',filename=f'uploads/{filename}',_external=True)}),200
    except Exception as e:
        mydb.rollback()
        print('ADD ITEM ERROR',str(e))
        if save_path and os.path.exists(save_path):
            os.remove(save_path)
        return jsonify({'status':'failed','message':str(e)}),500
    finally:
        if cursor:
            cursor.close()
            
@app.route('/api/admin/items', methods=['GET'])
def viewallitems():
    # DEBUG
    print("ITEMS SESSION =", dict(session))
    print("ADMIN ID =", session.get("adminid"))
    cursor = None
    try:
        # login check
        if 'adminid' not in session:
            return jsonify({
                'status': 'failed',
                'message': 'pls login first'
            }), 401

        adminid = session.get('adminid')

        mydb.ping(reconnect=True)
        cursor = mydb.cursor(buffered=True)

        cursor.execute('''
            select 
                bin_to_uuid(itemid),
                item_name,
                item_description,
                item_about,
                price,
                quantity,
                category,
                item_filename,
                created_at
            from items
            where added_by = uuid_to_bin(%s)
        ''', [adminid])

        allitems_data = cursor.fetchall()

        products = []

        for item in allitems_data:
            products.append({
                'itemid': item[0],
                'itemname': item[1],
                'item_desc': item[2],
                'item_about': item[3],
                'price': float(item[4]),
                'quantity': item[5],
                'category': item[6],
                'image': url_for(
                    'static',
                    filename=f'uploads/{item[7]}',
                    _external=True
                )
            })

        return jsonify({
            'status': 'success',
            'products': products
        }), 200

    except Exception as e:
        print("VIEW ITEMS ERROR:", str(e))
        return jsonify({
            'status': 'failed',
            'message': str(e)
        }), 500

    finally:
        if cursor:
            cursor.close()
                
@app.route('/api/admin/item/<itemid>',methods=['GET'])
def viewitem(itemid):
        # DEBUG
    print("ITEMS SESSION =", dict(session))
    print("ADMIN ID =", session.get("adminid"))
    cursor=None
    try:
        print("SINGLE ITEM SESSION =", dict(session))
        print("ADMIN ID =", session.get("adminid"))
        if 'adminid' not in session:
            return jsonify({'status':'failed','message':'pls login first'}),401
        try:
            uuid.UUID(itemid)
        except ValueError:
            return jsonify({'status':'failed','message':'invalid item id'}),400
        adminid=session.get('adminid')
        mydb.ping(reconnect=True)
        cursor=mydb.cursor(buffered=True)
        cursor.execute('''select bin_to_uuid(itemid),item_name,item_description,item_about,price,quantity,category,item_filename,created_at from items where added_by=uuid_to_bin(%s) and itemid=uuid_to_bin(%s)''',[adminid,itemid])
        item_data=cursor.fetchone()
        if not item_data:
            return jsonify({'status':'failed','message':'item not found'}),404
        products={'itemid':item_data[0],
                              'itemname':item_data[1],
                              'item_desc':item_data[2],
                              'item_about':item_data[3],
                              'price':float(item_data[4]),
                              'quantity':item_data[5],
                              'category':item_data[6],
                              'image':url_for('static',filename=f'uploads/{item_data[7]}',_external=True)}
        return jsonify({'status':'success','products':products}),200
    except Exception as e:
        print("VIEW ITEMS ERROR:",str(e))
        return jsonify({'status':'failed','message':str(e)}),500
    finally:
        if cursor:
            cursor.close()

@app.route('/api/admin/delete-item/<itemid>',methods=['DELETE'])
def deleteitem(itemid):
        # DEBUG
    print("ITEMS SESSION =", dict(session))
    print("ADMIN ID =", session.get("adminid"))
    cursor=None
    try:
        if 'adminid' not in session:
            return jsonify({'status':'failed','message':'pls login first'}),401
        try:
            uuid.UUID(itemid)
        except ValueError:
            return jsonify({'status':'failed','message':'invalid item id'}),400
        adminid=session.get('adminid')
        mydb.ping(reconnect=True)
        cursor=mydb.cursor(buffered=True)
        cursor.execute('''select bin_to_uuid(itemid),item_name,item_description,item_about,price,quantity,category,item_filename,created_at from items where added_by=uuid_to_bin(%s) and itemid=uuid_to_bin(%s)''',[adminid,itemid])
        item_data=cursor.fetchone()
        if not item_data:
            return jsonify({'status':'failed','message':'item not found'}),404
        image_name=item_data[7]
        remove_path=os.path.join(app.config['UPLOAD_FOLDER'],image_name)
        #delete item in DB
        cursor.execute('''delete from items where itemid=uuid_to_bin(%s) and added_by=uuid_to_bin(%s)''',[itemid,adminid])
        mydb.commit()
        #deleting image in static folder
        if os.path.exists(remove_path):
            os.remove(remove_path)
        return jsonify({'status':'success','message':'Item DELETE SUCCESSFULLY'}),200
    except Exception as e:
        mydb.rollback()
        print("DELETE ITEMS ERROR:",str(e))
        return jsonify({'status':'failed','message':str(e)}),500
    finally:
        if cursor:
            cursor.close()

@app.route('/api/admin/update-item/<itemid>', methods=['PUT'])
def updateitem(itemid):

    # DEBUG
    print("UPDATE SESSION =", dict(session))
    print("ADMIN ID =", session.get("adminid"))

    new_image_path = None
    old_image_path = None
    cursor = None

    try:
        # login check
        if 'adminid' not in session:
            return jsonify({
                'status': 'failed',
                'message': 'pls login First'
            }), 401

        # validate uuid
        try:
            uuid.UUID(itemid)
        except ValueError:
            return jsonify({
                'status': 'failed',
                'message': 'Invalid itemid'
            }), 400

        # receive form data
        updateditem_name = request.form.get('title', '').strip()
        updateditem_description = request.form.get('Description', '').strip()
        updateditem_about = request.form.get('About_item', '').strip()
        updateditem_quantity = request.form.get('quantity', '').strip()
        updateditem_price = request.form.get('price', '').strip()
        updateditem_category = request.form.get('category', '').strip()

        # validation
        if not updateditem_name:
            return jsonify({
                'status': 'failed',
                'message': 'Item name required'
            }), 400

        try:
            updateditem_price = float(updateditem_price)
            updateditem_quantity = int(updateditem_quantity)
        except ValueError:
            return jsonify({
                'status': 'failed',
                'message': 'Invalid price or quantity'
            }), 400

        mydb.ping(reconnect=True)
        cursor = mydb.cursor(buffered=True)

        adminid = session.get('adminid')

        # fetch old item
        cursor.execute('''
            select 
                bin_to_uuid(itemid),
                item_name,
                item_description,
                item_about,
                price,
                quantity,
                category,
                item_filename,
                created_at
            from items
            where added_by=uuid_to_bin(%s)
            and itemid=uuid_to_bin(%s)
        ''', [adminid, itemid])

        item_data = cursor.fetchone()

        if not item_data:
            return jsonify({
                'status': 'failed',
                'message': 'item not found'
            }), 404

        old_image = item_data[7]
        filename = old_image

        updateditem_filedata = request.files.get('file')

        print("FILE DATA =", updateditem_filedata)

        # new image upload
        if updateditem_filedata:

            uploaded_filename = updateditem_filedata.filename

            # extension validation
            if not allowed_file(uploaded_filename):
                return jsonify({
                    'status': 'failed',
                    'message': 'only png,jpg,jpeg,webp,gif allowed'
                }), 400

            # mime validation
            if not updateditem_filedata.mimetype.startswith('image/'):
                return jsonify({
                    'status': 'failed',
                    'message': 'Invalid image'
                }), 400

            orig_secure = secure_filename(uploaded_filename)

            ext = os.path.splitext(orig_secure)[1]

            filename = genotp() + ext

            # save new image
            new_image_path = os.path.join(
                app.config['UPLOAD_FOLDER'],
                filename
            )

            updateditem_filedata.save(new_image_path)

            old_image_path = os.path.join(
                app.config['UPLOAD_FOLDER'],
                old_image
            )

        # update db
        cursor.execute('''
            update items 
            set item_name=%s,
                item_description=%s,
                item_about=%s,
                price=%s,
                quantity=%s,
                category=%s,
                item_filename=%s
            where itemid=uuid_to_bin(%s)
            and added_by=uuid_to_bin(%s)
        ''', [
            updateditem_name,
            updateditem_description,
            updateditem_about,
            updateditem_price,
            updateditem_quantity,
            updateditem_category,
            filename,
            itemid,
            adminid
        ])

        print("UPDATED SUCCESSFULLY")

        mydb.commit()

        # delete old image after success
        if (
            updateditem_filedata and
            old_image_path and
            os.path.exists(old_image_path)
        ):
            os.remove(old_image_path)

        return jsonify({
            'status': 'success',
            'message': 'Item Updated successfully',
            'image': url_for(
                'static',
                filename=f'uploads/{filename}',
                _external=True
            )
        }), 200

    except Exception as e:

        mydb.rollback()

        print("UPDATE ITEM ERROR:", str(e))

        if (
            new_image_path and
            os.path.exists(new_image_path)
        ):
            os.remove(new_image_path)

        return jsonify({
            'status': 'failed',
            'message': str(e)
        }), 500

    finally:
        if cursor:
            cursor.close()
                    
@app.route('/api/admin/profile-update',methods=['PUT'])
def adminprofileupdate():
    new_image_path=None
    old_image_path=None
    cursor=None
    try:
        if 'adminid' not in session:
            return jsonify({'status':'failed','message':'pls login First'}),401
        #receive form data
        updated_adminname=request.form.get('adminname','').strip()
        updated_adminaddress=request.form.get('address','').strip()
        updated_adminphone=request.form.get('ph_no','').strip()
        #validation
        if not updated_adminname:
            return jsonify({'status':'failed','message':'Name required'}),400
        mydb.ping(reconnect=True)
        cursor=mydb.cursor(buffered=True)
        adminid=session.get('adminid')
        #fetching Existing item details
        cursor.execute('''select adminid,admin_username,admin_phoneno,admin_address,admin_filename from admindata where adminid=uuid_to_bin(%s)''',[adminid])
        admin_data=cursor.fetchone()
        if not admin_data:
            return jsonify({'status':'failed','message':'Admin not found'}),404
        old_image=admin_data[4]
        updated_adminprofile=request.files.get('file','')
        #default old image
        filename=old_image
        #if new image uploaded
        if updated_adminprofile:
            uploaded_filename=updated_adminprofile.filename
            #extension validation
            if not allowed_file(uploaded_filename):
                return jsonify({'status':'failed','message':'only png,jpg,jpeg,webp,gif allowed'}),400
            #mime validation
            if not updated_adminprofile.mimetype.startswith('image/'):
                return jsonify({'status':'failed','message':'Invalid image'}),404
            orig_secure=secure_filename(uploaded_filename)
            ext=os.path.splitext(orig_secure)[1] #[filename,extension] we are extracting only extension
            #generating new filename 
            filename=genotp()+ext
            print(filename)
            #save new image in satic folder
            new_image_path=os.path.join(app.config['UPLOAD_FOLDER'],filename)
            updated_adminprofile.save(new_image_path)
            #old imagepath
            if old_image:
                old_image_path=os.path.join(app.config['UPLOAD_FOLDER'],old_image)
        #update database
        cursor.execute('''update admindata set admin_username=%s,admin_address=%s,admin_phoneno=%s,admin_filename=%s where adminid=uuid_to_bin(%s)''',[updated_adminname,updated_adminaddress,updated_adminphone,filename,adminid])
        mydb.commit()
        cursor.close()
        #deleting old image After db success
        if (updated_adminprofile and old_image_path and os.path.exists(old_image_path)):
            os.remove(old_image_path)
        return jsonify({'status':'success','message':'Admin profile updated successfully','profile_image':url_for('static',filename=f'uploads/{filename}',_external=True)}),200
    except Exception as e:
        mydb.rollback()
        print('UPDATE Admin Error',str(e))
        #remove newly uploaded image if db fails
        if (new_image_path and os.path.exists(new_image_path)):
            os.remove(new_image_path)
        return jsonify({'status':'failed','message':str(e)}),500
    finally:
        if cursor:
            cursor.close()
@app.route('/api/admin/logout',methods=['POST'])
def adminlogout():
    try:
        if 'adminid' not in session:
            return jsonify({'status':'failed','message':'pls login First'}),401
        #clear complete session
        session.clear()
        return jsonify({'status':'success','message':'Logout Successful'}),200
    except Exception as e:
        return jsonify({'status':'failed','message':str(e)}),500
@app.route('/api/user/register',methods=['POST'])
def usercreate():
    try:
        data=request.get_json()
        print(data)
        if not data:
            return jsonify({'status':'failed','message':'No input data'}),400
        user_name=data.get('username','').strip()
        user_email=data.get('useremail','').strip()
        user_address=data.get('useraddress','').strip()
        user_password=data.get('userpassword','').strip()
        user_phone=data.get('userphone','').strip()
        user_gender=data.get('usergender','').strip()
        #validation
        if not user_name:
            return jsonify({'status':'failed','message':'Username required'}),400
        email_pattern=r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_pattern,user_email):
            return jsonify({'status':'failed','message':'Invalid email'}),400
        try:
            mydb.ping(reconnect=True)
            cursor=mydb.cursor(buffered=True)
            cursor.execute('select count(*) from userdata where useremail=%s',[user_email])
            email_exists=cursor.fetchone()[0]
            if email_exists > 0:
                return jsonify({'status':'failed','message':'Email already registered'}),400
        except Exception as e:
            print(" Mysql Error",str(e))
            return jsonify({'status':'failed','message':str(e)}),500
        if len(user_password)<6:
            return jsonify({'status':'failed','message':'password too short'}),400
        #hash value for password encryption
        hashed_password=bcrypt.generate_password_hash(user_password).decode('utf-8')
        gotp=genotp() #generating otp
        userdata={'user_username':user_name,'user_useremail':user_email,'user_userpassword':hashed_password,'user_useraddress':user_address,'user_phone':user_phone,'user_gender':user_gender,'user_otp':gotp}
        subject='User Registration Verification'
        body=f''' Hello User,
                  Your OTP is :{gotp}
                  This OTP is valid for 5 minutes.
                  BUYROUTE Team'''
        send_mail(to=user_email,subject=subject,body=body)
        token=endata(userdata)
        return jsonify({'status':'success',
                        'message':'OTP sent successfully',
                        'token':token}),200
    except Exception as e:
        print('Error occurs:',str(e))
        return jsonify({'status':'failed','message':str(e)}),500
    finally:
        if cursor:
            cursor.close()
@app.route('/api/user/verify-otp',methods=['POST'])
def userotpverify():
    cursor=None
    try:
        data=request.get_json()
        if not data:
            return jsonify({'status':'failed','message':'No input data'}),400
        userotp=data.get('otp') #F6hS8j
        token=data.get('token') 
        if not userotp or not token:
            return jsonify({'status':'failed','message':'otp and token required'}),400
        #decrypt token safely
        try:
            user_details=dndata(token) 
        except Exception as e:
            return jsonify({'status':'failed','message':'invalid or expired token'}),400
        #otp verification
        if str(userotp) != str(user_details['user_otp']):
            return jsonify({'status':'failed','message':'Invalid otp'}),400
        #reconnect automatically if mysql connection loast
        mydb.ping(reconnect=True)
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select count(*) from userdata where useremail=%s',[user_details['user_useremail']])
        email_exists=cursor.fetchone()[0]
        if email_exists > 0:
            return jsonify({'status':'failed','message':'Email already registered'}),400
        cursor.execute('insert into userdata(userid,username,useremail,useraddress,userpassword,userphone,usergender) values(uuid_to_bin(uuid()),%s,%s,%s,%s,%s,%s)',[user_details['user_username'],user_details['user_useremail'],user_details['user_useraddress'],user_details['user_userpassword'],user_details['user_phone'],user_details['user_gender']])
        mydb.commit()
        return jsonify({'status':'success','message':'User Registered Successfully'}),400
    except Exception as e:
        mydb.rollback() #undo the transaction
        print(" Mysql Error",str(e))
        return jsonify({'status':'failed','message':str(e)}),500
    finally:
        if  cursor:
            cursor.close()
            
@app.route('/api/user/login',methods=['POST'])
def userlogin():
    cursor=None
    try:
        data=request.get_json()
        if not data:
            return jsonify({'status':'failed','message':'No input data'}),400
        login_email=data.get('email','').strip()
        login_password=data.get('password','').strip()
        if not login_email or not login_password:
            return jsonify({'status':'failed','message':'Email and password required'}),400
        #reconnect automatically if mysql connection lost
        mydb.ping(reconnect=True)
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select bin_to_uuid(userid),username,useremail,userpassword from userdata where useremail=%s',[login_email])
        user_data=cursor.fetchone()
        if not user_data:
            return jsonify({'status':'failed','message':'Invalid email'}),404
        userid=user_data[0]
        username=user_data[1]
        useremail=user_data[2]
        stored_password=user_data[3]
        if not bcrypt.check_password_hash(stored_password,login_password):
            return jsonify({'status':'failed','message':'Invalid password'}),401
        session.clear()

        session.permanent = True
        session['userid'] = userid
        session['useremail'] = useremail

        print("USER LOGIN SESSION =", dict(session))
        print("USER LOGIN COOKIES =", request.cookies)

        response = jsonify({
            'status': 'success',
            'message': 'Login successful',
            'user': {
                'userid': userid,
                'username': username,
                'useremail': useremail
            }
        })

        response.set_cookie(
    "testcookie",
    "hello123",
    secure=False,
    httponly=False
)

        return response, 200
    except Exception as e:
        print('Mysql Error:',str(e))
        return jsonify({'status':'failed','message':str(e)}),500
    finally:
        if cursor:
            cursor.close()
            
@app.route('/api/user/logout')
def logout():
    ...

# ADD HERE
@app.route("/check-cookie")
def check_cookie():
    print("CHECK COOKIE =", request.cookies)
    print("CHECK SESSION =", dict(session))
    return jsonify({
        "cookies": dict(request.cookies),
        "session": dict(session)
    })

if __name__ == "__main__":
    app.run(debug=True)            
            

@app.route('/api/cart/add', methods=['POST'])
def addcart():
    cursor = None
    try:
        # DEBUG
        print("===== CART DEBUG =====")
        print("COOKIES:", request.cookies)
        print("SESSION:", dict(session))
        print("HEADERS:", dict(request.headers))
        print("======================")

        # LOGIN CHECK
        if "userid" not in session:
            return jsonify({
                "status": "failed",
                "message": "pls login first"
            }), 401

        # GET DATA
        data = request.get_json()

        if not data:
            return jsonify({
                'status': 'failed',
                'message': 'No input data'
            }), 400

        itemid = data.get("itemid")
        quantity = int(data.get("quantity", 1))

        print("ITEM ID =", itemid)
        print("QUANTITY =", quantity)

        if not itemid:
            return jsonify({
                'status': 'failed',
                'message': 'Itemid required'
            }), 400

        # DB CONNECTION
        mydb.ping(reconnect=True)
        cursor = mydb.cursor(buffered=True)

        userid = session.get("userid")

        # CHECK ITEM EXISTS
        cursor.execute(
            '''
            SELECT quantity 
            FROM items 
            WHERE itemid = uuid_to_bin(%s)
            ''',
            [itemid]
        )

        item_quantity = cursor.fetchone()

        if not item_quantity:
            return jsonify({
                'status': 'failed',
                'message': 'Item not found'
            }), 404

        available_stock = item_quantity[0]

        if quantity > available_stock:
            return jsonify({
                'status': 'failed',
                'message': 'Insufficient stock'
            }), 400

        # CHECK IF ITEM ALREADY IN CART
        cursor.execute(
            '''
            SELECT quantity 
            FROM cart 
            WHERE userid = uuid_to_bin(%s)
            AND itemid = uuid_to_bin(%s)
            ''',
            [userid, itemid]
        )

        existing_cart = cursor.fetchone()

        # UPDATE CART
        if existing_cart:
            new_quantity = existing_cart[0] + quantity

            if new_quantity > available_stock:
                return jsonify({
                    'status': 'failed',
                    'message': 'Insufficient stock'
                }), 400

            cursor.execute(
                '''
                UPDATE cart
                SET quantity = %s
                WHERE itemid = uuid_to_bin(%s)
                AND userid = uuid_to_bin(%s)
                ''',
                [new_quantity, itemid, userid]
            )

            message = "Cart quantity updated"

        # INSERT NEW ITEM
        else:
            cursor.execute(
                '''
                INSERT INTO cart(cartid, itemid, userid, quantity)
                VALUES(uuid_to_bin(uuid()), uuid_to_bin(%s), uuid_to_bin(%s), %s)
                ''',
                [itemid, userid, quantity]
            )

            message = "Item added to Cart"

        mydb.commit()

        return jsonify({
            'status': 'success',
            'message': message
        }), 200

    except Exception as e:
        mydb.rollback()
        print("MYSQL ERROR =", str(e))

        return jsonify({
            'status': 'failed',
            'message': str(e)
        }), 500

    finally:
        if cursor:
            cursor.close() 
                  
@app.route('/api/cart/view',methods=['GET'])
def viewcart():
    cursor=None
    try:
        #login check
        if not session.get('userid'):
            return jsonify({'status':'failed','message':'Pls login first'}),401
        #reconnect mysql automatically
        mydb.ping(reconnect=True)
        cursor=mydb.cursor(buffered=True)
        userid=session.get('userid')
        #fetch the cart items
        cursor.execute('''select bin_to_uuid(i.itemid),i.item_name,i.price,c.quantity,i.category,i.item_filename from cart c inner join items i on c.itemid=i.itemid where c.userid=uuid_to_bin(%s)''',[userid])
        cart_items=cursor.fetchall() #list tuples
        #empty cart
        if not cart_items:
            return jsonify({'status':'failed','message':'Cart is empty'}),404
        subtotal=0
        items_data=[]
        for item in cart_items:
            itemid=item[0]
            itemname=item[1]
            item_price=float(item[2])
            item_quantity=int(item[3])
            item_category=item[4]
            item_imgname=item[5]
            total=item_price * item_quantity
            subtotal += total
            image_url=url_for('static',filename=f'uploads/{item_imgname}',_external=True)
            items_data.append({'itemid':itemid,'itemname':itemname,'price':item_price,'quantity':item_quantity,'category':item_category,'image':image_url,'total':total})
        delivery=40
        tax=round(subtotal*0.05,2)
        grand_total=subtotal+tax+delivery
        return jsonify({'status':'success','cart_items':items_data,'summary':{'subtotal':subtotal,'delivery':delivery,'tax':tax,'grand_total':grand_total}}),200
    except Exception as e:
        print('MYSQL ERROR:',str(e))
        return jsonify({'status':'failed','message':str(e)}),500
    finally:
        if cursor:
            cursor.close()
@app.route('/api/cart/update',methods=['PUT'])
def updatecart():
    cursor=None
    try:
        #login check
        if not session.get('userid'):
            return jsonify({'status':'failed','message':'Pls login first'}),401
        data=request.get_json()
        if not data:
            return jsonify({'status':'failed','message':'No input data'}),400
        itemid=data.get('itemid')
        updated_quantity=int(data.get('quantity',0))
        #quantity validation
        if updated_quantity<=0:
            return jsonify({'status':'failed','message':'Quantity must be greater than 0'}),400
        #reconnect mysql automatically
        mydb.ping(reconnect=True)
        cursor=mydb.cursor(buffered=True)
        userid=session.get('userid')
        cursor.execute('select quantity from cart where itemid=uuid_to_bin(%s) and userid=uuid_to_bin(%s)',[itemid,userid])
        cart_item=cursor.fetchone()
        if not cart_item:
            return jsonify({'status':'failed','message':'Item not in cart'}),404
        #stock validation
        cursor.execute('select quantity from items where itemid=uuid_to_bin(%s)',[itemid])
        stock_item=cursor.fetchone()
        if not stock_item:
            return jsonify({'status':'failed','message':'Item not found'}),400
        available_stock=stock_item[0]
        if updated_quantity > available_stock:
            return jsonify({'status':'failed','message':'Insufficient stock'}),400
        # update quantity in cart
        cursor.execute('''UPDATE cart set quantity=%s where itemid=uuid_to_bin(%s) and userid=uuid_to_bin(%s)''',[updated_quantity,itemid,userid])
        mydb.commit()
        return jsonify({'status':'success','message':'cart updated succesfully'}),200
    except Exception as e:
        mydb.rollback()
        print("Mysql Error",str(e))
        return jsonify({'status':'failed','message':str(e)}),500
    finally:
        if cursor:
            cursor.close()   
@app.route('/api/cart/remove/<itemid>',methods=['DELETE'])
def removecart(itemid):
    cursor=None
    try:
        #login check
        if not session.get('userid'):
            return jsonify({'status':'failed','message':'Pls login first'}),401
        try:
            uuid.UUID(itemid)
        except ValueError:
            return jsonify({'status':'failed','message':'invalid item id'}),400
        #reconnect mysql automatically
        mydb.ping(reconnect=True)
        cursor=mydb.cursor(buffered=True)
        userid=session.get('userid')
        cursor.execute('select quantity from cart where itemid=uuid_to_bin(%s) and userid=uuid_to_bin(%s)',[itemid,userid])
        cart_item=cursor.fetchone()
        if not cart_item:
            return jsonify({'status':'failed','message':'Item not in cart'}),404
        # delete from cart
        cursor.execute('''delete from cart where itemid=uuid_to_bin(%s) and userid=uuid_to_bin(%s)''',[itemid,userid])
        mydb.commit()
        return jsonify({'status':'success','message':'cart item removed succesfully'}),200
    except Exception as e:
        mydb.rollback()
        print("Mysql Error",str(e))
        return jsonify({'status':'failed','message':str(e)}),500
    finally:
        if cursor:
            cursor.close()
@app.route('/api/payment/create-order',methods=['POST'])
def pay_cart():
    cursor=None
    try:
        if 'userid' not in session:
            return jsonify({'status':'failed','message':'Pls login first'}),401
        data=request.get_json()
        payment_type=data.get('type','cart')
        mydb.ping(reconnect=True)
        cursor=mydb.cursor(buffered=True)
        userid=session.get('userid')
        if payment_type=='cart':
            cursor.execute('select bin_to_uuid(i.itemid),i.item_name,i.price,c.quantity,i.category,i.item_filename from cart c inner join items i on c.itemid=i.itemid where c.userid=uuid_to_bin(%s)',[userid])
            cart_items=cursor.fetchall()
        else:
            itemid=data.get('itemid')
            quantity=int(data.get('quantity',1))
            cursor.execute('select bin_to_uuid(itemid),item_name,price,category,item_filename,quantity from items where itemid=uuid_to_bin(%s)',[itemid])
            item=cursor.fetchone()
            if not item:
                return jsonify({'status':'failed','message':'Item not found'}),401
            available_stock=item[5]
            if quantity> available_stock:
                return jsonify({'status':'failed','message':'Insufficient stock'}),400
            cart_items=[(item[0],item[1],item[2],quantity,item[3],item[4])]
        #empty cart check:
        if not cart_items:
            return jsonify({'status':'failed','message':'Cart is empty'}),404
        subtotal=0
        items_data=[]
        for item in cart_items:
            itemid=item[0]
            itemname=item[1]
            item_price=float(item[2])
            item_quantity=int(item[3])
            item_category=item[4]
            item_imgname=item[5]
            amount=item_price * item_quantity
            subtotal += amount
            image_url=url_for('static',filename=f'uploads/{item_imgname}',_external=True)
            items_data.append({'itemid':itemid,'itemname':itemname,'price':item_price,'quantity':item_quantity,'category':item_category,'image':image_url,'amount':amount})
        delivery=40
        tax=round(subtotal*0.05,2)
        grand_total=subtotal+tax+delivery
        razorpay_amount=int(grand_total*100)
        #create razorpay order
        order=client.order.create({
            "amount":razorpay_amount,
            "currency":"INR",
            "receipt":str(userid),
            "payment_capture":1
        })
        print('Order created',order,items_data)
        return jsonify({'status':'success','order':{
            'order_id':order['id'],
            'amount':order['amount'],
            'currency':order['currency']},
            'cart_items':items_data,
            'summary':{
                'subtotal':subtotal,
                'delivery':delivery,
                'tax':tax,
                'grand_total':grand_total
            },
            'razorpay_key':'rzp_test_SzppdEzy51SPYd'})
    except Exception as e:
        print("Payment Error",str(e))
        return jsonify({'status':'failed','message':str(e)}),500
    finally:
        if cursor:
            cursor.close()
@app.route('/api/payment/verify',methods=['POST'])
def verify_payment():
    cursor=None
    try:
        data=request.get_json()
        #------------- GET FRONTEND data
        payment_id=data.get('razorpay_payment_id')
        order_id=data.get('razorpay_order_id')
        signature=data.get('razorpay_signature')
        mode=data.get('mode','cart')

        #------- verify razorpay signature----
        params_dict={
            'razorpay_order_id':order_id,
            'razorpay_payment_id':payment_id,
            'razorpay_signature':signature
        }
        try:
            client.utility.verify_payment_signature(params_dict)
        except Exception as e:
            print('Payment Verification failed ',str(e))
            return jsonify({'status':'failed','message':'Payment verification failed'}),400
        #--------Login validation------
        if 'userid' not in session:
            return jsonify({'status':'failed','message':'Pls login'}),401
        #reconnect the mysql connection automatically
        mydb.ping(reconnect=True)
        cursor=mydb.cursor(buffered=True)
        userid=session.get('userid')
        #---------  Get the cart items-------
        if mode =='cart':
            cursor.execute('''select bin_to_uuid(i.itemid),i.item_name,i.price,c.quantity,i.category,i.item_filename from cart c inner join items i on c.itemid=i.itemid and c.userid=uuid_to_bin(%s)''',[userid])
            cart_items=cursor.fetchall()
        #---- single buy-----
        else:
            itemid=data.get('itemid')
            quantity=int(data.get('quantity',1))
            cursor.execute('''select bin_to_uuid(itemid),item_name,price,category,item_filename,quantity from items where itemid=uuid_to_bin(%s)''',[itemid])
            item=cursor.fetchone()
            if not item:
                return jsonify({'status':'failed','message':'item not found'}),404
            available_stock=item[5]
            if available_stock < quantity:
                return jsonify({'status':'failed','message':'Insufficient stock'}),400
            cart_items=[(item[0],item[1],item[2],quantity,item[3],item[4])]
        #--- Cart empty check
        if not cart_items:
            return jsonify({'status':'failed','message':'cart empty'}),404
        # calculate total
        subtotal=0
        for item in cart_items:
            itemid=item[0]
            itemname=item[1]
            item_price=float(item[2])
            item_quantity=int(item[3])
            item_category=item[4]
            item_imgname=item[5]
            amount=item_price * item_quantity
            subtotal += amount
            image_url=url_for('static',filename=f'uploads/{item_imgname}',_external=True)
        delivery=40
        tax=round(subtotal*0.05,2)
        grand_total=subtotal+tax+delivery
        #-------- STORE orders table
        cursor.execute('''insert into orders(razorpay_ordid,razorpay_payment,userid,total_amount,delivery,tax,grand_total) values(%s,%s,uuid_to_bin(%s),%s,%s,%s,%s)''',[order_id,payment_id,userid,subtotal,delivery,tax,grand_total])
        order_table_id=cursor.lastrowid  #fetching recent created orderid
        #------------------ store order item details
        insert_item_query='''insert into order_items(orderid,itemid,item_name,item_price,item_quantity,subtotal,item_category,item_filename) values(%s,uuid_to_bin(%s),%s,%s,%s,%s,%s,%s)'''
        ordered_items=[]
        for item in cart_items:
            itemid=item[0]
            item_name=item[1]
            item_price=float(item[2])
            item_quantity=int(item[3])
            item_category=item[4]
            item_img=item[5]
            amount=item_price * item_quantity
            cursor.execute(insert_item_query,[order_table_id,itemid,item_name,item_price,item_quantity,amount,item_category,item_img])
        #reduce stock
        cursor.execute('update items set quantity=quantity-%s where itemid=uuid_to_bin(%s)',[item_quantity,itemid])
        ordered_items.append({
            'itemid':itemid,
            'itemname':item_name,
            'price':item_price,
            'quantity':item_quantity,
            'subtotal':amount
        })
        #  clear cart
        if mode=='cart':
            cursor.execute('delete from cart where userid=uuid_to_bin(%s)',[userid])
        mydb.commit() # save orders,order_items,cart tables
        #--------- success response
        return jsonify({'status':'success','message':'payment verified successfully',
        'payment':{'payment_id':payment_id,'order_id':order_id},
        'summary':{'subtotal':subtotal,'delivery':delivery,'tax':tax,
        'grand_total':grand_total},'ordered_items':ordered_items})
    except Exception as e:
        mydb.rollback()
        print("Mysql Error:",str(e))
        return jsonify({'status':'failed','message':str(e)}),500
    finally:
        if cursor:
            cursor.close()
            
@app.route('/api/myorders',methods=['GET'])
def myorders():
    cursor=None
    try:
        if 'userid' not in session:
            return jsonify({'status':'failed','message':'pls login first'}),401
        mydb.ping(reconnect=True)
        cursor=mydb.cursor(buffered=True)
        userid=session.get('userid')
        #fetch all orders
        cursor.execute('select orderid,razorpay_ordid,razorpay_payment,total_amount,delivery,tax,grand_total,created_at from orders where userid=uuid_to_bin(%s) order by created_at desc',[userid])
        orders=cursor.fetchall()
        all_orders=[]
        for order in orders:
            orderid=order[0]
            #fetch ordered items
            cursor.execute('select bin_to_uuid(itemid),item_name,item_price,item_quantity,subtotal,item_category,item_filename from order_items where orderid=%s',[orderid])
            items=cursor.fetchall()
            order_items=[]
            for item in items:
                image_url=url_for('static',filename=f'uploads/{item[6]}',_external=True)
                order_items.append({
                    'itemid':item[0],
                    'itemname':item[1],
                    'price':float(item[2]),
                    'quantity':int(item[3]),
                    'subtotal':float(item[4]),
                    'category':item[5],
                    'image':image_url

                })
            all_orders.append({
                "orderid":orderid,
                "razorpay_order_id":order[1],
                "razorpay_payment_id":order[2],
                "subtotal":float(order[3]),
                "delivery":float(order[4]),
                "tax":float(order[5]),
                "grand_total":float(order[6]),
                "created_at":str(order[7]),
                "items":order_items
            })
        return jsonify({'status':'success','orders':all_orders}),200
    except Exception as e:
        print('Mysql error:',str(e))
        return jsonify({'status':'failed','message':str(e)}),500
    finally:
        if cursor:
            cursor.close()
            
@app.route('/api/products',methods=['GET'])
def index():
    cursor=None
    try:
        mydb.ping(reconnect=True)
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select bin_to_uuid(itemid),item_name,item_description,item_about,price,quantity,category,item_filename  from items')
        allitems_data=cursor.fetchall()
        products=[]
        for item in allitems_data:
            products.append({
                'itemid':item[0],
                'itemname':item[1],
                'item_desc':item[2],
                'item_about':item[3],
                'price':float(item[4]),
                'quantity':int(item[5]),
                'category':item[6],
                'image':url_for('static',filename=f'uploads/{item[7]}',_external=True)
            })
        return jsonify({'status':'success','products':products}),200
    except Exception as e:
        print('Mysql error:',str(e))
        return jsonify({'status':'failed','message':str(e)}),500
    finally:
        if cursor:
            cursor.close()
            
@app.route('/api/search', methods=['GET'])
def usersearch():
    cursor = None
    try:
        searchdata = request.args.get('q', '').strip()

        if not searchdata:
            return jsonify({
                'status': 'failed',
                'message': 'Search Query required'
            }), 400

        pattern = re.compile(r'^[A-Za-z0-9 ]+$', re.IGNORECASE)

        if not pattern.match(searchdata):
            return jsonify({
                'status': 'failed',
                'message': 'invalid search'
            }), 400

        mydb.ping(reconnect=True)
        cursor = mydb.cursor(buffered=True)

        cursor.execute('''
            SELECT
                bin_to_uuid(itemid),
                item_name,
                item_description,
                item_about,
                price,
                quantity,
                category,
                item_filename
            FROM items
            WHERE item_name LIKE %s
               OR item_description LIKE %s
               OR CAST(price AS CHAR) LIKE %s
               OR category LIKE %s
        ''',
        [
            '%' + searchdata + '%',
            '%' + searchdata + '%',
            '%' + searchdata + '%',
            '%' + searchdata + '%'
        ])

        allitem_data = cursor.fetchall()

        items = []

        for item in allitem_data:

            image_url = url_for(
                'static',
                filename=f'uploads/{item[7]}',
                _external=True
            )

            items.append({
                'itemid': item[0],
                'itemname': item[1],
                'item_desc': item[2],       # same as products api
                'item_about': item[3],     # same as products api
                'price': float(item[4]),
                'quantity': int(item[5]),
                'category': item[6],
                'image': image_url          # same as products api
            })

        return jsonify({
            'status': 'success',
            'total_items': len(items),
            'items': items
        }), 200

    except Exception as e:
        print("Search error:", str(e))
        return jsonify({
            'status': 'failed',
            'message': str(e)
        }), 500

    finally:
        if cursor:
            cursor.close()
                 
@app.route('/api/orders/<int:ordid>', methods=['GET'])
def myorder_details(ordid):

    cursor = None

    try:

        # Check login
        if 'userid' not in session:
            return jsonify({
                'status': 'failed',
                'message': 'pls login first'
            }), 401

        mydb.ping(reconnect=True)

        cursor = mydb.cursor(buffered=True)

        userid = session.get('userid')

        # Fetch order
        cursor.execute('''
            SELECT 
                orderid,
                razorpay_ordid,
                razorpay_payment,
                total_amount,
                delivery,
                tax,
                grand_total,
                created_at
            FROM orders
            WHERE userid = uuid_to_bin(%s)
            AND orderid = %s
        ''', [userid, ordid])

        order_data = cursor.fetchone()

        if not order_data:
            return jsonify({
                'status': 'failed',
                'message': 'Order not found'
            }), 404

        # Fetch ordered items
        cursor.execute('''
            SELECT
                order_detailsid,
                orderid,
                bin_to_uuid(itemid),
                item_name,
                item_price,
                item_quantity,
                subtotal,
                item_category,
                item_filename
            FROM order_items
            WHERE orderid = %s
        ''', [ordid])

        orders_itemsdata = cursor.fetchall()

        # Format order
        order_json = {
            'orderid': order_data[0],
            'razorpay_order_id': order_data[1],
            'razorpay_payment_id': order_data[2],
            'total_amount': float(order_data[3]),
            'delivery': float(order_data[4]),
            'tax': float(order_data[5]),
            'grand_total': float(order_data[6]),
            'created_at': str(order_data[7])
        }

        # Format items
        items_json = []

        for item in orders_itemsdata:

            image_url = url_for(
                'static',
                filename=f'uploads/{item[8]}',
                _external=True
            )

            items_json.append({
                'order_details_id': item[0],
                'order_id': item[1],
                'itemid': item[2],
                'item_name': item[3],
                'item_price': float(item[4]),
                'item_quantity': int(item[5]),
                'subtotal': float(item[6]),
                'item_category': item[7],
                'item_image': image_url
            })

        # RETURN OUTSIDE LOOP
        return jsonify({
            'status': 'success',
            'order': order_json,
            'items': items_json
        }), 200

    except Exception as e:

        print("order details error:", str(e))

        return jsonify({
            'status': 'failed',
            'message': str(e)
        }), 500

    finally:

        if cursor:
            cursor.close()
@app.route('/api/invoice/<int:ord_id>',methods=['GET'])
def get_invoice(ord_id):
    cursor=None
    try:
        if 'userid' not in session:
            return jsonify({'status':'failed','message':'pls login first'}),401
        mydb.ping(reconnect=True)
        cursor=mydb.cursor(buffered=True)
        userid=session.get('userid')
        #fetch all orders
        cursor.execute('select orderid,razorpay_ordid,razorpay_payment,total_amount,delivery,tax,grand_total,created_at from orders where userid=uuid_to_bin(%s)  and orderid=%s',[userid,ord_id])
        order_data=cursor.fetchone()
        if not order_data:
            return jsonify({'status':'failed','message':'Order not found'}),404
        print(order_data)
        cursor.execute('select item_name,item_price,item_quantity,subtotal,item_category,item_filename from order_items where orderid=%s',[ord_id])
        orders_itemsdata=cursor.fetchall()
        print(orders_itemsdata)
        #-----------------------create pdf buffer-------------
        pdf_buffer=BytesIO() # type: ignore
        #-----------------Create Document-------------
        doc=SimpleDocTemplate(pdf_buffer,pagesize=A4,rightMargin=30,leftMargin=30,topMargin=30,bottomMargin=20)
        styles=getSampleStyleSheet()
        elements=[]
        #------------Title-----------
        title=Paragraph("<b>BUYROUTE INVOICE</b>",styles["Title"])
        elements.append(title)
        elements.append(Spacer(1,15))
        #--------------------Order Details
        order_info=f"""<b>ORDER ID : </b>{order_data[0]}<br/>
                        <b>RAZORPAY ORDER ID: </b>{order_data[1]}<br/>
                        <b>PAYMENT ID : </b>{order_data[2]}<br/>
                        <b>ORDER DATE : </b>{order_data[7]}<br/>"""
        order_para=Paragraph(order_info,styles['BodyText'])
        elements.append(order_para)
        elements.append(Spacer(1,10))
        elements.append(HRFlowable(width="100%"))
        elements.append(Spacer(1,15))
        #------------------Table Data---------items
        table_data=[['Item Name','Category','Price','Quantity','Subtotal']]
        for item in orders_itemsdata:
            table_data.append([item[0],item[4],f'₹{float(item[1])}',str(item[2]),f"₹{float(item[3])}"])
        #------ Create Table -----------------
        table=Table(table_data,colWidths=[180,100,80,70,80])
        #-----------------Table Styles
        table.setStyle(
            TableStyle([
                ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#0d6efd')),
                ('TEXTCOLOR',(0,0),(-1,0),colors.white),
                ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
                ('FONTSIZE',(0,0),(-1,-1),10),
                ('BOTTOMPADDING',(0,0),(-1,0),10),
                ('GRID',(0,0),(-1,-1),1,colors.black),
                ('BACKGROUND',(0,1),(-1,-1),colors.beige),
                ('ALIGN',(2,1),(-1,-1),'CENTER'),
            ])
        )
        elements.append(table)
        elements.append(Spacer(1,20))
        #--------------------SUMMARY------------
        summary=f"""
        <b>ITEMS Total : </b>₹{float(order_data[3])}<br/><br/>
        <b>Delivery: </b>₹{float(order_data[4])}<br/><br/>
        <b>Tax: </b>₹{float(order_data[5])}<br/><br/>
        <b>Grand Total: </b>₹{float(order_data[6])}"""
        summary_para=Paragraph(summary,styles['Heading3'])
        elements.append(summary_para)
        elements.append(Spacer(1,25))
        #------------------Footer------------
        footer=Paragraph('Thank you for shopping with BUYROUTE',
        styles['Italic'])
        elements.append(footer)
        #---------------Build PDF
        doc.build(elements)
        pdf_buffer.seek(0)
        #--------------RESPONSE------------
        response=make_response(pdf_buffer.getvalue())
        response.headers['Content-Type']='application.pdf'
        response.headers['Content-Disposition']=(
            f'attachment; filename=invoice_{ord_id}.pdf'
        )
        return response
    except Exception as e:
        print(f'Invoice Error:',e)
        return jsonify({'status':'failed','message':str(e)}),500
    else:
        if cursor:
            cursor.close()
            
@app.route('/api/buy_now',methods=['POST'])
def buy_now():
    cursor=None
    try:
        #login check
        if not session.get('userid'):
            return jsonify({'status':'failed','message':'Pls login first'}),401
        data=request.get_json()
        if not data:
            return jsonify({'status':'failed','message':'No input data'}),400
        itemid=data.get('itemid')
        quantity=int(data.get('quantity',1))
        if not itemid:
            return jsonify({'status':'failed','message':'Item id required'}),400
         #quantity validation
        if quantity<=0:
            return jsonify({'status':'failed','message':'Quantity must be greater than 0'}),400
        #reconnect mysql automatically
        mydb.ping(reconnect=True)
        cursor=mydb.cursor(buffered=True)
        userid=session.get('userid')
        #stock validation
        cursor.execute('select bin_to_uuid(itemid),item_name,item_description,item_about,price,quantity,category,item_filename from items where itemid=uuid_to_bin(%s)',[itemid])
        item_data=cursor.fetchone()
        if not item_data:
            return jsonify({'status':'failed','message':'Item not found'}),400
        available_stock=item_data[5]
        if quantity > available_stock:
            return jsonify({'status':'failed','message':'Insufficient stock'}),400
        image_url=url_for('static',filename=f'uploads/{item_data[7]}',_external=True)
        #-------------Storing single buy item in session temp
        print(session,'before single buy')
        session['single_buy']={
            itemid:[item_data[1],quantity,item_data[4],item_data[5],item_data[6],item_data[7]]
        }
        session.modified=True
        print(session,'After single buy')
        return jsonify({
            'status':'success','message':'Single buy item stored successfully',
            'payment_type':'single',
            'item':{
                'itemid':item_data[0],
                'itemname':item_data[1],
                'description':item_data[2],
                'about':item_data[3],
                'price':float(item_data[4]),
                'quantity':quantity,
                'stock':item_data[5],
                'category':item_data[6],
                'image':image_url
            },
            #frontend will use this
            'next_url':'/api/payment/create-order'
        })
    except Exception as e:
        print(f'Buy now Error:',str(e))
        return jsonify({'status':'failed','message':str(e)}),500
    finally:
        if cursor:
            cursor.close()
            
@app.route('/api/items/<itemid>', methods=['GET'])
def descitem(itemid):
    cursor = None
    try:
        try:
            uuid.UUID(itemid)
        except ValueError:
            return jsonify({'status':'failed','message':'invalid item id'}),400
        
        mydb.ping(reconnect=True)
        cursor = mydb.cursor(buffered=True)

        cursor.execute("""
            SELECT
                bin_to_uuid(itemid),
                item_name,
                item_description,
                item_about,
                price,
                quantity,
                category,
                item_filename,
                created_at
            FROM items
            WHERE itemid = uuid_to_bin(%s)
            
        """, [itemid])

        item_data = cursor.fetchone()

        if not item_data:
            return jsonify({
                'status': 'failed',
                'message': 'Item not found'
            }), 404

        item_details= {
            'itemid': item_data[0],
            'itemname': item_data[1],
            'item_desc': item_data[2],
            'item_about': item_data[3],
            'price': float(item_data[4]),
            'quantity': int(item_data[5]),
            'category': item_data[6],
            'image_url': url_for(
                'static',
                filename=f'uploads/{item_data[7]}',
                _external=True
            ),
            'created_at': item_data[8]
        }

        return jsonify({
            'status': 'success',
            'item': item_details
        }), 200

    except Exception as e:
        print("VIEW SINGLE ITEM ERROR :", str(e))
        return jsonify({
            'status': 'failed',
            'message': str(e)
        }), 500

    finally:
        if cursor:
            cursor.close()
            
@app.route('/api/add-review/<itemid>',methods=['POST'])
def addreview(itemid):
    cursor=None
    try:
        #login check
        if not session.get('userid'):
            return jsonify({'status':'failed','message':'pls login first'}),401

        data=request.get_json()
        if not data:
            return jsonify({'status':'failed','message':'No input data'}),400
        rating=data.get('rating')
        review_text=data.get('review_text')
        if not rating or not review_text:
            return jsonify({'status':'failed','message':'rating and review required'})
        if int(rating) < 1 or int(rating) > 5:
            return jsonify({
                'status':'failed',
                'message':'rating must be between 1 and 5'
            }),400
        #reconnect mysql automatically
        mydb.ping(reconnect=True)
        cursor=mydb.cursor(buffered=True)
        userid=session.get('userid')
        cursor.execute('select count(*) from items where itemid=uuid_to_bin(%s)',[itemid])
        item_exists=cursor.fetchone()[0]
        if item_exists==0:
            return jsonify({'status':'failed','message':'item not found'}),400

        #--------------------insert review
        cursor.execute('''insert into reviews(r_id,r_text,rating,itemid,userid) values (uuid_to_bin(uuid()),%s,%s,uuid_to_bin(%s),uuid_to_bin(%s))''',[review_text,rating,itemid,userid])
        mydb.commit()
        return jsonify({'status':'success','message':'Review added successfully'}),201
    except Exception as e:
        mydb.rollback()
        print(f'Review Error,{e}')
        return jsonify({'status':'failed','message':str(e)}),500
    finally:
        if cursor:
            cursor.close()           
  
@app.route('/api/reviews/<itemid>', methods=['GET'])
def get_reviews(itemid):

    cursor = None

    try:

        # validate uuid
        try:
            uuid.UUID(itemid)
        except ValueError:
            return jsonify({
                'status': 'failed',
                'message': 'invalid item id'
            }), 400

        mydb.ping(reconnect=True)

        cursor = mydb.cursor(dictionary=True)

        cursor.execute("""

            SELECT
                r.rating,
                r.r_text,
                u.username

            FROM reviews r

            INNER JOIN userdata u
                ON r.userid = u.userid

            WHERE r.itemid = uuid_to_bin(%s)

            ORDER BY r_id DESC

        """, [itemid])

        reviews = cursor.fetchall()

        return jsonify({
            'status': 'success',
            'reviews': reviews
        }), 200

    except Exception as e:

        print("REVIEW FETCH ERROR =", str(e))

        return jsonify({
            'status': 'failed',
            'message': str(e)
        }), 500

    finally:
        if cursor:
            cursor.close()

from utils.stoken import endata


@app.route('/api/forgotpassword', methods=['POST'])
def forgotpassword():

    cursor = None

    try:

        data = request.get_json()

        if not data:
            return jsonify({
                "status": "failed",
                "message": "No input data"
            }), 400

        f_email = data.get("email")

        if not f_email:
            return jsonify({
                "status": "failed",
                "message": "Email required"
            }), 400

        mydb.ping(reconnect=True)

        cursor = mydb.cursor(buffered=True)

        cursor.execute(
            '''
            SELECT count(*)
            FROM userdata
            WHERE useremail=%s
            ''',
            [f_email]
        )

        count_email = cursor.fetchone()

        if count_email[0] == 1:

            token = endata(f_email)

            # frontend route
            reset_link = (
                f"http://localhost:5173/"
                f"reset-password/{token}"
            )

            subject = "Reset Password Link"

            body = (
                f"Click below link to reset password:\n\n"
                f"{reset_link}"
            )

            send_mail(
                to=f_email,
                subject=subject,
                body=body
            )

            return jsonify({
                "status": "success",
                "message": "Reset link sent successfully"
            }), 200

        return jsonify({
            "status": "failed",
            "message": "Email not found"
        }), 404

    except Exception as e:

        print("FORGOT PASSWORD ERROR =", str(e))

        return jsonify({
            "status": "failed",
            "message": str(e)
        }), 500

    finally:
        if cursor:
            cursor.close()            
           
@app.route('/api/resetpassword/<token>', methods=['POST'])
def resetpassword(token):

    data = request.get_json()

    npassword = data.get('password')
    cpassword = data.get('confirm_password')

    if npassword != cpassword:
        return {
            "status": "error",
            "message": "Passwords do not match"
        }, 400

    try:

        decoded = dndata(token)
        email = decoded["email"]
        hashed_pwd = bcrypt.generate_password_hash(
            npassword
        ).decode("utf-8")
        cursor = mydb.cursor(buffered=True)

        cursor.execute(
            'update userdata set userpassword=%s where useremail=%s',
            [hashed_pwd, email]
        )

        mydb.commit()

        return {
            "status": "success",
            "message": "Password updated successfully"
        }, 200

    except Exception as e:
        return {
            "status": "error",
            "message": f"Invalid or expired token,{str(e)}"
        }, 400
    finally:
        if cursor:
            cursor.close()
            
@app.route('/api/admin/forgotpassword', methods=['POST'])
def adminforgotpassword():

    cursor = None

    try:

        data = request.get_json()

        if not data:
            return jsonify({
                "status": "failed",
                "message": "No input data"
            }), 400

        a_email = data.get("email")

        if not a_email:
            return jsonify({
                "status": "failed",
                "message": "Email required"
            }), 400

        mydb.ping(reconnect=True)
        cursor = mydb.cursor(buffered=True)

        cursor.execute(
            '''
            SELECT count(*)
            FROM admindata
            WHERE admin_useremail=%s
            ''',
            [a_email]
        )   

        count_email = cursor.fetchone()

        if count_email[0] == 1:

            token = endata({
                "admin_email": a_email
            })

            reset_link = (
                f"http://localhost:5173/"
                f"admin-reset-password/{token}"
            )

            send_mail(
                to=a_email,
                subject="Admin Reset Password",
                body=f"Click below link:\n{reset_link}"
            )

            return jsonify({
                "status": "success",
                "message": "Reset link sent successfully"
            }), 200

        return jsonify({
            "status": "failed",
            "message": "Email not found"
        }), 404

    except Exception as e:

        return jsonify({
            "status": "failed",
            "message": str(e)
        }), 500

    finally:
        if cursor:
            cursor.close()

@app.route('/api/admin/resetpassword/<token>', methods=['POST'])
def adminresetpassword(token):

    cursor = None

    try:

        data = request.get_json()

        password = data.get("password")
        confirm = data.get("confirm_password")

        if password != confirm:
            return jsonify({
                "status": "failed",
                "message": "Passwords do not match"
            }), 400

        decoded = dndata(token)

        email = decoded["admin_email"]

        hashed_pwd = bcrypt.generate_password_hash(
            password
        ).decode("utf-8")

        cursor = mydb.cursor(buffered=True)

        cursor.execute(
            '''
            UPDATE admindata
            SET admin_password=%s
            WHERE admin_useremail=%s
            ''',
            [hashed_pwd, email]
        )

        mydb.commit()

        return jsonify({
            "status": "success",
            "message": "Password updated successfully"
        }), 200

    except Exception as e:

        return jsonify({
            "status": "failed",
            "message": str(e)
        }), 400

    finally:
        if cursor:
            cursor.close()

@app.route('/api/category/<ctype>', methods=['GET'])
def category(ctype):
    cursor = None
    try:

        mydb.ping(reconnect=True)
        cursor = mydb.cursor(buffered=True)

        cursor.execute('''SELECT bin_to_uuid(itemid),item_name,item_description,item_about,price,quantity,category,
                item_filename,created_at FROM items where category=%s''', [ctype])

        allitems_data = cursor.fetchall()

        if not allitems_data:
            return jsonify({'status': 'failed','message': 'no items found'}), 404

        products= []
        for item in allitems_data:
            products.append({
            'itemid': item[0],
            'itemname': item[1],
            'item_desc': item[2],
            'item_about': item[3],
            'price': float(item[4]),
            'quantity': item[5],
            'category': item[6],
            'image': url_for('static',filename=f'uploads/{item[7]}',_external=True)})

        return jsonify({'status': 'success','category': ctype,'total_items':len(products),'products':products}), 200

    except Exception as e:
        print("category ERROR :", str(e))
        return jsonify({'status': 'failed','message': str(e)}), 500

    finally:
        if cursor:
            cursor.close()            
            
@app.route("/check-cookie")
def check_cookie():
    print("CHECK COOKIE =", request.cookies)
    print("CHECK SESSION =", dict(session))
    return jsonify({
        "cookies": dict(request.cookies),
        "session": dict(session)
    })                       
        
if __name__=='__main__':
    app.run()