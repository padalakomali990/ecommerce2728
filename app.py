import sys
sys.dont_write_bytecode = True
from flask import Flask,request,redirect,url_for,jsonify
from flask_bcrypt import Bcrypt
import re
from otp import genotp
from utils.cmail import send_mail
from utils.stoken import endata,dndata
from mysql.connector import (connection)
mydb=connection.MySQLConnection(user='root',host='localhost',password='Komali@123',db='ecommercedb')
app=Flask(__name__)
bcrypt=Bcrypt(app)
@app.route('/api/admin/register',methods=['POST'])
def admincreate():
    try:
        data=request.get_json()
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
        if len(admin_password)<6:
            return jsonify({'status':'failed','message':'password too short'}),400
        hashed_password=bcrypt.generate_password_hash(admin_password).decode('utf-8')
        gotp=genotp()
        admindata={'admin_username':admin_name,'admin_useremail':admin_email,
                   'admin_userpassword':hashed_password,'admin_address':admin_address,
                   'admin_agree':admin_agree,'admin_phone':admin_phone,'admin_otp':gotp}
        subject='Admin Registration Verification'
        body=f'''Hello Admin,
                Your OTP is:{gotp}
                This OTP is valid for 5 minutes.
                BUYROUTE Team'''
        send_mail(to=admin_email,subject=subject,body=body)
        token=endata(admindata)
        return jsonify({'status':'success','message':'OTP sent successfully','token':token}),200
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
        userotp=data.get('otp')
        token=data.get('token')
        if not userotp or not token:
            return jsonify({'status':'failed','message':'otp and token required'}),400
        try:
            admin_details=dndata(token)
        except Exception as e:
            return jsonify({'status':'failed','message':'invalid or expried token'}),400
        #otp verification
        if str(userotp) != str(admin_details['admin_otp']):
            return jsonify({'status':'failed','message':'Invalid otp'}),400
        #reconnect automatically if mysql connection lost
        mydb.ping(reconnect=True)
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select count(*) from admindata where admin_useremail=%s',
                       [admin_details['admin_useremail']])
        email_exists=cursor.fetchone()[0]
        if email_exists > 0:
            return jsonify({'status':'failed','message':'Email already registered'}),400
        cursor.execute('insert into admindata(adminid,admin_username,admin_useremail,admin_address,admin_password,admin_phoneno,admin_agree)values(uuid_to_bin(uuid()),%s,%s,%s,%s,%s,%s)',[admin_details['admin_username'],admin_details['admin_useremail'],admin_details['admin_address'],admin_details['admin_userpassword'],admin_details['admin_phone'],admin_details['admin_agree']])
        mydb.commit()
        return jsonify({'status':'success','message':'Admin Registered Successfully'}),200
    except Exception as e:
        mydb.rollback()
        print('Mysql Error',str(e))
        return jsonify({'status':'failed','message':str(e)}),500
    finally:
        if cursor:
            cursor.close()    

if __name__=='__main__':
    app.run()