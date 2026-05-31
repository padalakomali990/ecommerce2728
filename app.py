import sys
sys.dont_write_bytecode = True
from flask import Flask,request,redirect,url_for,jsonify
from flask_bcrypt import Bcrypt
import re
from otp import genotp
from utils.cmail import send_mail
from utils.stoken import endata,dndata

app=Flask(__name__)
bcrypt=Bcrypt(app)
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
            return jsonify({'status':'failed','message':'username required'}),400
        email_pattern=r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_pattern,admin_email):
            return jsonify({'status':'failed','message':'invalid email'}),400
        if len(admin_password)<6:
            return jsonify({'status':'failed','message':'password too short'}),400
        #hash value for password encryption
        hashed_password=bcrypt.generate_password_hash(admin_password).decode('utf-8')
        gotp=genotp() #generating otp
        admindata={'admin_username':admin_name,'admin_useremail':admin_email,'admin_userpassword':hashed_password,'admin_address':admin_address,'admin_agree':admin_agree,'admin_phone':admin_phone,'admin_otp':gotp}
        subject='Admin Registration Verfication'
        body=f''' Hello Admin,
                  your OTP is :{gotp}
                  This OTP is valid for 5 minutes.
                  BUYROUTE Team'''
        send_mail(to=admin_email,subject=subject,body=body)
        token=endata(admindata)
        
        return jsonify({'status':'success','message':'OTP sent successfully','token':token}),200
    except Exception as e:
        print('Error occurs:',str(e))
        return jsonify({'status':'failed','message':str(e)}),500

if __name__=='__main__':
    app.run()
                