import smtplib
from email.message import EmailMessage

EMAIL = "padalakomali990@gmail.com"
APP_PASSWORD = "qfhn lxsa niwg xdol"

def send_mail(to, subject, body):

    server = smtplib.SMTP_SSL(
        'smtp.gmail.com',
        465
    )

    server.login(
        EMAIL,
        APP_PASSWORD
    )

    msg = EmailMessage()

    msg['From'] = EMAIL
    msg['To'] = to
    msg['Subject'] = subject

    msg.set_content(body)

    server.send_message(msg)

    server.quit()