import smtplib
import random
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def generate_random_code():
    random_number = random.randint(1000, 9999)
    return str(random_number)

def send_code(email):
    msg = MIMEMultipart()
    msg['From'] = "jade.shaheduni@gmail.com"
    msg['To'] = email
    msg['Subject'] = "Verification"

    otp_code = generate_random_code()
    body = f"Hey! Here is your verification code: {otp_code}"
    msg.attach(MIMEText(body, 'plain'))

    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_username = "jade.shaheduni@gmail.com"
    smtp_password = "qqtwdphrytmmigmo"

    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    server.login(smtp_username, smtp_password)
    text = msg.as_string()
    server.sendmail(smtp_username, email, text)
    server.quit()

    return otp_code
