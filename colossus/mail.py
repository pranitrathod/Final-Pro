"""

This python file is a part of an open-source
project Colossus (https://github.com/Kiinitix/Colossus).

Sending mail through Mailtrap (https://mailtrap.io/) for testing only.
can be modified according to different SMTP domains.

Required fields -> SMTP Login details from configurations.ini

"""
import smtplib
from os.path import basename
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from configparser import ConfigParser
from email.mime.image import MIMEImage

def mail(privateKey,encryptedMsgObj):
    configur = ConfigParser()
    configur.read('configurations.ini')

    msg = MIMEMultipart()

    msg['Subject'] = 'Test mail with attachment'
    msg['From'] = configur.get('SMTPlogin', 'sender_address')
    msg['To'] = configur.get('SMTPlogin', 'receiver_address')

    key_file = 'keys.txt'
    keys = open(key_file, 'w')
    # L = ["Private Key: ", str(privateKey), "\nCipher key: ", str(ciphertext), "\nonce: ",  str(nonce),"\nauthTag: ",  str(authTag),"\Cipher text Pub Key: ",  str(ciphertextPubKey)]
    L=["Private key:",str(privateKey),"\nEncryptedMsgObject:",str(encryptedMsgObj)]
    keys.writelines(L)
    keys.close()

    # text = "Private Key: {} \nCipher Key: {}\nNonce: {} \nauthTag: {} \nciperTextPubtext: {} ".format(str(privateKey), str(ciphertext), str(nonce),str(authTag),str(ciphertextPubKey))
    text="Private Key: {} \n Encrypted Msg Obj {}".format(str(privateKey),str(encryptedMsgObj))
    # decrypt.py must be in the same directry, in case the location is modified it shouldbe reflected here also
    filename = 'decrypt.py'
    with open(filename, 'r') as f:
        part = MIMEApplication(f.read(), Name=basename(filename))


    part['Content-Disposition'] = 'attachment; filename="{}"'.format(basename(filename))
    msg.attach(part)
    msg.attach(MIMEText(text, "plain"))

    with smtplib.SMTP("smtp.mailtrap.io", 2525) as server:
        server.login(configur.get('SMTPlogin', 'mailtrap_user'), configur.get('SMTPlogin', 'mailtrap_password'))
        server.sendmail(configur.get('SMTPlogin', 'sender_address'), configur.get('SMTPlogin', 'receiver_address'), msg.as_string())
        print("Successfully sent email")
