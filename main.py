# Waitman Gobble <ns@waitman.net> 650-209-7836
import struct
import os
import sys
import psycopg2
import json
import yubico
import gnupg
import re
import time
from hashlib import blake2b
from PyQt5.QtWidgets import QMainWindow, QApplication, QPushButton, QPlainTextEdit
from PyQt5 import uic

def clnstr(s):
    s = re.sub(r'[^a-zA-Z]', '', s) # remove nonalpha. we do this to normalize hash
    return s.lower()

def clntel(s):
    s = re.sub(r'[^0-9]', '', s) # remove non-number. we do this to normalize hash
    return s

def clnelm(s):
    s = s.translate(s.maketrans('', '', ' \n\t\r')) # remove space and newline chars. we do this to normalize hash
    return s.lower()

class UI(QMainWindow):

    def __init__(self):
        super(UI, self).__init__()
        uic.loadUi("safedata.ui", self)

        self.namePrefix = self.findChild(QPlainTextEdit, "namePrefix")
        self.firstName = self.findChild(QPlainTextEdit, "firstName")
        self.middleName = self.findChild(QPlainTextEdit, "middleName")
        self.lastName = self.findChild(QPlainTextEdit, "lastName")
        self.secondLastName = self.findChild(QPlainTextEdit, "secondLastName")
        self.nameSuffix = self.findChild(QPlainTextEdit, "nameSuffix")
        self.phone = self.findChild(QPlainTextEdit, "phone")
        self.email = self.findChild(QPlainTextEdit, "email")
        self.dob = self.findChild(QPlainTextEdit, "dob")
        self.button = self.findChild(QPushButton, "createRecordButton")
        self.button.clicked.connect(self.clickedBtn)

        self.show()

    def clickedBtn(self):
        x = {
            "namePrefix": self.namePrefix.toPlainText(),
            "firstName": self.firstName.toPlainText(),
            "middleName": self.middleName.toPlainText(),
            "lastName": self.lastName.toPlainText(),
            "secondLastName": self.secondLastName.toPlainText(),
            "nameSuffix": self.nameSuffix.toPlainText(),
            "phone": self.phone.toPlainText(),
            "email": self.email.toPlainText(),
            "dob": self.dob.toPlainText(),
        }
        try:
            unencrypted_string = json.dumps(x)
        except:
            print("Invalid JSON value")
        finally:
            try:
                # path to gpg home
                gpg = gnupg.GPG(gnupghome='/home/wago/.gnupg')
                # first id is public key id to encrypt the data 'to', second is our public id for signing
                encrypted_data = gpg.encrypt(unencrypted_string, 'E26107679233DCF6', sign='6778F616B4278FB0')
            except:
                print("Encryption Error")
            finally:
                # hash 1 is Last Name, First Name, Telephone
                h1 = blake2b()
                h1.update(clnstr(self.lastName.toPlainText()).encode('utf-8'))
                h1.update(clnstr(self.firstName.toPlainText()).encode('utf-8'))
                h1.update(clntel(self.phone.toPlainText()).encode('utf-8'))
                h1str = str(h1.hexdigest().encode('utf-8'))
                # hash 2 is Last Name, First Name, Email Address
                h2 = blake2b()
                h2.update(clnstr(self.lastName.toPlainText()).encode('utf-8'))
                h2.update(clnstr(self.firstName.toPlainText()).encode('utf-8'))
                h2.update(clnelm(self.email.toPlainText()).encode('utf-8'))
                h2str = str(h2.hexdigest().encode('utf-8'))

                try:
                    cur = conn.cursor()
                    # check for dup records
                    cur.execute("SELECT idx FROM ix WHERE hkey=%s OR hkey=%s",(h1str,h2str))
                    if cur.rowcount>0:
                        print("Cannot Insert, record exists") # probably want to do an update or merge
                    else:
                        cur.execute("INSERT INTO dx (dat,sequence) VALUES (%s,%s) RETURNING idx",(str(encrypted_data),int(time.time())))
                        row = cur.fetchone()
                        if row is not None:
                            #insert search keys
                            idx = row[0]
                            cur.execute("INSERT INTO ix (dxidx,hkey) VALUES (%s,%s)",(idx,h1str))
                            cur.execute("INSERT INTO ix (dxidx,hkey) VALUES (%s,%s)",(idx,h2str))
                        else:
                            print("Insert Failed idx=0")
                except (Exception, psycopg2.DatabaseError) as error:
                    print(error)
                finally:
                    print("Record Inserted")

                cur.close
try:
    # using certificate authentication with postgres username set in common name field of cert
    conn = psycopg2.connect(dbname='DBNAME', host='DBHOST', port='5432',
            sslmode='verify-full',
            sslrootcert='server.ca',
            sslcert='client.crt',
            sslkey='client.key')
except ConnectionError as e:
    print("Could not connect to database server.")
    print(e)
    sys.exit(1)
finally:
    conn.autocommit = True
    print("Database connection succeeded.")


try:
    # if you dont have the key plugged into your usb you will prompt be prompted to insert it
    # so maybe we don't need to check and bail if it's not plugged in.
    yubikey = yubico.find_yubikey(debug=False)
    print("Yubikey Firmware Version: {}".format(yubikey.version()))
except yubico.yubico_exception.YubicoError as e:
    print("ERROR: {}".format(e.reason))
    sys.exit(1)


app = QApplication(sys.argv)
window = UI()
app.exec_()
