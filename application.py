from flask import Flask, render_template, flash, redirect, url_for, session, request, logging , Response, send_from_directory
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators, SelectField, SubmitField
from wtforms.fields.html5 import EmailField
from flask_wtf.file import FileField, FileRequired, FileAllowed
from passlib.hash import sha256_crypt
from functools import wraps
from werkzeug import secure_filename
from flask_uploads import UploadSet, configure_uploads, IMAGES, patch_request_class
import hashlib
import requests, json, random, os, dateutil.parser

#Flask Configuration
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'C:\\Users\\BN000353100\\Documents\\My Project\\Digital Evidence Management\\uploads'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'])

#File Name Splitter
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

#Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'CCMApp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

#Init MySQL
mysql = MySQL(app)

#Check If Users Logged In
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, please log in!', 'danger')
            return redirect(url_for('login'))
    return wrap

#Check If Username is not Admin Can Be Edited
def admincheck(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if session['role'] == '1':
            return f(*args, **kwargs)
        else:
            return render_template('404.html')
           
    return wrap

#Index
@app.route('/')
def index():
    return render_template('home.html')

#Case List
@app.route('/caseList')
@is_logged_in
def caseList():
    #Create Cursor
    cur= mysql.connection.cursor()

    #Get Case
    username = session['name']
    result = cur.execute("SELECT cases.title FROM cases JOIN users ON cases.casesid = users.casesid WHERE name LIKE %s", [username])
    cases = cur.fetchall()

    if result > 0:
        return render_template('case_repos.html', cases = cases)
    else:
        msg= 'No Case Found'
        return render_template('case_repos.html', msg = msg)

    #Close Connection
    cur.close()

#Register Form Class
class RegisterForm(Form): 
    name = StringField('Name', [validators.Length(min = 1, max = 50)])
    username = StringField('Username', [validators.Length(min = 4, max = 25)])
    email = StringField('Email', [validators.Length(min = 6, max = 50)])
    role = SelectField('Role', coerce = int, choices=[(0,'Please select...'), (1, 'Police'), (2, 'Witness'), (3, 'Prosecutor'), (4, 'Judge')])
    password = PasswordField('Password', [
        validators.DataRequired(), 
        validators.EqualTo('confirm', message = 'Password do not match!')])
    confirm = PasswordField('Confirm Password')

#User Register
@app.route('/register', methods = ['GET', 'POST'])
@is_logged_in
@admincheck
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        username = form.username.data
        email = form.email.data
        role = form.role.data
        casesid = session['casesid']
        password = sha256_crypt.encrypt(str(form.password.data))

        #Create Cursor
        cur = mysql.connection.cursor()

        #Execute Query
        cur.execute("INSERT INTO users(name, username, email, role, password, casesid) VALUES(%s, %s, %s, %s, %s, %s)", (name, username, email, role, password, casesid))

        #Commit to Database
        mysql.connection.commit()

        #Close Connection
        cur.close()

        flash('The person are now registered and can login!', 'success')

        return redirect(url_for('dashboard'))
    return render_template('register.html', form = form)

#Display Page
@app.route('/displayPage/<string:title>')
@is_logged_in
def displayPage(title):
    #Create Cursor
    cur = mysql.connection.cursor()

    #Get Evidence
    result = cur.execute("SELECT * FROM cases JOIN evidences ON cases.casesid = evidences.casesid WHERE cases.title LIKE %s",[title])
    cases = cur.fetchall()

    #Get Case
    result2 = cur.execute("SELECT * FROM cases WHERE title = %s ",[title])
    dcase = cur.fetchone()

    #Get People
    result3 = cur.execute("SELECT * FROM cases JOIN users ON cases.casesid = users.casesid WHERE cases.title LIKE %s",[title])
    dpeople = cur.fetchall()
        
    #Store Session
    casesid = dcase['casesid']
    session['casesid'] = casesid
    
    if result2 > 0:
        return render_template('displayPage.html', cases=cases, dcase=dcase, dpeople=dpeople)
    else:
        msg= 'No Case Found'
        return render_template('dashboard.html',msg=msg)
    

    #Close Connection
    cur.close()

#Upload File
@app.route('/upload_file', methods=['GET', 'POST'])
@is_logged_in
@admincheck
def upload_file():
   
    #Create Cursor
    cur = mysql.connection.cursor()

    evidenceid = session['evidenceid']

    #Get Case by Title
    result = cur.execute("SELECT casesid FROM evidences WHERE evidenceid = %s", [evidenceid])

    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            fileUpload = file.save(os.path.join(app.config['UPLOAD_FOLDER'],filename))
            hasher = hashlib.sha256()
            with open(r'C:\\Users\\BN000353100\\Documents\\My Project\\Digital Evidence Management\\uploads\\'+filename, "rb") as afile:
                for chunk in iter(lambda: afile.read(4096), b""):
                    hasher.update(chunk)
            hashing = hasher.hexdigest()
            result = cur.execute("UPDATE evidences SET evidencelocation = %s, evidenceHash = %s, evidencestatus = '0' WHERE evidenceid = %s", (filename, hashing, evidenceid))
            mysql.connection.commit()
            cur.close()
            flash('File has been uploaded!', 'success')
            return redirect(url_for('dashboard'))

    return render_template('add_evidence.html')

#Download File
@app.route('/uploads/<string:evidencelocation>')
@is_logged_in
def uploaded_file(evidencelocation):
    return send_from_directory(app.config['UPLOAD_FOLDER'], evidencelocation, as_attachment=False)

#User Login
@app.route('/login', methods = ['GET', 'POST'])
def login():
    if request.method == 'POST':
        
        #Get Form Fields
        username = request.form['username']
        password_candidate = request.form['password']

        #Create Cursor
        cur = mysql.connection.cursor()

        #Get User by  Username
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            #Get Stored Hash
            data = cur.fetchone()
            password = data['password']

            #Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                #Passed
                session['logged_in'] = True
                
                #Storing Name in Session
                name = data['name']
                session['name'] = name

                #Storing Role in Session
                role = data['role']
                session['role'] = role


                flash('You are now logged in!', 'success')
                
                if session['role'] == '1':
                    return redirect(url_for('dashboard'))
                elif session['role']== '2':
                    return redirect(url_for('caseList'))
                elif session['role']== '3':
                    return redirect(url_for('caseList'))
                elif session['role']== '4':
                    return redirect(url_for('caseList'))    
            else :
                error = 'Invalid login'
                return render_template('login.html', error = error)

            #Close Connection
            cur.close()

        else :
            error = 'Username not found'
            return render_template('login.html', error = error)

    return render_template('login.html')

#Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out.', 'success')
    return redirect(url_for('login'))

#Dashboard
@app.route('/dashboard')
@is_logged_in
@admincheck
def dashboard():
    #Create Cursor
    cur= mysql.connection.cursor()

    #Get Case
    result = cur.execute("SELECT * FROM cases")
    cases = cur.fetchall()

    if result > 0:
        return render_template('dashboard.html',cases=cases)
    else:
        msg= 'No Case Found'
        return render_template('dashboard.html',msg=msg)

    #Close Connection
    cur.close()

#Case Form Class
class CaseForm(Form):
    caseID = StringField('caseID', [validators.Length(min = 1, max = 10)])
    title = StringField('Title', [validators.Length(min = 1, max = 200)])
    witness = StringField('Witness', [validators.Length(min = 1, max = 200)])
    content = TextAreaField('Content', [validators.Length(min = 1)])
    timestamp = StringField('Time Retrieved', [validators.Length(min = 1, max = 10)])
    date = StringField('Date Retrieved', [validators.Length(min = 1, max = 10)])
   
#Add Case
@app.route('/add_case', methods =['GET', 'POST'])
@is_logged_in
@admincheck
def add_case():
    form = CaseForm(request.form)
    if request.method == 'POST' and form.validate():
        caseID = form.caseID.data
        title = form.title.data
        witness = form.witness.data
        content = form.content.data
        timestamp = form.timestamp.data
        date = form.date.data
        caseStatus = '1'
        
        #Create Cursor
        cur = mysql.connection.cursor()
        
        #Execute
        cur.execute("INSERT INTO cases (caseID, title, witness, content, timestamp, date, caseStatus, author) VALUES(%s, %s, %s, %s, %s, %s, %s, %s)",(caseID, title, witness, content, timestamp, date, caseStatus, session['name']))

        #Commit to DB
        mysql.connection.commit()
        
        #Close Connection
        cur.close()

        flash('Case Inserted','success')

        return redirect(url_for('dashboard'))

    return render_template('add_case_detailed.html',form=form)

#Feedback Form Class
class FeedbackForm(Form): 
    fbFirstName = StringField('First Name', [validators.Length(min = 1, max = 50)])
    fbLastName = StringField('Last Name', [validators.Length(min = 1, max = 50)])
    fbEmail = EmailField('Email Address', [validators.DataRequired(), validators.Email()])
    fbType = SelectField(u'Feedback Type', choices=[('fbComment', 'Comments'), ('fbBugReports', 'Bug Reports'), ('fbQuestions', 'Questions')])
    fbContent = TextAreaField('Describe Feedback', [validators.Length(min = 1)])

#Add Feedback
@app.route('/feedback', methods = ['GET', 'POST'])
@is_logged_in
def feedback():
    form = FeedbackForm(request.form)
    if request.method == 'POST' and form.validate():
        fbFirstName = form.fbFirstName.data
        fbLastName = form.fbLastName.data
        fbEmail = form.fbEmail.data
        fbType = form.fbType.data
        fbContent = form.fbContent.data

        #Create Cursor
        cur = mysql.connection.cursor()

        #Execute Query
        cur.execute("INSERT INTO feedbacks(fbAuthor, fbFirstName, fbLastName, fbEmail, fbType, fbContent) VALUES(%s, %s, %s, %s, %s, %s)", (session['name'], fbFirstName, fbLastName, fbEmail, fbType, fbContent))

        #Commit to Database
        mysql.connection.commit()

        #Close Connection
        cur.close()

        flash('Thank you for your feedback, we will answer as soon as we can.', 'success')

        return redirect(url_for('caseList'))
    return render_template('add_feedback.html', form = form)

#Report List
@app.route('/reportList')
@is_logged_in
@admincheck
def reportList():
    #Create Cursor
    cur= mysql.connection.cursor()

    #Get Case
    result = cur.execute("SELECT * FROM feedbacks")
    feedbacks = cur.fetchall()

    if result > 0:
        return render_template('feedback_repos.html', feedbacks=feedbacks)
    else:
        msg= 'No Feedback for Now'
        return render_template('feedback_repos.html', msg=msg)

    #Close Connection
    cur.close()

#Display Page
@app.route('/feedbackPage/<string:fbAuthor>')
@is_logged_in
def feedbackPage(fbAuthor):
    #Create Cursor
    cur = mysql.connection.cursor()

    #Get Feedback
    result = cur.execute("SELECT * FROM feedbacks WHERE fbAuthor LIKE %s", [fbAuthor])
    feedback = cur.fetchone()
    
    return render_template('feedback_page.html', feedback = feedback)

#Edit Case
@app.route('/edit_case/<string:casesid>', methods =['GET', 'POST'])
@is_logged_in
@admincheck
def edit_case(casesid):
    #Create cursor
    cur = mysql.connection.cursor()

    #Get Case by Title
    result = cur.execute("SELECT * FROM cases WHERE casesid = %s", [casesid])
    case = cur.fetchone()

    #Store Ha
    casesid = case['casesid']
    session['casesid'] = casesid

    #Get Form
    form = CaseForm(request.form)

    #Populate Case Form Field
    form.caseID.data = case['caseID']
    form.title.data = case['title']
    form.witness.data = case['witness']
    form.content.data = case['content']
    form.timestamp.data = case['timestamp']
    form.date.data = case['date']

    if request.method == 'POST' and form.validate():
        caseID = request.form['caseID']
        title = request.form['title']
        witness = request.form['witness']
        content = request.form['content']
        timestamp = request.form['timestamp']
        date = request.form['date']
        
        #Create Cursor
        cur = mysql.connection.cursor()

        #Execute
        cur.execute("UPDATE cases SET caseID = %s, title = %s, witness = %s, content = %s, timestamp = %s, date = %s WHERE casesid = %s",(caseID, title, witness, content, timestamp, date, casesid))

        #Commit to DB
        mysql.connection.commit()

        #Close Connection
        cur.close()

        flash('Case Updated!','success')

        return redirect(url_for('dashboard'))

    return render_template('edit_case.html',form = form, case=case)

#Approval Case
@app.route('/approval', methods = ['GET', 'POST'])
@is_logged_in
def approval():

        #Create Cursor
        cur = mysql.connection.cursor()

        casesid =  session['casesid']
        role = session['role']

        #Execute
        cur.execute("UPDATE cases SET caseStatus = %s  WHERE casesid = %s;", (role, casesid))

        #Commit to DB
        mysql.connection.commit()

        #Close Connection
        cur.close()

        flash('Case has been approved by you.','success')

        return redirect(url_for('caseList'))

#Delete Case
@app.route('/delete_case/<string:casesid>', methods = ['POST'])
@is_logged_in
@admincheck
def delete_case(casesid):

        #Create Cursor
        cur = mysql.connection.cursor()

        #Execute
        cur.execute("DELETE FROM cases WHERE casesid = %s",[casesid])

        #Commit to DB
        mysql.connection.commit()

        #Close Connection
        cur.close()

        flash('Case Deleted!','success')

        return redirect(url_for('dashboard'))

#Delete Case
@app.route('/delete_users/<string:username>', methods = ['POST'])
@is_logged_in
@admincheck
def delete_users(username):

        #Create Cursor
        cur = mysql.connection.cursor()

        #Execute
        cur.execute("DELETE FROM users WHERE username = %s",[username])

        #Commit to DB
        mysql.connection.commit()

        #Close Connection
        cur.close()

        flash('Users Deleted!','success')

        return redirect(url_for('dashboard'))

#Popover Evidence
@app.route('/evidence/<evidenceid>/popup', methods = ['POST', 'GET'])
@is_logged_in
def evidencePopup(evidenceid):
    cur = mysql.connection.cursor()

    #Get Evidence Detail
    cur.execute("SELECT * FROM evidences WHERE evidenceid = %s", [evidenceid])
    evidence = cur.fetchone()
    return render_template('evidence_popup.html', evidence = evidence)

#Transfer to Blockchain Evidence Only
@app.route('/submitEvidenceComposer/<string:evidenceid>',methods = ['POST', 'GET'])
@is_logged_in
def submitEvidenceComposer(evidenceid):
    cur = mysql.connection.cursor()

    #Change evidenceStatus from 0 to 1
    eStatus = 1
    cur.execute("UPDATE evidences SET evidenceStatus = %s  WHERE evidenceid = %s;", (eStatus, evidenceid))
    mysql.connection.commit()


    #Get Evidence
    result = cur.execute("SELECT * FROM evidences JOIN cases ON evidences.casesid = cases.casesid WHERE evidences.evidenceid LIKE %s", [evidenceid])
    evidence = cur.fetchone()

    caseID = evidence['caseID']
    evidenceID = evidence['evidenceid']
    evidenceName = evidence['evidencename']
    evidenceType = evidence['evidencetype']
    evidenceTimestamp = evidence['evidencetimestamp']
    evidenceDate = evidence['evidencedate']
    evidenceLocation = evidence['evidencelocation']
    evidenceHash = evidence['evidenceHash']
        
    json_val = {
        "$class": "org.network.ccase.Evidence",
        "evidenceID": evidenceID,
        "caseID": caseID.encode('utf-8'),
        "evidenceName": evidenceName.encode('utf-8'),
        "evidenceType": evidenceType.encode('utf-8'),
        "evidenceTimestamp": evidenceTimestamp.encode('utf-8'),
        "evidenceDate": evidenceDate.encode('utf-8'),
        "evidenceLocation": evidenceLocation.encode('utf-8'),
        "evidenceHash": evidenceHash.encode('utf-8'),
        "owner": 'PLC001'
        }

    cur.close()
    r = requests.post('http://192.168.1.118:3000/api/Evidence', data = json_val)
    flash('Added to Blockchain','success')

    return redirect(url_for('dashboard'))

#Transfer to Blockchain Case Only
@app.route('/submitCaseComposer/<string:casesid>',methods = ['POST', 'GET'])
@is_logged_in
def submitCaseComposer(casesid):
    cur = mysql.connection.cursor()

    #Change caseStatus from 4 to 5
    cStatus = 5
    cur.execute("UPDATE cases SET caseStatus = %s  WHERE casesid = %s;", (cStatus, casesid))
    mysql.connection.commit()

    #Get Case by Title
    result = cur.execute("SELECT * FROM cases WHERE casesid = %s", [casesid])
    case = cur.fetchone()

    caseID = case['caseID']
    caseStatus = case['caseStatus']
    caseTitle = case['title']
    caseAuthor = case['author']
    caseWitness = case['witness']
    caseContent = case['content']
    caseTimestamp = case['timestamp']
    caseDate = case['date']
    caseCreateDate = case['timestamp']

    json_val = {
        "$class": "org.network.ccase.Case",
        "caseID": caseID.encode('utf-8'),
        "caseStatus": caseStatus.encode('utf-8'),
        "caseTitle": caseTitle.encode('utf-8'),
        "caseAuthor": caseAuthor.encode('utf-8'),
        "caseWitness": caseWitness.encode('utf-8'),
        "caseContent": caseContent.encode('utf-8'),
        "caseTimestamp": caseTimestamp.encode('utf-8'),
        "caseDate": caseDate.encode('utf-8'),
        "caseCreateDate": caseCreateDate.encode('utf-8'),
        "owner": 'PLC001'
    }

    cur.close()
    r = requests.post('http://192.168.1.118:3000/api/Case', data = json_val)
    flash('Added to Blockchain','success')

    return redirect(url_for('dashboard'))
    
#Evidence Form Class
class EvidenceForm(Form):
    evidencename = StringField('Evidence Name', [validators.Length(min = 5, max = 10)])
    evidencetimestamp = StringField('Evidence Timestamp', [validators.Length(min = 1, max = 10)])
    evidencetype = SelectField(u'Evidence Type', choices=[('images', 'Images'), ('doc_docx', 'Document'), ('doc_pdf', 'PDF'), ('doc_txt', 'Text')])
    evidencedate = StringField('Evidence Date', [validators.Length(min = 1, max = 10)])

#Add Evidence
@app.route('/add_evidenceDB', methods =['GET', 'POST'])
@is_logged_in
@admincheck
def add_evidenceDB():
    form = EvidenceForm(request.form)
    if request.method == 'POST' and form.validate():
        evidencename = form.evidencename.data
        evidencetype = form.evidencetype.data
        evidencetimestamp = form.evidencetimestamp.data
        evidencedate = form.evidencedate.data
        casesid = session['casesid']
        
        #evidenceLocation = photos.save(form.evidenceLocation.data)
        #file_url = photos.url(evidenceLocation)
        
        #Create Cursor
        cur = mysql.connection.cursor()

        #Execute
        cur.execute("INSERT INTO evidences (evidencename, evidencetype, evidencetimestamp, evidencedate, casesid) VALUES(%s, %s, %s, %s, %s)",(evidencename, evidencetype, evidencetimestamp, evidencedate, casesid))

        #Commit to DB
        mysql.connection.commit()

        result = cur.execute("SELECT * FROM evidences WHERE evidencename = %s", [evidencename])
        data = cur.fetchone()

        #Storing evidenceid Session
        evidenceid = data['evidenceid']
        session['evidenceid'] = evidenceid

        #Close Connection
        cur.close()

        flash('Evidence Inserted','success')
        return redirect(url_for('upload_file'))

    return render_template('add_case_composer.html',form=form)

# When running this app on the local machine. default the port to 8000
port = int(os.getenv('PORT', 5000))

#Entry point to open our program
if __name__ == "__main__":
    app.secret_key='S3cr3t123'
    app.run(host='0.0.0.0', port=port, debug=True)
