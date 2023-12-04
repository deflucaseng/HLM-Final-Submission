from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from sqlalchemy import asc, desc
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt



app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a secret key for production
# Use MySQL configuration for phpMyAdmin
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/users'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

bcrypt = Bcrypt(app)

# Define a User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    password_hash = db.Column(db.String(120), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Criminals(db.Model):
    Criminal_ID = db.Column(db.Numeric(6, 0), primary_key=True)
    Last = db.Column(db.String(15))
    First = db.Column(db.String(10))
    Street = db.Column(db.String(30))
    City = db.Column(db.String(20))
    State = db.Column(db.String(2))
    Zip = db.Column(db.String(5))
    Phone = db.Column(db.String(10))
    V_status = db.Column(db.String(1), default='N')
    P_status = db.Column(db.String(1), default='N')

class Prob_officer(db.Model):
    Prob_ID = db.Column(db.Numeric(5), primary_key=True)
    Last = db.Column(db.String(15))
    First = db.Column(db.String(10))
    Street = db.Column(db.String(30))
    City = db.Column(db.String(20))
    State = db.Column(db.String(2))
    Zip = db.Column(db.String(5))
    Phone = db.Column(db.String(10))
    Email = db.Column(db.String(30))
    Status = db.Column(db.String(1), nullable=False)

class Officers(db.Model):
    Officer_ID = db.Column(db.Numeric(8), primary_key=True)
    Last = db.Column(db.String(15))
    First = db.Column(db.String(10))
    Precinct = db.Column(db.String(4), nullable=False)
    Badge = db.Column(db.String(14), unique=True)
    Phone = db.Column(db.String(10))
    Status = db.Column(db.String(1), default='A')

class Alias(db.Model):
    Alias_ID = db.Column(db.Numeric(6, 0), primary_key=True)
    Criminal_ID = db.Column(db.Numeric(6, 0), db.ForeignKey('criminals.Criminal_ID'))
    Alias = db.Column(db.String(20))

class Crimes(db.Model):
    Crime_ID = db.Column(db.Numeric(9, 0), primary_key=True)
    Criminal_ID = db.Column(db.Numeric(6, 0), db.ForeignKey('criminals.Criminal_ID'))
    Classification = db.Column(db.String(1), default='U')
    Status = db.Column(db.String(2))
    Date_charged = db.Column(db.Date)
    Hearing_date = db.Column(db.Date)
    Appeal_cut_date = db.Column(db.Date)

class Appeals(db.Model):
    Appeal_ID = db.Column(db.Numeric(5, 0), primary_key=True)
    Crime_ID = db.Column(db.Numeric(9, 0), db.ForeignKey('crimes.Crime_ID'))
    Filing_date = db.Column(db.Date)
    Hearing_date = db.Column(db.Date)
    Status = db.Column(db.String(1), default='P')

class Sentences(db.Model):
    Sentence_ID = db.Column(db.Numeric(6, 0), primary_key=True)
    Criminal_ID = db.Column(db.Numeric(6, 0), db.ForeignKey('criminals.Criminal_ID'))
    Type = db.Column(db.String(1))
    Prob_ID = db.Column(db.Numeric(5, 0), db.ForeignKey('prob_officer.Prob_ID'))
    Start_date = db.Column(db.Date)
    End_date = db.Column(db.Date)
    Violations = db.Column(db.Numeric(3, 0), nullable=False)

class Crime_charges(db.Model):
    Charge_ID = db.Column(db.Numeric(10, 0), primary_key=True)
    Crime_ID = db.Column(db.Numeric(9, 0), db.ForeignKey('crimes.Crime_ID'))
    Crime_code = db.Column(db.Numeric(3, 0))  # ForeignKey depends on Crime_codes model
    Charge_status = db.Column(db.String(2))
    Fine_amount = db.Column(db.DECIMAL(7, 2))
    Court_fee = db.Column(db.DECIMAL(7, 2))
    Amount_paid = db.Column(db.DECIMAL(7, 2))
    Pay_due_date = db.Column(db.Date)

class Crime_officers(db.Model):
    Crime_ID = db.Column(db.Numeric(9, 0), db.ForeignKey('crimes.Crime_ID'), primary_key=True)
    Officer_ID = db.Column(db.Numeric(8, 0), db.ForeignKey('officers.Officer_ID'), primary_key=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Check if the app successfully connects to the database
try:
    with app.app_context():
        db.create_all()
    print("Successfully connected to the database!")
except Exception as e:
    print(f"Failed to connect to the database. Error: {e}")

@app.route('/')
def home():
    success_message = request.args.get('success_message')
    return render_template('home.html', success_message=success_message)



@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/criminal')
def criminal():
    return render_template('criminal.html')

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/signin')
def signin():
    return render_template('signin.html')

@app.route('/user_accounts')
@login_required
def user_accounts():
    users = User.query.all()
    return render_template('user_accounts.html', users=users)

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return 'Username already exists', 400

    new_user = User(username=username)
    new_user.set_password(password)
    
    db.session.add(new_user)
    db.session.commit()

    return 'User registered successfully'

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    user = User.query.filter_by(username=username).first()

    if user and user.password == password: #cannot work with hash_login_check
        login_user(user)
        success_message = "Successfully Logged In!"
        # Add the success_message parameter when redirecting to the home page
        return redirect(url_for('home', success_message=success_message))
    else:
        return 'Invalid username or password', 401

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)


@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user = User.query.get(user_id)

    if request.method == 'POST':
        # Update user information
        user.username = request.form['username']
        user.password = request.form['password']
        db.session.commit()
        return redirect(url_for('user_accounts'))

    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    user = User.query.get(user_id)
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('user_accounts'))

@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return 'Username already exists', 400

        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('user_accounts'))

    return render_template('add_user.html')

@app.route('/criminal_accounts')
@login_required
def criminal_accounts():
    criminal = Criminals.query.all()
    return render_template('criminal_accounts.html', criminal=criminal)

@app.route('/criminal_add', methods=['GET', 'POST'])
@login_required
def criminal_add():
    if request.method == 'POST':
        new_criminal = Criminals(
            Criminal_ID=request.form['Criminal_ID'],
            Last=request.form['Last'],
            First=request.form['First'],
            Street=request.form['Street'],
            City=request.form['City'],
            State=request.form['State'],
            Zip=request.form['Zip'],
            Phone=request.form['Phone'],
            V_status=request.form['V_status'],
            P_status=request.form['P_status']
        )
        db.session.add(new_criminal)
        db.session.commit()
        return redirect(url_for('criminal_accounts'))
    return render_template('criminal_add.html')

@app.route('/criminal_delete/<int:criminal_id>')
@login_required
def criminal_delete(criminal_id):
    criminal = Criminals.query.get(criminal_id)
    db.session.delete(criminal)
    db.session.commit()
    return redirect(url_for('criminal_accounts'))

@app.route('/criminal_edit/<int:criminal_id>', methods=['GET', 'POST'])
@login_required
def criminal_edit(criminal_id):
    criminal = Criminals.query.get(criminal_id)
    if request.method == 'POST':
        criminal.Criminal_ID = request.form['Criminal_ID']
        criminal.Last = request.form['Last']
        criminal.First = request.form['First']
        criminal.Street = request.form['Street']
        criminal.City = request.form['City']
        criminal.State = request.form['State']
        criminal.Zip = request.form['Zip']
        criminal.Phone = request.form['Phone']
        criminal.V_status = request.form['V_status']
        criminal.P_status = request.form['P_status']
        db.session.commit()
        return redirect(url_for('criminal_accounts'))
    return render_template('criminal_edit.html', criminal=criminal)

@app.route('/prob_officer_accounts')
@login_required
def prob_officer_accounts():
    officers = Prob_officer.query.all()
    return render_template('prob_officer_accounts.html', officers=officers)

@app.route('/prob_officer_edit/<int:prob_id>', methods=['GET', 'POST'])
@login_required
def prob_officer_edit(prob_id):
    officer = Prob_officer.query.get(prob_id)
    if request.method == 'POST':
        officer.Last = request.form['Last']
        officer.First = request.form['First']
        officer.Street = request.form['Street']
        officer.City = request.form['City']
        officer.State = request.form['State']
        officer.Zip = request.form['Zip']
        officer.Phone = request.form['Phone']
        officer.Email = request.form['Email']
        officer.Status = request.form['Status']
        db.session.commit()
        return redirect(url_for('prob_officer_accounts'))
    return render_template('prob_officer_edit.html', officer=officer)

@app.route('/prob_officer_delete/<int:prob_id>')
@login_required
def prob_officer_delete(prob_id):
    officer = Prob_officer.query.get(prob_id)
    db.session.delete(officer)
    db.session.commit()
    return redirect(url_for('prob_officer_accounts'))

@app.route('/prob_officer_add', methods=['GET', 'POST'])
@login_required
def prob_officer_add():
    if request.method == 'POST':
        new_officer = Prob_officer(
            Prob_ID=request.form['Prob_ID'],
            Last=request.form['Last'],
            First=request.form['First'],
            Street=request.form['Street'],
            City=request.form['City'],
            State=request.form['State'],
            Zip=request.form['Zip'],
            Phone=request.form['Phone'],
            Email=request.form['Email'],
            Status=request.form['Status']
        )
        db.session.add(new_officer)
        db.session.commit()
        return redirect(url_for('prob_officer_accounts'))
    return render_template('prob_officer_add.html')

@app.route('/officer_accounts')
@login_required
def officer_accounts():
    officers = Officers.query.all()
    return render_template('officer_accounts.html', officers=officers)

@app.route('/officer_add', methods=['GET', 'POST'])
@login_required
def officer_add():
    if request.method == 'POST':
        new_officer = Officers(
            Officer_ID=request.form['Officer_ID'],
            Last=request.form['Last'],
            First=request.form['First'],
            Precinct=request.form['Precinct'],
            Badge=request.form['Badge'],
            Phone=request.form['Phone'],
            Status=request.form['Status']
        )
        db.session.add(new_officer)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            # Handle exceptions like duplicate entries, etc.
            return str(e), 400
        return redirect(url_for('officer_accounts'))
    
    return render_template('officer_add.html')

@app.route('/officer_edit/<int:officer_id>', methods=['GET', 'POST'])
@login_required
def officer_edit(officer_id):
    officers = Officers.query.get(officer_id)
    if request.method == 'POST':
        officers.Last = request.form['Last']
        officers.First = request.form['First']
        officers.Precinct = request.form['Precinct']
        officers.Badge = request.form['Badge']
        officers.Phone = request.form['Phone']
        officers.Status = request.form['Status']
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            # Handle exceptions
            return str(e), 400
        return redirect(url_for('officer_accounts'))

    return render_template('officer_edit.html', officers=officers)

@app.route('/officer_delete/<int:officer_id>')
@login_required
def officer_delete(officer_id):
    officers = Officers.query.get(officer_id)
    db.session.delete(officers)
    db.session.commit()
    return redirect(url_for('officer_accounts'))

@app.route('/alias_accounts')
@login_required
def alias_accounts():
    aliases = Alias.query.all()
    return render_template('alias_accounts.html', aliases=aliases)

@app.route('/alias_add', methods=['GET', 'POST'])
@login_required
def alias_add():
    if request.method == 'POST':
        new_alias = Alias(
            Alias_ID=request.form['Alias_ID'],
            Criminal_ID=request.form['Criminal_ID'],
            Alias=request.form['Alias']
        )
        db.session.add(new_alias)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return str(e), 400
        return redirect(url_for('alias_accounts'))
    return render_template('alias_add.html')


@app.route('/alias_edit/<int:alias_id>', methods=['GET', 'POST'])
@login_required
def alias_edit(alias_id):
    alias = Alias.query.get_or_404(alias_id)
    if request.method == 'POST':
        alias.Alias_ID = request.form['Alias_ID']
        alias.Criminal_ID = request.form['Criminal_ID']
        alias.Alias = request.form['Alias']
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return str(e), 400
        return redirect(url_for('alias_accounts'))
    return render_template('alias_edit.html', alias=alias)

@app.route('/alias_delete/<int:alias_id>')
@login_required
def alias_delete(alias_id):
    alias = Alias.query.get_or_404(alias_id)
    db.session.delete(alias)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return str(e), 400
    return redirect(url_for('alias_accounts'))

@app.route('/crimes_accounts')
@login_required
def crimes_accounts():
    crimes = Crimes.query.all()
    return render_template('crimes_accounts.html', crimes=crimes)

@app.route('/crimes_add', methods=['GET', 'POST'])
@login_required
def crimes_add():
    if request.method == 'POST':
        new_crime = Crimes(
            Crime_ID=request.form['Crime_ID'],
            Criminal_ID=request.form['Criminal_ID'],
            Classification=request.form['Classification'],
            Status=request.form['Status'],
            Date_charged=request.form['Date_charged'],
            Hearing_date=request.form['Hearing_date'],
            Appeal_cut_date=request.form['Appeal_cut_date']
        )
        db.session.add(new_crime)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return str(e), 400
        return redirect(url_for('crimes_accounts'))
    return render_template('crimes_add.html')

@app.route('/crimes_edit/<int:crime_id>', methods=['GET', 'POST'])
@login_required
def crimes_edit(crime_id):
    crime = Crimes.query.get_or_404(crime_id)
    if request.method == 'POST':
        crime.Criminal_ID = request.form['Criminal_ID']
        crime.Classification = request.form['Classification']
        crime.Status = request.form['Status']
        crime.Date_charged = request.form['Date_charged']
        crime.Hearing_date = request.form['Hearing_date']
        crime.Appeal_cut_date = request.form['Appeal_cut_date']
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return str(e), 400
        return redirect(url_for('crimes_accounts'))
    return render_template('crimes_edit.html', crime=crime)

@app.route('/crimes_delete/<int:crime_id>')
@login_required
def crimes_delete(crime_id):
    crime = Crimes.query.get_or_404(crime_id)
    db.session.delete(crime)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return str(e), 400
    return redirect(url_for('crimes_accounts'))

@app.route('/appeals_accounts')
@login_required
def appeals_accounts():
    appeals = Appeals.query.all()
    return render_template('appeals_accounts.html', appeals=appeals)

@app.route('/appeals_add', methods=['GET', 'POST'])
@login_required
def appeals_add():
    if request.method == 'POST':
        new_appeal = Appeals(
            Appeal_ID=request.form['Appeal_ID'],
            Crime_ID=request.form['Crime_ID'],
            Filing_date=request.form['Filing_date'],
            Hearing_date=request.form['Hearing_date'],
            Status=request.form['Status']
        )
        db.session.add(new_appeal)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return str(e), 400
        return redirect(url_for('appeals_accounts'))
    return render_template('appeals_add.html')

@app.route('/appeals_edit/<int:appeal_id>', methods=['GET', 'POST'])
@login_required
def appeals_edit(appeal_id):
    appeal = Appeals.query.get_or_404(appeal_id)
    if request.method == 'POST':
        appeal.Crime_ID = request.form['Crime_ID']
        appeal.Filing_date = request.form['Filing_date']
        appeal.Hearing_date = request.form['Hearing_date']
        appeal.Status = request.form['Status']
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return str(e), 400
        return redirect(url_for('appeals_accounts'))
    return render_template('appeals_edit.html', appeal=appeal)

@app.route('/appeals_delete/<int:appeal_id>')
@login_required
def appeals_delete(appeal_id):
    appeal = Appeals.query.get_or_404(appeal_id)
    db.session.delete(appeal)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return str(e), 400
    return redirect(url_for('appeals_accounts'))


@app.route('/sentences_accounts')
@login_required
def sentences_accounts():
    sentences = Sentences.query.all()
    return render_template('sentences_accounts.html', sentences=sentences)

@app.route('/sentences_add', methods=['GET', 'POST'])
@login_required
def sentences_add():
    if request.method == 'POST':
        new_sentence = Sentences(
            Sentence_ID=request.form['Sentence_ID'],
            Criminal_ID=request.form['Criminal_ID'],
            Type=request.form['Type'],
            Prob_ID=request.form['Prob_ID'],
            Start_date=request.form['Start_date'],
            End_date=request.form['End_date'],
            Violations=request.form['Violations']
        )
        db.session.add(new_sentence)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return str(e), 400
        return redirect(url_for('sentences_accounts'))
    return render_template('sentences_add.html')

@app.route('/sentences_edit/<int:sentence_id>', methods=['GET', 'POST'])
@login_required
def sentences_edit(sentence_id):
    sentence = Sentences.query.get(sentence_id)
    if request.method == 'POST':
        sentence.Criminal_ID = request.form['Criminal_ID']
        sentence.Type = request.form['Type']
        sentence.Prob_ID = request.form['Prob_ID']
        sentence.Start_date = request.form['Start_date']
        sentence.End_date = request.form['End_date']
        sentence.Violations = request.form['Violations']
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return "error", 400
        return redirect(url_for('sentences_accounts'))
    return render_template('sentences_edit.html', sentence=sentence)

@app.route('/sentences_delete/<int:sentence_id>')
@login_required
def sentences_delete(sentence_id):
    sentence = Sentences.query.get(sentence_id)
    db.session.delete(sentence)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return "error", 400
    return redirect(url_for('sentences_accounts'))

@app.route('/crime_charges_accounts')
@login_required
def crime_charges_accounts():
    charges = Crime_charges.query.all()
    return render_template('crime_charges_accounts.html', charges=charges)

@app.route('/crime_charges_add', methods=['GET', 'POST'])
@login_required
def crime_charges_add():
    if request.method == 'POST':
        new_charge = Crime_charges(
            Charge_ID=request.form['Charge_ID'],
            Crime_ID=request.form['Crime_ID'],
            Crime_code=request.form['Crime_code'],
            Charge_status=request.form['Charge_status'],
            Fine_amount=request.form['Fine_amount'],
            Court_fee=request.form['Court_fee'],
            Amount_paid=request.form['Amount_paid'],
            Pay_due_date=request.form['Pay_due_date']
        )
        db.session.add(new_charge)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return "error", 400
        return redirect(url_for('crime_charges_accounts'))
    return render_template('crime_charges_add.html')

@app.route('/crime_charges_edit/<int:charge_id>', methods=['GET', 'POST'])
@login_required
def crime_charges_edit(charge_id):
    charge = Crime_charges.query.get_or_404(charge_id)
    if request.method == 'POST':
        charge.Crime_ID = request.form['Crime_ID']
        charge.Crime_code = request.form['Crime_code']
        charge.Charge_status = request.form['Charge_status']
        charge.Fine_amount = request.form['Fine_amount']
        charge.Court_fee = request.form['Court_fee']
        charge.Amount_paid = request.form['Amount_paid']
        charge.Pay_due_date = request.form['Pay_due_date']
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return "error", 400
        return redirect(url_for('crime_charges_accounts'))
    return render_template('crime_charges_edit.html', charge=charge)

@app.route('/crime_charges_delete/<int:charge_id>')
@login_required
def crime_charges_delete(charge_id):
    charge = Crime_charges.query.get(charge_id)
    db.session.delete(charge)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return "haha", 400
    return redirect(url_for('crime_charges_accounts'))

@app.route('/crime_officers_accounts')
@login_required
def crime_officers_accounts():
    crime_officers = Crime_officers.query.all()
    return render_template('crime_officers_accounts.html', crime_officers=crime_officers)

@app.route('/crime_officers_add', methods=['GET', 'POST'])
@login_required
def crime_officers_add():
    if request.method == 'POST':
        new_crime_officer = Crime_officers(
            Crime_ID=request.form['Crime_ID'],
            Officer_ID=request.form['Officer_ID']
        )
        db.session.add(new_crime_officer)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return "haha", 400
        return redirect(url_for('crime_officers_accounts'))
    return render_template('crime_officers_add.html')

@app.route('/crime_officers_edit/<int:crime_id>/<int:officer_id>', methods=['GET', 'POST'])
@login_required
def crime_officers_edit(crime_id, officer_id):
    crime_officer = Crime_officers.query.filter_by(Crime_ID=crime_id, Officer_ID=officer_id).first_or_404()
    if request.method == 'POST':
        crime_officer.Crime_ID = request.form['Crime_ID']
        crime_officer.Officer_ID = request.form['Officer_ID']
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return "lol", 400
        return redirect(url_for('crime_officers_accounts'))
    return render_template('crime_officers_edit.html', crime_officer=crime_officer)

@app.route('/crime_officers_delete/<int:crime_id>/<int:officer_id>')
@login_required
def crime_officers_delete(crime_id, officer_id):
    crime_officer = Crime_officers.query.filter_by(Crime_ID=crime_id, Officer_ID=officer_id).first_or_404()
    db.session.delete(crime_officer)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return str(e), 400
    return redirect(url_for('crime_officers_accounts'))

@app.route('/user-options')
@login_required
def user_options():
    # Check if the current user is an admin
    if current_user.username in ['Hongjie', 'Mohan', 'Lucas']:
        role = 'Admin (View and Edit)'
    else:
        role = 'User (View only)'

    return render_template('user_options.html', role=role)

@app.after_request
def add_header(response):
    response.cache_control.max_age = 0
    return response

if __name__ == '__main__':
    app.run(debug=True)