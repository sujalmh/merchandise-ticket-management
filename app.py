from flask import Flask, render_template, redirect, request, url_for, flash, jsonify, send_from_directory, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image
import csv
from io import StringIO, BytesIO
import os
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

sizes = ['S', 'M', 'L']

class SuperAdmin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    
    @property
    def is_super_admin(self):
        return True
    
    def get_id(self):
        return f"superadmin-{self.id}"

    def __repr__(self):
        return '<SuperAdmin {}>'.format(self.username)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usn = db.Column(db.String(11), unique=True, nullable=False)
    name = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(50), nullable=False)
    phone_number = db.Column(db.String(20), unique=True, nullable=False)
    is_cr = db.Column(db.Boolean, default=False)
    is_organiser = db.Column(db.Boolean, default=False)
    branch_id = db.Column(db.Integer, db.ForeignKey('branch.id'), nullable=False)
    class_id = db.Column(db.Integer, db.ForeignKey('class.id'), nullable=False)
    size_id = db.Column(db.Integer, db.ForeignKey('size.id'), nullable=True) 
    shirt_status = db.Column(db.Boolean, default=False)
    size = db.relationship('Size', back_populates='users')
    branch = db.relationship('Branch', back_populates="users")
    class_ = db.relationship('Class', back_populates="users")
    paid = db.Column(db.Boolean, default=False)
    payment_proof_url = db.Column(db.String(255), nullable=True)
    def get_id(self):
        return f"user-{self.id}"

    @property
    def is_super_admin(self):
        return False
    
class Branch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    code = db.Column(db.String(10), unique=True, nullable=False)
    classes = db.relationship('Class', backref='branch', lazy=True)  
    users = db.relationship('User', back_populates="branch")

class Size(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    size_name = db.Column(db.String(11), unique=True, nullable=False)  
    users = db.relationship('User', back_populates='size')

class Class(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sem = db.Column(db.String(10), nullable=False)
    section = db.Column(db.String(10), nullable=False)
    branch_id = db.Column(db.Integer, db.ForeignKey('branch.id'), nullable=False)
    users = db.relationship('User', back_populates="class_")
    payment_qrs = db.relationship('PaymentQR', secondary='paymentqr_class', back_populates='classes')

class PaymentQR(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image_url = db.Column(db.String(255), nullable=False)
    classes = db.relationship('Class', secondary='paymentqr_class', back_populates='payment_qrs')

class PaymentQRClass(db.Model):
    __tablename__ = 'paymentqr_class'
    payment_qr_id = db.Column(db.Integer, db.ForeignKey('payment_qr.id'), primary_key=True)
    class_id = db.Column(db.Integer, db.ForeignKey('class.id'), primary_key=True)

def create_super_admin(app):
    with app.app_context():
        super_admin_exists = SuperAdmin.query.first() is not None
        if not super_admin_exists:
            username = "superadmin"  
            password = "superpassword"
            hashed_password = generate_password_hash(password)
            super_admin = SuperAdmin(username=username, password=hashed_password)
            db.session.add(super_admin)
            db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    if user_id.startswith('user-'):
        return User.query.get(int(user_id.split('user-')[1]))
    elif user_id.startswith('superadmin-'):
        superadmin_id = int(user_id.split('superadmin-')[1])
        return db.session.get(SuperAdmin, superadmin_id)
    return None

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        usn = request.form.get('usn').upper()
        existing_user = User.query.filter_by(usn=usn).first()
        if existing_user:
            flash('USN already exists. Please use a different USN.', 'danger')
            return redirect(url_for('register'))
        branch_code = usn[5:7]
        branch = Branch.query.filter_by(code=branch_code).first()
        if not branch:
            flash('Invalid USN or branch code.')
            return redirect(url_for('register'))
        name = request.form.get('name').upper()
        phone_number = request.form.get('phone_number')
        password = request.form.get('password')
        class_id = request.form.get('class_id', type=int)
        selected_size = request.form.get('size') 
        size = Size.query.filter_by(size_name=selected_size).first()
        hashed_password = generate_password_hash(password)
        new_user = User(usn=usn, password=hashed_password, name=name, phone_number=phone_number, branch_id=branch.id, class_id=class_id, size_id=size.id)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('user_dashboard'))
    branches = Branch.query.all()
    return render_template('register.html', branches=branches)

@app.route('/forgot_password', methods=['GET', 'POST'])
@login_required
def forgot_password():
    if not current_user.is_cr and current_user.is_organiser:
        return redirect(url_for('user_dashboard'))

    class_users = User.query.filter_by(class_id=current_user.class_id).order_by(User.usn).all()
    return render_template('forgot_password.html', users=class_users, class_=current_user.class_)

@app.route('/change_password/<usn>', methods=['GET', 'POST'])
@login_required
def change_password(usn):
    if request.method == 'POST':
        password = request.form.get('password')
        hashed_password = generate_password_hash(password)
        user = User.query.filter_by(usn=usn).first()
        
        if user.class_.sem!=current_user.class_.sem and user.class_.section!=current_user.class_.section:
            flash('Can\'t change password of other classes.', 'warning')
            return redirect(url_for('forgot_password'))
        if user:
            user.password = hashed_password
            db.session.commit()
            flash('Password updated successfully.', 'success')
            return redirect(url_for('forgot_password'))
        else:
            flash('User not found.', 'error')
            return redirect(url_for('forgot_password'))
    user = User.query.filter_by(usn=usn).first()
    if user.class_.sem!=current_user.class_.sem and user.class_.section!=current_user.class_.section:
        flash('Can\'t change password of other classes.', 'warning')
        return redirect(url_for('forgot_password'))
    return render_template('change_password.html', usn=usn)
       
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usn = request.form.get('usn')
        usn_user = usn.upper()
        password = request.form.get('password')
        user = User.query.filter_by(usn=usn_user).first()
        if user and check_password_hash(user.password, password):
            login_user(user, remember=True)
            return redirect(url_for('user_dashboard'))
        superadmin = SuperAdmin.query.filter_by(username=usn.lower()).first()
        if superadmin and check_password_hash(superadmin.password, password):
            login_user(superadmin, remember=True)
            return redirect(url_for('admin_dashboard'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/cr_payment_dashboard/<int:class_id>')
@login_required
def cr_payment_dashboard(class_id):
    if not current_user.is_cr:
        flash('Access restricted to class representatives.', 'error')
        return redirect(url_for('user_dashboard'))
    print(current_user.class_id)
    if (current_user.is_cr and class_id == current_user.class_id) or current_user.is_organiser:
        class_users = User.query.filter_by(class_id=class_id).order_by(User.usn).all()
        return render_template('cr_payment_dashboard.html', users=class_users, class_=current_user.class_)

    return redirect(url_for('user_dashboard'))
    
@app.route('/organiser_dashboard')
@login_required
def organiser_dashboard():
    if not current_user.is_organiser:
        flash('Access restricted to organisers.', 'error')
        return redirect(url_for('user_dashboard'))
    return render_template('organiser_dashboard.html')

def generate_image_url():
    app_root = os.path.dirname(os.path.abspath(__file__))
    image_path = './static/images/sentia-logo-qr.png'

    with Image.open(image_path) as image:
        img_buffer = BytesIO()
        image.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        img_data = base64.b64encode(img_buffer.getvalue()).decode('utf-8')
        data_url = f'data:image/png;base64,{img_data}'
        return data_url

@app.route('/dashboard')
@login_required
def user_dashboard():
    if current_user.get_id().startswith("superadmin"):
        return redirect(url_for('admin_dashboard'))

    if current_user and current_user.size:
        size_name = current_user.size.size_name
    else:
        size_name = 'Not selected'
    # if current_user.paid:
    #     data=generate_image_url()
    # else:
    #     data=None        

    return render_template('dashboard.html', user=current_user, size_name=size_name, img_data=None)

@app.route('/change_size', methods=['POST'])
@login_required
def change_size():
    data = request.get_json()
    new_size = data.get('size')
    
    if not new_size:
        return jsonify({'message': 'Size not provided.'}), 400
    
    size_obj = Size.query.filter_by(size_name=new_size).first()
    if size_obj:
        current_user.size_id = size_obj.id
        db.session.commit()
        return jsonify({'message': 'Size updated successfully.'}), 200
    else:
        return jsonify({'message': 'Size not found.'}), 404

@app.route('/get_sizes')
def get_sizes():
    sizes = Size.query.all()
    sizes_data = [size.size_name for size in sizes]
    return jsonify(sizes_data)

@app.route('/get_semesters/<branch_code>')
def get_semesters(branch_code):
    semesters = set([cls.sem for cls in Class.query.join(Branch).filter(Branch.code == branch_code)])
    return jsonify(sorted(list(semesters)))

@app.route('/get_classes/<branch_code>/<semester>')
def get_classes(branch_code, semester):
    classes = Class.query.join(Branch).filter(Branch.code == branch_code, Class.sem == semester).all()
    classes_data = {cls.id: cls.section for cls in classes}
    return jsonify(classes_data)

@app.route('/get_branches')
def get_branches():
    branches = Branch.query.all()
    branches_data = {branch.code: branch.name for branch in branches}
    return jsonify(branches_data)

@app.route('/')
@login_required
def index():
    if current_user:
        if current_user.is_super_admin:
            return render_template('admin_dashboard.html',user=current_user)
        return render_template('dashboard.html',user=current_user)
    return redirect(url_for('login'))


@app.route('/toggle_admin/<int:user_id>', methods=['POST'])
@login_required
def toggle_admin(user_id):
    if not current_user.is_super_admin:
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('index'))

    user = User.query.get_or_404(user_id)
    user.is_cr = not user.is_cr
    db.session.commit()
    flash(f'Admin status for {user.username} has been updated.', 'success')
    return redirect(url_for('index'))

@app.route('/admin/manage', methods=['GET'])
@login_required
def manage():
    if not current_user.is_super_admin:
        return 'Access denied', 403
    branches = Branch.query.all()
    return render_template('manage.html', branches=branches)

@app.route('/add_branch', methods=['POST'])
@login_required
def add_branch():
    if not current_user.is_super_admin:
        return 'Access denied', 403
    branch_name = request.form.get('branch_name')
    branch_code = request.form.get('branch_code')  
    if branch_name and branch_code:
        existing_branch = Branch.query.filter_by(code=branch_code).first()
        if existing_branch is None:
            new_branch = Branch(name=branch_name, code=branch_code.upper())
            db.session.add(new_branch)
            db.session.commit()
        else:
            flash('Branch code already exists.')
    else:
        flash('Branch name and code are required.')
    return redirect(url_for('manage'))

@app.route('/add_size', methods=['POST'])
def add_size():
    size_name = request.form.get('size_name')
    
    if Size.query.filter_by(size_name=size_name).first():
        flash('Size already exists.', 'error')
        return redirect(url_for('add_size_form'))

    new_size = Size(size_name=size_name)
    db.session.add(new_size)
    db.session.commit()
    
    flash('New size added successfully.', 'success')
    return redirect(url_for('add_size_form'))

@app.route('/admin/add_size_form')
def add_size_form():
    return render_template('add_size.html')


@app.route('/add_class', methods=['POST'])
@login_required
def add_class():
    alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if not current_user.is_super_admin:
        return 'Access denied', 403
    branch_id = request.form.get('branch_id', type=int)
    sem = request.form.get('sem', type=str)
    section = request.form.get('section', type=str)
    if branch_id and sem:
        
        new_section = "Section "+str(section)
        new_class = Class(sem=sem, section=new_section, branch_id=branch_id)
        db.session.add(new_class)
        db.session.commit()
        flash('New class added successfully.', 'success')
    else:
        flash('Error: Missing branch ID or semester.', 'error')
    return redirect(url_for('manage'))

@app.route('/delete_class', methods=['POST'])
@login_required
def delete_class():
    if not current_user.is_super_admin:
        return 'Access denied', 403
    class_id = request.form.get('class_id', type=int)
    if class_id:
        class_to_delete = Class.query.get(class_id)
        if class_to_delete:
            db.session.delete(class_to_delete)
            db.session.commit()
            flash('Class deleted successfully.', 'success')
        else:
            flash('Error: Class not found.', 'error')
    else:
        flash('Error: Missing class ID.', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_super_admin:
        return 'Access denied', 403
    branches = Branch.query.all()
    for branch in branches:
        semesters = {}
        for class_ in branch.classes:
            if class_.sem in semesters:
                semesters[class_.sem].append(class_)
            else:
                semesters[class_.sem] = [class_]
        branch.semesters = semesters
    return render_template('admin_dashboard.html', branches=branches)

def rot(text):
    result = []
    for char in text:
        if 'A' <= char <= 'Z':
            result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
        elif 'a' <= char <= 'z':
            result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
        else:
            result.append(char)
    return ''.join(result)

@app.route('/user_details/<usn>')
@login_required
def user_details(usn):
    usn = rot(usn)
    print(usn)
    user = User.query.filter_by(usn=usn.upper()).first()
    if user:
        return jsonify({
            'usn': user.usn,
            'paid': user.paid,
            'tshirt_status': user.shirt_status
        })
    else:
        return jsonify({'error': 'User not found'}), 404

@app.route('/admin/class_users/<int:class_id>')
@login_required
def class_users(class_id):
    if not current_user.is_super_admin:
        return 'Access denied', 403
    users = User.query.filter_by(class_id=class_id).all()

    class_ = Class.query.get(class_id)
    return render_template('class_users.html', users=users, class_=class_)

@app.route('/admin/export_details')
@login_required
def export_details():
    if not current_user.is_super_admin:
        return 'Access denied', 403
    users = User.query.order_by(User.branch_id).all()

    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['USN', 'Name', 'Phone Number','Branch', 'Semester', 'Section', 'Size', 'Paid'])

    for user in users:
        user = User.query.get(user.id)
        row = [
            user.usn if user else 'Unknown',
            user.name,
            user.phone_number,
            user.branch.name,
            user.class_.sem, 
            user.class_.section,
            user.size.size_name, 
            'Yes' if user.paid else 'No'
        ]
        cw.writerow(row)

    response = make_response(si.getvalue())
    response.headers['Content-Disposition'] = f'attachment; filename=details.csv'
    response.headers['Content-type'] = 'text/csv'
    return response

@app.route('/toggle_cr/<int:user_id>', methods=['POST'])
@login_required
def toggle_cr(user_id):
    if not current_user.is_super_admin:
        flash('Only superadmins can perform this action.', 'error')
        return redirect(url_for('index'))

    user = User.query.get_or_404(user_id)
    user.is_cr = not user.is_cr
    db.session.commit()

    flash(f"CR status toggled for user {user.usn}.", 'success')
    return redirect(url_for('class_users', class_id=user.class_id))

@app.route('/toggle_organiser/<int:user_id>', methods=['POST'])
@login_required
def toggle_organiser(user_id):
    if not current_user.is_super_admin:
        flash('Only superadmins can perform this action.', 'error')
        return redirect(url_for('index'))

    user = User.query.get_or_404(user_id)
    user.is_organiser = not user.is_organiser
    db.session.commit()

    flash(f"CR status toggled for user {user.usn}.", 'success')
    return redirect(url_for('class_users', class_id=user.class_id))

@app.route('/toggle_paid/<usn>', methods=['POST'])
@login_required
def toggle_paid(usn):
    if not current_user.get_id().startswith("superadmin"):
        if not current_user.is_cr or not current_user.is_organiser:
            flash('Only superadmins can perform this action.', 'error')
            print("lol")
            return redirect(url_for('user_dashboard'))

    user = User.query.filter_by(usn=usn.upper()).first()
    user.paid = not user.paid
    db.session.commit()

    flash(f"Paid status toggled for user {user.usn}.", 'success')
    print(current_user.class_id)
    return redirect(url_for('cr_payment_dashboard', class_id=current_user.class_id))

@app.route('/toggle_paid_qr/<int:user_id>', methods=['POST'])
@login_required
def toggle_paid_qr(user_id):
    if not current_user.is_cr or not current_user.is_organiser:
        flash('Only superadmins can perform this action.', 'error')
        return redirect(url_for('user_dashboard'))

    user = User.query.get_or_404(user_id)
    user.paid = not user.paid
    db.session.commit()

    flash(f"Paid status toggled for user {user.usn}.", 'success')
    return redirect(url_for('user_images'))

@app.route('/toggle_shirt_status/<usn>', methods=['POST'])
@login_required
def toggle_shirt_status(usn):
    user = User.query.filter_by(usn=usn.upper()).first()
    if user and user.paid:
        user.shirt_status = not user.shirt_status
        db.session.commit()
        return jsonify({'success': True, 'shirt_status': user.shirt_status})
    else:
        return jsonify({'error': 'User not found'}), 404

@app.route('/admin/secret')
@login_required
def secret():
    if current_user.is_super_admin:
        return render_template('secret.html')

@app.route('/admin/download/db')
@login_required
def download_db():
    FILES_DIRECTORY = './instance'

    return send_from_directory(FILES_DIRECTORY, 'db.sqlite', as_attachment=True)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_uploaded_file(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        save_path = os.path.join('./static', 'uploads/payment_qr', filename)
        file.save(save_path)
        return os.path.join('uploads/payment_qr', filename)
    return None

@app.route('/admin/upload_qr', methods=['GET', 'POST'])
def upload_qr():
    if request.method == 'POST':
        image_url = save_uploaded_file(request.files['qr_image'])
        classes_ids = request.form.getlist('classes[]')
        payment_qr = PaymentQR(image_url=image_url)
        for class_id in classes_ids:
            class_ = Class.query.get(class_id)
            if class_:
                payment_qr.classes.append(class_)
        db.session.add(payment_qr)
        db.session.commit()
        return redirect(url_for('admin_dashboard'))
    classes = Class.query.all()
    return render_template('upload_qr.html', classes=classes)

def save_proof_file(user, file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)

        save_path = os.path.join('static', 'uploads/payment_proofs', filename)
        file.save(save_path)

        user.payment_proof_url = os.path.join('uploads/payment_proofs', filename)
        db.session.commit()
        return True
    return False

@app.route('/make_payment', methods=['GET', 'POST'])
@login_required
def make_payment():
    qr_codes = PaymentQR.query.join(PaymentQR.classes).filter(Class.id == current_user.class_id).all()

    qr_code_url = 'static/' + qr_codes[0].image_url if qr_codes else None
    
    if request.method == 'POST':
        user = current_user
        proof_file = request.files['proof_file']
        if save_proof_file(user, proof_file):
            flash('Payment proof uploaded successfully.', 'success')
        else:
            flash('Invalid file format.', 'error')
        return redirect(url_for('user_dashboard'))
    return render_template('upload_proof.html', qr_code_url=qr_code_url)

@app.route('/payment_proofs')
@login_required
def payment_proofs():
    if not (current_user.get_id().startswith("superadmin")):
        if not(  current_user.is_cr or current_user.is_organiser ):
            return redirect(url_for('user_dashboard'))
    
    branches = Branch.query.all()
    for branch in branches:
        semesters = {}
        for class_ in branch.classes:
            if class_.sem in semesters:
                semesters[class_.sem].append(class_)
            else:
                semesters[class_.sem] = [class_]
        branch.semesters = semesters
    return render_template('payment_proofs.html', branches=branches)

@app.route('/admin/approve_payments/<class_id>')
@login_required
def approve_payments(class_id):
    users_with_images = User.query \
                            .filter(User.payment_proof_url.isnot(None)) \
                            .filter(User.paid == False) \
                            .filter(User.class_id == int(class_id)) \
                            .all()
    return render_template('user_images.html', users=users_with_images)


@app.route('/admin/edit_branches')
def edit_branches():
    branches = Branch.query.all()
    return render_template('edit_branches.html', branches=branches)

if __name__ == '__main__':
    create_super_admin(app)
    app.run(host="0.0.0.0", debug=True)
