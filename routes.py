from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from bson import ObjectId
from models.user import User
from pymongo import MongoClient
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from flask_mail import Message
from extensions import mail, mongo, oauth
from models.user import User
from dotenv import load_dotenv
from imap_tools import MailBox, AND
from datetime import datetime, timedelta

import os
import re
import random
import bcrypt
import smtplib

load_dotenv()
email_user = os.getenv('EMAIL_USER')
email_pass = os.getenv('EMAIL_PASS')

main = Blueprint('main', __name__)
client = MongoClient('mongodb+srv://user:OG2QqFuCYwkoWBek@capstone.fqvkpyn.mongodb.net/?retryWrites=true&w=majority')
db = client['busty_db']
dbcuaca = client['cuaca_db']
user_model = User(db)

auth = Blueprint('auth', __name__, url_prefix='/auth')

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(email, otp, expiry_minutes=1):
    msg = Message('Kode OTP Busty Kamu', recipients=[email])
    msg.body = f'''
    Kode OTP kamu adalah: {otp}
    
    OTP ini hanya berlaku selama {expiry_minutes} menit.
    Jangan bagikan kode ini ke siapa pun.
    '''
    mail.send(msg)

def check_latest_email():
    with MailBox('imap.gmail.com').login(email_user, email_pass, 'INBOX') as mailbox:
        emails = list(mailbox.fetch(AND(seen=False), limit=1, reverse=True))
        if len(emails) == 0:
            return None
        return emails[0]

def extract_link(email_text):
    url_pattern = re.compile(r'https?://[^\s]+')
    match = url_pattern.search(email_text)
    if match:
        return match.group()
    return None

def extract_otp(email_text):
    otp_pattern = re.compile(r'\b\d{6}\b')
    match = otp_pattern.search(email_text)
    if match:
        return match.group()
    return None

@main.route('/')
def index():
    return render_template('index.html', year=datetime.now().year)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = user_model.find_by_email(email)

        if not user:
            flash('Email tidak terdaftar.', 'danger')
            return redirect(url_for('auth.login'))
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id'])
            session['username'] = user['username']
            flash(f'Selamat datang, {user["username"]}!', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Password salah.', 'danger')
            return redirect(url_for('auth.login'))
        
    return render_template('auth/login.html')

# routes.py

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        # no_hp = request.form['no_hp']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Password dan konfirmasi tidak sama.', 'danger')
            return redirect(url_for('auth.register'))

        existing_user = user_model.find_by_email(email)
        if existing_user:
            flash('Email sudah terdaftar.', 'danger')
            return redirect(url_for('auth.register'))

        otp = generate_otp()
        expired_time = datetime.utcnow() + timedelta(minutes=1)

        user_model.create_user(
            username,
            email,
            
            generate_password_hash(password),
            otp,
            expired_time
        )

        session['email_temp'] = email

        send_otp_email(email, otp, 1)

        flash('Kode OTP telah dikirim ke email kamu.', 'info')
        return redirect(url_for('auth.verify_otp'))

    return render_template('auth/register.html')

@auth.route('/register-google')
def register_google():
    redirect_uri = url_for('auth.google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@auth.route('/google/callback')
def google_callback():
    token = oauth.google.authorize_access_token()
    resp = oauth.google.get('userinfo')
    user_info = resp.json()

    email = user_info.get('email')
    username = user_info.get('name')

    existing_user = user_model.find_by_email(email)
    if existing_user:
        flash('Email sudah terdaftar. Silakan login.', 'info')
        return redirect(url_for('auth.login'))

    user_model.create_user(
        username=username,
        email=email,
        password=None,
        otp=None,
        otp_expired=None,
        is_verified=True
    )

    flash('Registrasi berhasil menggunakan Google. Silakan login.', 'success')
    return redirect(url_for('auth.login'))

@auth.route('/login-google')
def login_google():
    redirect_uri = url_for('auth.google_login_callback', _external=True)
    print("Redirect URI:", redirect_uri)
    return oauth.google.authorize_redirect(redirect_uri)

@auth.route('/google/login/callback')
def google_login_callback():
    token = oauth.google.authorize_access_token()
    resp = oauth.google.get('userinfo')
    user_info = resp.json()

    email = user_info.get('email')
    username = user_info.get('given_name') 

    if not email:
        flash('Gagal mengambil email dari Google.', 'danger')
        return redirect(url_for('auth.login'))

    existing_user = user_model.find_by_email(email)

    if existing_user:
        session['user_id'] = str(existing_user['_id'])
        session['username'] = existing_user.get('username', username)
        flash(f'Selamat datang kembali, {session["username"]}!', 'success')
        return redirect(url_for('main.dashboard'))
    else:
        user_model.create_user(
            username=username,
            email=email,
            password=None,
            otp=None,
            otp_expired=None,
            is_verified=True
        )
        new_user = user_model.find_by_email(email)
        session['user_id'] = str(new_user['_id'])
        session['username'] = username
        flash('Registrasi dan login berhasil menggunakan Google.', 'success')
        return redirect(url_for('main.dashboard'))


@auth.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        input_otp = request.form['otp']
        email = session.get('email_temp')

        if not email:
            flash('Session expired. Silakan register ulang.', 'danger')
            return redirect(url_for('auth.register'))

        success, message = user_model.verify_otp(email, input_otp)
        if success:
            session.pop('email_temp', None)
            flash('Verifikasi berhasil. Silakan login.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash(message, 'danger')

    return render_template('auth/verify_otp.html')


@auth.route('/resend-otp', methods=['POST'])
def resend_otp():
    email = session.get('email_temp')
    if not email:
        flash('Session expired. Silakan register ulang.', 'danger')
        return redirect(url_for('auth.register'))

    otp = generate_otp()
    expired_time = datetime.utcnow() + timedelta(minutes=1)
    user_model.set_otp(email, otp, expired_time)

    send_otp_email(email, otp)

    flash('Kode OTP baru telah dikirim ke email kamu. Berlaku selama 1 menit.', 'info')
    return redirect(url_for('auth.verify_otp'))



@auth.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        pass
    return render_template('auth/forgot_password.html')

@main.route('/dashboard')
def dashboard():
    return render_template('cms_page/dashboard.html')

# Route Pengguna

@main.route('/pengguna')
def list_pengguna():
    search_query = request.args.get('search', '').strip().lower()
    users = user_model.get_all_users()

    if search_query:
        users = [user for user in users if search_query in user.get('username', '').lower()]

    return render_template('cms_page/pengguna/user.html', users=users)

@main.route('/hapus-pengguna', methods=['POST'])
def hapus_pengguna():
    user_id = request.form.get('user_id')

    if user_id:
        try:
            deleted = user_model.delete_user_by_id(user_id)
            if deleted:
                flash("Pengguna berhasil dihapus.", "success")
            else:
                flash("Pengguna tidak ditemukan.", "error")
        except Exception as e:
            flash(f"Gagal menghapus pengguna: {e}", "error")
    else:
        flash("ID pengguna tidak valid.", "error")

    return redirect(url_for('main.list_pengguna'))

@main.route('/edit-pengguna/<user_id>')
def edit_pengguna(user_id):
    user = user_model.find_by_id(ObjectId(user_id))
    if not user:
        flash("Pengguna tidak ditemukan.", "error")
        return redirect(url_for('main.list_pengguna'))
    return render_template('cms_page/pengguna/edit_pengguna.html', user=user)


@main.route('/update-pengguna', methods=['POST'])
def update_pengguna():
    user_id = request.form.get('user_id')
    username = request.form.get('username')
    email = request.form.get('email')

    if not user_id or not username or not email:
        flash("Data tidak lengkap.", "error")
        return redirect(url_for('main.list_pengguna'))

    try:
        user_model.update_user(user_id, {
            "username": username,
            "email": email
        })
        flash("Pengguna berhasil diperbarui.", "success")
    except Exception as e:
        flash(f"Gagal memperbarui pengguna: {e}", "error")

    return redirect(url_for('main.list_pengguna'))



# Route Detail Cuaca

@main.route('/detail-cuaca')
def detail_cuaca():
    mode = request.args.get('mode', 'card')
    search_daerah = request.args.get('search_daerah', '').lower()
    
    # Ambil semua data dari MongoDB
    cuaca_data = list(dbcuaca['prakiraan_cuaca'].find())

    # Parsing suhu + handle error kalau formatnya aneh
    for item in cuaca_data:
        suhu_str = item.get('suhu', '0')
        try:
            # Ambil angka pertama dari suhu
            item['suhu'] = int(suhu_str.split()[0])
        except:
            item['suhu'] = 0  # Default ke 0 kalau gagal parsing
            
        item['cuaca'] = item.get('cuaca', 'Tidak diketahui')    

    # Filter data berdasarkan input search
    if search_daerah:
        cuaca_data = [
            item for item in cuaca_data
            if search_daerah in (item.get('provinsi') or '').lower()
            or search_daerah in (item.get('kab_kota') or '').lower()
            or search_daerah in (item.get('kecamatan') or '').lower()
            or search_daerah in (item.get('kelurahan') or '').lower()
        ]

    return render_template(
        'cms_page/detail_cuaca.html',
        cuaca_data=cuaca_data,
        mode=mode,
        search_daerah=search_daerah
    )
    
@main.route('/jadwal')
def jadwal():
    return render_template('cms_page/jadwal/jadwal.html')

# Rute
    
@main.route('/rute')
def list_rute():
    search_nama = request.args.get('search_nama', '').lower()
    rute_data = list(db['rute_operasional'].find())

    # filter berdasarkan pencarian nama bus atau nopol
    if search_nama:
        rute_data = [
            item for item in rute_data
            if search_nama in item.get('tanggal', '').lower() or
               search_nama in item.get('terminal_tujuan', '').lower()
        ]

    return render_template('cms_page/rute/rute.html', rute_data=rute_data)


@main.route('/tambah-rute', methods=['GET', 'POST'])
def tambah_rute():
    if request.method == 'POST':
        terminal_awal = request.form.get('terminal_awal')
        terminal_tujuan = request.form.get('terminal_tujuan')
        tanggal = request.form.get('tanggal')
        jumlah_penumpang = request.form.get('jumlah_penumpang')

        if not all([terminal_awal, terminal_tujuan, tanggal, jumlah_penumpang]):
            flash("Harap isi semua data yang diperlukan.", "error")
            return redirect(url_for('main.tambah_rute'))

        # Simpan ke MongoDB
        db['rute_operasional'].insert_one({
            'terminal_awal': terminal_awal,
            'terminal_tujuan': terminal_tujuan,
            'tanggal': tanggal,
	        'jumlah_penumpang': jumlah_penumpang,
            'created_at': datetime.utcnow()
        })

        flash("Data armada berhasil ditambahkan.", "success")
        return redirect(url_for('main.list_rute'))

    return render_template('cms_page/rute/tambah_rute.html')
# Route Armada

@main.route('/armada')
def list_armada():
    search_nama = request.args.get('search_nama', '').lower()
    armada_data = list(db['armada'].find())
    if search_nama:
        armada_data = [
            item for item in armada_data
            if search_nama in item.get('nama_bus', '').lower() or
               search_nama in item.get('nopol', '').lower()
        ]

    return render_template('cms_page/armada/armada.html', armada_data=armada_data)


@main.route('/tambah-armada', methods=['GET', 'POST'])
def tambah_armada():
    if request.method == 'POST':
        nopol = request.form.get('nopol')
        nama_bus = request.form.get('nama_bus')
        status = request.form.get('status')
        detail_status = request.form.get('detail_status')

        if not all([nopol, nama_bus, status]):
            flash("Harap isi semua data yang diperlukan.", "error")
            return redirect(url_for('main.tambah_armada'))

        db['armada'].insert_one({
            'nopol': nopol,
            'nama_bus': nama_bus,
            'status': status,
            'detail_status': detail_status,
            'created_at': datetime.utcnow()
        })

        flash("Data armada berhasil ditambahkan.", "success")
        return redirect(url_for('main.list_armada'))

    return render_template('cms_page/armada/tambah_armada.html')

@main.route('/hapus-armada', methods=['POST'])
def hapus_armada():
    armada_id = request.form.get('armada_id')
    if armada_id:
        try:
            result = db['armada'].delete_one({'_id': ObjectId(armada_id)})
            if result.deleted_count > 0:
                flash("Armada berhasil dihapus.", "success")
            else:
                flash("Armada tidak ditemukan.", "error")
        except Exception as e:
            flash(f"Gagal menghapus armada: {e}", "error")
    else:
        flash("ID armada tidak valid.", "error")
    return redirect(url_for('main.list_armada'))


@main.route('/cms/edit-armada/<armada_id>', methods=['GET'])
def edit_armada(armada_id):
    try:
        armada_data = db['armada'].find_one({'_id': ObjectId(armada_id)})
    except Exception as e:
        flash(f"ID armada tidak valid: {e}", "error")
        return redirect(url_for('main.list_armada'))

    if not armada_data:
        flash("Armada tidak ditemukan.", "error")
        return redirect(url_for('main.list_armada'))

    return render_template('cms_page/armada/edit_armada.html', armada_data=armada_data)


@main.route('/update-armada', methods=['POST'])
def update_armada():
    armada_id = request.form.get('armada_id')
    nopol = request.form.get('nopol')
    nama_bus = request.form.get('nama_bus')
    status = request.form.get('status')
    detail_status = request.form.get('detail_status')

    if not armada_id or not nopol or not nama_bus or not status:
        flash("Data tidak lengkap.", "error")
        return redirect(url_for('main.list_armada'))

    try:
        result = db['armada'].update_one(
            {'_id': ObjectId(armada_id)},
            {'$set': {
                'nopol': nopol,
                'nama_bus': nama_bus,
                'status': status,
                'detail_status': detail_status,
                'updated_at': datetime.utcnow()
            }}
        )
        if result.modified_count > 0:
            flash("Data armada berhasil diperbarui.", "success")
        else:
            flash("Tidak ada perubahan pada data armada.", "info")
    except Exception as e:
        flash(f"Gagal update armada: {e}", "error")

    return redirect(url_for('main.list_armada'))



@main.route('/artikel')
def list_artikel():
    search_judul = request.args.get('search_judul', '').lower()
    artikel_data = list(db['artikel'].find())
    if search_judul:
        artikel_data = [
            item for item in artikel_data
            if search_judul in item.get('judul', '').lower() or
               search_judul in item.get('created_at', '').lower()
        ]
    return render_template('cms_page/artikel/artikel.html', artikel_data=artikel_data)

@main.route('/tambah-artikel', methods=['GET', 'POST'])
def tambah_artikel():
    if request.method == 'POST':
        image_file = request.files.get('image')
        judul = request.form.get('judul')
        sub_judul = request.form.get('sub_judul')
        konten = request.form.get('konten')

        if not all([image_file, judul, sub_judul, konten]):
            flash("Harap isi semua data yang diperlukan.", "error")
            return redirect(url_for('main.tambah_artikel'))

        filename = secure_filename(image_file.filename)
        filepath = os.path.join('static/image', filename)
        image_file.save(filepath)

        db['artikel'].insert_one({
            'image': filename,
            'judul': judul,
            'sub_judul': sub_judul,
            'konten': konten,
            'created_at': datetime.utcnow()
        })

        flash("Data artikel berhasil ditambahkan.", "success")
        return redirect(url_for('main.list_artikel'))

    return render_template('cms_page/artikel/tambah_artikel.html')

@auth.route('/logout')
def logout():
    return redirect(url_for('auth.login'))