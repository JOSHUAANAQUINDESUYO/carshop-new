from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from pathlib import Path
import functools
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse, urljoin
import os
import uuid
from werkzeug.utils import secure_filename
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "cars.db"
UPLOAD_FOLDER = BASE_DIR / "static" / "uploads"
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)
app.secret_key = "replace-with-a-random-secret"  # for flash messages
app.config['UPLOAD_FOLDER'] = str(UPLOAD_FOLDER)

# ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    # create DB/tables if missing and insert sample/default rows only when tables empty
    conn = get_db_connection()
    conn.execute("""CREATE TABLE IF NOT EXISTS cars (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        brand TEXT NOT NULL,
        model TEXT NOT NULL,
        year INTEGER NOT NULL,
        price REAL NOT NULL,
        status TEXT NOT NULL
    );""")
    # users table now has a role column: 'superadmin', 'admin', 'customer'
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'customer'
    );""")

    # ensure image_filename column exists (add if missing)
    cols = conn.execute("PRAGMA table_info(cars);").fetchall()
    col_names = [c['name'] for c in cols]
    if 'image_filename' not in col_names:
        conn.execute("ALTER TABLE cars ADD COLUMN image_filename TEXT;")

    # MIGRATE users table: add role if missing and set sensible defaults
    user_cols = conn.execute("PRAGMA table_info(users);").fetchall()
    user_col_names = [c['name'] for c in user_cols]
    if 'role' not in user_col_names:
        # add role column (may be NULL for existing rows)
        conn.execute("ALTER TABLE users ADD COLUMN role TEXT;")
        # set empty/null roles to 'customer'
        conn.execute("UPDATE users SET role = 'customer' WHERE role IS NULL OR role = '';")
        # promote existing 'admin' username to role 'admin' if present
        conn.execute("UPDATE users SET role = 'admin' WHERE username = 'admin';")

    # ensure there is at least one superadmin
    super_count = conn.execute("SELECT COUNT(*) AS cnt FROM users WHERE role = 'superadmin'").fetchone()
    if super_count['cnt'] == 0:
        # try to insert a default superadmin only if username not already taken
        exists = conn.execute("SELECT 1 FROM users WHERE username = ?", ("superadmin",)).fetchone()
        if not exists:
            default_pw_hash = generate_password_hash("superadminpass")  # change this default in production
            conn.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                         ("superadmin", default_pw_hash, "superadmin"))
        else:
            # if username 'superadmin' exists but wasn't role 'superadmin', promote it
            conn.execute("UPDATE users SET role = 'superadmin' WHERE username = 'superadmin'")

    # insert sample cars if none exist (keep existing behavior)
    cur = conn.execute("SELECT COUNT(*) AS cnt FROM cars").fetchone()
    if cur['cnt'] == 0:
        conn.execute("INSERT INTO cars (brand, model, year, price, status) VALUES (?, ?, ?, ?, ?)",
                     ("Toyota", "Corolla", 2018, 450000.00, "Available"))
        conn.execute("INSERT INTO cars (brand, model, year, price, status) VALUES (?, ?, ?, ?, ?)",
                     ("Honda", "Civic", 2019, 550000.00, "Sold"))

    # ensure orders and order_items tables exist
    conn.execute("""CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        total REAL NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );""")
    conn.execute("""CREATE TABLE IF NOT EXISTS order_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        car_id INTEGER NOT NULL,
        price REAL NOT NULL,
        FOREIGN KEY(order_id) REFERENCES orders(id),
        FOREIGN KEY(car_id) REFERENCES cars(id)
    );""")

    conn.commit()
    conn.close()

def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return decorated_function

# add helper to validate "next" redirects
def is_safe_url(target):
    if not target:
        return False
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return (test_url.scheme in ('http', 'https')) and (ref_url.netloc == test_url.netloc)

# require login for most endpoints (user will be asked to log in first)
@app.before_request
def require_login():
    # allow static files and the login/logout/register endpoints
    allowed_endpoints = {'login', 'logout', 'static', 'register'}
    # request.endpoint may be None for some cases (ignore)
    if request.endpoint is None:
        return
    if request.endpoint not in allowed_endpoints and 'user_id' not in session:
        return redirect(url_for('login', next=request.path))

# add roles_required decorator
def roles_required(*roles):
    def decorator(f):
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login', next=request.path))
            if session.get('role') not in roles:
                flash('Forbidden: insufficient permissions.', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return wrapped
    return decorator

# backward-compatible alias (fixes NameError when @role_required is used)
role_required = roles_required

@app.route('/')
def index():
    conn = get_db_connection()
    cars = conn.execute("SELECT * FROM cars ORDER BY id DESC").fetchall()
    conn.close()
    return render_template('index.html', cars=cars, username=session.get('username'))

@app.route('/add', methods=('GET','POST'))
@roles_required('admin', 'superadmin')
def add_car():
    if request.method == 'POST':
        brand = request.form['brand'].strip()
        model = request.form['model'].strip()
        year = request.form['year'].strip()
        price = request.form['price'].strip()
        status = request.form['status'].strip()
        image = request.files.get('image')

        if not (brand and model and year and price and status):
            flash('All fields are required.', 'danger')
        else:
            try:
                year_i = int(year)
                price_f = float(price)
            except ValueError:
                flash('Year must be an integer and Price must be a number.', 'danger')
                return render_template('add_car.html', form=request.form)

            image_filename = None
            if image and image.filename:
                if allowed_file(image.filename):
                    filename = secure_filename(image.filename)
                    unique = f"{uuid.uuid4().hex}_{filename}"
                    save_path = os.path.join(app.config['UPLOAD_FOLDER'], unique)
                    image.save(save_path)
                    image_filename = unique
                else:
                    flash('Invalid image format.', 'danger')
                    return render_template('add_car.html', form=request.form)

            conn = get_db_connection()
            conn.execute(
                "INSERT INTO cars (brand, model, year, price, status, image_filename) VALUES (?, ?, ?, ?, ?, ?)",
                (brand, model, year_i, price_f, status, image_filename)
            )
            conn.commit()
            conn.close()
            flash('Car added successfully.', 'success')
            return redirect(url_for('index'))

    return render_template('add_car.html')

@app.route('/edit/<int:car_id>', methods=('GET','POST'))
@roles_required('admin', 'superadmin')
def edit_car(car_id):
    conn = get_db_connection()
    car = conn.execute("SELECT * FROM cars WHERE id = ?", (car_id,)).fetchone()
    if car is None:
        conn.close()
        flash('Car not found.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        brand = request.form['brand'].strip()
        model = request.form['model'].strip()
        year = request.form['year'].strip()
        price = request.form['price'].strip()
        status = request.form['status'].strip()
        image = request.files.get('image')

        if not (brand and model and year and price and status):
            flash('All fields are required.', 'danger')
        else:
            try:
                year_i = int(year)
                price_f = float(price)
            except ValueError:
                flash('Year must be an integer and Price must be a number.', 'danger')
                return render_template('edit_car.html', car=car)

            new_image_filename = car['image_filename']
            if image and image.filename:
                if allowed_file(image.filename):
                    # remove old image if exists
                    if car['image_filename']:
                        old_path = os.path.join(app.config['UPLOAD_FOLDER'], car['image_filename'])
                        try:
                            if os.path.exists(old_path):
                                os.remove(old_path)
                        except Exception:
                            pass
                    filename = secure_filename(image.filename)
                    unique = f"{uuid.uuid4().hex}_{filename}"
                    save_path = os.path.join(app.config['UPLOAD_FOLDER'], unique)
                    image.save(save_path)
                    new_image_filename = unique
                else:
                    flash('Invalid image format.', 'danger')
                    return render_template('edit_car.html', car=car)

            conn.execute(
                "UPDATE cars SET brand=?, model=?, year=?, price=?, status=?, image_filename=? WHERE id=?",
                (brand, model, year_i, price_f, status, new_image_filename, car_id)
            )
            conn.commit()
            conn.close()
            flash('Car updated successfully.', 'success')
            return redirect(url_for('index'))

    conn.close()
    return render_template('edit_car.html', car=car)

@app.route('/delete/<int:car_id>', methods=('POST',))
@roles_required('admin', 'superadmin')
def delete_car(car_id):
    conn = get_db_connection()
    car = conn.execute("SELECT * FROM cars WHERE id = ?", (car_id,)).fetchone()
    if car and car['image_filename']:
        img_path = os.path.join(app.config['UPLOAD_FOLDER'], car['image_filename'])
        try:
            if os.path.exists(img_path):
                os.remove(img_path)
        except Exception:
            pass
    conn.execute("DELETE FROM cars WHERE id = ?", (car_id,))
    conn.commit()
    conn.close()
    flash('Car deleted.', 'info')
    return redirect(url_for('index'))

# new routes for login/logout
@app.route('/login', methods=('GET','POST'))
def login():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','').strip()
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']  # store role
            flash('Logged in successfully.', 'success')
            next_raw = request.args.get('next')
            next_page = next_raw if is_safe_url(next_raw) else url_for('index')
            return redirect(next_page)
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')

# public registration for customers
@app.route('/register', methods=('GET','POST'))
def register():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','').strip()
        if not (username and password):
            flash('Username and password required.', 'danger')
            return render_template('register.html', form=request.form)
        conn = get_db_connection()
        exists = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if exists:
            conn.close()
            flash('Username already taken.', 'danger')
            return render_template('register.html', form=request.form)
        pw_hash = generate_password_hash(password)
        conn.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                     (username, pw_hash, "customer"))
        conn.commit()
        conn.close()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

# superadmin can create admin accounts
@app.route('/create_admin', methods=('GET','POST'))
@role_required('superadmin')
def create_admin():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','').strip()
        if not (username and password):
            flash('Username and password required.', 'danger')
            return render_template('create_admin.html', form=request.form)
        conn = get_db_connection()
        exists = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if exists:
            conn.close()
            flash('Username already exists.', 'danger')
            return render_template('create_admin.html', form=request.form)
        pw_hash = generate_password_hash(password)
        conn.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                     (username, pw_hash, "admin"))
        conn.commit()
        conn.close()
        flash('Admin account created.', 'success')
        return redirect(url_for('index'))
    return render_template('create_admin.html')

# superadmin can view all registered accounts
@app.route('/users')
@role_required('superadmin')
def view_users():
    conn = get_db_connection()
    users = conn.execute("SELECT id, username, role FROM users ORDER BY id").fetchall()
    conn.close()
    return render_template('users.html', users=users)

# add logout route so url_for('logout') builds correctly
@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

# session cart helpers
def get_cart():
	if 'cart' not in session:
		session['cart'] = []
	return session['cart']

def add_to_cart_session(car_id):
	cart = get_cart()
	if car_id not in cart:
		cart.append(car_id)
		session['cart'] = cart

def remove_from_cart_session(car_id):
	cart = get_cart()
	if car_id in cart:
		cart.remove(car_id)
		session['cart'] = cart

# add_to_cart route (customers only)
@app.route('/add_to_cart/<int:car_id>', methods=('POST',))
@roles_required('customer')
def add_to_cart(car_id):
	conn = get_db_connection()
	car = conn.execute("SELECT * FROM cars WHERE id = ?", (car_id,)).fetchone()
	conn.close()
	if car is None:
		flash('Car not found.', 'danger')
		return redirect(url_for('index'))
	if car['status'].lower() != 'available':
		flash('Car is not available.', 'warning')
		return redirect(url_for('index'))
	add_to_cart_session(car_id)
	flash('Added to cart.', 'success')
	return redirect(url_for('index'))

# remove from cart
@app.route('/remove_from_cart/<int:car_id>', methods=('POST',))
@roles_required('customer')
def remove_from_cart(car_id):
	remove_from_cart_session(car_id)
	flash('Removed from cart.', 'info')
	return redirect(url_for('view_cart'))

# view cart
@app.route('/cart')
@roles_required('customer')
def view_cart():
	cart = get_cart()
	if not cart:
		items = []
	else:
		placeholders = ','.join('?' for _ in cart)
		conn = get_db_connection()
		items = conn.execute(f"SELECT * FROM cars WHERE id IN ({placeholders})", tuple(cart)).fetchall()
		conn.close()
	return render_template('cart.html', items=items)

# checkout - create order, mark cars as Sold
@app.route('/checkout', methods=('POST',))
@roles_required('customer')
def checkout():
	cart = get_cart()
	if not cart:
		flash('Cart is empty.', 'danger')
		return redirect(url_for('view_cart'))

	conn = get_db_connection()
	# fetch current car entries and ensure availability
	placeholders = ','.join('?' for _ in cart)
	cars = conn.execute(f"SELECT * FROM cars WHERE id IN ({placeholders})", tuple(cart)).fetchall()
	# ensure all requested cars still available
	for c in cars:
		if c['status'].lower() != 'available':
			conn.close()
			flash(f"Car {c['brand']} {c['model']} is not available.", 'danger')
			return redirect(url_for('view_cart'))
	# compute total
	total = sum(c['price'] for c in cars)
	created_at = datetime.utcnow().isoformat()
	# insert order
	cur = conn.execute("INSERT INTO orders (user_id, total, created_at) VALUES (?, ?, ?)",
					   (session['user_id'], total, created_at))
	order_id = cur.lastrowid
	# insert order items and mark cars sold
	for c in cars:
		conn.execute("INSERT INTO order_items (order_id, car_id, price) VALUES (?, ?, ?)",
					 (order_id, c['id'], c['price']))
		conn.execute("UPDATE cars SET status = 'Sold' WHERE id = ?", (c['id'],))
	conn.commit()
	conn.close()
	# clear cart
	session.pop('cart', None)
	flash('Purchase successful. Order created.', 'success')
	return render_template('order_success.html', order_id=order_id, items=cars, total=total)

# view my orders
@app.route('/my_orders')
@login_required
def my_orders():
	conn = get_db_connection()
	orders = conn.execute("SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC", (session['user_id'],)).fetchall()
	# fetch items for each order
	order_list = []
	for o in orders:
		items = conn.execute("SELECT oi.*, c.brand, c.model FROM order_items oi JOIN cars c ON oi.car_id = c.id WHERE oi.order_id = ?", (o['id'],)).fetchall()
		order_list.append({'order': o, 'items': items})
	conn.close()
	return render_template('my_orders.html', orders=order_list)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)