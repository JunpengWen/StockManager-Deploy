import io
from collections import defaultdict

from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash
import sqlite3
import os
from flask import send_file
from werkzeug.routing import ValidationError
from werkzeug.utils import secure_filename
from apscheduler.schedulers.background import BackgroundScheduler
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.colors import HexColor

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for flashing messages

VALID_STORES = [
    "Kusan Uyghur Cuisine, 1516 N 4th Street, San Jose, CA 95112",
    "Kusan Bazaar, 510 Barber Ln, Milpitas, CA 95035"
]

# Define DATABASE path properly
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, 'instance', 'stock_manager.db')

# Define the upload folder
UPLOAD_FOLDER = 'static/uploads'  # Path to the folder where uploaded files will be saved
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Allowed file extensions

# Configure the Flask app
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit file size to 16MB

# Add after app configuration
scheduler = BackgroundScheduler(daemon=True)

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


# Helper function to validate file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    # Create instance folder if it doesn't exist
    db_dir = os.path.dirname(DATABASE)
    os.makedirs(db_dir, exist_ok=True)

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()

        # Add 'is_authorized' column only if it doesn't exist
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN is_authorized INTEGER DEFAULT 0")
            print("Added 'is_authorized' column.")
        except sqlite3.OperationalError:
            print("'is_authorized' column already exists.")


        # Create tables with proper store_address fields
        cursor.execute('''CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,  
            category TEXT,
            max_stock_level INTEGER,
            in_stock_level INTEGER,
            reorder_level INTEGER,
            picture TEXT,
            supplier_id INTEGER,
            store_address TEXT NOT NULL,
            unit TEXT DEFAULT NULL,
            FOREIGN KEY (supplier_id) REFERENCES suppliers(id),
            UNIQUE(name, store_address)  -- Add composite constraint
        )''')

        # Keep original categories table structure
        cursor.execute('''CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE
        )''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            employee_name TEXT,
            store_address TEXT NOT NULL,  -- Store assignment
            role TEXT NOT NULL CHECK(role IN ('owner', 'employee', 'manager', 'server', 'line_cook', 'prep_cook')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            phone_number TEXT DEFAULT NULL,
            email TEXT DEFAULT NULL
        )''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS stock_updates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            item_id INTEGER NOT NULL,
            stock_before INTEGER NOT NULL,
            stock_after INTEGER NOT NULL,
            updated_at TIMESTAMP DEFAULT (datetime('now', 'localtime')),
            store_address TEXT NOT NULL,  -- Track store context
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (item_id) REFERENCES items(id)
        )''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS suppliers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            contact_info TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_categories (
                user_id INTEGER NOT NULL,
                category TEXT NOT NULL,
                PRIMARY KEY (user_id, category),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''CREATE INDEX IF NOT EXISTS idx_stock_updates_updated_at 
                       ON stock_updates(updated_at)''')

        cursor.execute(
            ''' CREATE TABLE IF NOT EXISTS units ( id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL ) ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS stores (
                id   INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL        -- full address string
        )
        ''')

        cursor.executemany(
            'INSERT OR IGNORE INTO stores (name) VALUES (?)',
            [('Kusan Uyghur Cuisine, 1516 N 4th Street, San Jose, CA 95112',),
             ('Kusan Bazaar, 510 Barber Ln, Milpitas, CA 95035',)]
        )

        # Default data setup
        cursor.execute('INSERT OR IGNORE INTO categories (name) VALUES (?)', ("Default",))

        # Create default owner with valid store address
        cursor.execute('SELECT COUNT(*) FROM users')
        if cursor.fetchone()[0] == 0:
            cursor.execute('''
                INSERT INTO users (
                    username, password, employee_name, 
                    store_address, phone_number, email, 
                    role, is_authorized
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                "owner",
                "ownerpass",
                "Owner Name",
                "Kusan Uyghur Cuisine, 1516 N 4th Street, San Jose, CA 95112",
                "1234567890",
                "owner@example.com",
                "owner",
                1
            ))

        # Ensure all owners are authorized
        cursor.execute('UPDATE users SET is_authorized = 1 WHERE role = "owner"')
        conn.commit()


# Auto-initialize database when the app starts
with app.app_context():
    init_db()  # Checks and creates tables if missing


# Route for the login page
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, role, store_address, is_authorized 
                    FROM users 
                    WHERE username = ? AND password = ?
                ''', (username, password))
                user = cursor.fetchone()

                if not user:
                    return render_template('userlogin.html',
                                           error_message='Invalid username or password')

                if user['is_authorized'] == 0:
                    return render_template('userlogin.html',
                                           error_message='Account pending authorization')

                # Store critical user info in session
                session.update({
                    'user_id': user['id'],
                    'role': user['role'],
                    'store_address': user['store_address'],
                    'authorized': True,
                    '_csrf_validated': True,  # Explicit CSRF validation marker
                    'username': username
                })

                # Debug log
                print(f"User {username} ({user['role']}) logged in to {user['store_address']}")

                # Redirect based on role with proper access control
                if user['role'] == 'owner':
                    return redirect(url_for('owner_dashboard'))
                elif user['role'] == 'manager':
                    return redirect(url_for('manager_dashboard'))
                elif user['role'] in ['employee', 'server', 'line_cook', 'prep_cook']:
                    return redirect(url_for('employee_dashboard'))
                else:
                    return render_template('userlogin.html', error_message='Invalid role assigned to the user.')

        except Exception as e:
            return render_template('userlogin.html',
                                   error_message=f'Login error: {str(e)}')

    return render_template('userlogin.html')


# Route for registration
@app.route('/register', methods=['GET', 'POST'])
def register():


    if request.method == 'POST':
        data = request.get_json()
        if not data:
            return jsonify({'message': 'Invalid JSON format'}), 400

        required_fields = ['username', 'password', 'employee_name',
                           'phone_number', 'email', 'store_address']
        missing = [field for field in required_fields if (field not in data or not data.get(field))]
        if missing:
            return jsonify({'message': f'Missing fields: {", ".join(missing)}'}), 400

        # Validate store address
        if data['store_address'] not in get_stores():
            return jsonify({'message': 'Invalid store selection'}), 400

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO users (
                        username, password, employee_name,
                        phone_number, email, store_address, 
                        role, is_authorized
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    data['username'],
                    data['password'],  # Use plain password directly
                    data['employee_name'],
                    data['phone_number'],
                    data['email'],
                    data['store_address'],
                    'employee',  # Default role
                    0  # Requires authorization
                ))
                conn.commit()
                return jsonify({
                    'message': 'Registration successful! Awaiting owner approval',
                    'store': data['store_address']
                }), 200

        except sqlite3.IntegrityError as e:
            error_msg = 'Database error occurred'
            if 'UNIQUE constraint failed: users.username' in str(e):
                error_msg = 'Username already exists'
            return jsonify({'message': f'Error: {error_msg}'}), 400

        except Exception as e:
            return jsonify({'message': f'Server error: {str(e)}'}), 500

    return render_template('register.html')


@app.route('/pending_accounts', methods=['GET'])
def pending_accounts():
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # 构建基础查询
        base_query = '''
            SELECT id, username, role, employee_name, 
                   store_address, phone_number, email 
            FROM users 
            WHERE is_authorized = 0
        '''
        params = []

        # 非 owner 用户只能查看自己门店的待授权账户
        if session.get('role') != 'owner':
            base_query += ' AND store_address = ?'
            params.append(session.get('store_address'))

        # 显式处理空值情况
        cursor.execute(base_query, params)
        raw_accounts = cursor.fetchall()
        accounts = [dict(account) for account in raw_accounts] if raw_accounts else []

        # 添加 debug 日志输出 (上线后可移除)
        print(f"[DEBUG] Pending accounts query returns {len(accounts)} records")

    return jsonify(accounts)


# 添加新的路由：获取单个账户详细信息（包含密码）
@app.route('/account/<int:account_id>', methods=['GET'])
def get_account_detail(account_id):
    # 验证登录状态
    if 'authorized' not in session:
        return jsonify({'message': 'Unauthorized'}), 401

    # 获取请求者权限
    current_role = session.get('role')
    current_store = session.get('store_address')

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # 查询目标账户
        cursor.execute('''
            SELECT * FROM users
            WHERE id = ?
        ''', (account_id,))
        account = cursor.fetchone()

        if not account:
            return jsonify({'message': 'Account not found'}), 404

        # 权限验证：owner可以查看所有，其他人只能查看自己门店的账户
        if current_role != 'owner' and account['store_address'] != current_store:
            return jsonify({'message': 'Unauthorized access'}), 403


        # 获取该账户允许访问的类别
        cursor.execute('''
            SELECT category FROM user_categories
            WHERE user_id = ?
        ''', (account_id,))
        allowed_categories = [row['category'] for row in cursor.fetchall()]

        # 获取系统所有类别
        cursor.execute('SELECT name FROM categories')
        all_categories = [row['name'] for row in cursor.fetchall()]

        # 返回完整账户信息（包含明文密码）
        return jsonify({
            'id': account['id'],
            'username': account['username'],
            'role': account['role'],
            'employee_name': account['employee_name'],
            'store_address': account['store_address'],
            'phone_number': account['phone_number'],
            'email': account['email'],
            'allowed_categories': allowed_categories,
            'all_categories': all_categories,
            'password': account['password']  # 返回明文密码
        }), 200


@app.route('/update_user_categories/<int:user_id>', methods=['POST'])
def update_user_categories(user_id):
    if 'authorized' not in session or session.get('role') != 'owner':
        return jsonify({'message': 'Unauthorized'}), 401

    data = request.json
    categories = data.get('categories', [])

    # 验证类别是否存在
    with get_db_connection() as conn:
        cursor = conn.cursor()
        existing_categories = set(row['name'] for row in cursor.execute('SELECT name FROM categories').fetchall())
        invalid_categories = set(categories) - existing_categories

        if invalid_categories:
            return jsonify({
                'message': f'Invalid categories: {", ".join(invalid_categories)}',
                'valid_categories': list(existing_categories)
            }), 400

        try:
            cursor.execute('DELETE FROM user_categories WHERE user_id = ?', (user_id,))
            for category in categories:
                cursor.execute('''
                    INSERT INTO user_categories (user_id, category)
                    VALUES (?, ?)
                ''', (user_id, category))
            conn.commit()
            return jsonify({
                'message': 'User categories updated successfully',
                'updated_categories': categories
            }), 200
        except sqlite3.Error as e:
            conn.rollback()
            return jsonify({
                'message': f'Database error: {str(e)}'
            }), 500

def allowed_categories_for(user_id):
    with get_db_connection() as c:
        cur = c.cursor()
        cur.execute('SELECT category FROM user_categories WHERE user_id=?', (user_id,))
        return [r['category'] for r in cur.fetchall()]


@app.route('/authorize_account/<int:account_id>', methods=['POST'])
def authorize_account(account_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Verify store access
        cursor.execute('SELECT store_address FROM users WHERE id = ?', (account_id,))
        account = cursor.fetchone()

        if not account:
            return jsonify({'message': 'Account not found'}), 404

        if session.get('role') != 'owner' and account['store_address'] != session.get('store_address'):
            return jsonify({'message': 'Unauthorized to modify this account'}), 403

        cursor.execute('UPDATE users SET is_authorized = 1 WHERE id = ?', (account_id,))
        conn.commit()

        return jsonify({'message': 'Account authorized successfully'}), 200


@app.route('/reject_account/<int:account_id>', methods=['POST'])
def reject_account(account_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Verify store access
        cursor.execute('SELECT store_address FROM users WHERE id = ?', (account_id,))
        account = cursor.fetchone()

        if not account:
            return jsonify({'message': 'Account not found'}), 404

        if session.get('role') != 'owner' and account['store_address'] != session.get('store_address'):
            return jsonify({'message': 'Unauthorized to modify this account'}), 403

        cursor.execute('DELETE FROM users WHERE id = ?', (account_id,))
        conn.commit()

        return jsonify({'message': 'Account rejected successfully'}), 200


# Route for the owner dashboard
@app.route('/owner_dashboard', methods=['GET', 'POST'])
def owner_dashboard():
    if session.get('role') != 'owner':
        return redirect(url_for('login'))

    # 集中处理POST请求（表单+JSON）
    if request.method == 'POST':
        return handle_owner_post_request()

    # 处理GET请求
    return handle_owner_get_request()


def handle_owner_post_request():
    try:
        # -----------------------------------------------------------------
        # 1.  grab raw data   (unchanged)
        # -----------------------------------------------------------------
        if request.is_json:
            data = request.get_json()
            store_address = data.get('store_address', '')
            picture_path  = None
        else:
            data          = request.form
            store_address = data.get('store_address')
            picture       = request.files.get('picture')
            picture_path  = save_uploaded_file(picture) if picture else None

        # -----------------------------------------------------------------
        # 2.  special case:  "all"  => duplicate into every VALID_STORE
        # -----------------------------------------------------------------
        if store_address == 'all':
            inserted, skipped = 0, []
            stores = get_stores()
            
            if not stores:
                return handle_error('No stores configured in the system', 400)
            
            # Use a single database connection for all stores to ensure consistency
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                for store in stores:
                    local_data = dict(data)  # shallow copy
                    local_data['store_address'] = store
                    
                    try:
                        validated = validate_item_data(local_data)  # existing helper
                    except ValidationError as e:
                        # If validation fails for any store, rollback and return error
                        conn.rollback()
                        return handle_error(f'Validation error for {store}: {str(e)}', 400)

                    try:
                        cursor.execute('''
                            INSERT INTO items (
                                name, category, max_stock_level,
                                in_stock_level, reorder_level,
                                picture, supplier_id, store_address, unit
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            validated['name'], validated['category'],
                            validated['max_stock_level'], validated['in_stock_level'],
                            validated['reorder_level'], picture_path,
                            validated['supplier_id'], store,
                            validated['unit']
                        ))
                        inserted += 1
                    except sqlite3.IntegrityError:
                        skipped.append(store)  # duplicate – ignore
                        # Continue with next store instead of breaking
                        continue
                    except Exception as e:
                        # If any other error occurs, rollback and return error
                        conn.rollback()
                        return handle_error(f'Error adding to {store}: {str(e)}', 500)
                
                # Commit all successful insertions at once
                conn.commit()

            # Build detailed success message
            if inserted == 0:
                msg = f'Item already exists in all stores: {", ".join(s.split(",")[0] for s in skipped)}'
            elif inserted == len(stores):
                msg = f'Successfully added to all {inserted} store(s)'
            else:
                msg = f'Added to {inserted} store(s). Skipped (exists): {", ".join(s.split(",")[0] for s in skipped)}'

            return jsonify({'message': msg}), 201 if request.is_json else \
                   flash(msg, 'success') or redirect(url_for('owner_dashboard'))

        # 增强数据验证
        validated_data = validate_item_data(data)

        # 数据库操作
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO items (
                    name, category, max_stock_level, 
                    in_stock_level, reorder_level, 
                    picture, supplier_id, store_address,unit
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                validated_data['name'],
                validated_data['category'],
                validated_data['max_stock_level'],
                validated_data['in_stock_level'],
                validated_data['reorder_level'],
                picture_path,
                validated_data['supplier_id'],
                store_address,
                validated_data['unit']
            ))
            conn.commit()

        # 根据请求类型返回响应
        if request.is_json:
            return jsonify({'message': 'Item added successfully'}), 201
        else:
            flash('Item saved successfully!', 'success')
            return redirect(url_for('owner_dashboard'))

    except ValidationError as e:
        return handle_error(str(e), 400)
    except sqlite3.IntegrityError as e:
        return handle_error('Item name already exists', 409)
    except Exception as e:
        return handle_error('Server error', 500)


def save_uploaded_file(file):
    if file and allowed_file(file.filename):
        # Generate secure filename and save
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        return filename  # Returns relative path to stored file
    return None


def handle_error(message, status_code):
    if request.is_json:
        return jsonify({'message': message}), status_code
    else:
        flash(message, 'error')
        return redirect(url_for('owner_dashboard'))


def handle_owner_get_request():
    store_filter = request.args.get('store', '')
    params = []

    # 构建查询条件
    query = 'SELECT * FROM items'
    if store_filter:
        query += ' WHERE store_address = ?'
        params.append(store_filter)

    # 执行查询
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        items = cursor.fetchall()

    return render_template('owner_dashboard.html',
                           items=items,
                           valid_stores=get_stores(),
                           selected_store=store_filter)


# 辅助函数
# ------------------------------------------------------------------------
#  Item-data validator  –  now "store_address" may be the literal string
#  "all" so the Owner can duplicate an item into every real store.
# ------------------------------------------------------------------------
def validate_item_data(data):
    """
    Ensure the incoming item payload is complete and sane.
    Returns a dict with correctly-typed values or raises ValidationError.
    """

    required_fields = {
        'name'            : (str, lambda x: len(x) >= 2),
        'category'        : (str, lambda x: x in get_categories()),
        'max_stock_level' : (int, lambda x: x > 0),
        'in_stock_level'  : (int, lambda x: x >= 0),
        'reorder_level'   : (int, lambda x: x >= 0),
        'supplier_id': (int, lambda x: x > 0),  # 改为验证supplier_id
        # accept real store addresses OR the keyword "all"
        'store_address'   : (str, lambda x: x in get_stores() or x.lower() == 'all')
    }

    validated = {}
    for field, (cast_type, check_func) in required_fields.items():
        value = data.get(field)
        if value in (None, ''):
            raise ValidationError(f'Missing required field: {field}')
        try:
            value = cast_type(value)
            if not check_func(value):
                raise ValueError
        except (ValueError, TypeError):
            raise ValidationError(f'Invalid value for {field}')
        validated[field] = value

    raw_unit = data.get('unit', '').strip()
    if raw_unit:
        if raw_unit not in get_units():
            raise ValidationError('Unit must be chosen from master list')
        validated['unit'] = raw_unit
    else:
        validated['unit'] = None

    # Business rule: reorder level < max stock
    if validated['reorder_level'] >= validated['max_stock_level']:
        raise ValidationError('Reorder Level must be less than Max Stock Level')

    # 验证供应商是否存在
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT 1 FROM suppliers WHERE id = ?', (validated['supplier_id'],))
        if not cursor.fetchone():
            raise ValidationError("Invalid supplier ID")

    # Duplicate-name check only when a concrete store is specified
    if validated['store_address'].lower() != 'all':
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT 1 FROM items
                WHERE name = ? AND store_address = ?
            ''', (validated['name'], validated['store_address']))
            if cursor.fetchone():
                raise ValidationError(
                    f"Item '{validated['name']}' already exists in "
                    f"{validated['store_address']}"
                )

    return validated


def get_categories():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT name FROM categories')
        return [row['name'] for row in cursor.fetchall()]


# Route for the employee dashboard
@app.route('/employee_dashboard')
def employee_dashboard():
    current_store = session.get('store_address')
    with get_db_connection() as conn:
        cursor = conn.cursor()

        base_query = 'SELECT * FROM items'
        params = []

        if session.get('role') != 'owner':
            base_query += ' WHERE store_address = ?'
            params.append(session.get('store_address'))

        cursor.execute(base_query, params)
        items = cursor.fetchall()

    return render_template('employee_dashboard.html',
                           items=items,
                           current_store=current_store,
                           username = session.get('username')
                           )


@app.route('/manager_dashboard')
def manager_dashboard():
    if session.get('role') != 'manager':
        return redirect(url_for('login'))

    current_store = session.get('store_address', "Current Store")

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM items WHERE store_address = ?', (current_store,))
        items = cursor.fetchall()

    return render_template('manager_dashboard.html',
                           items=items,
                           current_store=current_store)  # 新增模板变量传递门店地址


# Route for managing categories
@app.route('/categories', methods=['GET', 'POST'])
def categories():
    with get_db_connection() as conn:
        cursor = conn.cursor()

        if request.method == 'POST':
            categories = request.json.get('categories', [])
            cursor.execute('DELETE FROM categories')
            for category in categories:
                cursor.execute('INSERT INTO categories (name) VALUES (?)', (category.strip(),))
            conn.commit()
            return jsonify({'message': 'Categories updated globally for all stores'})

        # -------- GET ----------
        if session.get('role') in ['employee','server','line_cook','prep_cook']:
            cursor.execute('''
                SELECT category FROM user_categories
                 WHERE user_id = ?
            ''', (session['user_id'],))
            return jsonify([r['category'] for r in cursor.fetchall()])

        cursor.execute('SELECT name FROM categories')
        return jsonify([row['name'] for row in cursor.fetchall()])

@app.route('/stores', methods=['GET', 'POST'])
def stores():
    with get_db_connection() as conn:
        cur = conn.cursor()
        if request.method == 'POST':
            names = request.json.get('stores', [])
            cur.execute('DELETE FROM stores')
            for n in names:
                cur.execute('INSERT INTO stores (name) VALUES (?)', (n.strip(),))
            conn.commit()
            return jsonify({'message': 'Store list updated'})
        cur.execute('SELECT name FROM stores')
        return jsonify([r['name'] for r in cur.fetchall()])


# Route for managing accounts with multi-store support
@app.route('/accounts', methods=['GET', 'POST'])
def accounts():
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Handle account deletion
        if request.method == 'POST':
            user_id = request.json.get('id')

            # Security validation
            cursor.execute('''
                SELECT store_address, role 
                FROM users 
                WHERE id = ?
            ''', (user_id,))
            target_account = cursor.fetchone()

            if not target_account:
                return jsonify({'message': 'Error: User does not exist.'}), 404

            # Get current user's permissions
            current_user_role = session.get('role')
            current_user_store = session.get('store_address')

            # Validate store access for non-owners
            if current_user_role != 'owner' and target_account['store_address'] != current_user_store:
                return jsonify({
                    'message': 'Unauthorized: Cannot modify accounts from other stores'
                }), 403

            # Prevent owner account deletion
            if target_account['role'] == 'owner':
                return jsonify({
                    'message': 'Error: Owner accounts cannot be deleted'
                }), 403

            # Delete account
            cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
            conn.commit()

            return jsonify({'message': 'Account deleted successfully!'}), 200

        # Handle account listing
        if session.get('role') == 'owner':
            # Owner sees all accounts from all stores
            cursor.execute('''
                SELECT id, username, role, employee_name, 
                       store_address, phone_number, email 
                FROM users 
                WHERE is_authorized = 1
            ''')
            authorized_accounts = cursor.fetchall()

            cursor.execute('''
                SELECT id, username, role, employee_name,
                       store_address, phone_number, email 
                FROM users 
                WHERE is_authorized = 0
            ''')
            pending_accounts = cursor.fetchall()
        else:
            # Non-owners only see accounts from their store
            current_store = session.get('store_address')

            cursor.execute('''
                SELECT id, username, role, employee_name,
                       store_address, phone_number, email 
                FROM users 
                WHERE is_authorized = 1 
                AND store_address = ?
            ''', (current_store,))
            authorized_accounts = cursor.fetchall()

            cursor.execute('''
                SELECT id, username, role, employee_name,
                       store_address, phone_number, email 
                FROM users 
                WHERE is_authorized = 0 
                AND store_address = ?
            ''', (current_store,))
            pending_accounts = cursor.fetchall()

        # Format response data
        def format_account(account):
            return {
                'id': account['id'],
                'username': account['username'],
                'role': account['role'] if 'role' in account.keys() else 'N/A',  # Direct access + key check
                'employee_name': account['employee_name'] or 'N/A',
                'store_address': account['store_address'] or 'N/A',
                'phone_number': account['phone_number'] or 'N/A',
                'email': account['email'] or 'N/A',
            }

        return jsonify({
            'authorized_accounts': [format_account(a) for a in authorized_accounts],
            'pending_accounts': [format_account(p) for p in pending_accounts]
        })


@app.route('/update_account/<int:account_id>', methods=['POST'])
def update_account(account_id):

    data = request.json
    required_fields = ['username', 'role', 'employee_name', 'store_address', 'phone_number', 'email']
    allowed_categories = data.get('allowed_categories', [])

    # Validate input
    if any(field not in data for field in required_fields):
        return jsonify({'message': 'Missing required fields'}), 400

    current_user_role = session.get('role')
    current_user_store = session.get('store_address')

    with get_db_connection() as conn:
        try:
            cursor = conn.cursor()

            # Verify account exists and get current store
            cursor.execute('''
                SELECT id, role, store_address FROM users 
                WHERE id = ?
            ''', (account_id,))
            target_account = cursor.fetchone()

            if not target_account:
                return jsonify({'message': 'Account not found'}), 404

            # Authorization checks
            if current_user_role != 'owner':
                # 双重验证: session和真实数据库状态
                cursor.execute('SELECT role FROM users WHERE id = ?', (session.get('user_id'),))
                actual_role = cursor.fetchone()['role']

                if actual_role != 'owner' or session.get('role') != 'owner':
                    # 强制同步session和数据库角色状态
                    session['role'] = actual_role
                    return jsonify({'message': '系统检测到权限异常，请重新登录'}), 403

            # Owner-specific validation
            if current_user_role == 'owner':
                # Validate store address for owner edits
                if data['store_address'] not in get_stores():
                    return jsonify({'message': 'Invalid store address'}), 400

                # Ensure at least one owner remains
                if target_account['role'] == 'owner' and data['role'] != 'owner':
                    cursor.execute('SELECT COUNT(*) FROM users WHERE role = "owner"')
                    if cursor.fetchone()[0] == 1:
                        return jsonify({'message': 'System must have at least one owner'}), 400

            # Build update parameters
            update_data = [
                data['username'],
                data['role'],
                data['employee_name'],
                data['store_address'],
                data['phone_number'],
                data['email'],
                account_id  # account_id 放在最后
            ]

            password_clause = ''
            if data.get('password'):
                password_clause = ', password = ?'
                # 将密码插入到倒数第二个位置（account_id 之前）
                update_data.insert(-1, data['password'])

            # 转换为元组
            update_data = tuple(update_data)

            # 执行 SQL
            cursor.execute(f'''
                UPDATE users SET 
                    username = ?, 
                    role = ?, 
                    employee_name = ?, 
                    store_address = ?, 
                    phone_number = ?, 
                    email = ?{password_clause}
                WHERE id = ?
            ''', update_data)

            # 更新允许的类别
            cursor.execute('DELETE FROM user_categories WHERE user_id = ?', (account_id,))
            for category in allowed_categories:
                cursor.execute('''
                    INSERT INTO user_categories (user_id, category)
                    VALUES (?, ?)
                ''', (account_id, category))

            conn.commit()

            if cursor.rowcount == 0:
                return jsonify({'message': 'No changes detected'}), 200

            return jsonify({'message': 'Account updated successfully'}), 200

        except sqlite3.IntegrityError as e:
            return jsonify({'message': 'Username already exists'}), 409
        except Exception as e:
            return jsonify({'message': f'Server error: {str(e)}'}), 500


@app.route('/items')
def get_items():
    if 'authorized' not in session:
        return jsonify({'message': 'Unauthorized'}), 401

    current_role   = session['role']
    current_store  = session['store_address']
    user_id        = session['user_id']
    store_filter   = request.args.get('store','')

    base = '''
        SELECT i.id,i.name,i.category,i.max_stock_level,i.in_stock_level,
               i.reorder_level,i.picture,s.name AS supplier,
               i.store_address,i.unit
          FROM items i
     LEFT JOIN suppliers s ON i.supplier_id=s.id
        WHERE 1=1
    '''
    params = []

    # ► store limitation (non-owner may see only own store)
    if current_role != 'owner':
        base   += ' AND i.store_address = ?'
        params += [current_store]
    elif store_filter and store_filter.lower()!='all':
        base   += ' AND i.store_address = ?'
        params += [store_filter]

    # ► category limitation (only "front-line" roles are restricted)
    if current_role in ['employee','server','line_cook','prep_cook']:
        cats   = allowed_categories_for(user_id)
        if not cats:                    # no categories → no data
            return jsonify([])
        base  += f" AND i.category IN ({','.join('?'*len(cats))})"
        params.extend(cats)

    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute(base, params)
        items = cur.fetchall()
    return jsonify([dict(r) for r in items])


@app.route('/items/<int:item_id>', methods=['GET'])
def get_item(item_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT 
                i.id, i.name, i.category, i.max_stock_level, 
                i.in_stock_level, i.reorder_level, 
                i.picture, s.name AS supplier, i.supplier_id, i.store_address, i.unit
            FROM items i
            LEFT JOIN suppliers s ON i.supplier_id = s.id
            WHERE i.id = ?
        ''', (item_id,))
        item = cursor.fetchone()
        if not item:
            return jsonify({'message': 'Item not found'}), 404
        return jsonify(dict(item))


@app.route('/delete_item/<int:item_id>', methods=['POST'])
def delete_item(item_id):
    print(f"DELETE request received for item_id: {item_id}")
    if not session.get('authorized'):
        return jsonify({'message': 'Unauthorized'}), 401

    current_user_role = session.get('role')
    current_user_store = session.get('store_address')

    with get_db_connection() as conn:
        try:
            cursor = conn.cursor()

            # Get item's store address
            cursor.execute('''
                SELECT store_address FROM items 
                WHERE id = ?
            ''', (item_id,))
            item = cursor.fetchone()

            if not item:
                return jsonify({'message': 'Item not found'}), 404

            # Store validation for non-owners
            if current_user_role != 'owner' and item['store_address'] != current_user_store:
                return jsonify({'message': 'Unauthorized to delete items from other stores'}), 403

            # Delete the item
            cursor.execute('DELETE FROM items WHERE id = ?', (item_id,))

            # Delete associated stock updates
            cursor.execute('DELETE FROM stock_updates WHERE item_id = ?', (item_id,))

            conn.commit()

            return jsonify({
                'message': f'Item {item_id} deleted successfully',
                'store_affected': item['store_address']
            }), 200

        except Exception as e:
            conn.rollback()
            return jsonify({'message': f'Deletion failed: {str(e)}'}), 500


@app.route('/update_item/<int:item_id>', methods=['POST'])
def update_item(item_id):
    # ---------- 0.  basic guards ----------
    if not request.is_json:
        return jsonify({'message': 'Only JSON accepted'}), 400
    if 'authorized' not in session:
        return jsonify({'message': 'Unauthorized'}), 401

    current_role   = session['role']
    current_store  = session['store_address']
    data           = request.get_json()

    # ---------- 1.  required fields & type-casts ----------
    required = ['name', 'category', 'max_stock_level', 'in_stock_level',
                'reorder_level', 'supplier_id', 'store_address']
    for f in required:
        if f not in data:
            return jsonify({'message': f'Missing field: {f}'}), 400
    try:
        data['max_stock_level'] = int(data['max_stock_level'])
        data['in_stock_level']  = int(data['in_stock_level'])
        data['reorder_level']   = int(data['reorder_level'])
        data['supplier_id']     = int(data['supplier_id'])
    except ValueError:
        return jsonify({'message': 'Numeric fields must be integers'}), 400

    # ---------- 2.  business rules ----------
    if data['reorder_level'] >= data['max_stock_level']:
        return jsonify({'message': 'Reorder level must be less than max stock'}), 400

    # Unit must be in master list (or NULL)
    unit_value = (data.get('unit') or '').strip() or None
    if unit_value and unit_value not in get_units():
        return jsonify({'message': 'Unit must be chosen from master list'}), 400

    # ---------- 3.  locate the item & store-access check ----------
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute('SELECT store_address FROM items WHERE id = ?', (item_id,))
        item = cur.fetchone()
        if not item:
            return jsonify({'message': 'Item not found'}), 404

        if current_role != 'owner' and item['store_address'] != current_store:
            return jsonify({'message': 'No permission to modify this item'}), 403

        # ---------- 4.  duplicate-name check within the same store ----------
        cur.execute('''
            SELECT 1 FROM items
            WHERE id <> ? AND name = ? AND store_address = ?
        ''', (item_id, data['name'], item['store_address']))
        if cur.fetchone():
            return jsonify({'message': 'Item name already exists in this store'}), 409

        # ---------- 5.  perform the update ----------
        cur.execute('''
            UPDATE items SET
                name            = ?,
                category        = ?,
                max_stock_level = ?,
                in_stock_level  = ?,
                reorder_level   = ?,
                supplier_id     = ?,
                store_address   = ?,
                unit            = ?
            WHERE id = ?
        ''', (data['name'], data['category'], data['max_stock_level'],
              data['in_stock_level'], data['reorder_level'],
              data['supplier_id'], data['store_address'],
              unit_value, item_id))
        conn.commit()

    return jsonify({'message': 'Item updated successfully'}), 200




@app.route('/delete_stock_update/<int:record_id>', methods=['DELETE'])
def delete_stock_update(record_id):
    # Security validation
    if 'authorized' not in session:
        return jsonify({'message': 'Unauthorized'}), 401

    current_role = session.get('role')
    if current_role not in ['manager', 'owner']:
        return jsonify({'message': 'Insufficient privileges'}), 403

    current_store = session.get('store_address')

    with get_db_connection() as conn:
        try:
            cursor = conn.cursor()

            # fetch the base record once
            cursor.execute('SELECT store_address FROM stock_updates WHERE id=?', (record_id,))
            record = cursor.fetchone()
            if not record:
                return jsonify({'message': 'Record not found'}), 404

            # Determine the batch-minute, category and store
            cursor.execute('''
                 SELECT strftime('%Y-%m-%d %H:%M', su.updated_at) AS ts_min,
                        i.category                                 AS cat
                   FROM stock_updates su
                   JOIN items i ON su.item_id = i.id
                  WHERE su.id = ?
            ''', (record_id,))
            snap = cursor.fetchone()
            ts_min = snap['ts_min'];
            cat = snap['cat']

            # 2. Validate store access for non-owners
            if current_role != 'owner' and record['store_address'] != current_store:
                return jsonify({'message': 'Unauthorized to modify records from other stores'}), 403

            # 3. Delete all rows of that batch (minute-level precision)
            cursor.execute('''
                DELETE FROM stock_updates
                 WHERE strftime('%Y-%m-%d %H:%M', updated_at)=?
                   AND store_address = ?
                   AND item_id IN (SELECT id FROM items WHERE category=?)
            ''', (ts_min, record['store_address'], cat))

            deleted_count = cursor.rowcount
            conn.commit()

            return jsonify({
                'message': f'Stock update batch deleted successfully ({deleted_count} records)',
                'deleted_store': record['store_address']
            }), 200

        except Exception as e:
            conn.rollback()
            return jsonify({'message': f'Deletion failed: {str(e)}'}), 500


@app.route('/delete_user_stock_updates/<string:username>', methods=['DELETE'])
def delete_user_stock_updates(username):
    """Delete all stock updates for a specific user with store validation"""
    if 'authorized' not in session:
        return jsonify({'message': 'Unauthorized'}), 401

    current_role = session.get('role')
    current_store = session.get('store_address')

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Validate user exists and get store association
            cursor.execute('''
                SELECT id, store_address 
                FROM users 
                WHERE username = ?
            ''', (username,))
            user = cursor.fetchone()

            if not user:
                return jsonify({'message': 'User not found'}), 404

            # Authorization check
            if current_role != 'owner':
                if current_store != user['store_address']:
                    return jsonify({
                        'message': 'Unauthorized: Cannot modify records from other stores'
                    }), 403

            # Delete with store validation
            cursor.execute('''
                DELETE FROM stock_updates 
                WHERE user_id = ?
                AND EXISTS (
                    SELECT 1 FROM items 
                    WHERE items.id = stock_updates.item_id 
                    AND items.store_address = ?
                )
            ''', (user['id'], user['store_address']))

            conn.commit()

            return jsonify({
                'message': f'Deleted {cursor.rowcount} stock updates for {username}',
                'store_affected': user['store_address']
            }), 200

    except Exception as e:
        return jsonify({'message': f'Deletion failed: {str(e)}'}), 500


@app.route('/download_stock_report', methods=['GET'])
def download_stock_report():
    """Generate store-specific stock warning PDF report using Platypus Table."""

    # Authorization check
    if 'authorized' not in session:
        return jsonify({'message': 'Unauthorized'}), 401

    current_role = session.get('role')
    current_store = session.get('store_address')
    store_filter = request.args.get('store', current_store)

    if current_role != 'owner':
        store_filter = current_store

    # Validate store access
    if current_role != 'owner' and store_filter != current_store:
        return jsonify({'message': 'Unauthorized to access this store'}), 403

    if store_filter not in get_stores():
        return jsonify({'message': 'Invalid store selection'}), 400

    short_name = store_filter.split(',')[0].strip()

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT 
                i.name,
                i.in_stock_level,
                i.max_stock_level,
                i.unit,
                s.name AS supplier_name,
                COALESCE(u.employee_name, 'System') AS updated_by,
                su.updated_at AS last_updated
            FROM items i
            LEFT JOIN suppliers s ON i.supplier_id = s.id
            LEFT JOIN (
                SELECT item_id, MAX(updated_at) AS latest
                FROM stock_updates
                GROUP BY item_id
            ) latest ON i.id = latest.item_id
            LEFT JOIN stock_updates su 
                   ON su.item_id = latest.item_id
                  AND su.updated_at = latest.latest
            LEFT JOIN users u ON su.user_id = u.id
            WHERE i.in_stock_level <= i.reorder_level
            AND i.store_address = ?
            ORDER BY s.name, i.name
        ''', (store_filter,))
        rows = cursor.fetchall()

        from collections import defaultdict
        grouped = defaultdict(list)

        def with_unit(n, unit):
            return f"{n} {unit}" if unit else str(n)

        for r in rows:
            supplier = r['supplier_name'] or 'Unknown supplier'
            grouped[supplier].append(r)

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter,
                                leftMargin=36, rightMargin=36,
                                topMargin=48, bottomMargin=36)

        styles = getSampleStyleSheet()
        SUPPLIER_CLR = HexColor("#ff8800")  # warm orange
        from reportlab.lib.styles import ParagraphStyle
        
        headingSupp = ParagraphStyle('SuppHead',
                                     parent=styles['Heading3'],
                                     textColor=SUPPLIER_CLR)

        title = ParagraphStyle('RptTitle',
                               parent=styles['Title'],
                               fontSize=14,
                               leading=16)
        
        subtitle = ParagraphStyle('SubTitle',
                                  parent=styles['Normal'],
                                  fontSize=10,
                                  leading=12,
                                  textColor=HexColor("#666666"))

        # Get current date and time
        from datetime import datetime
        current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        story = [Paragraph(f"{short_name} – Stock Warnings Report", title),
                 Paragraph(f"Generated on: {current_datetime}", subtitle),
                 Spacer(1, 12)]

        if not rows:
            story.append(Paragraph("No stock warnings found.", styles['Normal']))
        else:
            HEADER_BG = HexColor("#003366")
            HEADER_FG = colors.whitesmoke
            ROW_EVEN_BG = HexColor("#F4F7FA")
            ROW_ODD_BG = colors.white
            RESTOCK_BG = HexColor("#FFF4CC")
            GRID_CLR = HexColor("#B0BEC5")

            for supplier in sorted(grouped):
                story.append(Paragraph(f"‣ Supplier: {supplier}", headingSupp))
                story.append(Spacer(1, 4))

                data = [["Item Name", "Restock Qty", "Current", "Update Date", "Updated By"]]

                for r in grouped[supplier]:
                    restock = r['max_stock_level'] - r['in_stock_level']
                    u = r['unit']
                    # Format the update date
                    update_date = r['last_updated'][:16] if r['last_updated'] else 'N/A'
                    data.append([
                        r['name'],
                        with_unit(restock, u),
                        with_unit(r['in_stock_level'], u),
                        update_date,
                        r['updated_by'] or 'System'
                    ])

                tbl = Table(data,
                            colWidths=[180, 80, 60, 100, 80])

                tbl.setStyle(TableStyle([
                    ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 10),
                    ('FONT', (0, 1), (-1, -1), 'Helvetica', 10),
                    ('BACKGROUND', (0, 0), (-1, 0), HEADER_BG),
                    ('TEXTCOLOR', (0, 0), (-1, 0), HEADER_FG),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1),
                     (ROW_EVEN_BG, ROW_ODD_BG)),
                    ('BACKGROUND', (1, 1), (1, -1), RESTOCK_BG),
                    ('FONT', (1, 1), (1, -1), 'Helvetica-Bold', 10),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('GRID', (0, 0), (-1, -1), 0.25, GRID_CLR),
                ]))
                story.extend([tbl, Spacer(1, 10)])

        doc.build(story)
        buffer.seek(0)

        from datetime import date
        fname = f"Stock_Report_{short_name.replace(' ', '_')}_{date.today()}.pdf"
        return send_file(buffer, as_attachment=True,
                         download_name=fname, mimetype='application/pdf')





# ---------------------------------------------------------------
#  Comprehensive UPDATE report (All categories from one session)
# ---------------------------------------------------------------
@app.route('/download_comprehensive_update_report')
def download_comprehensive_update_report():
    if 'authorized' not in session:
        return jsonify({'message': 'Unauthorized'}), 401

    rec_id = int(request.args.get('record', 0))
    snap = batch_minute(rec_id)
    if not snap:
        return jsonify({'message': 'Invalid record id'}), 404

    ts_min = snap['ts_min']
    store = snap['store']
    employee = request.args.get('employee', 'System')

    # non-owner can only touch own store
    if session['role'] != 'owner' and store != session['store_address']:
        return jsonify({'message': 'Unauthorized store'}), 403

    short = store.split(',')[0].strip()

    # Get the specific category for this record
    category = request.args.get('category', '')
    
    with get_db_connection() as c:
        cur = c.cursor()
        
        # Get all items updated in this session for the specific category
        cur.execute('''
            SELECT i.name,
                   i.category,
                   su.stock_after AS current,
                   i.reorder_level,
                   i.max_stock_level,
                   i.unit,
                   s.name AS supplier_name
            FROM stock_updates su
            JOIN items i ON su.item_id = i.id
            LEFT JOIN suppliers s ON i.supplier_id = s.id
            WHERE su.store_address = ?
            AND strftime('%Y-%m-%d %H:%M', su.updated_at) = ?
            AND i.category = ?
            ORDER BY s.name, i.name
        ''', (store, ts_min, category))
        rows = cur.fetchall()

    # ---------- PDF ----------
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter,
                           leftMargin=36, rightMargin=36,
                           topMargin=48, bottomMargin=36)

    styles = getSampleStyleSheet()
    title = styles['Title']
    title.fontSize = 14
    title.leading = 16

    from reportlab.lib.styles import ParagraphStyle
    subtitle = ParagraphStyle(
        'Updater',
        parent=styles['Heading3'],
        alignment=1,
        fontSize=12,
        leading=14,
        textColor=HexColor("#198754")
    )

    category_heading = ParagraphStyle(
        'CategoryHead',
        parent=styles['Heading2'],
        fontSize=12,
        leading=14,
        textColor=HexColor("#0d6efd")
    )

    story = [Paragraph(f"{short} – {category} Update Report", title),
             Spacer(1, 4),
             Paragraph(f"Updated by {employee} at {ts_min}", subtitle),
             Spacer(1, 12)]

    if not rows:
        story.append(Paragraph("No items found in this update session.", styles['Normal']))
    else:
        data = [["Item", "Restock", "Current", "Reorder", "Max", "Supplier"]]
        def u(n, unit): return f"{n} {unit}" if unit else str(n)

        for r in rows:
            restock = r['max_stock_level'] - r['current']
            data.append([
                r['name'],
                u(restock, r['unit']),
                u(r['current'], r['unit']),
                u(r['reorder_level'], r['unit']),
                u(r['max_stock_level'], r['unit']),
                r['supplier_name'] or 'N/A'
            ])

        from reportlab.platypus import Table, TableStyle
        from reportlab.lib import colors
        GRID = HexColor("#B0BEC5")
        tbl = Table(data, colWidths=[160, 60, 55, 55, 55, 100])
        tbl.setStyle(TableStyle([
            ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 10),
            ('BACKGROUND', (0, 0), (-1, 0), HexColor("#003366")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1),
             (HexColor("#F4F7FA"), colors.white)),
            ('GRID', (0, 0), (-1, -1), .25, GRID),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            # Highlight Restock column (column 1) with red background and bold text
            ('BACKGROUND', (1, 1), (1, -1), HexColor("#FFE6E6")),
            ('FONT', (1, 1), (1, -1), 'Helvetica-Bold', 10),
            ('TEXTCOLOR', (1, 1), (1, -1), HexColor("#DC3545"))
        ]))
        story.extend([tbl, Spacer(1, 12)])

    doc.build(story)
    buffer.seek(0)
    from datetime import date
    fname = f"{short.replace(' ', '_')}_{category.replace(' ', '_')}_Update_{date.today()}.pdf"
    return send_file(buffer, as_attachment=True,
                     download_name=fname,
                     mimetype='application/pdf')


@app.route('/create_account', methods=['POST'])
def create_account():

    # Authorization check
    if 'authorized' not in session:
        return jsonify({'message': 'Unauthorized'}), 401

    current_role = session.get('role')
    current_store = session.get('store_address')
    data = request.json

    # Validate required fields
    required_fields = ['username', 'password', 'employee_name', 'phone_number', 'email', 'role']
    if not all(field in data for field in required_fields):
        return jsonify({'message': 'Missing required fields'}), 400

    # Authorization and validation logic
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Validate store address
            store_address = data.get('store_address', current_store)

            # Non-owners can only create accounts in their own store
            if current_role != 'owner':
                if 'store_address' in data and data['store_address'] != current_store:
                    return jsonify({'message': 'Cannot create accounts in other stores'}), 403
                store_address = current_store  # Force current store for non-owners

            # Verify store is valid
            if store_address not in get_stores():
                return jsonify({'message': 'Invalid store address'}), 400

            # Prevent role escalation
            if current_role != 'owner' and data['role'] == 'owner':
                return jsonify({'message': 'Only owners can create owner accounts'}), 403

            # Validate phone number format
            phone = data['phone_number']
            if not (len(phone) == 10 and phone.isdigit()):
                return jsonify({'message': 'Invalid phone number format'}), 400

            # Validate email format
            email = data['email']
            if '@' not in email or '.' not in email.split('@')[-1]:
                return jsonify({'message': 'Invalid email format'}), 400

            # Check password complexity
            password = data['password']
            if len(password) < 8 or not any(c.isupper() for c in password):
                return jsonify({'message': 'Password must be at least 8 characters with uppercase'}), 400

            cursor.execute('''
                INSERT INTO users (
                    username, password, employee_name,
                    store_address, phone_number, email,
                    role, is_authorized
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                data['username'],
                password,
                data['employee_name'],
                store_address,
                phone,
                email,
                data['role'],
                1 if data['role'] == 'owner' else 0  # Auto-authorize owners
            ))

            # Ensure at least one owner per store
            if data['role'] == 'owner':
                cursor.execute('''
                    UPDATE users SET is_authorized = 1 
                    WHERE store_address = ? AND role = 'owner'
                ''', (store_address,))

            conn.commit()
            return jsonify({
                'message': 'Account created successfully',
                'store': store_address,
                'requires_authorization': 0 if data['role'] == 'owner' else 1
            }), 201

    except sqlite3.IntegrityError as e:
        error_map = {
            'username': 'Username already exists',
            'phone_number': 'Phone number already registered',
            'email': 'Email address already in use'
        }
        error_field = next((k for k in error_map if k in str(e)), 'database')
        return jsonify({'message': f'{error_map.get(error_field, "Database error")}'}), 409

    except Exception as e:
        return jsonify({'message': f'Server error: {str(e)}'}), 500


@app.route('/set_stock_level/<int:item_id>', methods=['POST'])
def set_stock_level(item_id):
    # Authentication and store validation
    if 'store_address' not in session or 'role' not in session:
        return jsonify({'message': 'User not authenticated or store not assigned'}), 401

    current_store = session['store_address']
    user_role = session['role']
    user_id = session.get('user_id')

    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            # Get item details with store information
            cursor.execute('''
                SELECT id, in_stock_level, max_stock_level, reorder_level, name, store_address 
                FROM items 
                WHERE id = ?
            ''', (item_id,))
            item = cursor.fetchone()

            if not item:
                return jsonify({'message': 'Item not found.'}), 404

            # Store validation (owners can modify any store, others only their own)
            if user_role != 'owner' and item['store_address'] != current_store:
                return jsonify({'message': 'Unauthorized to modify items in this store'}), 403

            # Validate input
            data = request.json
            new_stock_level = data.get('in_stock_level')
            if not isinstance(new_stock_level, int) or new_stock_level < 0:
                return jsonify({'message': 'Invalid stock level'}), 400

            if new_stock_level > item['max_stock_level']:
                return jsonify({
                    'message': f'Cannot exceed Max Stock Level ({item["max_stock_level"]})',
                    'max_stock': item['max_stock_level']
                }), 400

            # Record stock update with store information
            cursor.execute('''
                INSERT INTO stock_updates 
                (user_id, item_id, stock_before, stock_after, store_address)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, item_id, item['in_stock_level'], new_stock_level, item['store_address']))

            # NEW – keep only the 100 newest rows of this user
            cursor.execute('''
                DELETE FROM stock_updates
                      WHERE user_id = ?
                        AND id NOT IN (
                            SELECT id
                              FROM stock_updates
                             WHERE user_id = ?
                          ORDER BY updated_at DESC
                             LIMIT 100
                        )
            ''', (user_id, user_id))

            # Update item stock
            cursor.execute('''
                UPDATE items 
                SET in_stock_level = ? 
                WHERE id = ? AND store_address = ?
            ''', (new_stock_level, item_id, item['store_address']))

            conn.commit()

            # Generate warning if needed
            warning = None
            if new_stock_level <= item['reorder_level']:
                warning = {
                    'message': f'Stock for "{item["name"]}" has hit Reorder Level',
                    'item_id': item_id,
                    'current_stock': new_stock_level,
                    'reorder_level': item['reorder_level']
                }

            return jsonify({
                'message': 'Stock updated successfully',
                'new_stock': new_stock_level,
                'store': item['store_address'],
                'warning': warning
            }), 200

        except sqlite3.Error as e:
            conn.rollback()
            return jsonify({'message': f'Database error: {str(e)}'}), 500
        except Exception as e:
            return jsonify({'message': f'Server error: {str(e)}'}), 500


@app.route('/stock_update_history', methods=['GET'])
def stock_update_history():
    """Get multi-store stock update history grouped by user"""
    try:
        if 'authorized' not in session:
            return jsonify({'message': 'Unauthorized'}), 401

        store_filter = request.args.get('store', 'all')
        current_role = session.get('role')

        base_query = '''
            SELECT 
                su.id, 
                su.store_address,
                u.username, 
                i.name AS item_name, 
                i.category AS category,
                su.stock_before, 
                su.stock_after, 
                su.updated_at,
                i.max_stock_level,
                i.unit
            FROM stock_updates su
            JOIN users u ON su.user_id = u.id
            JOIN items i ON su.item_id = i.id
        '''
        params = []
        filters = []

        # Validate store filter format


        if current_role != 'owner':
            filters.append('su.store_address = ?')
            params.append(session.get('store_address'))
        elif store_filter.lower() != 'all':
            if store_filter not in get_stores():
                return jsonify({'message': 'Invalid store filter'}), 400
            filters.append('su.store_address = ?')
            params.append(store_filter)

        if filters:
            base_query += ' WHERE ' + ' AND '.join(filters)

        base_query += ' ORDER BY su.updated_at DESC'

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(base_query, params)
            raw_history = cursor.fetchall()

        # Process data with proper structure
        user_history = defaultdict(lambda: {
            'username': None,
            'records' : []
        })

        for row in raw_history:
            u            = row['username']
            store_addr   = row['store_address']
            category     = row['category']
            ts_min      = row['updated_at'][:16]          # keep up to min
            composite_id = (store_addr, ts_min, category)  # Group by store, timestamp, and category

            usr = user_history[u]
            if usr['username'] is None:
                usr['username'] = u

            # Check if we already have a record for this category update session
            existing_record = None
            for record in usr['records']:
                if (record['store_address'] == store_addr and 
                    record['updated_at'][:16] == ts_min and
                    record['category'] == category):
                    existing_record = record
                    break

            if existing_record is None:
                # Calculate restock amount
                restock = row['max_stock_level'] - row['stock_after'] if row['max_stock_level'] and row['stock_after'] else 0
                
                # Create new record for this category update session
                usr['records'].append({
                    'id'           : row['id'],        # one representative id
                    'updated_at'   : row['updated_at'],
                    'store_address': store_addr,
                    'category'     : category,         # Single category per record
                    'categories'   : [category],       # Keep for compatibility with frontend
                    'item_name'    : row['item_name'],
                    'max_stock_level': row['max_stock_level'],
                    'unit'         : row['unit'],
                    'restock'      : restock
                })

        # Sort records newest-first and limit to 100 per user
        for usr in user_history.values():
            usr['records'].sort(key=lambda r: r['updated_at'], reverse=True)
            usr['records'] = usr['records'][:100]

        return jsonify(list(user_history.values()))

    except sqlite3.Error as e:
        app.logger.error(f"Database error: {str(e)}")
        return jsonify({'message': 'Database operation failed'}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500


def batch_minute(record_id):
    """Return (timestamp-to-min, store, category) for any stock_updates.id"""
    with get_db_connection() as c:
        cur = c.cursor()
        cur.execute('''
            SELECT strftime('%Y-%m-%d %H:%M', su.updated_at)     AS ts_min,
                   i.category                                     AS cat,
                   su.store_address                              AS store
              FROM stock_updates su
              JOIN items i ON su.item_id = i.id
             WHERE su.id = ?
        ''', (record_id,))
        return cur.fetchone()

@app.route('/suppliers', methods=['GET', 'POST'])
def suppliers():
    with get_db_connection() as conn:
        cursor = conn.cursor()

        if request.method == 'POST':
            suppliers = request.json.get('suppliers', [])
            cursor.execute('DELETE FROM suppliers')
            for supplier in suppliers:
                cursor.execute('INSERT INTO suppliers (name) VALUES (?)', (supplier.strip(),))
            conn.commit()
            return jsonify({'message': 'Suppliers updated globally for all stores'})

        # 确保返回包含id和name的对象列表
        cursor.execute('SELECT id, name FROM suppliers')
        suppliers = [dict(id=row[0], name=row[1]) for row in cursor.fetchall()]
        return jsonify(suppliers)

@app.route('/suppliers/<int:supplier_id>', methods=['DELETE'])
def delete_supplier(supplier_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            # 首先检查是否有物品使用此供应商
            cursor.execute('SELECT COUNT(*) FROM items WHERE supplier_id = ?', (supplier_id,))
            if cursor.fetchone()[0] > 0:
                return jsonify({
                    'message': 'Cannot delete supplier - items are still associated with it'
                }), 400

            cursor.execute('DELETE FROM suppliers WHERE id = ?', (supplier_id,))
            conn.commit()
            return jsonify({'message': 'Supplier deleted successfully'}), 200
        except sqlite3.Error as e:
            return jsonify({'error': str(e)}), 500

@app.route('/logout')
def logout():
    session.clear()  # Clear all session data
    return redirect(url_for('login'))

def cleanup_stock_history():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            conn.execute('BEGIN IMMEDIATE')

            # Get pre-cleanup metrics
            cursor.execute('''SELECT COUNT(*) FROM stock_updates''')
            initial_count = cursor.fetchone()[0]

            # Delete records older than 30 days using SQLite's time
            cursor.execute('''
                DELETE FROM stock_updates
                WHERE updated_at < datetime('now', '-30 days', 'localtime')
            ''')

            # B. NEW – size based cleanup (100-row cap per user)
            cursor.execute('''
                DELETE FROM stock_updates
                      WHERE id IN (
                          SELECT id FROM (
                              SELECT id,
                                     ROW_NUMBER() OVER
                                         (PARTITION BY user_id
                                          ORDER BY updated_at DESC) AS rn
                                FROM stock_updates
                          )
                          WHERE rn > 100
                      )
            ''')

            # Get cleanup metrics
            deleted_count = cursor.rowcount
            cursor.execute('''SELECT COUNT(*) FROM stock_updates''')
            remaining_count = cursor.fetchone()[0]

            conn.commit()

            app.logger.info(
                f"30-day cleanup completed. Removed {deleted_count} entries. "
                f"Initial: {initial_count}, Remaining: {remaining_count}"
            )

    except sqlite3.Error as e:
        app.logger.error(f"Database error during 30-day cleanup: {str(e)}")
        conn.rollback()
    except Exception as e:
        app.logger.error(f"Unexpected error in 30-day cleanup: {str(e)}")
        conn.rollback()

def get_units():
    with get_db_connection() as c:
        cur = c.cursor()
        cur.execute('SELECT name FROM units')
        return [r['name'] for r in cur.fetchall()]

def get_stores():
    with get_db_connection() as c:
        cur = c.cursor()
        cur.execute('SELECT name FROM stores')
        return [r['name'] for r in cur.fetchall()]

@app.route('/units', methods=['GET', 'POST'])
def units():
    with get_db_connection() as conn:
        cur = conn.cursor()
        if request.method == 'POST':
            names = request.json.get('units', [])
            cur.execute('DELETE FROM units')
            for n in names:
                cur.execute('INSERT INTO units (name) VALUES (?)', (n.strip(),))
            conn.commit()
            return jsonify({'message': 'Units updated'})
        # --- GET ---
        cur.execute('SELECT name FROM units')
        return jsonify([r['name'] for r in cur.fetchall()])


# Configure scheduler to run daily at 2 AM
scheduler.add_job(
    cleanup_stock_history,
    'cron',
    hour=2,
    minute=0,
    max_instances=1,
    coalesce=True,
    misfire_grace_time=3600  # 1 hour grace period
)

@app.before_request
def check_authorization():
    if request.endpoint not in ['login', 'register', 'static', 'stores']:
        # Enhanced security checks
        if not all(key in session for key in ('user_id', 'role', 'store_address', '_csrf_validated')):
            session.clear()
            return redirect(url_for('login'))
        # Rotating session token for security
        session['_csrf_validated'] = os.urandom(24).hex()


@app.after_request
def add_header(response):
    # Prevent caching of sensitive pages
    if request.path.startswith('/owner_dashboard'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response


@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


if __name__ == '__main__':
    scheduler.start()
    app.run(debug=False)
else:
    try:
        print("Running in production environment - attempting alternative scheduler configuration")
        # Either attempt with different settings or disable
        scheduler.configure(options={'apscheduler.daemon': False})
        scheduler.start()
    except RuntimeError as e:
        print(f"Scheduler disabled: {str(e)}")
        print("Stock history cleanup will not run automatically")
