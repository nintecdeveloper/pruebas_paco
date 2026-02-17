import os
import json
import secrets
from datetime import datetime, date, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
import io
import re

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'oslaprint_pro_2026_secure_key')
database_url = os.environ.get('DATABASE_URL', 'sqlite:///' + os.path.join(basedir, 'oslaprint.db'))
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'txt'}

# Crear carpeta de uploads si no existe
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- MODELOS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    email = db.Column(db.String(100), unique=True, nullable=False, index=True)  # ✅ CORREGIDO: unique=True
    password_hash = db.Column(db.String(512))
    role = db.Column(db.String(20))  # 'admin' o 'tech'
    reset_token = db.Column(db.String(100), unique=True, nullable=True)
    reset_token_expiry = db.Column(db.DateTime, nullable=True)

class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(250), nullable=False)
    link = db.Column(db.String(500), nullable=True)
    notes = db.Column(db.Text)
    has_support = db.Column(db.Boolean, default=False)
    # ✅ NUEVO: horario de soporte — 'lv'=L-V / 'ls'=L-S / 'ld'=L-D
    support_schedule = db.Column(db.String(5), nullable=True)

class TechProfile(db.Model):
    """Perfil extendido de técnico - datos personales y notas internas del admin"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    user = db.relationship('User', backref=db.backref('profile', uselist=False))
    full_name = db.Column(db.String(150), nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    address = db.Column(db.String(250), nullable=True)
    emergency_contact = db.Column(db.String(150), nullable=True)
    emergency_phone = db.Column(db.String(20), nullable=True)
    start_date = db.Column(db.String(10), nullable=True)
    dni = db.Column(db.String(20), nullable=True)
    internal_notes = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.now)

class ServiceType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    color = db.Column(db.String(7), default='#6c757d')
    
    def __repr__(self):
        return f"{self.name}"

class StockCategory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('stock_category.id'), nullable=True)
    parent = db.relationship('StockCategory', remote_side=[id], backref='subcategories')

class Stock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, default=0)
    category_id = db.Column(db.Integer, db.ForeignKey('stock_category.id'), nullable=True)
    category = db.relationship('StockCategory', backref='items')
    min_stock = db.Column(db.Integer, default=5)
    description = db.Column(db.Text)
    supplier = db.Column(db.String(100), nullable=True)  # ✅ NUEVO CAMPO PROVEEDOR

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tech_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=True)
    client_name = db.Column(db.String(100))
    description = db.Column(db.Text)
    
    date = db.Column(db.Date, default=date.today)
    start_time = db.Column(db.String(10)) 
    end_time = db.Column(db.String(10))   
    
    service_type_id = db.Column(db.Integer, db.ForeignKey('service_type.id'))
    parts_text = db.Column(db.String(200))  
    
    stock_item_id = db.Column(db.Integer, db.ForeignKey('stock.id'), nullable=True)
    stock_quantity_used = db.Column(db.Integer, default=0)
    stock_action = db.Column(db.String(20))

    status = db.Column(db.String(20), default='Pendiente')  # Pendiente o Completado
    
    # Campos para firma digital
    signature_data = db.Column(db.Text)
    signature_client_name = db.Column(db.String(100))
    signature_timestamp = db.Column(db.DateTime)
    
    # Archivos adjuntos
    attachments = db.Column(db.Text)  # JSON
    
    # Cronómetro de parte (solo inicio y fin)
    work_start_time = db.Column(db.DateTime)
    work_end_time = db.Column(db.DateTime)
    # Duración total medida por el cronómetro del técnico (formato HH:MM:SS)
    work_duration = db.Column(db.String(20), nullable=True)

    tech = db.relationship('User', backref='tasks')
    client = db.relationship('Client', backref='tasks')
    service_type = db.relationship('ServiceType', backref='tasks')
    stock_item = db.relationship('Stock', backref='tasks')

class Alarm(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    alarm_type = db.Column(db.String(50))
    title = db.Column(db.String(100))
    description = db.Column(db.Text)
    client_name = db.Column(db.String(100), nullable=True)
    stock_item_id = db.Column(db.Integer, db.ForeignKey('stock.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    is_read = db.Column(db.Boolean, default=False)
    priority = db.Column(db.String(20), default='normal')

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

# --- FUNCIONES AUXILIARES ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_password(password):
    """Validar contraseña con requisitos de seguridad"""
    if len(password) < 6:
        return False, "La contraseña debe tener al menos 6 caracteres"
    if not re.search(r'[A-Z]', password):
        return False, "La contraseña debe contener al menos una mayúscula"
    if not re.search(r'[a-z]', password):
        return False, "La contraseña debe contener al menos una minúscula"
    if not re.search(r'[0-9]', password):
        return False, "La contraseña debe contener al menos un número"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "La contraseña debe contener al menos un carácter especial"
    return True, "Contraseña válida"

def validate_email(email):
    """Validar formato de email"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def check_low_stock():
    """Verificar stock bajo y crear alarmas"""
    try:
        low_items = Stock.query.filter(Stock.quantity <= Stock.min_stock).all()
        for item in low_items:
            existing = Alarm.query.filter_by(
                alarm_type='low_stock',
                stock_item_id=item.id,
                is_read=False
            ).first()
            
            if not existing:
                alarm = Alarm(
                    alarm_type='low_stock',
                    title=f'Stock bajo: {item.name}',
                    description=f'El stock de {item.name} está en {item.quantity} unidades (mínimo: {item.min_stock})',
                    stock_item_id=item.id,
                    priority='high'
                )
                db.session.add(alarm)
        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        print(f"Error en check_low_stock: {str(e)}")

# --- CONTEXT PROCESSOR ---
@app.context_processor
def inject_globals():
    try:
        unread_alarms = 0
        if current_user.is_authenticated and current_user.role == 'admin':
            unread_alarms = Alarm.query.filter_by(is_read=False).count()
        
        employees = User.query.filter_by(role='tech').all() if current_user.is_authenticated and current_user.role == 'admin' else []
        
        return {
            'all_service_types': ServiceType.query.order_by(ServiceType.name).all(),
            'unread_alarms_count': unread_alarms,
            'employees': employees,
            'now': datetime.now  # ✅ Añadir función now para templates
        }
    except Exception as e:
        print("ERROR context_processor:", e)
        return {
            'all_service_types': [],
            'unread_alarms_count': 0,
            'employees': [],
            'now': datetime.now
        }

# Filtro Jinja2 para parsear JSON
@app.template_filter('from_json')
def from_json_filter(value):
    """Parsear JSON string a objeto Python"""
    if not value:
        return []
    try:
        return json.loads(value)
    except:
        return []

# --- RUTAS PRINCIPALES ---
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Usuario o contraseña incorrectos', 'danger')
    
    return render_template('login.html')

@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    """Procesar solicitud de recuperación de contraseña"""
    try:
        email = request.form.get('email', '').strip()
        
        if not email:
            flash('Por favor ingresa tu correo electrónico', 'danger')
            return redirect(url_for('login'))
        
        # ✅ MEJORADO: Buscar TODOS los usuarios con este email (puede haber varios)
        users = User.query.filter_by(email=email).all()
        
        if not users:
            # Por seguridad, no revelamos si el email existe o no
            flash('Si el correo existe en nuestro sistema, recibirás un enlace de recuperación', 'info')
            return redirect(url_for('login'))
        
        # ✅ Generar token para CADA usuario con este email
        for user in users:
            reset_token = secrets.token_urlsafe(32)
            user.reset_token = reset_token
            user.reset_token_expiry = datetime.now() + timedelta(hours=24)
            
            # En producción, aquí se enviaría un email con el enlace
            # Por ahora, mostramos el enlace en consola para desarrollo
            reset_link = url_for('reset_password', token=reset_token, _external=True)
            print("\n" + "="*60)
            print("🔐 ENLACE DE RECUPERACIÓN DE CONTRASEÑA")
            print("="*60)
            print(f"Usuario: {user.username} ({user.role})")
            print(f"Email: {user.email}")
            print(f"Enlace: {reset_link}")
            print("="*60 + "\n")
        
        db.session.commit()
        
        num_accounts = len(users)
        if num_accounts > 1:
            flash(f'Se han generado {num_accounts} enlaces de recuperación para las cuentas asociadas a este email. Revisa la consola del servidor.', 'success')
        else:
            flash('Se ha generado un enlace de recuperación. Revisa la consola del servidor.', 'success')
        
        return redirect(url_for('login'))
        
    except Exception as e:
        print(f"Error en forgot_password: {str(e)}")
        flash('Error al procesar la solicitud', 'danger')
        return redirect(url_for('login'))

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Página y procesamiento de restablecimiento de contraseña"""
    # Verificar que el token sea válido
    user = User.query.filter_by(reset_token=token).first()
    
    if not user:
        flash('Token de recuperación inválido', 'danger')
        return redirect(url_for('login'))
    
    # Verificar que el token no haya expirado
    if user.reset_token_expiry < datetime.now():
        flash('El token de recuperación ha expirado', 'danger')
        # Limpiar el token expirado
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            new_password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            
            # Validar que las contraseñas coincidan
            if new_password != confirm_password:
                flash('Las contraseñas no coinciden', 'danger')
                return redirect(url_for('reset_password', token=token))
            
            # Validar requisitos de seguridad
            is_valid, message = validate_password(new_password)
            if not is_valid:
                flash(message, 'danger')
                return redirect(url_for('reset_password', token=token))
            
            # Actualizar contraseña
            user.password_hash = generate_password_hash(new_password)
            
            # Limpiar token
            user.reset_token = None
            user.reset_token_expiry = None
            
            db.session.commit()
            
            flash('✅ Contraseña restablecida correctamente. Ya puedes iniciar sesión.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            print(f"Error resetting password: {str(e)}")
            flash('Error al restablecer la contraseña', 'danger')
            return redirect(url_for('reset_password', token=token))
    
    # Mostrar formulario de reset
    return render_template('reset_password.html', token=token)


@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        empleados = User.query.filter_by(role='tech').all()
        clients = Client.query.order_by(Client.name).all()
        services = ServiceType.query.all()
        informes = Task.query.filter_by(status='Completado').order_by(Task.date.desc()).limit(50).all()
        stock_items = Stock.query.order_by(Stock.name).all()
        # ✅ Obtener categorías para el panel de stock
        stock_categories = StockCategory.query.filter_by(parent_id=None).all()
        # ✅ NUEVO: todas las categorías (incluidas subcategorías) para el selector de edición
        all_categories = StockCategory.query.order_by(StockCategory.name).all()
        
        return render_template('admin_panel.html', 
                             empleados=empleados,
                             clients=clients,
                             services=services,
                             informes=informes,
                             stock_items=stock_items,
                             stock_categories=stock_categories,
                             all_categories=all_categories,
                             today_date=date.today().strftime('%Y-%m-%d'))
    else:
        pending_tasks = Task.query.filter_by(
            tech_id=current_user.id, 
            status='Pendiente'
        ).order_by(Task.date.asc()).all()
        
        stock_items = Stock.query.filter(Stock.quantity > 0).order_by(Stock.name).all()
        stock_categories = StockCategory.query.filter_by(parent_id=None).order_by(StockCategory.name).all()
        
        return render_template('tech_panel.html',
                             pending_tasks=pending_tasks,
                             stock_items=stock_items,
                             stock_categories=stock_categories,
                             today_date=date.today().strftime('%Y-%m-%d'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    try:
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        
        if not check_password_hash(current_user.password_hash, current_password):
            flash('Contraseña actual incorrecta', 'danger')
            return redirect(url_for('dashboard'))
        
        is_valid, message = validate_password(new_password)
        if not is_valid:
            flash(message, 'danger')
            return redirect(url_for('dashboard'))
        
        current_user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        
        flash('✅ Contraseña actualizada correctamente', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        print(f"Error changing password: {e}")
        flash('Error al cambiar la contraseña', 'danger')
        return redirect(url_for('dashboard'))

# --- GESTIÓN DE USUARIOS ---
@app.route('/manage_users', methods=['POST'])
@login_required
def manage_users():
    if current_user.role != 'admin':
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    
    action = request.form.get('action')
    
    try:
        if action == 'add':
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '')
            role = request.form.get('role', 'tech')
            
            # ✅ VALIDACIONES MEJORADAS
            if not username or not email or not password:
                flash('Todos los campos son obligatorios', 'danger')
                return redirect(url_for('dashboard'))
            
            # Validar formato de email
            if not validate_email(email):
                flash('El formato del correo electrónico no es válido', 'danger')
                return redirect(url_for('dashboard'))
            
            # ✅ VALIDACIÓN: Verificar username único
            if User.query.filter_by(username=username).first():
                flash('Ya existe un usuario con ese nombre', 'danger')
                return redirect(url_for('dashboard'))
            
            # ✅ VALIDACIÓN: Verificar email único
            if User.query.filter_by(email=email).first():
                flash('Ya existe un usuario con ese correo electrónico', 'danger')
                return redirect(url_for('dashboard'))
            
            # Validar contraseña
            is_valid, message = validate_password(password)
            if not is_valid:
                flash(message, 'danger')
                return redirect(url_for('dashboard'))
            
            new_user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                role=role
            )
            db.session.add(new_user)
            db.session.commit()
            
            flash(f'Usuario {username} creado correctamente', 'success')
        
        elif action == 'delete':
            user_id = request.form.get('user_id')
            user = User.query.get(user_id)
            
            if user and user.id != current_user.id:
                # ✅ Verificar si tiene tareas asignadas
                if user.tasks:
                    flash(f'No se puede eliminar el usuario porque tiene {len(user.tasks)} tareas asignadas', 'danger')
                    return redirect(url_for('dashboard'))
                
                db.session.delete(user)
                db.session.commit()
                flash('Usuario eliminado correctamente', 'success')
            else:
                flash('No puedes eliminar tu propio usuario', 'danger')
        
        else:
            flash('Acción no válida', 'danger')
    
    except IntegrityError as e:
        db.session.rollback()
        print(f"Error de integridad en manage_users: {str(e)}")
        if 'username' in str(e).lower():
            flash('Error: El nombre de usuario ya existe', 'danger')
        elif 'email' in str(e).lower():
            flash('Error: El correo electrónico ya existe', 'danger')
        else:
            flash('Error de integridad en la base de datos', 'danger')
    except SQLAlchemyError as e:
        db.session.rollback()
        print(f"Error en manage_users: {str(e)}")
        flash('Error al procesar la solicitud', 'danger')
    
    return redirect(url_for('dashboard'))

# --- GESTIÓN DE CLIENTES ---
@app.route('/manage_clients', methods=['POST'])
@login_required
def manage_clients():
    if current_user.role != 'admin':
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    
    action = request.form.get('action')
    
    if action == 'add':
        name = request.form.get('name')
        phone = request.form.get('phone')
        email = request.form.get('email')
        address = request.form.get('address')
        link = request.form.get('link', '')
        notes = request.form.get('notes', '')
        has_support = request.form.get('has_support') == 'on'
        support_schedule = request.form.get('support_schedule', '') if has_support else None
        
        if Client.query.filter_by(name=name).first():
            flash('Ya existe un cliente con ese nombre', 'danger')
            return redirect(url_for('dashboard'))
        
        new_client = Client(
            name=name,
            phone=phone,
            email=email,
            address=address,
            link=link,
            notes=notes,
            has_support=has_support,
            support_schedule=support_schedule if support_schedule else None
        )
        db.session.add(new_client)
        db.session.commit()
        
        flash(f'Cliente {name} añadido correctamente', 'success')
    
    elif action == 'edit':
        client_id = request.form.get('client_id')
        client = Client.query.get(client_id)
        
        if client:
            # Verificar si el nombre está siendo cambiado y si ya existe otro cliente con ese nombre
            new_name = request.form.get('name')
            if new_name != client.name:
                existing_client = Client.query.filter_by(name=new_name).first()
                if existing_client:
                    flash('Ya existe un cliente con ese nombre', 'danger')
                    return redirect(url_for('dashboard'))
            
            client.name = new_name
            client.phone = request.form.get('phone')
            client.email = request.form.get('email')
            client.address = request.form.get('address')
            client.link = request.form.get('link', '')
            client.notes = request.form.get('notes', '')
            has_support_value = request.form.get('has_support')
            client.has_support = (has_support_value == 'on' or has_support_value == 'true')
            # ✅ NUEVO: guardar horario de soporte
            client.support_schedule = request.form.get('support_schedule', '') if client.has_support else None
            
            db.session.commit()
            flash('Cliente actualizado correctamente', 'success')
    
    elif action == 'delete':
        client_id = request.form.get('client_id')
        client = Client.query.get(client_id)
        
        if client:
            db.session.delete(client)
            db.session.commit()
            flash('Cliente eliminado correctamente', 'success')
    
    return redirect(url_for('dashboard'))

# --- GESTIÓN DE TIPOS DE SERVICIO ---
@app.route('/manage_services', methods=['POST'])
@login_required
def manage_services():
    if current_user.role != 'admin':
        flash('No autorizado', 'danger')
        return redirect(url_for('dashboard'))
    
    action = request.form.get('action')
    
    if action == 'add':
        name = request.form.get('name')
        color = request.form.get('color', '#6c757d')
        
        if ServiceType.query.filter_by(name=name).first():
            flash('Ya existe un tipo de servicio con ese nombre', 'danger')
            return redirect(url_for('dashboard'))
        
        new_service = ServiceType(name=name, color=color)
        db.session.add(new_service)
        db.session.commit()
        
        flash(f'Tipo de servicio {name} añadido correctamente', 'success')
    
    elif action == 'delete':
        service_id = request.form.get('service_id')
        service = ServiceType.query.get(service_id)
        
        if service:
            db.session.delete(service)
            db.session.commit()
            flash('Tipo de servicio eliminado correctamente', 'success')
    
    return redirect(url_for('dashboard'))

# --- GESTIÓN DE STOCK ---
@app.route('/manage_stock', methods=['POST'])
@login_required
def manage_stock():
    if current_user.role != 'admin':
        return jsonify({'success': False, 'msg': 'No autorizado'}), 403
    
    action = request.form.get('action')
    
    if action == 'add':
        try:
            name = request.form.get('name', '').strip()
            if not name:
                return jsonify({'success': False, 'msg': 'El nombre del producto es obligatorio'})

            # ✅ CORRECCIÓN CRÍTICA: usar subcategory_id si está seleccionado, si no usar category_id
            subcategory_id = request.form.get('subcategory_id', '').strip()
            category_id    = request.form.get('category_id', '').strip()
            final_category_id = subcategory_id if subcategory_id else category_id

            # Validar que la categoría exista (si se proporcionó)
            if final_category_id:
                cat = StockCategory.query.get(int(final_category_id))
                if not cat:
                    return jsonify({'success': False, 'msg': 'La categoría seleccionada no existe'})

            # ✅ CORRECCIÓN: int() dentro de try para evitar crash con valores inválidos
            try:
                quantity  = int(request.form.get('quantity', 0))
                min_stock = int(request.form.get('min_stock', 5))
            except (ValueError, TypeError):
                return jsonify({'success': False, 'msg': 'Los campos de cantidad deben ser números enteros'})

            if quantity < 0:
                return jsonify({'success': False, 'msg': 'La cantidad no puede ser negativa'})
            if min_stock < 0:
                return jsonify({'success': False, 'msg': 'El stock mínimo no puede ser negativo'})

            supplier    = request.form.get('supplier', '').strip()
            description = request.form.get('description', '').strip()

            new_item = Stock(
                name=name,
                category_id=int(final_category_id) if final_category_id else None,
                quantity=quantity,
                min_stock=min_stock,
                supplier=supplier,
                description=description
            )
            db.session.add(new_item)
            db.session.commit()
            check_low_stock()

            return jsonify({'success': True, 'msg': f'Producto "{name}" añadido correctamente'})

        except SQLAlchemyError as e:
            db.session.rollback()
            print(f"Error SQLAlchemy en manage_stock add: {str(e)}")
            return jsonify({'success': False, 'msg': 'Error al guardar en la base de datos'})
        except Exception as e:
            db.session.rollback()
            print(f"Error inesperado en manage_stock add: {str(e)}")
            return jsonify({'success': False, 'msg': f'Error inesperado: {str(e)}'})
    
    elif action == 'edit':  # ✅ NUEVA ACCIÓN PARA EDITAR
        item_id = request.form.get('item_id')
        item = Stock.query.get(item_id)
        
        if item:
            item.name = request.form.get('name')
            item.min_stock = int(request.form.get('min_stock', 5))
            item.supplier = request.form.get('supplier', '')
            item.category_id = int(request.form.get('category_id')) if request.form.get('category_id') else None
            
            db.session.commit()
            check_low_stock()
            return jsonify({'success': True, 'msg': 'Artículo actualizado correctamente'})
        
        return jsonify({'success': False, 'msg': 'Artículo no encontrado'})
    
    elif action == 'adjust':
        try:
            item_id = request.form.get('item_id')
            if not item_id:
                return jsonify({'success': False, 'msg': 'ID de artículo no proporcionado'})
            try:
                adjustment = int(request.form.get('adjustment', 0))
            except (ValueError, TypeError):
                return jsonify({'success': False, 'msg': 'El ajuste debe ser un número entero'})

            item = Stock.query.get(int(item_id))
            if not item:
                return jsonify({'success': False, 'msg': 'Artículo no encontrado'})

            new_qty = item.quantity + adjustment
            if new_qty < 0:
                return jsonify({'success': False, 'msg': f'Stock insuficiente. Stock actual: {item.quantity}'})

            item.quantity = new_qty
            db.session.commit()
            check_low_stock()
            return jsonify({'success': True, 'msg': 'Stock ajustado', 'new_quantity': item.quantity})
        except SQLAlchemyError as e:
            db.session.rollback()
            return jsonify({'success': False, 'msg': 'Error al ajustar el stock'})

    elif action == 'delete':
        try:
            item_id = request.form.get('item_id')
            if not item_id:
                return jsonify({'success': False, 'msg': 'ID de artículo no proporcionado'})
            item = Stock.query.get(int(item_id))
            if not item:
                return jsonify({'success': False, 'msg': 'Artículo no encontrado'})
            db.session.delete(item)
            db.session.commit()
            return jsonify({'success': True, 'msg': 'Artículo eliminado'})
        except SQLAlchemyError as e:
            db.session.rollback()
            return jsonify({'success': False, 'msg': 'Error al eliminar el artículo'})
    
    return jsonify({'success': False, 'msg': 'Acción no válida'})

@app.route('/manage_stock_categories', methods=['POST'])
@login_required
def manage_stock_categories():
    if current_user.role != 'admin':
        return jsonify({'success': False, 'msg': 'No autorizado'}), 403
    
    try:
        action = request.form.get('action')
        
        if action == 'add':
            name = request.form.get('name', '').strip()
            parent_id = request.form.get('parent_id', '').strip()
            
            if not name:
                return jsonify({'success': False, 'msg': 'El nombre de la categoría es obligatorio'})
            
            parent_id_val = int(parent_id) if parent_id and parent_id.isdigit() else None

            # ✅ CORRECCIÓN: verificar nombre único dentro del mismo nivel jerárquico
            duplicate = StockCategory.query.filter_by(name=name, parent_id=parent_id_val).first()
            if duplicate:
                return jsonify({'success': False, 'msg': f'Ya existe una {"subcategoría" if parent_id_val else "categoría"} con el nombre "{name}"'})
            
            # Validar que el padre exista si se especificó
            if parent_id_val:
                parent = StockCategory.query.get(parent_id_val)
                if not parent:
                    return jsonify({'success': False, 'msg': 'La categoría padre seleccionada no existe'})
                # No permitir subcategorías de subcategorías (máximo 2 niveles)
                if parent.parent_id is not None:
                    return jsonify({'success': False, 'msg': 'No se permiten más de 2 niveles de categorías'})
            
            new_category = StockCategory(
                name=name,
                parent_id=parent_id_val
            )
            db.session.add(new_category)
            db.session.commit()
            
            return jsonify({'success': True, 'msg': f'{"Subcategoría" if parent_id_val else "Categoría"} "{name}" creada correctamente', 'id': new_category.id})
        
        elif action == 'delete':
            category_id = request.form.get('category_id')
            category = StockCategory.query.get(category_id)
            
            if category:
                # Si tiene subcategorías, no permitir eliminar
                if category.subcategories:
                    return jsonify({'success': False, 'msg': 'No se puede eliminar una categoría con subcategorías'})
                
                # Los productos se quedan sin categoría (category_id = None)
                for item in category.items:
                    item.category_id = None
                
                db.session.delete(category)
                db.session.commit()
                
                return jsonify({'success': True, 'msg': 'Categoría eliminada'})
        
        return jsonify({'success': False, 'msg': 'Acción no válida'})
    
    except SQLAlchemyError as e:
        db.session.rollback()
        print(f"Error en manage_stock_categories: {str(e)}")
        return jsonify({'success': False, 'msg': f'Error en la base de datos: {str(e)}'})
    except Exception as e:
        db.session.rollback()
        print(f"Error inesperado en manage_stock_categories: {str(e)}")
        return jsonify({'success': False, 'msg': f'Error: {str(e)}'})

@app.route('/save_report', methods=['POST'])
@login_required
def save_report():
    """Guardar parte de trabajo desde el panel técnico"""
    try:
        linked_task_id = request.form.get('linked_task_id')
        client_name = request.form.get('client_name')
        service_type_name = request.form.get('service_type')
        task_date = datetime.strptime(request.form.get('date'), '%Y-%m-%d').date()
        entry_time = request.form.get('entry_time')
        exit_time = request.form.get('exit_time')
        description = request.form.get('description')
        parts_text = request.form.get('parts_text', '')
        
        # ✅ VALIDACIÓN: Campos obligatorios
        if not client_name or not entry_time or not exit_time:
            flash('⚠️ El nombre del cliente, hora de entrada y hora de salida son obligatorios', 'danger')
            return redirect(url_for('dashboard'))
        
        # Stock - Ahora soporta múltiples items con diferentes acciones
        stock_item_ids = request.form.getlist('stock_item_id[]')
        stock_qtys = request.form.getlist('stock_quantity[]')
        stock_actions = request.form.getlist('stock_action[]')
        
        # Firma digital (el campo HTML se llama 'signature_name', no 'signature_client_name')
        signature_data = request.form.get('signature_data')
        signature_name = request.form.get('signature_name') or request.form.get('signature_client_name', '')
        
        # Duración del cronómetro (formato HH:MM:SS, enviado desde el campo oculto)
        work_duration = request.form.get('work_duration', '').strip() or None
        
        if not signature_data:
            flash('⚠️ La firma del cliente es obligatoria', 'danger')
            return redirect(url_for('dashboard'))
        
        # Buscar cliente y servicio
        client = Client.query.filter_by(name=client_name).first()
        client_id = client.id if client else None
        
        service_type = ServiceType.query.filter_by(name=service_type_name).first()
        if not service_type:
            flash('Tipo de servicio no válido', 'danger')
            return redirect(url_for('dashboard'))
        
        # ✅ MEJORA: Procesar múltiples items de stock con diferentes acciones
        stock_items_used = []
        for i, item_id in enumerate(stock_item_ids):
            if item_id and item_id != '' and int(item_id) > 0:
                qty = int(stock_qtys[i]) if i < len(stock_qtys) and stock_qtys[i] else 0
                action = stock_actions[i] if i < len(stock_actions) else 'usar'
                
                if qty > 0:
                    stock_item = Stock.query.get(int(item_id))
                    if stock_item:
                        # Actualizar cantidad en stock según la acción
                        if action in ['usar', 'retirar']:
                            if stock_item.quantity >= qty:
                                stock_item.quantity -= qty
                            else:
                                flash(f'⚠️ No hay suficiente stock de {stock_item.name}', 'danger')
                                db.session.rollback()
                                return redirect(url_for('dashboard'))
                        elif action == 'devolver':
                            stock_item.quantity += qty
                        
                        stock_items_used.append({
                            'id': stock_item.id,
                            'name': stock_item.name,
                            'quantity': qty,
                            'action': action
                        })
        
        # Si hay una cita vinculada, actualizar esa tarea
        if linked_task_id and linked_task_id != 'none':
            task = Task.query.get(int(linked_task_id))
            if task and task.tech_id == current_user.id:
                # Actualizar la tarea existente
                task.description = description
                task.parts_text = parts_text
                task.signature_data = signature_data
                task.signature_client_name = signature_name
                task.signature_timestamp = datetime.now()
                task.status = 'Completado'
                task.work_end_time = datetime.now()
                if work_duration:
                    task.work_duration = work_duration
                
                # Guardar items de stock
                if stock_items_used:
                    task.stock_item_id = stock_items_used[0]['id']
                    task.stock_quantity_used = stock_items_used[0]['quantity']
                    task.stock_action = stock_items_used[0]['action']
                    if len(stock_items_used) > 1:
                        stock_details = ', '.join([f"{item['name']} ({item['quantity']}) - {item['action']}" for item in stock_items_used])
                        task.parts_text = f"{parts_text}\n[Stock: {stock_details}]" if parts_text else f"[Stock: {stock_details}]"
                
                # ✅ MEJORA: Manejar archivos adjuntos con metadatos completos
                if 'attachments' in request.files:
                    files = request.files.getlist('attachments')
                    attachments_data = []
                    
                    # Cargar attachments existentes si los hay
                    if task.attachments:
                        try:
                            attachments_data = json.loads(task.attachments)
                            if not isinstance(attachments_data, list):
                                attachments_data = []
                        except:
                            attachments_data = []
                    
                    for file in files:
                        if file and file.filename and allowed_file(file.filename):
                            original_filename = secure_filename(file.filename)
                            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                            saved_filename = f"task_{task.id}_{timestamp}_{original_filename}"
                            filepath = os.path.join(app.config['UPLOAD_FOLDER'], saved_filename)
                            file.save(filepath)
                            
                            # Guardar con metadatos
                            attachments_data.append({
                                'filename': saved_filename,
                                'original_name': original_filename,
                                'size': os.path.getsize(filepath)
                            })
                    
                    if attachments_data:
                        task.attachments = json.dumps(attachments_data)
                
                db.session.commit()
                check_low_stock()
                
                flash('✅ Parte vinculado completado y firmado correctamente.', 'success')
                return redirect(url_for('dashboard'))
        
        # Si no hay cita vinculada, crear una nueva tarea completada
        new_task = Task(
            tech_id=current_user.id,
            client_id=client_id,
            client_name=client_name,
            date=task_date,
            start_time=entry_time,
            end_time=exit_time,
            service_type_id=service_type.id,
            description=description,
            parts_text=parts_text,
            signature_data=signature_data,
            signature_client_name=signature_name,
            signature_timestamp=datetime.now(),
            status='Completado',
            work_end_time=datetime.now(),
            work_duration=work_duration
        )
        
        # Guardar items de stock
        if stock_items_used:
            new_task.stock_item_id = stock_items_used[0]['id']
            new_task.stock_quantity_used = stock_items_used[0]['quantity']
            new_task.stock_action = stock_items_used[0]['action']
            if len(stock_items_used) > 1:
                stock_details = ', '.join([f"{item['name']} ({item['quantity']}) - {item['action']}" for item in stock_items_used])
                new_task.parts_text = f"{parts_text}\n[Stock: {stock_details}]" if parts_text else f"[Stock: {stock_details}]"
        
        db.session.add(new_task)
        db.session.commit()
        
        # ✅ MEJORA: Manejar archivos adjuntos con metadatos completos
        if 'attachments' in request.files:
            files = request.files.getlist('attachments')
            attachments_data = []
            
            for file in files:
                if file and file.filename and allowed_file(file.filename):
                    original_filename = secure_filename(file.filename)
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    saved_filename = f"task_{new_task.id}_{timestamp}_{original_filename}"
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], saved_filename)
                    file.save(filepath)
                    
                    # Guardar con metadatos
                    attachments_data.append({
                        'filename': saved_filename,
                        'original_name': original_filename,
                        'size': os.path.getsize(filepath)
                    })
            
            if attachments_data:
                new_task.attachments = json.dumps(attachments_data)
                db.session.commit()
        
        check_low_stock()
        
        flash('✅ Parte de trabajo creado y firmado correctamente.', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        print(f"Error en save_report: {e}")
        flash(f'Error al guardar el parte: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/upload_task_file/<int:task_id>', methods=['POST'])
@login_required
def upload_task_file(task_id):
    task = Task.query.get_or_404(task_id)
    
    if current_user.role != 'admin' and current_user.id != task.tech_id:
        return jsonify({'success': False, 'msg': 'No autorizado'}), 403
    
    if 'file' not in request.files:
        return jsonify({'success': False, 'msg': 'No se envió ningún archivo'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'success': False, 'msg': 'Nombre de archivo vacío'}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"task_{task_id}_{timestamp}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        attachments = []
        if task.attachments:
            try:
                attachments = json.loads(task.attachments)
            except:
                pass
        
        attachments.append(filename)
        task.attachments = json.dumps(attachments)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'filename': filename,
            'msg': 'Archivo subido correctamente'
        })
    
    return jsonify({'success': False, 'msg': 'Tipo de archivo no permitido'}), 400

# --- API ENDPOINTS ---
@app.route('/api/tasks')
@login_required
def get_all_tasks():
    """Obtener todas las tareas para el calendario"""
    if current_user.role == 'admin':
        tech_id = request.args.get('tech_id')
        if tech_id:
            tasks = Task.query.filter_by(tech_id=int(tech_id)).all()
        else:
            tasks = Task.query.all()
    else:
        tasks = Task.query.filter_by(tech_id=current_user.id).all()
    
    events = []
    for task in tasks:
        service_type = ServiceType.query.get(task.service_type_id) if task.service_type_id else None
        color = service_type.color if service_type else '#6c757d'
        
        events.append({
            'id': task.id,
            'title': f"{task.client_name} - {service_type.name if service_type else 'Sin tipo'}",
            'start': f"{task.date}T{task.start_time}:00" if task.start_time else str(task.date),
            'end': f"{task.date}T{task.end_time}:00" if task.end_time else str(task.date),
            'backgroundColor': color,
            'borderColor': color,
            'extendedProps': {
                'client': task.client_name,
                'client_id': task.client_id,  # Agregar client_id para poder obtener más información
                'service_type': service_type.name if service_type else 'Sin tipo',
                'status': task.status,
                'tech_id': task.tech_id,
                'tech_name': task.tech.username if task.tech else 'Sin asignar',
                'desc': task.description or '',
                'has_signature': bool(task.signature_data)
            }
        })
    
    return jsonify(events)

@app.route('/api/clients_search')
@login_required
def api_clients_search():
    """API para autocompletado de clientes"""
    query = request.args.get('q', '').strip()
    
    if len(query) < 2:
        return jsonify([])
    
    clients = Client.query.filter(
        Client.name.ilike(f'%{query}%')
    ).order_by(Client.name).limit(10).all()
    
    return jsonify([{
        'id': c.id,
        'name': c.name,
        'phone': c.phone,
        'email': c.email,
        'address': c.address,
        'link': c.link,
        'has_support': c.has_support
    } for c in clients])

@app.route('/api/clients')
@login_required
def get_clients():
    """API para autocompletado de clientes (alias)"""
    return api_clients_search()

@app.route('/api/get_task_full/<int:task_id>')
@login_required
def get_task_full(task_id):
    """
    API para obtener datos completos de una tarea
    Usado cuando se selecciona una cita en el formulario de parte
    """
    task = Task.query.get_or_404(task_id)
    
    # Verificar permisos
    if current_user.role != 'admin' and current_user.id != task.tech_id:
        return jsonify({'success': False, 'msg': 'No autorizado'}), 403
    
    service_type = ServiceType.query.get(task.service_type_id) if task.service_type_id else None
    
    # ✅ INCLUIR INFORMACIÓN COMPLETA DEL CLIENTE
    client_info = None
    if task.client:
        client_info = {
            'name': task.client.name,
            'phone': task.client.phone,
            'email': task.client.email,
            'address': task.client.address,
            'link': task.client.link,
            'notes': task.client.notes,
            'has_support': task.client.has_support
        }
    
    return jsonify({
        'success': True,
        'data': {
            'id': task.id,
            'client_name': task.client_name,
            'client_info': client_info,  # ✅ AÑADIDO
            'date': task.date.strftime('%Y-%m-%d'),
            'start_time': task.start_time or '',
            'end_time': task.end_time or '',
            'service_type': service_type.name if service_type else '',
            'description': task.description or ''
        }
    })

@app.route('/api/task/<int:task_id>')
@login_required
def get_task_details(task_id):
    task = Task.query.get_or_404(task_id)
    
    if current_user.role != 'admin' and current_user.id != task.tech_id:
        return jsonify({'success': False, 'msg': 'No autorizado'}), 403
    
    attachments_list = []
    if task.attachments:
        try:
            attachments_list = json.loads(task.attachments)
        except:
            pass
    
    service_type = ServiceType.query.get(task.service_type_id) if task.service_type_id else None
    
    # ✅ INCLUIR INFORMACIÓN COMPLETA DEL CLIENTE
    client_info = None
    if task.client:
        client_info = {
            'name': task.client.name,
            'phone': task.client.phone,
            'email': task.client.email,
            'address': task.client.address,
            'link': task.client.link,
            'notes': task.client.notes,
            'has_support': task.client.has_support
        }
    
    return jsonify({
        'success': True,
        'data': {
            'id': task.id,
            'client_name': task.client_name,
            'client_info': client_info,  # ✅ AÑADIDO
            'date': task.date.strftime('%Y-%m-%d'),
            'start_time': task.start_time,
            'end_time': task.end_time,
            'service_type': service_type.name if service_type else 'Sin tipo',
            'service_type_id': task.service_type_id,
            'description': task.description,
            'parts_text': task.parts_text,
            'status': task.status,
            'tech_name': task.tech.username if task.tech else 'SIN TÉCNICO',
            'tech_id': task.tech_id,
            'attachments': attachments_list,
            'has_signature': bool(task.signature_data),
            'signature_client_name': task.signature_client_name,
            'signature_timestamp': task.signature_timestamp.strftime('%d/%m/%Y %H:%M') if task.signature_timestamp else None,
            'work_start_time': task.work_start_time.strftime('%H:%M') if task.work_start_time else None,
            'work_end_time': task.work_end_time.strftime('%H:%M') if task.work_end_time else None,
            'work_duration': task.work_duration or None,
            'stock_info': {
                'item_name': task.stock_item.name if task.stock_item else None,
                'quantity': task.stock_quantity_used,
                'action': task.stock_action
            } if task.stock_item else None
        }
    })

# ====== NUEVA RUTA: TECH_ANALYTICS (CORREGIDA - SIN INGRESOS NI TOP CLIENTES) ======
@app.route('/api/tech_analytics')
@login_required
def get_tech_analytics():
    """Estadísticas del técnico actual (para panel técnico)"""
    period = request.args.get('period', '30')
    
    # Calcular fecha de inicio según período
    if period == 'all':
        start_date = date(2020, 1, 1)  # Fecha arbitraria en el pasado
    else:
        days = int(period)
        start_date = date.today() - timedelta(days=days)
    
    # Obtener tareas del técnico en el período
    tasks = Task.query.filter(
        Task.tech_id == current_user.id,
        Task.status == 'Completado',
        Task.date >= start_date
    ).all()
    
    # Calcular estadísticas
    total_services = len(tasks)
    total_maintenances = sum(1 for t in tasks if t.service_type and 'manten' in t.service_type.name.lower())
    
    # Tiempo promedio
    total_time = 0
    time_count = 0
    for task in tasks:
        if task.work_start_time and task.work_end_time:
            duration = (task.work_end_time - task.work_start_time).total_seconds() / 3600
            total_time += duration
            time_count += 1
    
    avg_time = round(total_time / time_count, 1) if time_count > 0 else 0
    
    # Distribución por tipo de servicio
    service_distribution = {}
    for task in tasks:
        service_name = task.service_type.name if task.service_type else 'Sin tipo'
        service_distribution[service_name] = service_distribution.get(service_name, 0) + 1
    
    # Timeline de los últimos meses
    timeline_data = []
    for i in range(5, -1, -1):
        month_date = date.today() - timedelta(days=i*30)
        month_start = month_date.replace(day=1)
        if i > 0:
            next_month = month_date + timedelta(days=30)
            month_end = next_month.replace(day=1)
        else:
            month_end = date.today()
        
        month_tasks = Task.query.filter(
            Task.tech_id == current_user.id,
            Task.date >= month_start,
            Task.date < month_end,
            Task.status == 'Completado'
        ).count()
        
        timeline_data.append({
            'month': month_start.strftime('%b'),
            'services': month_tasks,
            'maintenances': month_tasks // 3  # Estimación
        })
    
    return jsonify({
        'total_services': total_services,
        'total_maintenances': total_maintenances,
        'avg_time': avg_time,
        'service_distribution': service_distribution,
        'timeline_data': timeline_data
    })

@app.route('/api/tech_stats/<int:tech_id>')
@login_required
def get_tech_stats(tech_id):
    """Análisis individual de trabajador con lista detallada de servicios"""
    if current_user.role != 'admin':
        return jsonify({'success': False, 'msg': 'No autorizado'}), 403
    
    tech = User.query.get_or_404(tech_id)
    tasks = Task.query.filter_by(tech_id=tech_id, status='Completado').all()
    
    service_stats = {}
    total_time = 0
    
    for task in tasks:
        service_type = ServiceType.query.get(task.service_type_id) if task.service_type_id else None
        service_name = service_type.name if service_type else 'Sin tipo'
        
        if service_name not in service_stats:
            service_stats[service_name] = {
                'count': 0,
                'tasks': []
            }
        
        service_stats[service_name]['count'] += 1
        service_stats[service_name]['tasks'].append({
            'id': task.id,
            'client': task.client_name,
            'date': task.date.strftime('%d/%m/%Y'),
            'time': f"{task.start_time} - {task.end_time}" if task.start_time and task.end_time else 'No especificado',
            'description': task.description or 'Sin descripción',  # ✅ AÑADIDO
            'has_attachments': bool(task.attachments),
            'has_signature': bool(task.signature_data)
        })
        
        if task.work_start_time and task.work_end_time:
            duration = (task.work_end_time - task.work_start_time).total_seconds() / 3600
            total_time += duration
    
    return jsonify({
        'success': True,
        'data': {
            'tech_name': tech.username,
            'total_completed': len(tasks),
            'total_hours': round(total_time, 2),
            'service_breakdown': service_stats
        }
    })

@app.route('/api/admin_analytics')
@login_required
def get_admin_analytics():
    """Estadísticas globales para el administrador"""
    if current_user.role != 'admin':
        return jsonify({'success': False, 'msg': 'No autorizado'}), 403
    
    tech_id = request.args.get('tech_id', type=int)
    period = request.args.get('period', 'all')
    
    query = Task.query
    
    if tech_id:
        query = query.filter_by(tech_id=tech_id)
    
    if period == 'week':
        week_ago = date.today() - timedelta(days=7)
        query = query.filter(Task.date >= week_ago)
    elif period == 'month':
        month_ago = date.today() - timedelta(days=30)
        query = query.filter(Task.date >= month_ago)
    
    all_tasks = query.all()
    completed_tasks = query.filter_by(status='Completado').all()
    pending_tasks = query.filter_by(status='Pendiente').all()
    
    task_types = {}
    total_for_percentage = len(completed_tasks) if completed_tasks else 1
    
    for task in completed_tasks:
        service_type = ServiceType.query.get(task.service_type_id) if task.service_type_id else None
        service_name = service_type.name if service_type else 'Sin tipo'
        service_color = service_type.color if service_type else '#6c757d'
        
        if service_name not in task_types:
            task_types[service_name] = {
                'count': 0,
                'color': service_color,
                'percentage': 0
            }
        
        task_types[service_name]['count'] += 1
    
    for service_name in task_types:
        count = task_types[service_name]['count']
        task_types[service_name]['percentage'] = round((count / total_for_percentage) * 100, 1)
    
    monthly_tasks = []
    for i in range(5, -1, -1):
        month_date = date.today() - timedelta(days=i*30)
        month_start = month_date.replace(day=1)
        if i > 0:
            next_month = month_date + timedelta(days=30)
            month_end = next_month.replace(day=1)
        else:
            month_end = date.today()
        
        month_tasks = Task.query.filter(
            Task.date >= month_start,
            Task.date < month_end,
            Task.status == 'Completado'
        )
        if tech_id:
            month_tasks = month_tasks.filter_by(tech_id=tech_id)
        
        monthly_tasks.append({
            'month': month_start.strftime('%b'),
            'count': month_tasks.count()
        })
    
    active_techs = User.query.filter_by(role='tech').count()
    
    return jsonify({
        'success': True,
        'data': {
            'total_tasks': len(all_tasks),
            'completed_tasks': len(completed_tasks),
            'pending_tasks': len(pending_tasks),
            'active_technicians': active_techs,
            'task_types': task_types,
            'monthly_tasks': monthly_tasks
        }
    })

@app.route('/api/tech_profile/<int:user_id>', methods=['GET'])
@login_required
def get_tech_profile(user_id):
    """Obtener perfil extendido de un técnico"""
    if current_user.role != 'admin':
        return jsonify({'success': False, 'msg': 'No autorizado'}), 403
    tech = User.query.filter_by(id=user_id, role='tech').first()
    if not tech:
        return jsonify({'success': False, 'msg': 'Técnico no encontrado'}), 404
    profile = tech.profile  # puede ser None si nunca se editó
    return jsonify({
        'success': True,
        'user': {'id': tech.id, 'username': tech.username, 'email': tech.email},
        'profile': {
            'full_name': profile.full_name if profile else '',
            'phone': profile.phone if profile else '',
            'address': profile.address if profile else '',
            'emergency_contact': profile.emergency_contact if profile else '',
            'emergency_phone': profile.emergency_phone if profile else '',
            'start_date': profile.start_date if profile else '',
            'dni': profile.dni if profile else '',
            'internal_notes': profile.internal_notes if profile else '',
            'updated_at': profile.updated_at.strftime('%d/%m/%Y %H:%M') if profile and profile.updated_at else ''
        }
    })

@app.route('/api/tech_profile/<int:user_id>', methods=['POST'])
@login_required
def save_tech_profile(user_id):
    """Guardar/actualizar perfil extendido de un técnico"""
    if current_user.role != 'admin':
        return jsonify({'success': False, 'msg': 'No autorizado'}), 403
    try:
        tech = User.query.filter_by(id=user_id, role='tech').first()
        if not tech:
            return jsonify({'success': False, 'msg': 'Técnico no encontrado'}), 404
        profile = tech.profile
        if not profile:
            profile = TechProfile(user_id=user_id)
            db.session.add(profile)
        profile.full_name = request.form.get('full_name', '').strip()
        profile.phone = request.form.get('phone', '').strip()
        profile.address = request.form.get('address', '').strip()
        profile.emergency_contact = request.form.get('emergency_contact', '').strip()
        profile.emergency_phone = request.form.get('emergency_phone', '').strip()
        profile.start_date = request.form.get('start_date', '').strip()
        profile.dni = request.form.get('dni', '').strip()
        profile.internal_notes = request.form.get('internal_notes', '').strip()
        profile.updated_at = datetime.now()
        db.session.commit()
        return jsonify({'success': True, 'msg': 'Perfil actualizado correctamente'})
    except SQLAlchemyError as e:
        db.session.rollback()
        print(f"Error guardando perfil técnico: {e}")
        return jsonify({'success': False, 'msg': 'Error al guardar el perfil'})

@app.route('/api/stock_categories')
@login_required
def get_stock_categories():
    """Obtener categorías de stock en formato jerárquico"""
    def build_tree(parent_id=None):
        categories = StockCategory.query.filter_by(parent_id=parent_id).all()
        result = []
        for cat in categories:
            result.append({
                'id': cat.id,
                'name': cat.name,
                'children': build_tree(cat.id),
                'items': [{'id': item.id, 'name': item.name, 'quantity': item.quantity, 'min_stock': item.min_stock, 'supplier': item.supplier or 'N/A'} 
                         for item in cat.items]
            })
        return result
    
    return jsonify(build_tree())

# ✅ NUEVA RUTA: Obtener info de un item de stock para editar
@app.route('/api/stock_item/<int:item_id>')
@login_required
def get_stock_item(item_id):
    """Obtener datos de un artículo de stock"""
    if current_user.role != 'admin':
        return jsonify({'success': False, 'msg': 'No autorizado'}), 403
    
    item = Stock.query.get_or_404(item_id)
    
    return jsonify({
        'success': True,
        'data': {
            'id': item.id,
            'name': item.name,
            'quantity': item.quantity,
            'min_stock': item.min_stock,
            'supplier': item.supplier or '',
            'category_id': item.category_id,
            'description': item.description or ''
        }
    })

# --- RUTAS DE ALARMAS ---
@app.route('/api/alarms')
@login_required
def get_alarms():
    if current_user.role != 'admin':
        return jsonify([])
    
    alarms = Alarm.query.order_by(Alarm.is_read.asc(), Alarm.created_at.desc()).all()
    return jsonify([{
        'id': a.id,
        'type': a.alarm_type,
        'title': a.title,
        'description': a.description,
        'client_name': a.client_name,
        'created_at': a.created_at.strftime('%d/%m/%Y %H:%M'),
        'is_read': a.is_read,
        'priority': a.priority
    } for a in alarms])

@app.route('/mark_alarm_read/<int:alarm_id>', methods=['POST'])
@login_required
def mark_alarm_read(alarm_id):
    if current_user.role != 'admin':
        return jsonify({'success': False}), 403
    
    alarm = Alarm.query.get_or_404(alarm_id)
    alarm.is_read = True
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/create_alarm', methods=['POST'])
@login_required
def create_alarm():
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    
    alarm_type = request.form.get('alarm_type')
    title = request.form.get('title')
    description = request.form.get('description')
    client_name = request.form.get('client_name', None)
    priority = request.form.get('priority', 'normal')
    
    new_alarm = Alarm(
        alarm_type=alarm_type,
        title=title,
        description=description,
        client_name=client_name,
        priority=priority
    )
    db.session.add(new_alarm)
    db.session.commit()
    
    flash('Alarma creada correctamente.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/print_report/<int:report_id>')
@login_required
def print_report(report_id):
    """Endpoint para imprimir/exportar reporte de trabajo"""
    try:
        task = Task.query.get_or_404(report_id)
        
        # Verificar permisos
        if current_user.role != 'admin' and task.tech_id != current_user.id:
            flash('No tienes permiso para ver este reporte', 'danger')
            return redirect(url_for('dashboard'))
        
        # Parsear archivos adjuntos si existen
        attachments_data = []
        if task.attachments:
            try:
                filenames = json.loads(task.attachments)
                for filename in filenames:
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    if os.path.exists(filepath):
                        file_size = os.path.getsize(filepath)
                        attachments_data.append({
                            'filename': filename,
                            'original_name': filename.split('_', 3)[-1] if '_' in filename else filename,
                            'size': file_size
                        })
            except Exception as e:
                print(f"Error parsing attachments: {e}")
                attachments_data = []
        
        return render_template('print_report.html', 
                             task=task,
                             attachments=attachments_data)
    except Exception as e:
        print(f"Error printing report {report_id}: {str(e)}")
        flash('Error al cargar el reporte', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/api/task_action/<int:task_id>/<action>', methods=['POST'])
@login_required
def task_action(task_id, action):
    """Endpoint para acciones sobre tareas (completar, eliminar, cancelar, toggle)"""
    task = Task.query.get_or_404(task_id)
    
    # Verificar permisos
    if current_user.role != 'admin' and task.tech_id != current_user.id:
        return jsonify({'success': False, 'msg': 'No autorizado'}), 403
    
    try:
        if action == 'complete':
            task.status = 'Completado'
            if not task.work_end_time:
                task.work_end_time = datetime.now()
            db.session.commit()
            return jsonify({'success': True, 'msg': 'Tarea completada', 'status': task.status})
        
        elif action == 'toggle':
            # Toggle entre Completado y Pendiente
            if task.status == 'Completado':
                task.status = 'Pendiente'
                task.work_end_time = None
            else:
                task.status = 'Completado'
                if not task.work_end_time:
                    task.work_end_time = datetime.now()
            db.session.commit()
            return jsonify({'success': True, 'msg': f'Tarea marcada como {task.status}', 'status': task.status})
        
        elif action == 'delete':
            db.session.delete(task)
            db.session.commit()
            return jsonify({'success': True, 'msg': 'Tarea eliminada'})
        
        elif action == 'cancel':
            task.status = 'Cancelado'
            db.session.commit()
            return jsonify({'success': True, 'msg': 'Tarea cancelada', 'status': task.status})
        
        else:
            return jsonify({'success': False, 'msg': 'Acción no válida'}), 400
    
    except Exception as e:
        print(f"Error in task_action: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'msg': 'Error al procesar la acción'}), 500

@app.route('/api/get_task/<int:task_id>')
@login_required
def get_task(task_id):
    """Obtener datos de una tarea específica"""
    task = Task.query.get_or_404(task_id)
    
    if current_user.role != 'admin' and task.tech_id != current_user.id:
        return jsonify({'success': False, 'msg': 'No autorizado'}), 403
    
    service_type = ServiceType.query.get(task.service_type_id) if task.service_type_id else None
    
    return jsonify({
        'success': True,
        'data': {
            'id': task.id,
            'client_name': task.client_name,
            'date': task.date.strftime('%Y-%m-%d'),
            'time': task.start_time or '',
            'service_type': service_type.name if service_type else '',
            'notes': task.description or ''
        }
    })

@app.route('/api/task_details/<int:task_id>')
@login_required
def api_task_details(task_id):
    """Obtener detalles completos de una tarea"""
    task = Task.query.get_or_404(task_id)
    
    if current_user.role != 'admin' and task.tech_id != current_user.id:
        return jsonify({'success': False, 'msg': 'No autorizado'}), 403
    
    service_type = ServiceType.query.get(task.service_type_id) if task.service_type_id else None
    
    # Parsear attachments
    attachments_list = []
    if task.attachments:
        try:
            attachments_list = json.loads(task.attachments)
        except:
            pass
    
    return jsonify({
        'success': True,
        'data': {
            'id': task.id,
            'client_name': task.client_name,
            'tech_name': task.tech.username if task.tech else 'Sin asignar',
            'date': task.date.strftime('%Y-%m-%d'),
            'start_time': task.start_time or '',
            'end_time': task.end_time or '',
            'service_type': service_type.name if service_type else 'Sin tipo',
            'status': task.status,
            'description': task.description or '',
            'parts_text': task.parts_text or '',
            'has_signature': bool(task.signature_data),
            'attachments': attachments_list,
            'stock_info': {
                'item_name': task.stock_item.name if task.stock_item else None,
                'quantity': task.stock_quantity_used,
                'action': task.stock_action
            } if task.stock_item else None
        }
    })

@app.route('/api/admin/all_tasks')
@login_required
def admin_all_tasks():
    """Endpoint para calendario global del admin"""
    if current_user.role != 'admin':
        return jsonify([])
    
    tasks = Task.query.all()
    events = []
    
    for task in tasks:
        service_type = ServiceType.query.get(task.service_type_id) if task.service_type_id else None
        color = service_type.color if service_type else '#6c757d'
        
        events.append({
            'id': task.id,
            'title': f"{task.client_name}",
            'start': f"{task.date}T{task.start_time}:00" if task.start_time else str(task.date),
            'end': f"{task.date}T{task.end_time}:00" if task.end_time else str(task.date),
            'backgroundColor': color,
            'borderColor': color,
            'extendedProps': {
                'client': task.client_name,
                'tech_name': task.tech.username if task.tech else 'Sin asignar',
                'service_type': service_type.name if service_type else 'Sin tipo',
                'status': task.status,
                'desc': task.description or '',
                'has_attachments': bool(task.attachments)
            }
        })
    
    return jsonify(events)

@app.route('/api/admin/tasks/<int:tech_id>')
@login_required
def admin_tech_tasks(tech_id):
    """Endpoint para calendario individual de un técnico desde admin"""
    if current_user.role != 'admin':
        return jsonify([])
    
    tasks = Task.query.filter_by(tech_id=tech_id).all()
    events = []
    
    for task in tasks:
        service_type = ServiceType.query.get(task.service_type_id) if task.service_type_id else None
        color = service_type.color if service_type else '#6c757d'
        
        events.append({
            'id': task.id,
            'title': f"{task.client_name}",
            'start': f"{task.date}T{task.start_time}:00" if task.start_time else str(task.date),
            'end': f"{task.date}T{task.end_time}:00" if task.end_time else str(task.date),
            'backgroundColor': color,
            'borderColor': color,
            'extendedProps': {
                'client': task.client_name,
                'service_type': service_type.name if service_type else 'Sin tipo',
                'status': task.status,
                'desc': task.description or ''
            }
        })
    
    return jsonify(events)

@app.route('/create_appointment', methods=['POST'])
@login_required
def create_appointment():
    """Endpoint para crear una nueva cita desde el panel técnico"""
    try:
        # Obtener datos del request (puede ser JSON o form)
        if request.is_json:
            data = request.json
            client_name = data.get('client_name')
            date_str = data.get('date')
            start_time = data.get('start_time')
            end_time = data.get('end_time', '')  # Opcional
            service_type_id = data.get('service_type_id')
            description = data.get('description', '')  # Opcional
        else:
            client_name = request.form.get('client_name')
            date_str = request.form.get('date')
            start_time = request.form.get('start_time')
            end_time = request.form.get('end_time', '')  # Opcional
            service_type_id = request.form.get('service_type_id')
            description = request.form.get('description', '')  # Opcional
        
        # Validación: SOLO estos 4 campos son obligatorios
        if not client_name or not date_str or not start_time or not service_type_id:
            return jsonify({
                'success': False, 
                'msg': 'Faltan campos obligatorios: Cliente, Fecha, Hora de inicio y Tipo de servicio son requeridos'
            }), 400
        
        # Buscar o crear cliente
        client = Client.query.filter_by(name=client_name).first()
        client_id = client.id if client else None
        
        # Convertir fecha
        task_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        
        # ✅ MEJORADO: Validación de duplicados con logging
        # Solo verifica si existe EXACTAMENTE la misma cita (mismo cliente, fecha, hora)
        print(f"🔍 Validando duplicados para: {client_name} | {task_date} | {start_time} | Tech: {current_user.id}")
        
        existing_task = Task.query.filter_by(
            tech_id=current_user.id,
            client_name=client_name,
            date=task_date,
            start_time=start_time,
            status='Pendiente'
        ).first()
        
        if existing_task:
            print(f"⚠️ Duplicado encontrado: Task ID {existing_task.id}")
            return jsonify({
                'success': False,
                'msg': f'Ya existe una cita pendiente para {client_name} el {task_date.strftime("%d/%m/%Y")} a las {start_time}'
            }), 400
        
        print(f"✅ No hay duplicados, creando cita...")
        
        # Crear tarea
        new_task = Task(
            tech_id=current_user.id,
            client_id=client_id,
            client_name=client_name,
            description=description if description else '',
            date=task_date,
            start_time=start_time,
            end_time=end_time if end_time else None,
            service_type_id=int(service_type_id),
            status='Pendiente'
        )
        
        db.session.add(new_task)
        db.session.commit()
        
        print(f"✅ Cita creada exitosamente: ID {new_task.id} | {client_name} | {task_date} | {start_time}")
        
        return jsonify({
            'success': True,
            'msg': 'Cita creada correctamente',
            'task_id': new_task.id
        })
        
    except Exception as e:
        print(f"Error creating appointment: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'msg': f'Error al crear la cita: {str(e)}'}), 500

@app.route('/edit_appointment/<int:task_id>', methods=['POST'])
@login_required
def edit_appointment(task_id):
    """Endpoint para editar una cita existente"""
    try:
        task = Task.query.get_or_404(task_id)
        
        # Verificar permisos
        if current_user.role != 'admin' and task.tech_id != current_user.id:
            flash('No autorizado', 'danger')
            return redirect(url_for('dashboard'))
        
        # Actualizar datos
        task.client_name = request.form.get('client_name')
        task.date = datetime.strptime(request.form.get('date'), '%Y-%m-%d').date()
        task.start_time = request.form.get('time')
        task.description = request.form.get('notes', '')
        
        # Actualizar tipo de servicio
        service_type_name = request.form.get('service_type')
        service_type = ServiceType.query.filter_by(name=service_type_name).first()
        if service_type:
            task.service_type_id = service_type.id
        
        db.session.commit()
        flash('Cita actualizada correctamente', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        print(f"Error editing appointment: {str(e)}")
        db.session.rollback()
        flash('Error al editar la cita', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/schedule_appointment', methods=['POST'])
@login_required
def schedule_appointment():
    """Endpoint para agendar nueva cita desde el panel admin"""
    try:
        if current_user.role != 'admin':
            flash('Solo administradores pueden agendar citas', 'danger')
            return redirect(url_for('dashboard'))
        
        tech_id = request.form.get('tech_id')
        client_name = request.form.get('client_name')
        date_str = request.form.get('date')
        time_str = request.form.get('time')
        service_type_name = request.form.get('service_type')
        notes = request.form.get('notes', '')
        
        # Validaciones
        if not all([tech_id, client_name, date_str, time_str, service_type_name]):
            flash('Todos los campos son obligatorios', 'danger')
            return redirect(url_for('dashboard'))
        
        # Buscar o crear cliente
        client = Client.query.filter_by(name=client_name).first()
        client_id = client.id if client else None
        
        # Buscar tipo de servicio
        service_type = ServiceType.query.filter_by(name=service_type_name).first()
        if not service_type:
            flash('Tipo de servicio no válido', 'danger')
            return redirect(url_for('dashboard'))
        
        # Convertir fecha
        task_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        
        # Crear tarea
        new_task = Task(
            tech_id=int(tech_id),
            client_id=client_id,
            client_name=client_name,
            description=notes,
            date=task_date,
            start_time=time_str,
            service_type_id=service_type.id,
            status='Pendiente'
        )
        
        db.session.add(new_task)
        db.session.commit()
        
        flash('Cita agendada correctamente', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        print(f"Error scheduling appointment: {str(e)}")
        db.session.rollback()
        flash('Error al agendar la cita', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/edit_stock_item/<int:item_id>', methods=['POST'])
@login_required
def edit_stock_item(item_id):
    """Endpoint para editar un elemento de stock"""
    try:
        if current_user.role != 'admin':
            return jsonify({'success': False, 'msg': 'No autorizado'}), 403
        
        item = Stock.query.get_or_404(item_id)
        
        name = request.form.get('name')
        quantity = request.form.get('quantity')
        min_stock = request.form.get('min_stock')
        supplier = request.form.get('supplier', '')
        description = request.form.get('description', '')
        category_id = request.form.get('category_id')
        
        if name:
            item.name = name
        if quantity is not None:
            item.quantity = int(quantity)
        if min_stock is not None:
            item.min_stock = int(min_stock)
        if supplier is not None:
            item.supplier = supplier
        if description is not None:
            item.description = description
        if category_id:
            item.category_id = int(category_id) if category_id != '' else None
        
        db.session.commit()
        check_low_stock()
        
        flash('Elemento actualizado correctamente', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        print(f"Error editing stock item: {str(e)}")
        db.session.rollback()
        flash('Error al actualizar el elemento', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/edit_stock_category/<int:category_id>', methods=['POST'])
@login_required
def edit_stock_category(category_id):
    """Endpoint para editar una categoría de stock"""
    try:
        if current_user.role != 'admin':
            return jsonify({'success': False, 'msg': 'No autorizado'}), 403
        
        category = StockCategory.query.get_or_404(category_id)
        
        name = request.form.get('name')
        parent_id = request.form.get('parent_id')
        
        if name:
            # Verificar que no exista otra categoría con el mismo nombre
            existing = StockCategory.query.filter(
                StockCategory.name == name,
                StockCategory.id != category_id
            ).first()
            
            if existing:
                flash('Ya existe una categoría con ese nombre', 'danger')
                return redirect(url_for('dashboard'))
            
            category.name = name
        
        if parent_id is not None:
            if parent_id == '':
                category.parent_id = None
            else:
                new_parent_id = int(parent_id)
                # Evitar ciclos: no puede ser padre de sí misma
                if new_parent_id == category_id:
                    flash('Una categoría no puede ser padre de sí misma', 'danger')
                    return redirect(url_for('dashboard'))
                # Evitar que una subcategoría se convierta en padre de su padre
                if category.parent_id == new_parent_id:
                    pass  # Sin cambios
                else:
                    category.parent_id = new_parent_id
        
        db.session.commit()
        flash('Categoría actualizada correctamente', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        print(f"Error editing category: {str(e)}")
        db.session.rollback()
        flash('Error al actualizar la categoría', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/api/stock_item/<int:item_id>')
@login_required
def api_get_stock_item(item_id):
    """API para obtener detalles de un elemento de stock"""
    try:
        item = Stock.query.get_or_404(item_id)
        return jsonify({
            'success': True,
            'data': {
                'id': item.id,
                'name': item.name,
                'quantity': item.quantity,
                'min_stock': item.min_stock,
                'supplier': item.supplier or '',
                'description': item.description or '',
                'category_id': item.category_id or ''
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'msg': str(e)}), 500

@app.route('/api/stock_category/<int:category_id>')
@login_required
def api_get_stock_category(category_id):
    """API para obtener detalles de una categoría de stock"""
    try:
        category = StockCategory.query.get_or_404(category_id)
        return jsonify({
            'success': True,
            'data': {
                'id': category.id,
                'name': category.name,
                'parent_id': category.parent_id or ''
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'msg': str(e)}), 500

@app.route('/api/task/<int:task_id>/attachments')
@login_required
def api_get_task_attachments(task_id):
    """API para obtener archivos adjuntos de una tarea"""
    try:
        task = Task.query.get_or_404(task_id)
        
        attachments_list = []
        if task.attachments:
            try:
                attachments_data = json.loads(task.attachments)
                if isinstance(attachments_data, list):
                    # Verificar si es formato nuevo (con metadatos) o antiguo (solo nombres)
                    for item in attachments_data:
                        if isinstance(item, dict):
                            # Formato nuevo: ya tiene metadata
                            # Asegurar que tiene todos los campos necesarios
                            attachments_list.append({
                                'filename': item.get('filename', ''),
                                'original_name': item.get('original_name', item.get('filename', 'archivo')),
                                'size': item.get('size', 0)
                            })
                        else:
                            # Formato antiguo: solo nombre de archivo (string)
                            filename = str(item)
                            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                            
                            # Extraer nombre original del filename
                            # Formato: task_X_TIMESTAMP_originalname.ext
                            parts = filename.split('_', 3)
                            original_name = parts[-1] if len(parts) >= 4 else filename
                            
                            # Obtener tamaño del archivo si existe
                            file_size = 0
                            if os.path.exists(filepath):
                                try:
                                    file_size = os.path.getsize(filepath)
                                except:
                                    file_size = 0
                            
                            attachments_list.append({
                                'filename': filename,
                                'original_name': original_name,
                                'size': file_size
                            })
            except json.JSONDecodeError as e:
                print(f"Error parsing attachments JSON: {e}")
                attachments_list = []
            except Exception as e:
                print(f"Error processing attachments: {e}")
                attachments_list = []
        
        return jsonify({
            'success': True,
            'attachments': attachments_list
        })
    except Exception as e:
        print(f"Error in api_get_task_attachments: {e}")
        return jsonify({'success': False, 'msg': str(e)}), 500

@app.route('/api/client/<int:client_id>')
@login_required
def api_get_client(client_id):
    """API para obtener información de un cliente"""
    try:
        client = Client.query.get_or_404(client_id)
        
        return jsonify({
            'success': True,
            'client': {
                'id': client.id,
                'name': client.name,
                'phone': client.phone,
                'email': client.email,
                'address': client.address,
                'link': client.link,
                'notes': client.notes,
                'has_support': client.has_support
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'msg': str(e)}), 500

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- ARCHIVOS ESTÁTICOS ---
@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    """Endpoint para descargar archivos adjuntos"""
    try:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Verificar que el archivo existe
        if not os.path.exists(filepath):
            print(f"Archivo no encontrado: {filepath}")
            return jsonify({'error': 'Archivo no encontrado'}), 404
        
        # Verificar que el archivo está dentro del directorio de uploads (seguridad)
        upload_folder = os.path.abspath(app.config['UPLOAD_FOLDER'])
        requested_path = os.path.abspath(filepath)
        
        if not requested_path.startswith(upload_folder):
            print(f"Intento de acceso fuera del directorio de uploads: {requested_path}")
            return jsonify({'error': 'Acceso denegado'}), 403
        
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except Exception as e:
        print(f"Error al servir archivo {filename}: {str(e)}")
        return jsonify({'error': f'Error al servir el archivo: {str(e)}'}), 500

# --- BLOQUE DE INICIALIZACIÓN ---
with app.app_context():
    db.create_all()
    
    # ✅ MIGRACIÓN: Ampliar columna 'password_hash' a VARCHAR(512) si es PostgreSQL
    try:
        from sqlalchemy import inspect, text as sa_text
        inspector = inspect(db.engine)
        if db.engine.dialect.name == 'postgresql':
            user_columns = {col['name']: col for col in inspector.get_columns('user')}
            ph_col = user_columns.get('password_hash')
            current_length = getattr(ph_col['type'], 'length', None) if ph_col else None
            if current_length is not None and current_length < 512:
                with db.engine.connect() as conn:
                    conn.execute(sa_text('ALTER TABLE "user" ALTER COLUMN password_hash TYPE VARCHAR(512)'))
                    conn.commit()
                    print("✓ Columna 'password_hash' ampliada a VARCHAR(512)")
    except Exception as e:
        print(f"Nota: Migración 'password_hash': {e}")

    # ✅ MIGRACIÓN: Añadir columna 'supplier' a Stock
    try:
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        stock_columns = [col['name'] for col in inspector.get_columns('stock')]
        
        if 'supplier' not in stock_columns:
            with db.engine.connect() as conn:
                conn.execute(db.text('ALTER TABLE stock ADD COLUMN supplier VARCHAR(100)'))
                conn.commit()
                print("✓ Columna 'supplier' añadida a Stock")
    except Exception as e:
        print(f"Nota: Migración 'supplier': {e}")
    
    # Migración: columna 'link'
    try:
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        columns = [col['name'] for col in inspector.get_columns('client')]
        if 'link' not in columns:
            with db.engine.connect() as conn:
                conn.execute(db.text('ALTER TABLE client ADD COLUMN link VARCHAR(500)'))
                conn.commit()
                print("✓ Columna 'link' añadida")
    except Exception as e:
        print(f"Nota: Migración de 'link': {e}")

    # ✅ MIGRACIÓN: Añadir columna 'work_duration' a Task
    try:
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        task_columns = [col['name'] for col in inspector.get_columns('task')]
        if 'work_duration' not in task_columns:
            with db.engine.connect() as conn:
                conn.execute(db.text('ALTER TABLE task ADD COLUMN work_duration VARCHAR(20)'))
                conn.commit()
                print("✓ Columna 'work_duration' añadida a Task")
    except Exception as e:
        print(f"Nota: Migración 'work_duration': {e}")

    # ✅ MIGRACIÓN: Añadir columna 'support_schedule' a Client
    try:
        inspector = inspect(db.engine)
        client_cols = [col['name'] for col in inspector.get_columns('client')]
        if 'support_schedule' not in client_cols:
            with db.engine.connect() as conn:
                conn.execute(db.text('ALTER TABLE client ADD COLUMN support_schedule VARCHAR(5)'))
                conn.commit()
                print("✓ Columna 'support_schedule' añadida a Client")
    except Exception as e:
        print(f"Nota: Migración 'support_schedule': {e}")
    
    # Usuarios de prueba
    if not User.query.filter_by(username='admin').first():
        db.session.add(User(
            username='admin',
            email='admin@oslaprint.com',
            role='admin', 
            password_hash=generate_password_hash('Admin123!')
        ))
    
    # 2. Técnico de prueba
    if not User.query.filter_by(username='tecnico').first():
        db.session.add(User(
            username='tecnico',
            email='tecnico@oslaprint.com',
            role='tech', 
            password_hash=generate_password_hash('Tecnico123!')
        ))
    
    # Tipos de Servicio
    if ServiceType.query.count() == 0:
        servicios = [
            {'name': 'Avería', 'color': '#fd7e14'},
            {'name': 'Revisión', 'color': '#0d6efd'},
            {'name': 'Instalación', 'color': '#6f42c1'},
            {'name': 'Mantenimiento', 'color': '#ffc107'},
            {'name': 'Otros servicios', 'color': '#20c997'}
        ]
        for s in servicios:
            db.session.add(ServiceType(name=s['name'], color=s['color']))
    
    # Categorías de Stock
    if StockCategory.query.count() == 0:
        copiadoras = StockCategory(name='Copiadoras')
        cajones = StockCategory(name='Cajones')
        tpv = StockCategory(name='TPV')
        recicladores = StockCategory(name='Recicladores')
        consumibles = StockCategory(name='Consumibles')
        
        db.session.add_all([copiadoras, cajones, tpv, recicladores, consumibles])
        db.session.commit()
        
        cashlogy = StockCategory(name='Cashlogy', parent_id=cajones.id)
        cashkeeper = StockCategory(name='Cashkeeper', parent_id=cajones.id)
        atca = StockCategory(name='ATCA', parent_id=cajones.id)
        
        db.session.add_all([cashlogy, cashkeeper, atca])
        db.session.commit()
    
    # Productos de Stock
    if Stock.query.count() == 0:
        copiadoras_cat = StockCategory.query.filter_by(name='Copiadoras').first()
        tpv_cat = StockCategory.query.filter_by(name='TPV').first()
        recicladores_cat = StockCategory.query.filter_by(name='Recicladores').first()
        consumibles_cat = StockCategory.query.filter_by(name='Consumibles').first()
        cashlogy_cat = StockCategory.query.filter_by(name='Cashlogy').first()
        cashkeeper_cat = StockCategory.query.filter_by(name='Cashkeeper').first()
        atca_cat = StockCategory.query.filter_by(name='ATCA').first()
        
        stock_items = [
            {'name': 'Copiadora HP LaserJet Pro', 'category_id': copiadoras_cat.id if copiadoras_cat else None, 'quantity': 3, 'min_stock': 1, 'supplier': 'HP España'},
            {'name': 'Copiadora Canon imageRUNNER', 'category_id': copiadoras_cat.id if copiadoras_cat else None, 'quantity': 2, 'min_stock': 1, 'supplier': 'Canon Iberia'},
            {'name': 'Cajón Cashlogy 1500', 'category_id': cashlogy_cat.id if cashlogy_cat else None, 'quantity': 5, 'min_stock': 2, 'supplier': 'Glory Global'},
            {'name': 'Cajón Cashlogy 2500', 'category_id': cashlogy_cat.id if cashlogy_cat else None, 'quantity': 3, 'min_stock': 1, 'supplier': 'Glory Global'},
            {'name': 'Cajón Cashkeeper Pro', 'category_id': cashkeeper_cat.id if cashkeeper_cat else None, 'quantity': 4, 'min_stock': 2, 'supplier': 'Cashkeeper Systems'},
            {'name': 'Cajón Cashkeeper Lite', 'category_id': cashkeeper_cat.id if cashkeeper_cat else None, 'quantity': 2, 'min_stock': 1, 'supplier': 'Cashkeeper Systems'},
            {'name': 'Cajón ATCA Standard', 'category_id': atca_cat.id if atca_cat else None, 'quantity': 3, 'min_stock': 1, 'supplier': 'ATCA Solutions'},
            {'name': 'Cajón ATCA Pro', 'category_id': atca_cat.id if atca_cat else None, 'quantity': 2, 'min_stock': 1, 'supplier': 'ATCA Solutions'},
            {'name': 'TPV Táctil 15"', 'category_id': tpv_cat.id if tpv_cat else None, 'quantity': 6, 'min_stock': 2, 'supplier': 'Epson POS'},
            {'name': 'TPV Táctil 17"', 'category_id': tpv_cat.id if tpv_cat else None, 'quantity': 4, 'min_stock': 2, 'supplier': 'Epson POS'},
            {'name': 'Reciclador 1', 'category_id': recicladores_cat.id if recicladores_cat else None, 'quantity': 2, 'min_stock': 1, 'supplier': 'Gunnebo'},
            {'name': 'Toner Genérico Negro', 'category_id': consumibles_cat.id if consumibles_cat else None, 'quantity': 15, 'min_stock': 5, 'supplier': 'Suministros Office'},
            {'name': 'Toner Genérico Color', 'category_id': consumibles_cat.id if consumibles_cat else None, 'quantity': 10, 'min_stock': 5, 'supplier': 'Suministros Office'},
        ]
        for item in stock_items:
            db.session.add(Stock(**item))
    
    # Cliente de ejemplo
    if Client.query.count() == 0:
        db.session.add(Client(
            name='Cliente Ejemplo',
            phone='900123456',
            email='ejemplo@cliente.com',
            address='Calle Ejemplo 1, Madrid',
            has_support=True
        ))
        
    db.session.commit()

# --- ARRANQUE ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)