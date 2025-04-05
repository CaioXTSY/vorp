import os
import re
import unicodedata
from datetime import datetime
from io import BytesIO
from pathlib import Path

import markdown
from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect, url_for, session,
    flash, jsonify, send_file
)
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import text
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from xhtml2pdf import pisa

# Pacotes necessários para envio de e-mail e token:
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

# Carrega variáveis de ambiente
load_dotenv()

# ---------------------------------------------------------------------------
# Configuração e Inicialização do App
# ---------------------------------------------------------------------------
app = Flask(__name__)
csrf = CSRFProtect(app)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'chave-secreta-trocar-em-producao')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///caiobook.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Pasta de uploads e extensões permitidas
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# Configurações de E-mail (Flask-Mail)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'   # ou smtp.sendgrid.net, etc.
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  # Ex: 'seuemail@gmail.com'
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # Senha de app
app.config['MAIL_DEFAULT_SENDER'] = ( 'VORP', os.getenv('MAIL_USERNAME') )

# Inicializa extensões
db = SQLAlchemy(app)
socketio = SocketIO(app, async_mode='threading')
mail = Mail(app)

# Itsdangerous serializer para gerar/validar tokens de reset de senha
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def generate_reset_token(email):
    """Gera um token para resetar a senha baseado no e-mail."""
    return serializer.dumps(email, salt='reset-senha')

def verify_reset_token(token, expiration=1800):
    """
    Verifica o token (expira em 1800 segundos = 30 min).
    Retorna o e-mail ou None se for inválido/expirado.
    """
    try:
        email = serializer.loads(token, salt='reset-senha', max_age=expiration)
    except:
        return None
    return email


# ---------------------------------------------------------------------------
# MODELOS (Models)
# ---------------------------------------------------------------------------
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    profile_photo = db.Column(db.String(200), nullable=True)
    full_name = db.Column(db.String(100), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    gender = db.Column(db.String(20), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    notes = db.relationship('Note', backref='user', lazy=True)
    versions = db.relationship('Version', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Note(db.Model):
    __tablename__ = 'note'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False)  # Link fixo
    content = db.Column(db.Text, nullable=False)
    is_public = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class Version(db.Model):
    __tablename__ = 'version'
    id = db.Column(db.Integer, primary_key=True)
    discipline = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


# ---------------------------------------------------------------------------
# FUNÇÕES AUXILIARES
# ---------------------------------------------------------------------------
def is_logged_in():
    return 'user_id' in session

def is_admin():
    return is_logged_in() and session.get('username') == 'admin'

def allowed_file(filename):
    ext = filename.rsplit('.', 1)[1].lower()
    return '.' in filename and ext in app.config['ALLOWED_EXTENSIONS']

def slugify(value):
    """
    Converte um texto em um slug amigável (usado em URLs).
    """
    value = unicodedata.normalize('NFKD', value).encode('ascii', 'ignore').decode('ascii')
    value = re.sub(r'[^\w\s-]', '', value).strip().lower()
    value = re.sub(r'[-\s]+', '-', value)
    return value

def generate_unique_slug(title):
    """
    Gera um slug único para cada nota, evitando duplicatas.
    """
    base_slug = slugify(title)
    slug = base_slug
    counter = 1
    while Note.query.filter_by(slug=slug).first() is not None:
        slug = f"{base_slug}-{counter}"
        counter += 1
    return slug

def update_schema():
    """
    Exemplo de lógica para atualizar o schema (opcional).
    Pode ser substituído por Flask-Migrate ou migrations.
    """
    result = db.session.execute(text("PRAGMA table_info(note)"))
    columns = [row[1] for row in result]
    if 'slug' not in columns:
        db.session.execute(text("ALTER TABLE note ADD COLUMN slug TEXT"))
        db.session.commit()
        notes = Note.query.all()
        for note in notes:
            if not note.slug:
                note.slug = generate_unique_slug(note.title)
        db.session.commit()


# ---------------------------------------------------------------------------
# CONTEXT PROCESSORS E TEMPLATE FILTERS
# ---------------------------------------------------------------------------
@app.context_processor
def inject_user():
    return {'is_logged_in': is_logged_in, 'is_admin': is_admin}

@app.context_processor
def inject_current_year():
    return {'current_year': datetime.utcnow().year}

@app.template_filter('datetime_format')
def datetime_format(value, format="%d/%m/%Y %H:%M"):
    if not value:
        return ""
    return value.strftime(format)


# ---------------------------------------------------------------------------
# ROTAS - AUTENTICAÇÃO
# ---------------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_form = request.form['username']
        password_form = request.form['password']
        user = User.query.filter_by(username=username_form).first()
        if user and user.check_password(password_form):
            session['user_id'] = user.id
            session['username'] = user.username
            flash("Login realizado com sucesso!", "success")
            return redirect(url_for('list_notes'))
        else:
            flash("Usuário ou senha inválidos.", "danger")
            return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash("Logout realizado com sucesso!", "success")
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if is_logged_in():
        flash("Você já está logado.", "info")
        return redirect(url_for('list_notes'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not username or not email or not password or not confirm_password:
            flash("Preencha todos os campos obrigatórios.", "danger")
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash("As senhas não coincidem.", "danger")
            return redirect(url_for('register'))
        
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Nome de usuário ou e-mail já existe.", "danger")
            return redirect(url_for('register'))
        
        new_user = User(
            username=username,
            email=email,
        )
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash("Usuário registrado com sucesso! Faça login.", "success")
        return redirect(url_for('login'))
    
    return render_template('register.html')


# ---------------------------------------------------------------------------
# ROTA - ESQUECI A SENHA (FORGOT PASSWORD)
# ---------------------------------------------------------------------------
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        user = User.query.filter_by(email=email).first()
        if user:
            token = generate_reset_token(user.email)
            reset_url = url_for('reset_password', token=token, _external=True)
            
            subject = "Recuperação de Senha - VORP"
            body = f"Olá, clique no link para redefinir sua senha:\n{reset_url}"
            
            msg = Message(subject, recipients=[email], body=body)
            mail.send(msg)

            flash("Verifique seu e-mail para redefinir a senha.", "info")
            return redirect(url_for('login'))
        else:
            flash("E-mail não encontrado.", "danger")
            return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = verify_reset_token(token)
    if not email:
        flash("Token inválido ou expirado.", "danger")
        return redirect(url_for('forgot_password'))
    
    user = User.query.filter_by(email=email).first_or_404()
    
    if request.method == 'POST':
        new_password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        if new_password != confirm_password or not new_password:
            flash("As senhas não coincidem ou estão vazias.", "danger")
            return redirect(url_for('reset_password', token=token))
        
        user.set_password(new_password)
        db.session.commit()
        flash("Senha atualizada com sucesso!", "success")
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)


# ---------------------------------------------------------------------------
# PERFIL DO USUÁRIO E EDIÇÃO
# ---------------------------------------------------------------------------
@app.route('/profile/<string:username>')
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    if is_logged_in() and session['user_id'] == user.id:
        notes = Note.query.filter_by(user_id=user.id).order_by(Note.updated_at.desc()).all()
    else:
        notes = Note.query.filter_by(user_id=user.id, is_public=True).order_by(Note.updated_at.desc()).all()
    
    notes_count = len(notes)
    created_at = user.created_at
    recent_notes = notes[:3]
    recent_activity_count = 5
    activity_percentage = 60
    streak_days = 3
    user_level = 2
    experience_points = 120
    level_progress = 40
    remaining_points = 80
    achievements = [
        {
            'name': 'Primeira Nota',
            'description': 'Crie a primeira nota',
            'icon': 'star',
            'unlocked': notes_count >= 1
        },
        {
            'name': 'Dez Notas',
            'description': 'Crie 10 notas',
            'icon': 'star',
            'unlocked': notes_count >= 10
        },
        {
            'name': 'Maratonista',
            'description': 'Acesse o sistema 7 dias consecutivos',
            'icon': 'fire',
            'unlocked': streak_days >= 7
        },
    ]
    
    return render_template(
        'profile.html',
        user=user,
        notes_count=notes_count,
        created_at=created_at,
        recent_notes=recent_notes,
        recent_activity_count=recent_activity_count,
        activity_percentage=activity_percentage,
        streak_days=streak_days,
        user_level=user_level,
        experience_points=experience_points,
        level_progress=level_progress,
        remaining_points=remaining_points,
        achievements=achievements
    )


@app.route('/profile_edit', methods=['GET', 'POST'])
def profile_edit():
    """
    Lida com a edição do perfil do usuário, incluindo upload de imagem e alteração de senha.
    """
    if not is_logged_in():
        flash("Você precisa estar logado para editar seu perfil.", "warning")
        return redirect(url_for('login'))

    user = User.query.get_or_404(session['user_id'])

    if request.method == 'POST':
        # Upload da foto de perfil, se houver
        if 'profile_image' in request.files:
            file = request.files['profile_image']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{datetime.now().timestamp()}-{file.filename}")
                upload_dir = os.path.join(app.static_folder, 'uploads')
                os.makedirs(upload_dir, exist_ok=True)
                file_path = os.path.join(upload_dir, filename)
                file.save(file_path)
                user.profile_photo = f"/static/uploads/{filename}"

        # Campos básicos
        user.username = request.form.get('username', user.username).strip()
        user.email = request.form.get('email', user.email).strip()
        user.bio = request.form.get('bio', user.bio)

        # Lidar com mudança de senha
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if new_password or confirm_password:
            if not user.check_password(current_password):
                flash("Senha atual incorreta.", "danger")
                return redirect(url_for('profile_edit'))
            if new_password != confirm_password:
                flash("Nova senha e confirmação não coincidem.", "danger")
                return redirect(url_for('profile_edit'))
            user.set_password(new_password)

        db.session.commit()
        flash("Perfil atualizado com sucesso!", "success")
        return redirect(url_for('profile', username=user.username))

    return render_template('profile_edit.html', user=user)


# ---------------------------------------------------------------------------
# ROTAS - NOTAS
# ---------------------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/notes')
def list_notes():
    if not is_logged_in():
        flash("Você precisa estar logado para acessar suas notas.", "warning")
        return redirect(url_for('login'))
    user_id = session.get('user_id')
    notes = Note.query.filter_by(user_id=user_id).order_by(Note.updated_at.desc()).all()
    return render_template('notes.html', notes=notes)

@app.route('/notes/new', methods=['POST'])
def new_note():
    if not is_logged_in():
        flash("Você precisa estar logado para criar notas.", "warning")
        return redirect(url_for('login'))
    
    title = request.form.get('title', '').strip()
    if not title:
        flash("O título não pode estar vazio.", "danger")
        return redirect(url_for('list_notes'))
    
    slug = generate_unique_slug(title)
    note = Note(title=title, slug=slug, content="", is_public=False, user_id=session['user_id'])
    db.session.add(note)
    db.session.commit()
    
    flash("Nota criada com sucesso!", "success")
    return redirect(url_for('list_notes'))

@app.route('/notes/<int:note_id>')
def view_note(note_id):
    note = Note.query.get_or_404(note_id)
    if not note.is_public:
        current_user_id = session.get('user_id', 0)
        if current_user_id != note.user_id:
            flash("Esta nota é privada.", "danger")
            return redirect(url_for('login'))
    md_instance = markdown.Markdown(extensions=['fenced_code', 'tables', 'toc', 'codehilite'])
    html_content = md_instance.convert(note.content)
    toc = md_instance.toc
    return render_template('view_note.html', note=note, html_content=html_content, toc=toc)

@app.route('/notes/<int:note_id>/edit', methods=['GET', 'POST'])
def edit_note(note_id):
    if not is_logged_in():
        flash("Você precisa estar logado para editar notas.", "warning")
        return redirect(url_for('login'))
    note = Note.query.get_or_404(note_id)
    if note.user_id != session['user_id']:
        flash("Você não tem permissão para editar esta nota.", "danger")
        return redirect(url_for('list_notes'))
    
    if request.method == 'POST':
        note.title = request.form['title'].strip()
        note.content = request.form['content']
        note.is_public = True if request.form.get('is_public') == 'on' else False
        db.session.commit()
        flash("Nota atualizada com sucesso!", "success")
        return redirect(url_for('view_note', note_id=note.id))
    return render_template('edit_note.html', note=note)

@app.route('/notes/<int:note_id>/delete', methods=['POST'])
def delete_note(note_id):
    if not is_logged_in():
        flash("Você precisa estar logado para excluir notas.", "warning")
        return redirect(url_for('login'))
    note = Note.query.get_or_404(note_id)
    if note.user_id != session['user_id']:
        flash("Você não tem permissão para excluir esta nota.", "danger")
        return redirect(url_for('list_notes'))
    db.session.delete(note)
    db.session.commit()
    flash("Nota excluída com sucesso.", "success")
    return redirect(url_for('list_notes'))

@app.route('/notes/<int:note_id>/toggle_public', methods=['POST'])
def toggle_public(note_id):
    if not is_logged_in():
        return jsonify({'status': 'error', 'message': 'Você precisa estar logado.'}), 403
    note = Note.query.get_or_404(note_id)
    if note.user_id != session['user_id']:
        return jsonify({'status': 'error', 'message': 'Você não tem permissão para alterar esta nota.'}), 403
    note.is_public = not note.is_public
    db.session.commit()
    share_link = ""
    if note.is_public:
        share_link = f"{request.host_url.rstrip('/')}/p/{note.slug}"
    return jsonify({'status': 'success', 'share_link': share_link})

@app.route('/p/<string:slug>')
def public_note(slug):
    note = Note.query.filter_by(slug=slug, is_public=True).first_or_404()
    md_instance = markdown.Markdown(extensions=['fenced_code', 'tables', 'toc', 'codehilite'])
    html_content = md_instance.convert(note.content)
    toc = md_instance.toc
    return render_template('view_note.html', note=note, html_content=html_content, toc=toc)


# ---------------------------------------------------------------------------
# EXPORTAÇÃO DE NOTAS E BANCO DE DADOS
# ---------------------------------------------------------------------------
@app.route('/export/<int:note_id>', methods=['GET'])
def export_note(note_id):
    note = Note.query.get_or_404(note_id)
    if not note.is_public and (not is_logged_in() or note.user_id != session.get('user_id')):
        flash("Acesso negado para exportar esta nota.", "danger")
        return redirect(url_for('login'))
    try:
        import markdown
        html_content = markdown.markdown(
            note.content, 
            extensions=['fenced_code', 'tables', 'codehilite']
        )
        css = """
        <style>
            body { 
                font-family: Arial, sans-serif;
                line-height: 1.6;
                margin: 2cm;
                font-size: 12pt;
            }
            h1 { 
                color: #2d3748;
                border-bottom: 2px solid #2d3748;
                font-size: 18pt;
            }
            h2 { font-size: 16pt; }
            h3 { font-size: 14pt; }
            ul, ol { 
                margin-left: 20px;
                margin-bottom: 15px;
            }
            li { 
                margin: 8px 0;
                text-align: justify;
            }
            strong { font-weight: bold; }
            pre {
                background: #f8f9fa;
                padding: 15px;
                border-radius: 5px;
                border: 1px solid #dee2e6;
                overflow-x: auto;
                font-family: Consolas, monospace;
                font-size: 10pt;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }
            th, td {
                border: 1px solid #dee2e6;
                padding: 12px;
                text-align: left;
            }
            th {
                background-color: #f8f9fa;
                font-weight: bold;
            }
        </style>
        """
        full_html = f"""
        <!DOCTYPE html>
        <html>
            <head>
                <meta charset="utf-8">
                <title>{note.title}</title>
                {css}
            </head>
            <body>
                {html_content}
            </body>
        </html>
        """
        pdf_buffer = BytesIO()
        pisa.CreatePDF(
            src=BytesIO(full_html.encode('utf-8')),
            dest=pdf_buffer,
            encoding='utf-8'
        )
        pdf_buffer.seek(0)
        return send_file(
            pdf_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f"{note.title}.pdf"
        )
    except Exception as e:
        app.logger.error(f"Erro na geração do PDF: {str(e)}")
        flash("Falha ao gerar PDF.", "danger")
        return redirect(url_for('view_note', note_id=note.id))


# ---------------------------------------------------------------------------
# ADMIN
# ---------------------------------------------------------------------------
@app.route('/admin')
def admin_page():
    if not is_admin():
        flash("Acesso negado. Permissões insuficientes.", "danger")
        return redirect(url_for('login'))
    all_notes = Note.query.order_by(Note.updated_at.desc()).all()
    return render_template('admin.html', notes=all_notes)

@app.route('/admin/users')
def admin_users():
    if not is_admin():
        flash("Acesso negado. Permissões insuficientes.", "danger")
        return redirect(url_for('login'))
    users = User.query.order_by(User.username).all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/users/<int:user_id>')
def admin_view_user(user_id):
    if not is_admin():
        flash("Acesso negado. Permissões insuficientes.", "danger")
        return redirect(url_for('login'))
    user = User.query.get_or_404(user_id)
    notes = Note.query.filter_by(user_id=user.id).order_by(Note.updated_at.desc()).all()
    return render_template('admin_user_detail.html', user=user, notes=notes)

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
def admin_delete_user(user_id):
    if not is_admin():
        flash("Acesso negado. Permissões insuficientes.", "danger")
        return redirect(url_for('login'))
    user = User.query.get_or_404(user_id)
    if user.username == 'admin':
        flash("Não é possível remover o usuário admin.", "danger")
        return redirect(url_for('admin_users'))
    user_notes = Note.query.filter_by(user_id=user.id).all()
    for note in user_notes:
        db.session.delete(note)
    db.session.delete(user)
    db.session.commit()
    flash("Usuário removido com sucesso.", "success")
    return redirect(url_for('admin_users'))

@app.route('/admin/notes')
def admin_notes():
    if not is_admin():
        flash("Acesso negado. Permissões insuficientes.", "danger")
        return redirect(url_for('login'))
    notes = Note.query.order_by(Note.updated_at.desc()).all()
    return render_template('admin_notes.html', notes=notes)


# ---------------------------------------------------------------------------
# INICIALIZAÇÃO DA APLICAÇÃO
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        update_schema()  # Exemplo, se precisar criar coluna 'slug' em 'note'
        # Cria usuário admin padrão, se não existir
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(username='admin', email='admin@example.com')
            admin_user.set_password('admin')
            db.session.add(admin_user)
            db.session.commit()

    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, debug=True, host='0.0.0.0', port=port, allow_unsafe_werkzeug=True)
