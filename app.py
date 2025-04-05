import os
import re
import uuid
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
from openai import OpenAI
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from xhtml2pdf import pisa
from sqlalchemy import text

# -----------------------------------------------------------------------------
# Carregamento das Variáveis de Ambiente
# -----------------------------------------------------------------------------
load_dotenv()

# -----------------------------------------------------------------------------
# Configuração e Inicialização do App
# -----------------------------------------------------------------------------
app = Flask(__name__)
csrf = CSRFProtect(app)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'chave-secreta-trocar-em-producao')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///caiobook.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

db = SQLAlchemy(app)
socketio = SocketIO(app, async_mode='threading')

# -----------------------------------------------------------------------------
# MODELOS (Models)
# -----------------------------------------------------------------------------
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    # Novos campos para o perfil
    profile_photo = db.Column(db.String(200), nullable=True)  # Caminho para a foto de perfil
    full_name = db.Column(db.String(100), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    gender = db.Column(db.String(20), nullable=True)  # Ex: "Masculino", "Feminino", "Outro"

    versions = db.relationship('Version', backref='user', lazy=True)
    notes = db.relationship('Note', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Version(db.Model):
    __tablename__ = 'version'
    id = db.Column(db.Integer, primary_key=True)
    discipline = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Note(db.Model):
    __tablename__ = 'note'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False)  # Link fixo para acesso público
    content = db.Column(db.Text, nullable=False)
    is_public = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# -----------------------------------------------------------------------------
# FUNÇÕES AUXILIARES (Helper Functions)
# -----------------------------------------------------------------------------
def is_logged_in():
    return 'user_id' in session

def is_admin():
    return is_logged_in() and session.get('username') == 'admin'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

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
    Verifica e atualiza o esquema da tabela 'note'. Se a coluna 'slug' não existir,
    ela é adicionada e os registros existentes são atualizados.
    """
    result = db.session.execute(text("PRAGMA table_info(note)"))
    columns = [row[1] for row in result]
    if 'slug' not in columns:
        app.logger.info("Coluna 'slug' não encontrada. Atualizando o esquema da tabela 'note'...")
        db.session.execute(text("ALTER TABLE note ADD COLUMN slug TEXT"))
        db.session.commit()
        # Atualiza as notas existentes definindo o slug com base no título
        notes = Note.query.all()
        for note in notes:
            if not note.slug:
                note.slug = generate_unique_slug(note.title)
        db.session.commit()
        app.logger.info("Esquema atualizado com sucesso.")

# -----------------------------------------------------------------------------
# CONTEXT PROCESSORS E TEMPLATE FILTERS
# -----------------------------------------------------------------------------
@app.context_processor
def inject_user():
    return {'is_logged_in': is_logged_in, 'is_admin': is_admin}

@app.context_processor
def inject_current_year():
    return {'current_year': datetime.utcnow().year}

@app.template_filter('datetime_format')
def datetime_format(value, format="%d/%m/%Y %H:%M"):
    if value is None:
        return ""
    return value.strftime(format)

# -----------------------------------------------------------------------------
# ROTAS - AUTENTICAÇÃO E PERFIL DO USUÁRIO
# -----------------------------------------------------------------------------
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
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        full_name = request.form.get('full_name', '').strip()
        bio = request.form.get('bio', '').strip()
        gender = request.form.get('gender', '').strip()

        if not username or not password or not confirm_password:
            flash("Preencha todos os campos obrigatórios.", "danger")
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash("As senhas não coincidem.", "danger")
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash("Nome de usuário já existe.", "danger")
            return redirect(url_for('register'))
        
        new_user = User(
            username=username,
            full_name=full_name,
            bio=bio,
            gender=gender
        )
        new_user.set_password(password)
        
        # Processa o upload da foto de perfil, se houver
        profile_photo_file = request.files.get('profile_photo')
        if profile_photo_file and allowed_file(profile_photo_file.filename):
            filename = secure_filename(f"{datetime.now().timestamp()}-{profile_photo_file.filename}")
            upload_dir = os.path.join(app.static_folder, 'uploads')
            os.makedirs(upload_dir, exist_ok=True)
            filepath = os.path.join(upload_dir, filename)
            profile_photo_file.save(filepath)
            new_user.profile_photo = f"/static/uploads/{filename}"
        
        db.session.add(new_user)
        db.session.commit()
        
        flash("Usuário registrado com sucesso! Faça login.", "success")
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/profile/<string:username>')
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    if is_logged_in() and session.get('user_id') == user.id:
        notes = Note.query.filter_by(user_id=user.id).order_by(Note.updated_at.desc()).all()
    else:
        notes = Note.query.filter_by(user_id=user.id, is_public=True).order_by(Note.updated_at.desc()).all()
    return render_template('profile.html', user=user, notes=notes)

# -----------------------------------------------------------------------------
# ROTAS - UPLOAD DE IMAGENS
# -----------------------------------------------------------------------------
@app.route('/upload-image', methods=['POST'])
def upload_image():
    if 'image' not in request.files:
        return jsonify({'error': 'No image uploaded'}), 400
    file = request.files['image']
    if file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(f"{datetime.now().timestamp()}-{file.filename}")
        upload_dir = os.path.join(app.static_folder, 'uploads')
        os.makedirs(upload_dir, exist_ok=True)
        filepath = os.path.join(upload_dir, filename)
        file.save(filepath)
        return jsonify({'url': f"/static/uploads/{filename}"})
    return jsonify({'error': 'Upload failed'}), 500

# -----------------------------------------------------------------------------
# ROTAS - GERENCIAMENTO DE NOTAS
# -----------------------------------------------------------------------------
@app.route('/')
def index():
    return render_template("index.html")

@app.route('/notes')
def list_notes():
    if not is_logged_in():
        flash("Você precisa estar logado para acessar suas notas.", "warning")
        return redirect(url_for('login'))
    try:
        user_id = int(session['user_id'])
    except (ValueError, TypeError):
        flash("Sessão inválida. Faça login novamente.", "danger")
        return redirect(url_for('login'))
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
        try:
            current_user_id = int(session.get('user_id', 0))
        except (ValueError, TypeError):
            current_user_id = 0
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
    try:
        current_user_id = int(session.get('user_id', 0))
    except (ValueError, TypeError):
        flash("Sessão inválida. Faça login novamente.", "danger")
        return redirect(url_for('login'))
    if note.user_id != current_user_id:
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
    try:
        current_user_id = int(session.get('user_id', 0))
    except (ValueError, TypeError):
        flash("Sessão inválida. Faça login novamente.", "danger")
        return redirect(url_for('login'))
    if note.user_id != current_user_id:
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
    try:
        current_user_id = int(session.get('user_id', 0))
    except (ValueError, TypeError):
        return jsonify({'status': 'error', 'message': 'Sessão inválida.'}), 403
    if note.user_id != current_user_id:
        return jsonify({'status': 'error', 'message': 'Você não tem permissão para alterar esta nota.'}), 403
    note.is_public = not note.is_public
    db.session.commit()
    share_link = ""
    if note.is_public:
        share_link = f"{request.host_url.rstrip('/')}/p/{note.slug}"
    return jsonify({'status': 'success', 'share_link': share_link})

# Rota para acesso público via slug
@app.route('/p/<string:slug>')
def public_note(slug):
    note = Note.query.filter_by(slug=slug, is_public=True).first_or_404()
    md_instance = markdown.Markdown(extensions=['fenced_code', 'tables', 'toc', 'codehilite'])
    html_content = md_instance.convert(note.content)
    toc = md_instance.toc
    return render_template('view_note.html', note=note, html_content=html_content, toc=toc)

# -----------------------------------------------------------------------------
# ROTAS - EXPORTAÇÃO DE NOTAS E BANCO DE DADOS
# -----------------------------------------------------------------------------
@app.route('/export/<int:note_id>', methods=['GET'])
def export_note(note_id):
    note = Note.query.get_or_404(note_id)
    if not note.is_public and (not is_logged_in() or note.user_id != session.get('user_id')):
        flash("Acesso negado para exportar esta nota.", "danger")
        return redirect(url_for('login'))
    try:
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

@app.route('/admin/export_db', methods=['GET'])
def export_db():
    if not is_admin():
        flash("Acesso negado. Permissões insuficientes.", "danger")
        return redirect(url_for('login'))
    
    db_uri = app.config['SQLALCHEMY_DATABASE_URI']
    if db_uri.startswith("sqlite:///"):
        db_filename = db_uri.replace("sqlite:///", "", 1)
        db_path = os.path.abspath(os.path.join(app.root_path, 'instance', db_filename))
    else:
        flash("Exportação de banco de dados não suportada para este tipo de URI.", "danger")
        return redirect(url_for('admin_page'))
    
    app.logger.info(f"Tentando exportar banco de dados a partir do caminho: {db_path}")
    
    if not os.path.exists(db_path):
        flash(f"Banco de dados não encontrado no caminho: {db_path}", "danger")
        return redirect(url_for('admin_page'))
    
    return send_file(db_path, as_attachment=True, download_name="caiobook.db", mimetype="application/octet-stream")

# -----------------------------------------------------------------------------
# ROTAS - ADMIN (Painel Administrativo)
# -----------------------------------------------------------------------------
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

# -----------------------------------------------------------------------------
# ROTAS - ASSISTENTE IA (OpenAI)
# -----------------------------------------------------------------------------
@app.route('/ask', methods=['POST'])
@csrf.exempt
def ask_question():
    data = request.get_json()
    question = data.get('question', '')
    context = data.get('context', '')
    conversation_history = data.get('history', [])
    conversation_history = conversation_history[-10:]
    
    try:
        client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
        messages = [
            {
                "role": "system",
                "content": f"""
Você é Bonny, uma assistente de estudos eficiente, focada e com um tom profissional. Utilize o contexto abaixo apenas se for relevante:

{context}

Regras de estilo:
- Seja direto e objetivo nas respostas.
- Respostas claras e informativas (máximo de 2 parágrafos).
- Use Markdown básico para formatação.
- Se a pergunta não estiver relacionada ao contexto ou fora do escopo de estudos, informe educadamente que não pode ajudar com esse assunto.
- Se não houver informações suficientes, solicite mais detalhes de forma concisa.
"""
            }
        ]
        for msg in conversation_history:
            role = msg.get("role", "user").lower()
            content = msg.get("content", "")
            if role not in ["system", "user", "assistant"]:
                role = "user"
            messages.append({"role": role, "content": content})
        messages.append({"role": "user", "content": question})
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            temperature=0.4,
            max_tokens=5000
        )
        answer = response.choices[0].message.content
        return jsonify({'answer': answer})
    except Exception as e:
        app.logger.error(f"OpenAI API Error: {str(e)}")
        return jsonify({'error': 'Erro ao processar a pergunta'}), 500

@app.route('/process-ai', methods=['POST'])
@csrf.exempt
def process_ai():
    data = request.get_json()
    action = data.get('action', '')
    text = data.get('text', '')
    
    if not text or not action:
        return jsonify({'error': 'Parâmetros inválidos'}), 400
    
    try:
        client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
        
        if action == 'summarize':
            system_prompt = "Você é um assistente especializado em resumir textos. Crie um resumo conciso do texto fornecido, mantendo os pontos principais."
            user_prompt = f"Resuma o seguinte texto em um parágrafo curto:\n\n{text}"
        elif action == 'enhance':
            system_prompt = "Você é um assistente especializado em melhorar a escrita. Melhore o texto fornecido, mantendo o significado original, mas tornando-o mais claro, conciso e profissional."
            user_prompt = f"Melhore o seguinte texto:\n\n{text}"
        elif action == 'format-md':
            system_prompt = "Você é um assistente especializado em formatação Markdown. Converta o texto fornecido em Markdown bem formatado, adicionando cabeçalhos, listas, ênfase e outros elementos apropriados."
            user_prompt = f"Converta o seguinte texto em Markdown bem formatado:\n\n{text}"
        elif action == 'explain':
            system_prompt = "Você é um assistente educacional especializado em explicar conceitos de forma clara e concisa."
            user_prompt = f"Explique o seguinte conceito de forma simples e educativa:\n\n{text}"
        elif action == 'translate':
            system_prompt = "Você é um assistente especializado em tradução. Traduza o texto fornecido para o português, mantendo o significado e o tom originais."
            user_prompt = f"Traduza o seguinte texto para o português:\n\n{text}"
        else:
            return jsonify({'error': 'Ação não reconhecida'}), 400
        
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.4,
            max_tokens=2000
        )
        
        result = response.choices[0].message.content
        return jsonify({'result': result})
    
    except Exception as e:
        app.logger.error(f"OpenAI API Error: {str(e)}")
        return jsonify({'error': 'Erro ao processar a solicitação'}), 500


@app.route('/profile/edit', methods=['GET', 'POST'])
def edit_profile():
    if not is_logged_in():
        flash("Você precisa estar logado para editar seu perfil.", "warning")
        return redirect(url_for('login'))

    user = User.query.get_or_404(session['user_id'])
    
    if request.method == 'POST':
        user.full_name = request.form.get('full_name', '').strip()
        user.bio = request.form.get('bio', '').strip()
        user.gender = request.form.get('gender', '').strip()
        
        # Processa o upload da nova foto de perfil, se houver
        profile_photo_file = request.files.get('profile_photo')
        if profile_photo_file and allowed_file(profile_photo_file.filename):
            filename = secure_filename(f"{datetime.now().timestamp()}-{profile_photo_file.filename}")
            upload_dir = os.path.join(app.static_folder, 'uploads')
            os.makedirs(upload_dir, exist_ok=True)
            filepath = os.path.join(upload_dir, filename)
            profile_photo_file.save(filepath)
            user.profile_photo = f"/static/uploads/{filename}"
        
        db.session.commit()
        flash("Perfil atualizado com sucesso!", "success")
        return redirect(url_for('profile', username=user.username))
    
    return render_template('profile_edit.html', user=user)



# -----------------------------------------------------------------------------
# INICIALIZAÇÃO DA APLICAÇÃO
# -----------------------------------------------------------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        update_schema()  # Atualiza o esquema se necessário, adicionando a coluna "slug"
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(username='admin')
            admin_user.set_password('admin')  # Alterar para produção
            db.session.add(admin_user)
            db.session.commit()

    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, debug=True, host='0.0.0.0', port=port, allow_unsafe_werkzeug=True)
