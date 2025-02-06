import os
from pathlib import Path
from flask import (
    Flask, render_template, request, redirect, url_for, session,
    flash, jsonify, send_file
)
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import markdown
from datetime import datetime
from xhtml2pdf import pisa
from io import BytesIO
from flask_wtf.csrf import CSRFProtect
from openai import OpenAI
from dotenv import load_dotenv
import uuid

load_dotenv()

app = Flask(__name__)
csrf = CSRFProtect(app)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'chave-secreta-trocar-em-producao')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///meu_notion.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

db = SQLAlchemy(app)
socketio = SocketIO(app, async_mode='threading')

# -----------------------------------------------------------------------------
# MODELS
# -----------------------------------------------------------------------------

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
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
    content = db.Column(db.Text, nullable=False)
    is_public = db.Column(db.Boolean, default=False)
    hack_link = db.Column(db.String(64), unique=True, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# -----------------------------------------------------------------------------
# HELPER FUNCTIONS
# -----------------------------------------------------------------------------

def is_logged_in():
    return 'user_id' in session

def is_admin():
    return is_logged_in() and session.get('username') == 'admin'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# -----------------------------------------------------------------------------
# LOGIN / LOGOUT
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

# -----------------------------------------------------------------------------
# UPLOAD DE IMAGENS
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
# NOTAS (Funcionalidade estilo HackMD)
# -----------------------------------------------------------------------------


@app.route('/')
def index():
    return render_template("index.html")


@app.route('/notes/<int:note_id>/toggle_public', methods=['POST'])
def toggle_public(note_id):
    if not is_logged_in():
        return jsonify({'status': 'error', 'message': 'Você precisa estar logado.'}), 403

    note = Note.query.get_or_404(note_id)

    if note.user_id != session['user_id']:
        return jsonify({'status': 'error', 'message': 'Você não tem permissão para alterar esta nota.'}), 403

    if not note.is_public:
        note.is_public = True
        note.hack_link = uuid.uuid4().hex[:8]
    else:
        note.is_public = False
        note.hack_link = None

    db.session.commit()

    share_link = ""
    if note.is_public:
        share_link = f"{request.host_url.rstrip('/')}/p/{note.hack_link}"

    return jsonify({'status': 'success', 'share_link': share_link})



@app.route('/admin')
def admin_page():
    if not is_admin():
        flash("Acesso negado. Permissões insuficientes.", "danger")
        return redirect(url_for('login'))
    # Para o admin, vamos listar todas as notas (por exemplo)
    all_notes = Note.query.order_by(Note.updated_at.desc()).all()
    return render_template('admin.html', notes=all_notes)


@app.route('/export/<int:note_id>', methods=['GET'])
def export_note(note_id):
    note = Note.query.get_or_404(note_id)
    # Se a nota for privada e o usuário não for o dono, não permite exportação
    if not note.is_public and (not is_logged_in() or note.user_id != session.get('user_id')):
        flash("Acesso negado para exportar esta nota.", "danger")
        return redirect(url_for('login'))
    try:
        # Converte o conteúdo Markdown para HTML
        html_content = markdown.markdown(
            note.content, 
            extensions=['fenced_code', 'tables', 'codehilite']
        )
        # CSS para formatação do PDF (você pode ajustar conforme necessário)
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


@app.route('/notes')
def list_notes():
    if not is_logged_in():
        flash("Você precisa estar logado para acessar suas notas.", "warning")
        return redirect(url_for('login'))
    user_id = session['user_id']
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
    
    # Cria a nota com conteúdo vazio e visibilidade padrão (por exemplo, privado)
    note = Note(title=title, content="", is_public=False, user_id=session['user_id'])
    db.session.add(note)
    db.session.commit()
    
    flash("Nota criada com sucesso!", "success")
    return redirect(url_for('list_notes'))


@app.route('/notes/<int:note_id>')
def view_note(note_id):
    note = Note.query.get_or_404(note_id)
    # Se a nota for privada, exige que o usuário seja o dono
    if not note.is_public:
        if not is_logged_in() or session['user_id'] != note.user_id:
            flash("Esta nota é privada.", "danger")
            return redirect(url_for('login'))
    
    # Converte o conteúdo Markdown para HTML e gera o TOC
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
        is_public = True if request.form.get('is_public') == 'on' else False
        note.is_public = is_public
        if is_public and not note.hack_link:
            note.hack_link = uuid.uuid4().hex[:8]
        elif not is_public:
            note.hack_link = None
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

# Rota para acesso público via hack link
@app.route('/p/<string:hack_link>')
def public_note(hack_link):
    note = Note.query.filter_by(hack_link=hack_link, is_public=True).first_or_404()
    md_instance = markdown.Markdown(extensions=['fenced_code', 'tables', 'toc', 'codehilite'])
    html_content = md_instance.convert(note.content)
    toc = md_instance.toc
    return render_template('view_note.html', note=note, html_content=html_content, toc=toc)


from datetime import datetime

# Adicione este filtro personalizado
@app.template_filter('datetime_format')
def datetime_format(value, format="%d/%m/%Y %H:%M"):
    """Filtro para formatar datas no Jinja"""
    if value is None:
        return ""
    return value.strftime(format)

# -----------------------------------------------------------------------------
# PERFIL DO USUÁRIO
# -----------------------------------------------------------------------------

@app.route('/profile/<string:username>')
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    if is_logged_in() and session['user_id'] == user.id:
        notes = Note.query.filter_by(user_id=user.id).order_by(Note.updated_at.desc()).all()
    else:
        notes = Note.query.filter_by(user_id=user.id, is_public=True).order_by(Note.updated_at.desc()).all()
    return render_template('profile.html', user=user, notes=notes)

# -----------------------------------------------------------------------------
# ASSISTENTE IA (OpenAI)
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

# -----------------------------------------------------------------------------
# CONTEXT PROCESSORS
# -----------------------------------------------------------------------------

@app.context_processor
def inject_user():
    return {'is_logged_in': is_logged_in, 'is_admin': is_admin}

@app.context_processor
def inject_current_year():
    return {'current_year': datetime.utcnow().year}

# -----------------------------------------------------------------------------
# INIT
# -----------------------------------------------------------------------------

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(username='admin')
            admin_user.set_password('admin')  # Change in production
            db.session.add(admin_user)
            db.session.commit()

    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, debug=True, host='0.0.0.0', port=port, allow_unsafe_werkzeug=True)
