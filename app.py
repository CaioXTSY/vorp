import os
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
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
load_dotenv()  # Carrega variáveis do .env



# ----------------------------------------------------------------
# Configuração Flask
# ----------------------------------------------------------------
app = Flask(__name__)
csrf = CSRFProtect(app)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'chave-secreta-trocar-em-producao')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///meu_notion.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

db = SQLAlchemy(app)
socketio = SocketIO(app, async_mode='threading')  # eventlet ou gevent também funcionam

# ----------------------------------------------------------------
# Modelos
# ----------------------------------------------------------------

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    # Relacionamentos
    versions = db.relationship('Version', backref='user', lazy=True)

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


# ----------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------

def is_logged_in():
    return 'user_id' in session

def is_admin():
    return is_logged_in() and session.get('username') == 'admin'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def list_periods(base_path='notebooks'):
    """
    Retorna um dicionário:
    {
      "Periodo1": ["Calculo.md", "Fisica.md", ...],
      "Periodo2": ["Programacao.md", "Estatistica.md", ...]
    }
    """
    structure = {}
    base_dir = Path(base_path)

    if not base_dir.exists():
        return structure

    for period_dir in sorted(base_dir.iterdir()):
        if period_dir.is_dir():
            md_files = [
                f.name for f in period_dir.iterdir()
                if f.is_file() and f.suffix == '.md' and not f.name.endswith('_questoes.md')
            ]
            structure[period_dir.name] = sorted(md_files)
    return structure

def list_all_md_files(base_path='notebooks'):
    """Retorna lista de tuplas (period, filename) de todos os .md existentes (exceto _questoes)."""
    all_files = []
    periods = list_periods(base_path)
    for period, files in periods.items():
        for f in files:
            all_files.append((period, f))
    return all_files

def get_questoes_filename(disc_md):
    base_name = disc_md.replace('.md', '')
    return f"{base_name}_questoes.md"

# Slugify básico
def slugify(text):
    return ''.join(e for e in text.lower() if e.isalnum() or e == '-').strip()


# ----------------------------------------------------------------
# Rotas: Login / Logout
# ----------------------------------------------------------------

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
            return redirect(url_for('index'))
        else:
            flash("Usuário ou senha inválidos.", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash("Logout realizado com sucesso!", "success")
    return redirect(url_for('index'))


# ----------------------------------------------------------------
# Rotas: Principal (Index)
# ----------------------------------------------------------------

@app.route('/')
def index():
    periods = list_periods()
    return render_template('index.html', periods=periods)


@app.route('/periodo/<string:period_name>')
def list_disciplines(period_name):
    periods = list_periods()
    if period_name not in periods:
        flash("Período não encontrado.", "danger")
        return redirect(url_for('index'))

    disciplines = periods[period_name]

    # Para cada disciplina, podemos tentar pegar o last modified do arquivo
    discipline_info = []
    for disc_file in disciplines:
        md_path = Path('notebooks') / period_name / disc_file
        if md_path.exists():
            updated_at = datetime.fromtimestamp(md_path.stat().st_mtime)
        else:
            updated_at = None
        discipline_info.append({
            'filename': disc_file,
            'updated_at': updated_at
        })

    if is_logged_in():
        user = User.query.get(session['user_id'])

    return render_template(
        'list_disciplines.html',
        period_name=period_name,
        disciplines=discipline_info,  # agora contém {'filename', 'updated_at'}
    )


@app.template_filter('markdown')
def markdown_filter(text):
    return markdown.markdown(
        text,
        extensions=['fenced_code', 'tables', 'codehilite']
    )


@app.route('/upload-image', methods=['POST'])
def upload_image():
    if 'image' not in request.files:
        return jsonify({'error': 'No image uploaded'}), 400
        
    file = request.files['image']
    if file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400
        
    if file:
        filename = secure_filename(f"{datetime.now().timestamp()}-{file.filename}")
        upload_dir = os.path.join(app.static_folder, 'uploads')
        os.makedirs(upload_dir, exist_ok=True)
        filepath = os.path.join(upload_dir, filename)
        file.save(filepath)
        return jsonify({'url': f"/static/uploads/{filename}"})
    
    return jsonify({'error': 'Upload failed'}), 500

@app.route('/view/<string:period_name>/<string:md_file>')
def view_markdown(period_name, md_file):
    md_path = Path('notebooks') / period_name / md_file
    if not md_path.exists():
        flash("Arquivo não encontrado.", "danger")
        return redirect(url_for('list_disciplines', period_name=period_name))

    with open(md_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Converter Markdown => HTML com TOC
    html_content = markdown.markdown(content, extensions=['fenced_code', 'tables', 'toc', 'codehilite'])
    # Gerar TOC separado
    md_instance = markdown.Markdown(extensions=['toc'])
    md_instance.convert(content)
    toc = md_instance.toc

    return render_template(
        'view_markdown.html',
        period_name=period_name,
        md_file=md_file,
        html_content=html_content,
        markdown_content=content,
        toc=toc,
    )


@app.route('/edit/<string:period_name>/<string:md_file>', methods=['GET', 'POST'])
def edit_markdown(period_name, md_file):
    if not is_logged_in():
        flash("Você precisa estar logado para editar.", "warning")
        return redirect(url_for('login'))

    md_path = Path('notebooks') / period_name / md_file
    if not md_path.exists():
        flash("Arquivo não encontrado.", "danger")
        return redirect(url_for('list_disciplines', period_name=period_name))

    if request.method == 'POST':
        new_content = request.form['markdown_content']
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        # Salvar versão
        version = Version(discipline=md_file.replace('.md', ''), content=new_content, user_id=session['user_id'])
        db.session.add(version)
        db.session.commit()
        flash("Arquivo atualizado com sucesso!", "success")
        # Notificar via SocketIO (opcional)
        socketio.emit('update_markdown', 
             {'period': period_name, 'file': md_file},
             to='all',  # Envia para todos os clientes
             namespace='/')
        return redirect(url_for('view_markdown', period_name=period_name, md_file=md_file))

    # GET
    with open(md_path, 'r', encoding='utf-8') as f:
        current_content = f.read()

    return render_template('edit_markdown.html',
                           period_name=period_name,
                           md_file=md_file,
                           current_content=current_content)


# ----------------------------------------------------------------
# Rotas: Admin
# ----------------------------------------------------------------

@app.route('/admin')
def admin_page():
    if not is_admin():
        flash("Acesso negado. Permissões insuficientes.", "danger")
        return redirect(url_for('login'))

    all_md = list_all_md_files()
    return render_template('admin.html', all_md=all_md)


@app.route('/admin/new', methods=['GET', 'POST'])
def admin_new_md():
    if not is_admin():
        flash("Acesso negado. Permissões insuficientes.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        period_name = request.form['period_name'].strip()
        discipline = request.form['discipline'].strip()
        content = request.form['content']

        if not period_name or not discipline:
            flash("Período e Disciplina são obrigatórios.", "warning")
            return redirect(url_for('admin_new_md'))

        # Monta nome do arquivo .md
        filename = secure_filename(discipline) + ".md"
        md_path = Path('notebooks') / period_name / filename

        md_path.parent.mkdir(parents=True, exist_ok=True)
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(content)

        # Salvar versão inicial
        version = Version(discipline=discipline, content=content, user_id=session['user_id'])
        db.session.add(version)
        db.session.commit()

        flash(f"Disciplina '{discipline}' criada com sucesso no período '{period_name}'.", "success")
        return redirect(url_for('admin_page'))

    return render_template('admin_new.html')


@app.route('/admin/delete/<string:period_name>/<string:md_file>', methods=['POST'])
def delete_discipline(period_name, md_file):
    """
    Exclui o arquivo .md do sistema de arquivos, bem como registros associados (versões, comentários, feedback).
    """
    if not is_admin():
        flash("Acesso negado. Permissões insuficientes.", "danger")
        return redirect(url_for('login'))

    # Exclui arquivo do FS
    md_path = Path('notebooks') / period_name / md_file
    if md_path.exists():
        md_path.unlink()  # remove o arquivo
        # Também remover o arquivo de questões, se existir
        questoes_path = Path('notebooks') / period_name / get_questoes_filename(md_file)
        if questoes_path.exists():
            questoes_path.unlink()

    # Remover registros no banco
    disc_name = md_file.replace('.md', '')
    # Versões
    Version.query.filter_by(discipline=disc_name).delete()
    db.session.commit()

    flash("Disciplina deletada com sucesso!", "success")
    return redirect(url_for('admin_page'))


# ----------------------------------------------------------------
# Rotas: Questões
# ----------------------------------------------------------------

@app.route('/questoes/<string:period_name>/<string:disc_file>')
def view_questoes(period_name, disc_file):
    questoes_file = get_questoes_filename(disc_file)
    md_path = Path('notebooks') / period_name / questoes_file

    if md_path.exists():
        with open(md_path, 'r', encoding='utf-8') as f:
            content = f.read()
        html_content = markdown.markdown(content, extensions=['fenced_code', 'tables', 'codehilite'])
    else:
        html_content = None

    return render_template('view_questoes.html',
                           period_name=period_name,
                           disc_file=disc_file,
                           questoes_file=questoes_file,
                           html_content=html_content)


@app.route('/questoes/<string:period_name>/<string:disc_file>/edit', methods=['GET', 'POST'])
def edit_questoes(period_name, disc_file):
    if not is_logged_in():
        flash("Você precisa estar logado para editar.", "warning")
        return redirect(url_for('login'))

    questoes_file = get_questoes_filename(disc_file)
    md_path = Path('notebooks') / period_name / questoes_file

    if request.method == 'POST':
        new_content = request.form['markdown_content']
        md_path.parent.mkdir(parents=True, exist_ok=True)
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        # Salvar versão
        version = Version(discipline=disc_file.replace('.md', '_questoes'), content=new_content, user_id=session['user_id'])
        db.session.add(version)
        db.session.commit()
        flash("Questões atualizadas com sucesso!", "success")
        return redirect(url_for('view_questoes', period_name=period_name, disc_file=disc_file))

    # GET
    if md_path.exists():
        with open(md_path, 'r', encoding='utf-8') as f:
            current_content = f.read()
    else:
        current_content = ""

    return render_template('edit_questoes.html',
                           period_name=period_name,
                           disc_file=disc_file,
                           questoes_file=questoes_file,
                           current_content=current_content)


# ----------------------------------------------------------------
# Rotas Adicionais (Favoritos, Comentários, Feedbacks, Exportar PDF)
# ----------------------------------------------------------------


@app.route('/export/<string:period_name>/<string:md_file>', methods=['GET'])
def export_markdown(period_name, md_file):
    md_path = Path('notebooks') / period_name / md_file
    if not md_path.exists():
        flash("Arquivo não encontrado.", "danger")
        return redirect(url_for('list_disciplines', period_name=period_name))

    try:
        # Ler conteúdo do Markdown
        with open(md_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Converter Markdown para HTML
        html_content = markdown.markdown(
            content,
            extensions=['fenced_code', 'tables', 'toc', 'codehilite']
        )

        # CSS para formatação profissional
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

        # HTML completo
        full_html = f"""
        <!DOCTYPE html>
        <html>
            <head>
                <meta charset="utf-8">
                <title>{md_file.replace('.md', '')}</title>
                {css}
            </head>
            <body>
                {html_content}
            </body>
        </html>
        """

        # Gerar PDF
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
            download_name=f"{md_file.replace('.md', '')}.pdf"
        )

    except Exception as e:
        app.logger.error(f"Erro na geração do PDF: {str(e)}")
        flash("Falha ao gerar PDF. Verifique o console para detalhes.", "danger")
        return redirect(url_for('view_markdown', period_name=period_name, md_file=md_file))


# ----------------------------------------------------------------
# Context Processors
# ----------------------------------------------------------------

@app.context_processor
def inject_user():
    return {
        'is_logged_in': is_logged_in,
        'is_admin': is_admin
    }

@app.context_processor
def inject_current_year():
    return {
        'current_year': datetime.utcnow().year
    }


# ----------------------------------------------------------------
# Inicialização do BD & Criação de Admin
# ----------------------------------------------------------------

@app.route('/ask', methods=['POST'])
@csrf.exempt
def ask_question():

    data = request.get_json()
    question = data.get('question')
    context = data.get('context', '')[:12000]

    try:
        # Cria cliente OpenAI
        client = OpenAI(
            api_key=os.getenv('OPENAI_API_KEY'),
        )

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": f"""
                Você é um assistente de estudos chamado CAIO. Responda perguntas com base no seguinte contexto:
                {context}
                
                Regras:
                - Se a pergunta não estiver relacionada ao contexto, diga: "Esta pergunta parece estar fora do contexto do material estudado."
                - Mantenha as respostas curtas e diretas (máximo 3 parágrafos)
                - Use markdown básico para formatação (negrito, itálico, listas)
                - Se relevante, relacione conceitos com aplicações práticas
                """},
                {"role": "user", "content": question}
            ],
            temperature=0.3,
            max_tokens=500
        )

        answer = response.choices[0].message.content
        return jsonify({'answer': answer})

    except Exception as e:
        app.logger.error(f"OpenAI API Error: {str(e)}")
        return jsonify({'error': 'Erro ao processar a pergunta'}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # Verifica se o admin existe; se não, cria
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(username='admin')
            admin_user.set_password('admin')  # Trocar para algo seguro
            db.session.add(admin_user)
            db.session.commit()

    socketio.run(app, debug=True)
