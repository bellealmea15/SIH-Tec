
# app.py
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from collections import defaultdict
import pandas as pd
import re, psycopg2, itertools, random, os, bcrypt
from psycopg2.extras import RealDictCursor
from functools import wraps

# --- CONFIGURAÇÃO ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'uma-chave-secreta-final-e-segura-2025'

def get_db_connection():
    return psycopg2.connect(os.environ.get("DATABASE_URL"), cursor_factory=RealDictCursor)

def inicializar_banco():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role VARCHAR(20) NOT NULL
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS professores (
            id SERIAL PRIMARY KEY,
            nome VARCHAR(100) UNIQUE NOT NULL
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS disciplinas (
            id SERIAL PRIMARY KEY,
            nome VARCHAR(100) NOT NULL,
            aulas_semanais INT,
            professor_id INT REFERENCES professores(id) ON DELETE CASCADE
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS disponibilidade (
            id SERIAL PRIMARY KEY,
            professor_id INT REFERENCES professores(id) ON DELETE CASCADE,
            dia_semana VARCHAR(20),
            periodo VARCHAR(20),
            disponivel BOOLEAN
        );
    """)

    conn.commit()
    cursor.close()
    conn.close()
    print("✅ Banco de dados inicializado com sucesso!")

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Por favor, faça login para acessar esta página."
login_manager.login_message_category = "warning"


class User(UserMixin):
    def __init__(self, id, username, role):
        self.id, self.username, self.role = id, username, role
    def is_admin(self): 
        return self.role == 'admin'


@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM usuarios WHERE id = %s", (user_id,))
    u = cursor.fetchone()
    cursor.close()
    conn.close()
    return User(id=u['id'], username=u['username'], role=u['role']) if u else None


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            flash("Acesso restrito a administradores.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


# --- ROTAS DE AUTENTICAÇÃO ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(id) FROM usuarios")
    user_count = cursor.fetchone()['count']
    registration_enabled = user_count == 0
    cursor.close()
    conn.close()

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM usuarios WHERE username = %s", (username,))
        user_data = cursor.fetchone()
        cursor.close()
        conn.close()

        if user_data and bcrypt.checkpw(password, user_data['password_hash'].encode('utf-8')):
            login_user(User(id=user_data['id'], username=user_data['username'], role=user_data['role']))
            return redirect(url_for('dashboard'))
        else:
            flash('Usuário ou senha inválidos.', 'danger')

    return render_template('login.html', registration_enabled=registration_enabled)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(id) FROM usuarios")
    user_count = cursor.fetchone()['count']

    if user_count > 0:
        flash('O registro público está desativado. Novos usuários só podem ser criados por um administrador.', 'warning')
        cursor.close()
        conn.close()
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
        role = 'admin'

        cursor.execute("INSERT INTO usuarios (username, password_hash, role) VALUES (%s, %s, %s)", 
                       (username, hashed_password.decode('utf-8'), role))
        conn.commit()
        cursor.close()
        conn.close()
        flash('Conta de Administrador criada com sucesso! Faça o login.', 'success')
        return redirect(url_for('login'))

    cursor.close()
    conn.close()
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html')


# --- ROTAS DE GESTÃO ---
@app.route('/professores')
@login_required
def gerenciar_professores():
    conn = get_db_connection()
    cursor = conn.cursor()
    search_query = request.args.get('q', '')
    query = "SELECT * FROM professores WHERE nome ILIKE %s ORDER BY nome"
    cursor.execute(query, (f'%{search_query}%',))
    professores = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('gerenciar_professores.html', professores=professores, search_query=search_query)


@app.route('/professores/adicionar', methods=['POST'])
@login_required
def adicionar_professor():
    nome = request.form['nome'].strip()
    if nome:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO professores (nome) VALUES (%s)", (nome,))
            conn.commit()
            flash("Professor adicionado com sucesso!", "success")
        except psycopg2.errors.UniqueViolation:
            flash("Este professor já existe.", "warning")
        finally:
            cursor.close()
            conn.close()
    return redirect(url_for('gerenciar_professores'))


@app.route('/professores/editar/<int:id>', methods=['POST'])
@login_required
def editar_professor(id):
    nome = request.form['nome'].strip()
    if nome:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE professores SET nome = %s WHERE id = %s", (nome, id))
        conn.commit()
        cursor.close()
        conn.close()
        flash("Professor atualizado com sucesso!", "success")
    return redirect(url_for('gerenciar_professores'))


@app.route('/professores/remover/<int:id>', methods=['POST'])
@login_required
def remover_professor(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM professores WHERE id = %s", (id,))
    conn.commit()
    cursor.close()
    conn.close()
    flash("Professor removido com sucesso!", "success")
    return redirect(url_for('gerenciar_professores'))

# --- ROTAS DE DISCIPLINAS ---
@app.route('/disciplinas')
@login_required
def gerenciar_disciplinas():
    conn = get_db_connection()
    cursor = conn.cursor()

    search_query = request.args.get('q', '')

    query = """
        SELECT d.id, d.nome, d.aulas_semanais, d.professor_id, p.nome AS professor_nome
        FROM disciplinas d
        LEFT JOIN professores p ON d.professor_id = p.id
        WHERE d.nome ILIKE %s OR p.nome ILIKE %s
        ORDER BY d.nome;
    """

    cursor.execute(query, (f'%{search_query}%', f'%{search_query}%'))
    disciplinas = cursor.fetchall()

    cursor.execute("SELECT id, nome FROM professores ORDER BY nome")
    professores = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        'gerenciar_disciplinas.html',
        disciplinas=disciplinas,
        professores=professores,
        search_query=search_query
    )


@app.route('/disciplinas/adicionar', methods=['POST'])
@login_required
def adicionar_disciplina():
    nome = request.form['nome']
    aulas = request.form['aulas_semanais']
    professor_id = request.form['professor_id'] or None

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO disciplinas (nome, aulas_semanais, professor_id) VALUES (%s, %s, %s)",
        (nome, aulas, professor_id)
    )
    conn.commit()
    cursor.close()
    conn.close()

    flash("Disciplina adicionada com sucesso!", "success")
    return redirect(url_for('gerenciar_disciplinas'))

@app.route('/disciplinas/editar/<int:id>', methods=['POST'])
@login_required
def editar_disciplina(id):
    nome = request.form['nome']
    aulas = request.form['aulas_semanais']
    professor_id = request.form['professor_id'] or None

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE disciplinas SET nome=%s, aulas_semanais=%s, professor_id=%s WHERE id=%s",
        (nome, aulas, professor_id, id)
    )
    conn.commit()
    cursor.close()
    conn.close()

    flash("Disciplina atualizada com sucesso!", "success")
    return redirect(url_for('gerenciar_disciplinas'))

@app.route('/disciplinas/remover/<int:id>', methods=['POST'])
@login_required
def remover_disciplina(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM disciplinas WHERE id=%s", (id,))
    conn.commit()
    cursor.close()
    conn.close()

    flash("Disciplina removida com sucesso!", "success")
    return redirect(url_for('gerenciar_disciplinas'))


@app.route('/disponibilidade')
@login_required
def gerenciar_disponibilidade():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT d.id, d.dia_semana, d.periodo, d.disponivel, p.nome AS professor_nome
        FROM disponibilidade d
        JOIN professores p ON d.professor_id = p.id
        ORDER BY p.nome, d.dia_semana, d.periodo
    """)
    disponibilidade = cursor.fetchall()

    cursor.execute("SELECT id, nome FROM professores ORDER BY nome;")
    professores = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        'gerenciar_disponibilidade.html',
        disponibilidade=disponibilidade,
        professores=professores
    )

def limpar_e_popular_banco(df_disponibilidade, df_disciplinas):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("TRUNCATE TABLE disponibilidade RESTART IDENTITY CASCADE;")
    cursor.execute("TRUNCATE TABLE disciplinas RESTART IDENTITY CASCADE;")
    cursor.execute("TRUNCATE TABLE professores RESTART IDENTITY CASCADE;")

    professores = pd.concat([df_disponibilidade['professor'], df_disciplinas['professor']]).dropna().unique()
    prof_map = {}
    for prof in professores:
        cursor.execute("INSERT INTO professores (nome) VALUES (%s) RETURNING id;", (prof,))
        prof_map[prof] = cursor.fetchone()['id']
    conn.commit()

    for _, row in df_disciplinas.iterrows():
        prof_id = prof_map.get(row['professor'])
        if prof_id:
            cursor.execute(
                "INSERT INTO disciplinas (nome, aulas_semanais, professor_id) VALUES (%s, %s, %s)",
                (row['disciplina'], row['aulas_semanais'], prof_id)
            )

    for _, row in df_disponibilidade.iterrows():
        prof_id = prof_map.get(row['professor'])
        if prof_id:
            cursor.execute(
                "INSERT INTO disponibilidade (professor_id, dia_semana, periodo, disponivel) VALUES (%s, %s, %s, %s)",
                (prof_id, row['dia_semana'], row['periodo'], bool(row['disponivel']))
            )
    conn.commit()
    cursor.close()
    conn.close()

try:
    inicializar_banco()
except Exception as e:
    print("⚠️ Erro ao inicializar o banco:", e)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

# Função para processar o arquivo Excel (Adicionada)
def processar_planilha_disciplinas(caminho_arquivo):
    try:
        # Lendo a planilha. O cabeçalho real está na linha 4 (índice 3)
        df = pd.read_excel(caminho_arquivo, sheet_name='Planilha1', header=3)

        # Renomear colunas para os nomes esperados no código original
        df.rename(columns={
            'Componente': 'disciplina',
            'HA': 'aulas_semanais',
            'Professor Titular': 'professor'
        }, inplace=True)

        # Selecionar e limpar os dados
        df = df[['disciplina', 'aulas_semanais', 'professor']].copy()

        # Remover linhas onde disciplina ou professor estão vazios
        df.dropna(subset=['disciplina', 'professor'], inplace=True)

        # Tratar 'aulas_semanais' como numérico e converter para inteiro
        df['aulas_semanais'] = pd.to_numeric(df['aulas_semanais'], errors='coerce')
        df.dropna(subset=['aulas_semanais'], inplace=True)
        # O banco de dados espera INT. Vou converter para INT.
        df['aulas_semanais'] = df['aulas_semanais'].astype(int)
        
        return df

    except Exception as e:
        print(f"Ocorreu um erro ao processar a planilha: {e}")
        return None


@app.route('/upload_planilha', methods=['POST'])
@login_required
def upload_planilha():
    if 'file' not in request.files:
        flash('Nenhum arquivo enviado.', 'danger')
        return redirect(url_for('dashboard'))

    file = request.files['file']
    if file.filename == '':
        flash('Nenhum arquivo selecionado.', 'danger')
        return redirect(url_for('dashboard'))

    if file and file.filename.endswith(('.xlsx', '.xls')):
        filename = 'planilha_upload.xlsx'
        filepath = os.path.join('/tmp', filename)
        file.save(filepath)


        df_disciplinas = processar_planilha_disciplinas(filepath)
        df_disponibilidade = pd.DataFrame(columns=['professor', 'dia_semana', 'periodo', 'disponivel'])

        if df_disciplinas is not None:
            try:
                limpar_e_popular_banco(df_disponibilidade, df_disciplinas)
                flash('Planilha processada e banco de dados populado com sucesso!', 'success')
            except Exception as e:
                flash(f'Erro ao popular o banco de dados: {e}', 'danger')
        else:
            flash('Erro ao processar o conteúdo da planilha.', 'danger')

        os.remove(filepath)
        return redirect(url_for('dashboard'))

    flash('Formato de arquivo inválido. Por favor, envie um arquivo .xlsx ou .xls.', 'danger')
    return redirect(url_for('dashboard'))
