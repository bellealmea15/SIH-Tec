
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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
