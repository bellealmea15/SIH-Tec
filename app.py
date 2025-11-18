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
    # Substitua pela sua string de conexão real se não estiver usando variáveis de ambiente
    database_url = os.environ.get("DATABASE_URL", "postgresql://user:password@localhost/dbname")
    return psycopg2.connect(database_url, cursor_factory=RealDictCursor)

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
            professor_id INT REFERENCES professores(id) ON DELETE SET NULL
        );
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS disponibilidade (
            id SERIAL PRIMARY KEY,
            professor_id INT REFERENCES professores(id) ON DELETE CASCADE,
            dia_semana VARCHAR(20),
            periodo INT,
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
        flash('O registro público está desativado.', 'warning')
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


# --- ROTAS DE GESTÃO DE PROFESSORES ---
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
        FROM disciplinas d LEFT JOIN professores p ON d.professor_id = p.id
        WHERE d.nome ILIKE %s OR p.nome ILIKE %s ORDER BY d.nome;
    """
    cursor.execute(query, (f'%{search_query}%', f'%{search_query}%'))
    disciplinas = cursor.fetchall()
    cursor.execute("SELECT id, nome FROM professores ORDER BY nome")
    professores = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('gerenciar_disciplinas.html', disciplinas=disciplinas, professores=professores, search_query=search_query)


@app.route('/disciplinas/adicionar', methods=['POST'])
@login_required
def adicionar_disciplina():
    nome = request.form['nome']
    aulas = request.form['aulas_semanais']
    professor_id = request.form.get('professor_id')
    if professor_id == '0': professor_id = None
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO disciplinas (nome, aulas_semanais, professor_id) VALUES (%s, %s, %s)", (nome, aulas, professor_id))
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
    professor_id = request.form.get('professor_id')
    if professor_id == '0': professor_id = None
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE disciplinas SET nome=%s, aulas_semanais=%s, professor_id=%s WHERE id=%s", (nome, aulas, professor_id, id))
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


# --- ROTAS DE DISPONIBILIDADE ---
@app.route('/disponibilidade')
@login_required
def gerenciar_disponibilidade():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, nome FROM professores ORDER BY nome;")
    professores = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('gerenciar_disponibilidade.html', professores=professores)


# --- ROTAS DE USUÁRIOS ---
@app.route('/usuarios')
@login_required
@admin_required
def gerenciar_usuarios():
    search_query = request.args.get('q', '')
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "SELECT id, username, role FROM usuarios WHERE username ILIKE %s ORDER BY username"
    cursor.execute(query, (f'%{search_query}%',))
    usuarios = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('gerenciar_usuarios.html', usuarios=usuarios, search_query=search_query)


@app.route('/usuarios/adicionar', methods=['POST'])
@login_required
@admin_required
def adicionar_usuario():
    username = request.form['username']
    password = request.form['password'].encode('utf-8')
    role = request.form['role']
    hashed = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO usuarios (username, password_hash, role) VALUES (%s, %s, %s)", (username, hashed, role))
        conn.commit()
        flash("Usuário criado com sucesso!", "success")
    except psycopg2.errors.UniqueViolation:
        flash(f"O nome de usuário '{username}' já existe.", "danger")
    finally:
        cursor.close()
        conn.close()
    return redirect(url_for('gerenciar_usuarios'))


@app.route('/usuarios/remover/<int:id>', methods=['POST'])
@login_required
@admin_required
def remover_usuario(id):
    if id == current_user.id:
        flash("Você não pode remover a si mesmo.", "danger")
        return redirect(url_for('gerenciar_usuarios'))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM usuarios WHERE id = %s", (id,))
    conn.commit()
    cursor.close()
    conn.close()
    flash("Usuário removido com sucesso!", "success")
    return redirect(url_for('gerenciar_usuarios'))


# --- LIMPAR E POPULAR BANCO ---
def limpar_e_popular_banco(df_disponibilidade, df_disciplinas):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("TRUNCATE TABLE disponibilidade, disciplinas, professores RESTART IDENTITY CASCADE;")
    
    professores_disp = df_disponibilidade['professor'].dropna().unique() if not df_disponibilidade.empty else []
    professores_disc = df_disciplinas['professor'].dropna().unique() if not df_disciplinas.empty else []
    
    todos_professores = pd.unique(list(professores_disp) + list(professores_disc))

    prof_map = {}
    for prof in todos_professores:
        cursor.execute("INSERT INTO professores (nome) VALUES (%s) ON CONFLICT (nome) DO UPDATE SET nome=EXCLUDED.nome RETURNING id;", (prof,))
        prof_id = cursor.fetchone()['id']
        prof_map[prof] = prof_id

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
                (prof_id, row['dia_semana'], row['periodo'], row['disponivel'])
            )
    conn.commit()
    cursor.close()
    conn.close()


# --- IMPORTAÇÃO DE PLANILHAS ---
def processar_planilha_disciplinas(caminho_arquivo):
    try:
        df = pd.read_excel(caminho_arquivo, header=3) 
        df.rename(columns={
            df.columns[0]: 'disciplina',
            df.columns[1]: 'aulas_semanais',
            df.columns[2]: 'professor'
        }, inplace=True)
        df = df[['disciplina', 'aulas_semanais', 'professor']].copy()
        df.dropna(subset=['disciplina', 'professor'], inplace=True)
        df['aulas_semanais'] = pd.to_numeric(df['aulas_semanais'], errors='coerce')
        df.dropna(subset=['aulas_semanais'], inplace=True)
        df['aulas_semanais'] = df['aulas_semanais'].astype(int)
        return df
    except Exception as e:
        flash(f"Erro ao ler a planilha de Quadro de Aulas: {e}", "danger")
        return None

def processar_planilha_disponibilidade(caminho_arquivo):
    try:
        df = pd.read_excel(caminho_arquivo)
        coluna_professor = df.columns[0]
        colunas_dias = df.columns[1:]
        df_melted = df.melt(id_vars=[coluna_professor], value_vars=colunas_dias, var_name='dia_semana', value_name='periodos_disponiveis')
        df_melted.rename(columns={coluna_professor: 'professor'}, inplace=True)
        df_final = []
        for _, row in df_melted.iterrows():
            if pd.notna(row['periodos_disponiveis']):
                periodos_str = str(row['periodos_disponiveis']).split(',')
                for periodo in periodos_str:
                    if periodo.strip().isdigit():
                         df_final.append({
                            'professor': row['professor'],
                            'dia_semana': row['dia_semana'],
                            'periodo': int(periodo.strip()),
                            'disponivel': True
                        })
        return pd.DataFrame(df_final)
    except Exception as e:
        flash(f"Erro ao ler a planilha de Disponibilidade: {e}", "danger")
        return None

@app.route('/upload_e_processar', methods=['POST'])
@login_required
def upload_e_processar():
    if 'arquivoDisponibilidade' not in request.files or 'arquivoQuadroAulas' not in request.files:
        flash('É necessário enviar ambos os arquivos (Disponibilidade e Quadro de Aulas).', 'danger')
        return redirect(url_for('dashboard'))
    arquivo_disp = request.files['arquivoDisponibilidade']
    arquivo_quadro = request.files['arquivoQuadroAulas']
    if arquivo_disp.filename == '' or arquivo_quadro.filename == '':
        flash('Um ou mais arquivos não foram selecionados.', 'danger')
        return redirect(url_for('dashboard'))
    if arquivo_disp and arquivo_quadro:
        tmp_dir = '/tmp/app_uploads'
        os.makedirs(tmp_dir, exist_ok=True)
        caminho_disp = os.path.join(tmp_dir, 'temp_disponibilidade.xlsx')
        caminho_quadro = os.path.join(tmp_dir, 'temp_quadro_aulas.xlsx')
        arquivo_disp.save(caminho_disp)
        arquivo_quadro.save(caminho_quadro)
        df_disponibilidade = processar_planilha_disponibilidade(caminho_disp)
        df_disciplinas = processar_planilha_disciplinas(caminho_quadro)
        os.remove(caminho_disp)
        os.remove(caminho_quadro)
        if df_disponibilidade is not None and df_disciplinas is not None:
            try:
                limpar_e_popular_banco(df_disponibilidade, df_disciplinas)
                flash('Arquivos processados e banco de dados atualizado com sucesso!', 'success')
            except Exception as e:
                flash(f'Erro ao salvar os dados no banco: {e}', 'danger')
        else:
            flash('Falha ao processar um ou mais arquivos. Verifique o formato e o conteúdo das planilhas.', 'danger')
    return redirect(url_for('dashboard'))


# --- ROTA DA API PARA GERAR HORÁRIO ---
def coletar_dados_para_gerador():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT d.id, d.nome, d.aulas_semanais, d.professor_id, p.nome as professor_nome
        FROM disciplinas d JOIN professores p ON d.professor_id = p.id
    """)
    disciplinas = cursor.fetchall()
    if not disciplinas:
        raise ValueError("Não há disciplinas com professores atribuídos para gerar o horário.")
    cursor.execute("SELECT professor_id, dia_semana, periodo FROM disponibilidade WHERE disponivel = TRUE")
    disponibilidades_raw = cursor.fetchall()
    disponibilidade = defaultdict(list)
    for disp in disponibilidades_raw:
        disponibilidade[disp['professor_id']].append((disp['dia_semana'], disp['periodo']))
    if not disponibilidade:
        raise ValueError("Nenhum professor cadastrou sua disponibilidade.")
    cursor.close()
    conn.close()
    return disciplinas, disponibilidade

@app.route('/gerar_horario', methods=['POST'])
@login_required
def gerar_horario():
    try:
        disciplinas, disponibilidade = coletar_dados_para_gerador()
        horario_gerado = defaultdict(dict)
        aulas_nao_alocadas = []
        dias_semana = ["Segunda", "Terça", "Quarta", "Quinta", "Sexta"]
        periodos = [1, 2, 3, 4, 5]
        slots_ocupados_prof = defaultdict(list)
        for disc in disciplinas:
            alocadas = 0
            for _ in range(disc['aulas_semanais']):
                aula_foi_alocada = False
                for dia in random.sample(dias_semana, len(dias_semana)):
                    for periodo in random.sample(periodos, len(periodos)):
                        slot_horario = (dia, periodo)
                        if slot_horario in disponibilidade.get(disc['professor_id'], []) and \
                           slot_horario not in horario_gerado and \
                           slot_horario not in slots_ocupados_prof[disc['professor_id']]:
                            horario_gerado[slot_horario] = {"disciplina": disc['nome'], "professor": disc['professor_nome']}
                            slots_ocupados_prof[disc['professor_id']].append(slot_horario)
                            alocadas += 1
                            aula_foi_alocada = True
                            break
                    if aula_foi_alocada:
                        break
            if alocadas < disc['aulas_semanais']:
                aulas_nao_alocadas.append({
                    "disciplina": disc['nome'],
                    "professor": disc['professor_nome'],
                    "faltam_alocar": disc['aulas_semanais'] - alocadas
                })
        resultado_final = {
            "horario": [{"dia": dia, "periodo": periodo, **dados} for (dia, periodo), dados in horario_gerado.items()],
            "nao_alocadas": aulas_nao_alocadas
        }
        opcoes = [resultado_final for _ in range(10)]
        return jsonify({'success': True, 'opcoes': opcoes})
    except ValueError as ve:
        return jsonify({'success': False, 'message': str(ve)}), 400
    except Exception as e:
        print(f"ERRO INESPERADO: {e}")
        return jsonify({'success': False, 'message': f'Ocorreu um erro interno no servidor: {e}'}), 500


# --- INICIALIZA BANCO ---
try:
    with app.app_context():
        inicializar_banco()
except Exception as e:
    print(f"⚠️ Erro ao inicializar o banco de dados: {e}")


# --- EXECUÇÃO LOCAL ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)

    if __name__ == "__main__":
        