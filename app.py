# app.py
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from collections import defaultdict
import pandas as pd
import re, mysql.connector, itertools, random, os, bcrypt
from functools import wraps

# --- CONFIGURAÇÃO ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'uma-chave-secreta-final-e-segura-2025'
db_config = {'host': 'localhost', 'user': 'root', 'password': 'root777', 'database': 'sistema_horarios'}

# --- GESTÃO DE LOGIN E NÍVEIS DE ACESSO ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Por favor, faça login para acessar esta página."
login_manager.login_message_category = "warning"

class User(UserMixin):
    def __init__(self, id, username, role):
        self.id, self.username, self.role = id, username, role
    def is_admin(self): return self.role == 'admin'

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
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

def get_db_connection(): return mysql.connector.connect(**db_config)

# --- ROTAS DE AUTENTICAÇÃO ATUALIZADAS ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(id) FROM usuarios")
    user_count = cursor.fetchone()[0]
    cursor.close()
    conn.close()
    registration_enabled = user_count == 0

    if request.method == 'POST':
        username, password = request.form['username'], request.form['password'].encode('utf-8')
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM usuarios WHERE username = %s", (username,))
        user_data = cursor.fetchone()
        cursor.close()
        conn.close()
        if user_data and bcrypt.checkpw(password, user_data['password_hash'].encode('utf-8')):
            login_user(User(id=user_data['id'], username=user_data['username'], role=user_data['role']))
            return redirect(url_for('dashboard'))
        else: flash('Usuário ou senha inválidos.', 'danger')

    return render_template('login.html', registration_enabled=registration_enabled)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(id) FROM usuarios")
    user_count = cursor.fetchone()[0]
    
    if user_count > 0:
        flash('O registro público está desativado. Novos usuários só podem ser criados por um administrador.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        username, password = request.form['username'], request.form['password'].encode('utf-8')
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
        role = 'admin'
        
        cursor.execute("INSERT INTO usuarios (username, password_hash, role) VALUES (%s, %s, %s)", (username, hashed_password.decode('utf-8'), role))
        conn.commit()
        flash('Conta de Administrador criada com sucesso! Faça o login.', 'success')
        cursor.close()
        conn.close()
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

# --- ROTAS DE GESTÃO (CRUD) ---
# ... (todas as suas rotas de CRUD de professores, disciplinas, etc. permanecem aqui, sem alteração) ...
# Professores
@app.route('/professores')
@login_required
def gerenciar_professores():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    search_query = request.args.get('q', '')
    query = "SELECT * FROM professores WHERE nome LIKE %s ORDER BY nome"
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
        except mysql.connector.IntegrityError:
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

# Disciplinas
@app.route('/disciplinas')
@login_required
def gerenciar_disciplinas():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    search_query = request.args.get('q', '')
    query = """
    SELECT d.id, d.nome, d.aulas_semanais, d.professor_id, p.nome as professor_nome 
    FROM disciplinas d LEFT JOIN professores p ON d.professor_id = p.id 
    WHERE d.nome LIKE %s OR p.nome LIKE %s
    ORDER BY d.nome
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
    nome = request.form['nome'].strip()
    aulas = request.form['aulas_semanais']
    prof_id = request.form['professor_id']
    prof_id = prof_id if prof_id != '0' else None
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO disciplinas (nome, aulas_semanais, professor_id) VALUES (%s, %s, %s)", (nome, aulas, prof_id))
    conn.commit()
    cursor.close()
    conn.close()
    flash("Disciplina adicionada com sucesso!", "success")
    return redirect(url_for('gerenciar_disciplinas'))

@app.route('/disciplinas/editar/<int:id>', methods=['POST'])
@login_required
def editar_disciplina(id):
    nome = request.form['nome'].strip()
    aulas = request.form['aulas_semanais']
    prof_id = request.form['professor_id']
    prof_id = prof_id if prof_id != '0' else None

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE disciplinas SET nome = %s, aulas_semanais = %s, professor_id = %s WHERE id = %s", (nome, aulas, prof_id, id))
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
    cursor.execute("DELETE FROM disciplinas WHERE id = %s", (id,))
    conn.commit()
    cursor.close()
    conn.close()
    flash("Disciplina removida com sucesso!", "success")
    return redirect(url_for('gerenciar_disciplinas'))

# Disponibilidade
@app.route('/disponibilidade')
@login_required
def gerenciar_disponibilidade():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, nome FROM professores ORDER BY nome")
    professores = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('gerenciar_disponibilidade.html', professores=professores)

@app.route('/api/disponibilidade/<int:prof_id>')
@login_required
def get_disponibilidade(prof_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT dia_semana, periodo FROM disponibilidade WHERE professor_id = %s AND disponivel = TRUE", (prof_id,))
    disponivel = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify([f"{d['dia_semana']}-{d['periodo']}" for d in disponivel])

@app.route('/api/disponibilidade/atualizar', methods=['POST'])
@login_required
def atualizar_disponibilidade():
    data = request.json
    prof_id, dia, periodo, disponivel = data['professor_id'], data['dia'], data['periodo'], data['disponivel']
    conn = get_db_connection()
    cursor = conn.cursor()
    query = """
    INSERT INTO disponibilidade (professor_id, dia_semana, periodo, disponivel)
    VALUES (%s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE disponivel = %s
    """
    cursor.execute(query, (prof_id, dia, periodo, disponivel, disponivel))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({'success': True})

# Usuários
@app.route('/usuarios')
@login_required
@admin_required
def gerenciar_usuarios():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    search_query = request.args.get('q', '')
    query = "SELECT id, username, role FROM usuarios WHERE username LIKE %s ORDER BY username"
    cursor.execute(query, (f'%{search_query}%',))
    usuarios = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('gerenciar_usuarios.html', usuarios=usuarios, search_query=search_query)

@app.route('/usuarios/adicionar', methods=['POST'])
@login_required
@admin_required
def adicionar_usuario():
    username = request.form['username'].strip()
    password = request.form['password'].encode('utf-8')
    role = request.form['role']
    
    if username and password and role:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id FROM usuarios WHERE username = %s", (username,))
        if cursor.fetchone():
            flash("Este nome de usuário já existe.", "warning")
        else:
            hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
            cursor.execute("INSERT INTO usuarios (username, password_hash, role) VALUES (%s, %s, %s)", (username, hashed_password.decode('utf-8'), role))
            conn.commit()
            flash("Usuário criado com sucesso!", "success")
        cursor.close()
        conn.close()
    else:
        flash("Todos os campos são obrigatórios.", "danger")
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

# --- ROTAS DE API DE GERAÇÃO E IMPORTAÇÃO ---
@app.route('/upload_e_processar', methods=['POST'])
@login_required
def upload_e_processar():
    try:
        arquivo_disp = request.files['arquivoDisponibilidade']
        arquivo_quadro = request.files['arquivoQuadroAulas']
        disp_path, quadro_path = "temp_disp", "temp_quadro"
        arquivo_disp.save(disp_path)
        arquivo_quadro.save(quadro_path)
        df_disponibilidade = processar_disponibilidade(disp_path)
        df_disciplinas = processar_quadro_aulas(quadro_path)
        limpar_e_popular_banco(df_disponibilidade, df_disciplinas)
        os.remove(disp_path); os.remove(quadro_path)
        flash("Dados importados com sucesso! O conteúdo anterior foi substituído.", "success")
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash(f'Ocorreu um erro na importação: {str(e)}', "danger")
        return redirect(url_for('dashboard'))

# =============================================================================
# === INÍCIO DAS CORREÇÕES ===================================================
# =============================================================================

# NOVA FUNÇÃO: Para converter o dicionário do horário em uma tabela HTML
def formatar_horario_para_html(horario_dict, dias, periodos):
    html = "<table class='horario-table'>"
    html += "<thead><tr><th>Período</th>"
    for dia in dias:
        html += f"<th>{dia}</th>"
    html += "</tr></thead>"
    html += "<tbody>"
    for p in periodos:
        html += f"<tr><td>{p}ª Aula</td>"
        for d in dias:
            # .get() para evitar erro se a chave não existir
            # .replace() para quebras de linha funcionem em HTML
            aula_info = horario_dict.get(f"{d}-{p}", "--- VAGO ---").replace('\n', '<br>')
            html += f"<td>{aula_info}</td>"
        html += "</tr>"
    html += "</tbody></table>"
    return html

# ROTA ATUALIZADA: Agora retorna os dados no formato que o JavaScript espera
@app.route('/gerar_horario', methods=['POST'])
@login_required
def gerar_horario_endpoint():
    try:
        # Pega os resultados brutos da função de lógica
        resultados_brutos = gerar_melhores_horarios()
        
        horarios_html = []
        diagnosticos = []
        
        # Itera sobre os 10 melhores horários gerados
        for resultado in resultados_brutos.get('horarios', []):
            # Formata o horário em uma string de tabela HTML
            horarios_html.append(formatar_horario_para_html(resultado['horario'], ['Segunda', 'Terça', 'Quarta', 'Quinta', 'Sexta'], [1, 2, 3, 4, 5]))
            # Cria o objeto de diagnóstico
            diagnosticos.append({'nao_alocadas': resultado['nao_alocadas']})
            
        return jsonify({
            'success': True,
            'horarios': horarios_html,
            'diagnosticos': diagnosticos
        })
    except Exception as e:
        # Adiciona um print para facilitar o debug no terminal do Flask
        print(f"ERRO CRÍTICO em gerar_horario_endpoint: {e}")
        return jsonify({'mensagem': f'Ocorreu um erro crítico na geração do horário: {str(e)}'}), 500

# =============================================================================
# === FIM DAS CORREÇÕES =======================================================
# =============================================================================


# --- LÓGICA CENTRAL ---
def processar_disponibilidade(file_path):
    df = pd.read_excel(file_path, header=None)
    lines = df.apply(lambda row: ','.join(row.dropna().astype(str)), axis=1).tolist()
    disponibilidades, current_teacher = [], None
    dias_map = {'2ª': 'Segunda', '3ª': 'Terça', '4ª': 'Quarta', '5ª': 'Quinta', '6ª': 'Sexta', 'Sab': 'Sábado'}
    for line_num, line in enumerate(lines):
        if match := re.search(r'Docente: (.*)', line): current_teacher = match.group(1).strip()
        if "Aulas,Dias da Semana Manhã" in line and current_teacher:
            header_line = lines[line_num + 1].strip().split(',')
            try:
                indices_2a = [i for i, s in enumerate(header_line) if s == '2ª']
                if len(indices_2a) < 3: continue
                night_section_idx = indices_2a[2]
            except (ValueError, IndexError): continue
            for i in range(1, 6):
                if line_num + 1 + i >= len(lines): break
                data_line = lines[line_num + 1 + i].strip().split(',')
                for j in range(6):
                    col_idx = night_section_idx + j
                    if col_idx < len(header_line):
                        if day_name := dias_map.get(header_line[col_idx]):
                            disponivel = 1 if col_idx < len(data_line) and data_line[col_idx].strip().upper() == 'X' else 0
                            disponibilidades.append({'professor': current_teacher, 'dia_semana': day_name, 'periodo': i, 'disponivel': disponivel})
    return pd.DataFrame(disponibilidades)

def processar_quadro_aulas(file_path):
    df = pd.read_excel(file_path, header=2)
    df.columns = df.columns.str.strip()
    required_cols = ['Período', 'Componente', 'HA', 'Professor Ministrando']
    if not all(col in df.columns for col in required_cols):
        raise ValueError(f"Colunas necessárias não encontradas. Colunas no arquivo: {list(df.columns)}")
    df_processado = df[required_cols].copy()
    df_processado.rename(columns={'Período': 'periodo_desc', 'Componente': 'disciplina', 'HA': 'aulas_semanais', 'Professor Ministrando': 'professor'}, inplace=True)
    df_noite = df_processado[df_processado['periodo_desc'].astype(str).str.contains("Noite", na=False)].copy()
    df_noite['professor'] = df_noite['professor'].str.strip()
    df_noite.dropna(subset=['professor', 'aulas_semanais'], inplace=True)
    df_noite['aulas_semanais'] = pd.to_numeric(df_noite['aulas_semanais'], errors='coerce')
    df_noite.dropna(subset=['aulas_semanais'], inplace=True)
    df_noite['aulas_semanais'] = df_noite['aulas_semanais'].astype(int)
    return df_noite[df_noite['aulas_semanais'] > 0]

def limpar_e_popular_banco(df_disponibilidade, df_disciplinas):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SET FOREIGN_KEY_CHECKS = 0;")
    cursor.execute("TRUNCATE TABLE disponibilidade;")
    cursor.execute("TRUNCATE TABLE disciplinas;")
    cursor.execute("TRUNCATE TABLE professores;")
    cursor.execute("SET FOREIGN_KEY_CHECKS = 1;")
    professores = pd.concat([df_disponibilidade['professor'], df_disciplinas['professor']]).dropna().unique()
    prof_map = {}
    for prof in professores:
        cursor.execute("INSERT INTO professores (nome) VALUES (%s)", (prof,))
        prof_map[prof] = cursor.lastrowid
    conn.commit()
    for _, row in df_disciplinas.iterrows():
        prof_id = prof_map.get(row['professor'])
        if prof_id:
            cursor.execute("INSERT INTO disciplinas (nome, aulas_semanais, professor_id) VALUES (%s, %s, %s)", (row['disciplina'], row['aulas_semanais'], prof_id))
    for _, row in df_disponibilidade.iterrows():
        prof_id = prof_map.get(row['professor'])
        if prof_id:
            cursor.execute("INSERT INTO disponibilidade (professor_id, dia_semana, periodo, disponivel) VALUES (%s, %s, %s, %s)", (prof_id, row['dia_semana'], row['periodo'], bool(row['disponivel'])))
    conn.commit()
    cursor.close()
    conn.close()

def gerar_melhores_horarios(num_tentativas=50):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT d.id, d.nome, d.aulas_semanais, d.professor_id, p.nome as professor_nome FROM disciplinas d JOIN professores p ON d.professor_id = p.id")
    disciplinas = cursor.fetchall()
    cursor.execute("SELECT professor_id, dia_semana, periodo FROM disponibilidade WHERE disponivel = TRUE")
    disponibilidade_rows = cursor.fetchall()
    disponibilidade_prof = defaultdict(list)
    for row in disponibilidade_rows: disponibilidade_prof[row['professor_id']].append((row['dia_semana'], row['periodo']))
    cursor.execute("SELECT d.id, d.nome as disciplina_nome, p.nome as professor_nome FROM disciplinas d JOIN professores p ON d.professor_id = p.id")
    info_disciplinas = {row['id']: f"{row['disciplina_nome']}\n({row['professor_nome']})" for row in cursor.fetchall()}
    dias, periodos = ['Segunda', 'Terça', 'Quarta', 'Quinta', 'Sexta'], [1, 2, 3, 4, 5]
    horarios_gerados = []
    for _ in range(num_tentativas):
        aulas_para_alocar = []
        for d in disciplinas:
            for _ in range(d['aulas_semanais']): aulas_para_alocar.append({'disciplina_id': d['id'], 'professor_id': d['professor_id']})
        random.shuffle(aulas_para_alocar)
        horario_final = {slot: None for slot in itertools.product(dias, periodos)}
        aulas_alocadas_nesta_tentativa, aulas_nao_alocadas_nomes = 0, []
        for aula in aulas_para_alocar:
            prof_id, alocou = aula['professor_id'], False
            for slot in random.sample(disponibilidade_prof.get(prof_id, []), len(disponibilidade_prof.get(prof_id, []))):
                if horario_final.get(slot) is None:
                    horario_final[slot], aulas_alocadas_nesta_tentativa, alocou = aula['disciplina_id'], aulas_alocadas_nesta_tentativa + 1, True
                    break
            if not alocou:
                disciplina_info = next((d for d in disciplinas if d['id'] == aula['disciplina_id']), None)
                if disciplina_info: aulas_nao_alocadas_nomes.append(f"'{disciplina_info['nome']}' ({disciplina_info['professor_nome']})")
        buracos = 0
        for prof_id in disponibilidade_prof.keys():
            for dia in dias:
                aulas_do_prof_no_dia = sorted([p for (d, p), disc_id in horario_final.items() if d == dia and disc_id and next((d for d in disciplinas if d['id'] == disc_id),{}).get('professor_id') == prof_id])
                if len(aulas_do_prof_no_dia) > 1: buracos += (aulas_do_prof_no_dia[-1] - aulas_do_prof_no_dia[0] + 1) - len(aulas_do_prof_no_dia)
        horario_legivel = {f"{dia}-{periodo}": info_disciplinas.get(disc_id, "--- VAGO ---") for (dia, periodo), disc_id in horario_final.items()}
        horarios_gerados.append({'horario': horario_legivel, 'aulas_alocadas': aulas_alocadas_nesta_tentativa, 'buracos': buracos, 'nao_alocadas': list(set(aulas_nao_alocadas_nomes))})
    horarios_gerados.sort(key=lambda x: (-x['aulas_alocadas'], x['buracos']))
    cursor.close()
    conn.close()
    # A função original já retornava 'success', vamos mantê-la simples
    return {'horarios': horarios_gerados[:10]}

if __name__ == '__main__':
    app.run(debug=True, port=5001)