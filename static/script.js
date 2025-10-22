document.addEventListener('DOMContentLoaded', () => {
    // --- LÓGICA DO TEMA CLARO/ESCURO (GLOBAL) ---
    const themeToggle = document.getElementById('theme-toggle');
    const applyTheme = (theme) => {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('theme', theme);
    };
    const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) { applyTheme(savedTheme); } 
    else if (prefersDark) { applyTheme('dark'); } 
    else { applyTheme('light'); }
    if (themeToggle) {
        themeToggle.addEventListener('click', () => {
            const currentTheme = document.documentElement.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            applyTheme(newTheme);
        });
    }

    // Ativa os ícones Feather (GLOBAL) - Mais robusto
    try {
        if (typeof feather !== 'undefined' && feather !== null) {
            feather.replace();
        } else {
            console.warn('[DEBUG] Biblioteca Feather Icons (feather) não encontrada.');
        }
    } catch (e) {
        console.error('[DEBUG] Erro ao executar feather.replace():', e);
    }
    
    // --- LÓGICA DA PÁGINA DE DISPONIBILIDADE ---
    const professorSelect = document.getElementById('professor-select');
    if (professorSelect) {
        const gridCard = document.getElementById('availability-grid-card');
        
        professorSelect.addEventListener('change', async (e) => {
            const profId = e.target.value;
            if (profId) {
                const response = await fetch(`/api/disponibilidade/${profId}`);
                const disponivel = await response.json();
                document.getElementById('grid-title').textContent = `Grade de Disponibilidade de ${e.target.options[e.target.selectedIndex].text}`;
                document.querySelectorAll('.slot').forEach(slot => {
                    const key = `${slot.dataset.dia}-${slot.dataset.periodo}`;
                    slot.classList.toggle('available', disponivel.includes(key));
                });
                gridCard.style.display = 'block';
            } else {
                gridCard.style.display = 'none';
            }
        });

        document.querySelectorAll('.slot').forEach(slot => {
            slot.addEventListener('click', async () => {
                const profId = professorSelect.value;
                if (!profId) return;
                slot.classList.toggle('available');
                const isAvailable = slot.classList.contains('available');
                await fetch('/api/disponibilidade/atualizar', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        professor_id: profId,
                        dia: slot.dataset.dia,
                        periodo: slot.dataset.periodo,
                        disponivel: isAvailable
                    })
                });
            });
        });
    }

    // --- LÓGICA DO DASHBOARD (GERADOR) ---
    console.log('[DEBUG] Script carregado. Procurando elementos do Dashboard...');
    const btnGerarHorario = document.getElementById('btnGerarHorario');
    
    if (btnGerarHorario) {
        console.log('[DEBUG] Botão #btnGerarHorario ENCONTRADO. Configurando lógica do dashboard.');

        const statusDiv = document.getElementById('status');
        const resultadoContainer = document.getElementById('resultadoContainer');
        const seletorOpcoes = document.getElementById('seletorOpcoes');
        const horarioContainer = document.getElementById('horarioContainer');
        const listaNaoAlocadas = document.getElementById('listaNaoAlocadas');
        let resultadosGlobais = {}; 

        if (!statusDiv || !resultadoContainer || !seletorOpcoes || !horarioContainer || !listaNaoAlocadas) {
            console.error('[DEBUG] ERRO CRÍTICO: Um ou mais elementos do dashboard (status, resultadoContainer, etc.) NÃO FORAM ENCONTRADOS. Abortando.');
            return; 
        } else {
            console.log('[DEBUG] Todos os elementos do dashboard foram encontrados com sucesso.');
        }

        const popularSeletorOpcoes = (numOpcoes) => {
            seletorOpcoes.innerHTML = '';
            for (let i = 0; i < numOpcoes; i++) {
                const option = document.createElement('option');
                option.value = i;
                option.textContent = `Opção ${i + 1}`;
                seletorOpcoes.appendChild(option);
            }
            seletorOpcoes.addEventListener('change', (e) => {
                renderizarHorarioEDiagnostico(parseInt(e.target.value, 10));
            });
        };

        const renderizarHorarioEDiagnostico = (index) => {
            const horario = resultadosGlobais.horarios[index];
            const diagnostico = resultadosGlobais.diagnosticos[index];
            horarioContainer.innerHTML = horario; 
            listaNaoAlocadas.innerHTML = '';
            if (diagnostico.nao_alocadas && diagnostico.nao_alocadas.length > 0) {
                diagnostico.nao_alocadas.forEach(aula => {
                    const li = document.createElement('li');
                    li.textContent = aula;
                    listaNaoAlocadas.appendChild(li);
                });
            } else {
                const li = document.createElement('li');
                li.textContent = 'Todas as aulas foram alocadas com sucesso nesta opção.';
                listaNaoAlocadas.appendChild(li);
            }
        };

        console.log('[DEBUG] Adicionando listener de clique ao botão.');
        btnGerarHorario.addEventListener('click', async () => {
            console.log('[DEBUG] Botão CLICADO. Iniciando processo de geração de horário.');
            
            statusDiv.textContent = 'Gerando horários... Este processo pode levar alguns minutos.';
            statusDiv.className = 'status-message info';
            statusDiv.style.display = 'block';
            resultadoContainer.style.display = 'none';
            btnGerarHorario.disabled = true;
            btnGerarHorario.textContent = 'Processando...';

            try {
                console.log('[DEBUG] Enviando requisição POST para /gerar_horario...');
                const response = await fetch('/gerar_horario', { method: 'POST' });
                console.log('[DEBUG] Resposta recebida do servidor:', response);

                if (!response.ok) {
                    console.error('[DEBUG] A resposta do servidor NÃO foi OK. Status:', response.status);
                    const errorData = await response.json();
                    console.error('[DEBUG] Dados do erro vindos do servidor:', errorData);
                    throw new Error(errorData.mensagem || `Erro do servidor: ${response.status}`);
                }

                console.log('[DEBUG] A resposta foi OK. Analisando JSON...');
                resultadosGlobais = await response.json();
                console.log('[DEBUG] Dados JSON analisados:', resultadosGlobais);
                
                statusDiv.style.display = 'none';
                
                if (resultadosGlobais.horarios && resultadosGlobais.horarios.length > 0) {
                    console.log('[DEBUG] Horários recebidos. Populando o seletor e renderizando o primeiro resultado.');
                    popularSeletorOpcoes(resultadosGlobais.horarios.length);
                    renderizarHorarioEDiagnostico(0); 
                    resultadoContainer.style.display = 'block';
                } else {
                    console.warn('[DEBUG] Nenhum horário foi gerado ou retornado pelo servidor.');
                    statusDiv.textContent = 'Não foi possível gerar horários com os dados atuais.';
                    statusDiv.className = 'status-message warning';
                    statusDiv.style.display = 'block';
                }

            } catch (error) {
                console.error('[DEBUG] Ocorreu um erro no processo de fetch:', error);
                statusDiv.textContent = `Falha ao gerar horários: ${error.message}`;
                statusDiv.className = 'status-message error';
                statusDiv.style.display = 'block';
            } finally {
                console.log('[DEBUG] Processo finalizado. Reativando o botão.');
                btnGerarHorario.disabled = false;
                btnGerarHorario.innerHTML = '<i data-feather="cpu"></i> Gerar 10 Melhores Opções';
                if (typeof feather !== 'undefined' && feather !== null) feather.replace();
            }
        });
        console.log('[DEBUG] Listener de clique adicionado com sucesso.');

    } else {
        console.log('[DEBUG] Botão #btnGerarHorario NÃO ENCONTRADO nesta página. Lógica do dashboard ignorada.');
    }
});

// --- FUNÇÕES GLOBAIS PARA MODAIS (Podem ficar fora, pois são globais) ---
function openModal(modalId) { const modal = document.getElementById(modalId); if (modal) modal.style.display = 'block'; }
function closeModal(modalId) { const modal = document.getElementById(modalId); if (modal) modal.style.display = 'none'; }
function openAddModal() { openModal('addModal'); }
function closeAddModal() { closeModal('addModal'); }
function openUserModal() { openModal('userModal'); }
function closeUserModal() { closeModal('userModal'); }
function openEditModal(id, ...args) {
    const modal = document.getElementById('editModal');
    const editForm = document.getElementById('editForm');
    const editNomeInput = document.getElementById('editNome');
    const editAulasInput = document.getElementById('editAulas');
    const editProfessorSelect = document.getElementById('editProfessor');
    if (editAulasInput) {
        editForm.action = `/disciplinas/editar/${id}`;
        editNomeInput.value = args[0]; editAulasInput.value = args[1]; editProfessorSelect.value = args[2];
    } else {
        editForm.action = `/professores/editar/${id}`;
        editNomeInput.value = args[0];
    }
    openModal('editModal');
}
function closeEditModal() { closeModal('editModal'); }
window.onclick = function(event) { if (event.target.classList.contains('modal')) { event.target.style.display = 'none'; } }