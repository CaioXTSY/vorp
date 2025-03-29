// static/js/main.js

document.addEventListener('DOMContentLoaded', function() {
    // Inicializar Tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
      return new bootstrap.Tooltip(tooltipTriggerEl)
    })
    
    // Inicializar Highlight.js
    document.querySelectorAll('pre code').forEach((block) => {
        hljs.highlightBlock(block);
    });

    // Dark Mode Toggle
    const themeToggle = document.getElementById('themeToggle');
    if(themeToggle) {
        // Carregar preferência do usuário
        if(localStorage.getItem('theme') === 'dark') {
            document.body.classList.add('dark-mode');
            themeToggle.innerHTML = '<i class="fas fa-sun"></i>';
        } else {
            themeToggle.innerHTML = '<i class="fas fa-moon"></i>';
        }

        themeToggle.addEventListener('click', function() {
            document.body.classList.toggle('dark-mode');
            if(document.body.classList.contains('dark-mode')) {
                themeToggle.innerHTML = '<i class="fas fa-sun"></i>';
                localStorage.setItem('theme', 'dark');
            } else {
                themeToggle.innerHTML = '<i class="fas fa-moon"></i>';
                localStorage.setItem('theme', 'light');
            }
        });
    }

    // Search Functionality with Fuse.js
    const searchForm = document.getElementById('searchForm');
    const searchInput = document.getElementById('searchInput');
    const searchResultsModal = new bootstrap.Modal(document.getElementById('searchResultsModal'));
    const searchResultsList = document.getElementById('searchResultsList');

    const options = {
        keys: ['title', 'period'],
        threshold: 0.3
    };

    searchForm.addEventListener('submit', function(e) {
        e.preventDefault();
        const query = searchInput.value.trim();
        if(query.length === 0) {
            return;
        }
        const results = fuse.search(query);
        searchResultsList.innerHTML = '';
        if(results.length > 0) {
            results.forEach(result => {
                const item = document.createElement('li');
                item.classList.add('list-group-item');
                item.innerHTML = `<a href="${result.item.url}"><strong>${result.item.title}</strong></a> - ${result.item.period}`;
                searchResultsList.appendChild(item);
            });
        } else {
            const item = document.createElement('li');
            item.classList.add('list-group-item');
            item.textContent = '{{ gettext("Nenhum resultado encontrado.") }}';
            searchResultsList.appendChild(item);
        }
        searchResultsModal.show();
    });

    const socket = io();

    socket.on('connect', () => {
        console.log('Conectado ao servidor SocketIO');
    });

    socket.on('update_markdown', (data) => {
        // Exibir uma notificação de atualização
        alert('{{ gettext("Um arquivo foi atualizado.") }}');
        // Opcional: Implementar atualização dinâmica do conteúdo
    });
});
