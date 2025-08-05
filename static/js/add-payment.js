// static/js/add-payment.js

document.addEventListener('DOMContentLoaded', function () {
  // === Получаем данные из страницы ===
  const itemsDataScript = document.getElementById('items-data');
  const clientsDataScript = document.getElementById('clients-data');

  const items = itemsDataScript ? JSON.parse(itemsDataScript.textContent) : [];
  const allClients = clientsDataScript ? JSON.parse(clientsDataScript.textContent) : [];

  // === Создаём map по id для быстрого доступа ===
  const itemMap = {};
  items.forEach(item => {
    itemMap[item.id] = {
      price: item.price || 0,
      purchase_price: item.purchase_price || 0
    };
  });

  // === Элементы формы ===
  const clientSearch = document.getElementById('clientSearch');
  const searchResults = document.getElementById('searchResults');
  const amountInput = document.getElementById('amountInput');
  const itemSelect = document.getElementById('itemSelect');
  const profitSpan = document.getElementById('paymentProfit');

  // === Форматирование в рублях ===
  function formatRub(value) {
    return new Intl.NumberFormat('ru-RU', {
      style: 'currency',
      currency: 'RUB',
      minimumFractionDigits: 2
    }).format(value);
  }

  // === Обновление прибыли ===
  function updateProfit() {
    const selectedId = itemSelect.value;
    const item = itemMap[selectedId];
    const amount = parseFloat(amountInput.value) || 0;

    if (item && !isNaN(amount)) {
      const markupRatio = item.price > 0 ? (item.price - item.purchase_price) / item.price : 0;
      const profit = amount * markupRatio;
      profitSpan.textContent = formatRub(profit);
    } else {
      profitSpan.textContent = '—';
    }
  }

  // === Поиск клиентов ===
  if (clientSearch && searchResults) {
    clientSearch.addEventListener('input', function () {
      const query = this.value.trim().toLowerCase();
      searchResults.innerHTML = '';

      if (query.length > 0) {
        const matches = allClients.filter(client => client.toLowerCase().includes(query));
        if (matches.length > 0) {
          matches.slice(0, 5).forEach(client => {
            const item = document.createElement('a');
            item.className = 'list-group-item list-group-item-action';
            item.href = `?client_name=${encodeURIComponent(client)}`;
            item.innerHTML = `<i class="bi bi-person me-2"></i>${client}`;
            searchResults.appendChild(item);
          });
        } else {
          const item = document.createElement('div');
          item.className = 'list-group-item text-muted';
          item.textContent = 'Клиенты не найдены';
          searchResults.appendChild(item);
        }
        searchResults.style.display = 'block';
      } else {
        searchResults.style.display = 'none';
      }
    });

    // Скрыть результаты при клике вне поля
    document.addEventListener('click', function (e) {
      if (!clientSearch.contains(e.target) && !searchResults.contains(e.target)) {
        searchResults.style.display = 'none';
      }
    });
  }

  // Привязка событий
  if (itemSelect) itemSelect.addEventListener('change', updateProfit);
  if (amountInput) amountInput.addEventListener('input', updateProfit);

  // Инициализация
  updateProfit();
});