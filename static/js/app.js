// инвестор

 document.addEventListener('DOMContentLoaded', function () {
    const deleteModal = document.getElementById('deleteModal');
    const investorNameSpan = document.getElementById('modalInvestorName');
    const deleteForm = document.getElementById('deleteForm');

    deleteModal.addEventListener('show.bs.modal', function (event) {
      const button = event.relatedTarget;
      const investorId = button.getAttribute('data-investor-id');
      const investorName = button.getAttribute('data-investor-name');

      investorNameSpan.textContent = investorName;
      deleteForm.action = `/investors/delete/${investorId}`;
    });
  });


// balance
// === Инициализация модального окна удаления счёта ===
document.addEventListener('DOMContentLoaded', function () {
    const deleteModal = document.getElementById('deleteModal');
    if (deleteModal) {
        deleteModal.addEventListener('show.bs.modal', function (event) {
            const button = event.relatedTarget;
            const accountId = button.getAttribute('data-account-id');
            const accountName = button.getAttribute('data-account-name');
            document.getElementById('accountName').textContent = accountName;
            const deleteBtn = document.getElementById('deleteAccountBtn');
            deleteBtn.href = deleteBtn.href.replace(/\/\d+\/delete$/, `/${accountId}/delete`);
        });
    }

    // === Анимация появления карточек ===
    const cards = document.querySelectorAll('.col-12');
    cards.forEach((card, index) => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(20px)';
        card.style.animation = `fadeInUp 0.3s ease forwards ${index * 0.1}s`;
    });
});





//dashboard
// === Автозаполнение ФИО клиента ===
document.addEventListener('DOMContentLoaded', function () {
    const clientNameInput = document.getElementById('client_name');
    const autocompleteList = document.getElementById('autocomplete-list');

    if (clientNameInput && autocompleteList) {
        clientNameInput.addEventListener('input', function () {
            const query = this.value.trim();
            autocompleteList.innerHTML = '';

            if (query.length < 2) return;

            fetch(`/autocomplete?query=${encodeURIComponent(query)}`)
                .then(res => {
                    if (!res.ok) throw new Error('Network response was not ok');
                    return res.json();
                })
                .then(data => {
                    data.forEach(client => {
                        const item = document.createElement('button');
                        item.type = 'button';
                        item.className = 'list-group-item list-group-item-action';
                        item.textContent = client;
                        item.addEventListener('click', () => {
                            clientNameInput.value = client;
                            autocompleteList.innerHTML = '';
                        });
                        autocompleteList.appendChild(item);
                    });
                })
                .catch(err => console.error('Autocomplete error:', err));
        });

        // Скрыть список при клике вне поля
        document.addEventListener('click', function (e) {
            if (!clientNameInput.contains(e.target) && !autocompleteList.contains(e.target)) {
                autocompleteList.innerHTML = '';
            }
        });
    }
});

// === Расчёты для формы товара ===
document.addEventListener('DOMContentLoaded', function () {
    const purchasePriceInput = document.getElementById('purchase_price');
    const profitMarginInput = document.getElementById('profit_margin');
    const installmentPriceInput = document.getElementById('installment_price');
    const downPaymentInput = document.getElementById('down_payment');
    const installmentsInput = document.getElementById('installments');
    const monthlyPaymentInput = document.getElementById('monthly_payment');
    const marginDisplay = document.getElementById('margin_display');
    const installmentsValue = document.getElementById('installmentsValue');

    if (!purchasePriceInput) return; // Если форма не на странице — выходим

    // Функция: рассчитать цену в рассрочку
    function calculateInstallmentPrice() {
        const purchasePrice = parseFloat(purchasePriceInput.value) || 0;
        const margin = parseInt(profitMarginInput.value) || 0;
        const installmentPrice = purchasePrice * (1 + margin / 100);

        installmentPriceInput.value = installmentPrice.toFixed(2);
        marginDisplay.textContent = margin + "%";
        calculateMonthlyPayment();
    }

    // Функция: рассчитать ежемесячный платёж
    function calculateMonthlyPayment() {
        const price = parseFloat(installmentPriceInput.value) || 0;
        const downPayment = parseFloat(downPaymentInput.value) || 0;
        const installments = parseInt(installmentsInput.value) || 1;
        const monthly = (price - downPayment) / installments;

        monthlyPaymentInput.value = monthly > 0 ? monthly.toFixed(2) + " ₽" : "0 ₽";
    }

    // Форматирование: два знака после запятой
    function formatToTwoDecimals(input) {
        const value = parseFloat(input.value);
        input.value = !isNaN(value) ? value.toFixed(2) : "0.00";
    }

    // Обновление текста с количеством месяцев
    function updateInstallmentsLabel() {
        const value = installmentsInput.value;
        let suffix = " месяцев";
        if (value == 1) suffix = " месяц";
        else if (value >= 2 && value <= 4) suffix = " месяца";

        installmentsValue.textContent = value + suffix;
        calculateMonthlyPayment();
    }

    // Инициализация
    if (installmentsValue) updateInstallmentsLabel();
    calculateInstallmentPrice();
    calculateMonthlyPayment();

    // Слушатели событий
    if (purchasePriceInput) purchasePriceInput.addEventListener('input', calculateInstallmentPrice);
    if (profitMarginInput) profitMarginInput.addEventListener('input', calculateInstallmentPrice);
    if (installmentPriceInput) installmentPriceInput.addEventListener('input', calculateMonthlyPayment);
    if (downPaymentInput) downPaymentInput.addEventListener('input', calculateMonthlyPayment);
    if (installmentsInput) {
        installmentsInput.addEventListener('input', updateInstallmentsLabel);
        installmentsInput.addEventListener('change', calculateMonthlyPayment);
    }

    if (installmentPriceInput) installmentPriceInput.addEventListener('blur', e => formatToTwoDecimals(e.target));
    if (downPaymentInput) downPaymentInput.addEventListener('blur', e => formatToTwoDecimals(e.target));

    // Кастомная валидация Bootstrap
    const form = document.getElementById('itemForm');
    const optionalIds = ["guarantor_name", "guarantor_phone", "photo"];

    optionalIds.forEach(id => {
        const field = document.getElementById(id);
        if (!field) return;

        field.classList.add("optional-quiet");
        const clear = () => {
            if (!field.value || (field.type === "file" && field.files.length === 0)) {
                field.classList.remove("is-valid", "is-invalid");
            }
        };

        if (field.type === "file") {
            field.addEventListener("change", clear);
            field.addEventListener("blur", clear);
        } else {
            field.addEventListener("input", clear);
            field.addEventListener("blur", clear);
        }
    });

    // Подтверждение через модальное окно
    const confirmSubmitBtn = document.getElementById('confirmSubmit');
    if (confirmSubmitBtn) {
        confirmSubmitBtn.addEventListener('click', function () {
            if (form.checkValidity()) {
                form.submit();
            } else {
                form.classList.add("was-validated");
                optionalIds.forEach(id => {
                    const f = document.getElementById(id);
                    if (f && (!f.value || (f.type === "file" && f.files.length === 0))) {
                        f.classList.remove("is-valid", "is-invalid");
                    }
                });
                const firstInvalid = form.querySelector(":invalid");
                if (firstInvalid) {
                    setTimeout(() => {
                        firstInvalid.scrollIntoView({ behavior: "smooth", block: "center" });
                        firstInvalid.focus({ preventScroll: true });
                    }, 250);
                }
                const modal = bootstrap.Modal.getInstance(document.getElementById("confirmModal"));
                if (modal) modal.hide();
            }
        });
    }
});









// Expence.html
 // Валидация формы
  (function () {
    'use strict'

    const forms = document.querySelectorAll('.needs-validation')

    Array.from(forms).forEach(form => {
      form.addEventListener('submit', event => {
        if (!form.checkValidity()) {
          event.preventDefault()
          event.stopPropagation()
        }

        form.classList.add('was-validated')
      }, false)
    })
  })()



// === Валидация форм прихода/расхода ===
document.addEventListener('DOMContentLoaded', function () {
    const forms = document.querySelectorAll('.needs-validation');
    Array.from(forms).forEach(form => {
        form.addEventListener('submit', function (event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
                // Прокрутка к первому невалидному полю
                const firstInvalid = form.querySelector(':invalid');
                if (firstInvalid) {
                    firstInvalid.scrollIntoView({ behavior: 'smooth', block: 'center' });
                }
            }
            form.classList.add('was-validated');
        }, false);
    });
});





   //itempayments.html
  // === Расчёт прибыли с платежа ===
document.addEventListener('DOMContentLoaded', function () {
    const amountInput = document.getElementById('amount-input');
    const profitDisplay = document.getElementById('payment-profit');

    if (amountInput && profitDisplay) {
        // Получаем данные из страницы
        const itemsDataScript = document.getElementById('item-data');
        const itemData = itemsDataScript ? JSON.parse(itemsDataScript.textContent) : null;

        if (!itemData) {
            console.warn("Данные товара не найдены");
            return;
        }

        const { price = 0, purchase_price = 0 } = itemData;
        const markupRatio = price > 0 ? (price - purchase_price) / price : 0;

        function formatRub(value) {
            return new Intl.NumberFormat('ru-RU', {
                style: 'currency',
                currency: 'RUB',
                minimumFractionDigits: 2
            }).format(value);
        }

        amountInput.addEventListener('input', function () {
            const amount = parseFloat(this.value);
            if (!isNaN(amount)) {
                const profit = amount * markupRatio;
                profitDisplay.textContent = formatRub(profit);
            } else {
                profitDisplay.textContent = '—';
            }
        });
    }
});







// === Профиль пользователя: отслеживание изменений и маска телефона ===
document.addEventListener('DOMContentLoaded', function () {
    const profileForm = document.getElementById('profileForm');
    if (!profileForm) return; // Если форма не на странице — выходим

    const nameInput = document.getElementById('name');
    const phoneInput = document.getElementById('phone');
    const formButtons = document.getElementById('formButtons');
    const cancelButton = document.getElementById('cancelChanges');

    if (!nameInput || !phoneInput || !formButtons) return;

    // Сохраняем исходные значения
    const initialValues = {
        name: nameInput.value.trim(),
        phone: phoneInput.value.trim()
    };

    // Проверяем, есть ли изменения
    function checkForChanges() {
        const currentValues = {
            name: nameInput.value.trim(),
            phone: phoneInput.value.trim()
        };

        const hasChanges = currentValues.name !== initialValues.name ||
                           currentValues.phone !== initialValues.phone;

        if (hasChanges) {
            formButtons.classList.add('visible');
            formButtons.style.display = 'flex';
        } else {
            formButtons.classList.remove('visible');
            formButtons.style.display = 'none';
        }
    }

    // Отслеживаем изменения
    nameInput.addEventListener('input', checkForChanges);
    phoneInput.addEventListener('input', checkForChanges);

    // Кнопка "Отменить"
    if (cancelButton) {
        cancelButton.addEventListener('click', function () {
            nameInput.value = initialValues.name;
            phoneInput.value = initialValues.phone;
            formButtons.classList.remove('visible');
            formButtons.style.display = 'none';
        });
    }

    // Маска для телефона
    phoneInput.addEventListener('input', function (e) {
        let value = e.target.value.replace(/\D/g, ''); // Только цифры

        if (value.startsWith('8') && value.length > 1) {
            value = '7' + value.slice(1);
        } else if (!value.startsWith('7')) {
            value = '7' + value;
        }

        value = value.substring(0, 11); // Максимум 11 цифр

        let formatted = '+7';
        if (value.length > 1) formatted += ' (' + value.substring(1, 4);
        if (value.length >= 4) formatted += ') ' + value.substring(4, 7);
        if (value.length >= 7) formatted += '-' + value.substring(7, 9);
        if (value.length >= 9) formatted += '-' + value.substring(9, 11);

        e.target.value = formatted;
    });
});














//проверка клиента
// === Инициализация particles.js (если на странице есть #particles-js) ===
document.addEventListener('DOMContentLoaded', function () {
    const particlesContainer = document.getElementById('particles-js');
    if (window.particlesJS && particlesContainer) {
        particlesJS('particles-js', {
            "particles": {
                "number": {
                    "value": 100,
                    "density": {
                        "enable": true,
                        "value_area": 800
                    }
                },
                "color": {
                    "value": ["#ffffff", "#aaaaaa", "#666666"]
                },
                "shape": {
                    "type": "circle",
                    "stroke": {
                        "width": 0,
                        "color": "#000000"
                    }
                },
                "opacity": {
                    "value": 0.7,
                    "random": true,
                    "anim": {
                        "enable": true,
                        "speed": 0.5,
                        "opacity_min": 0.1,
                        "sync": false
                    }
                },
                "size": {
                    "value": 3,
                    "random": true,
                    "anim": {
                        "enable": true,
                        "speed": 5,
                        "size_min": 1,
                        "sync": false
                    }
                },
                "line_linked": {
                    "enable": false
                },
                "move": {
                    "enable": true,
                    "speed": 1.5,
                    "direction": "none",
                    "random": true,
                    "straight": false,
                    "out_mode": "out",
                    "bounce": false,
                    "attract": {
                        "enable": true,
                        "rotateX": 600,
                        "rotateY": 1200
                    }
                }
            },
            "interactivity": {
                "detect_on": "canvas",
                "events": {
                    "onhover": {
                        "enable": true,
                        "mode": "bubble"
                    },
                    "onclick": {
                        "enable": true,
                        "mode": "repulse"
                    },
                    "resize": true
                },
                "modes": {
                    "bubble": {
                        "distance": 100,
                        "size": 8,
                        "duration": 0.3,
                        "opacity": 0.8,
                        "speed": 3
                    },
                    "repulse": {
                        "distance": 100,
                        "duration": 0.4
                    }
                }
            },
            "retina_detect": true
        });
    }

    // === Функция открытия WhatsApp ===
    window.openWhatsApp = function(phone) {
        let cleanPhone = phone.replace(/\D/g, '');
        if (cleanPhone.startsWith('8') && cleanPhone.length === 11) {
            cleanPhone = '7' + cleanPhone.slice(1);
        } else if (!cleanPhone.startsWith('7')) {
            cleanPhone = '7' + cleanPhone;
        }
        const url = `https://wa.me/${cleanPhone}`;
        window.open(url, '_blank', 'noopener,noreferrer');
    };
});















// === Инициализация flatpickr (если на странице есть поле с классом .license-date-input) ===
document.addEventListener("DOMContentLoaded", function () {
  if (typeof flatpickr !== "undefined") {
    flatpickr(".license-date-input", {
      dateFormat: "d.m.Y",
      locale: {
        firstDayOfWeek: 1,
        weekdays: {
          shorthand: ['Вс', 'Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб'],
          longhand: ['Воскресенье', 'Понедельник', 'Вторник', 'Среда', 'Четверг', 'Пятница', 'Суббота']
        },
        months: {
          shorthand: ['Янв', 'Фев', 'Мар', 'Апр', 'Май', 'Июн', 'Июл', 'Авг', 'Сен', 'Окт', 'Ноя', 'Дек'],
          longhand: ['Январь', 'Февраль', 'Март', 'Апрель', 'Май', 'Июнь', 'Июль', 'Август', 'Сентябрь', 'Октябрь', 'Ноябрь', 'Декабрь']
        },
      },
      minDate: "today",
      allowInput: true,
    });
  }
});