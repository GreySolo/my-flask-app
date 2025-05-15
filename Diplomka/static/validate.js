document.addEventListener('DOMContentLoaded', function () {
    const form = document.getElementById('edit-profile-form');
    const phoneInput = document.getElementById('phone_number');
    const fieldsToCapitalize = ['last_name', 'first_name', 'middle_name'];
    const profileImageInput = document.getElementById('profile_image');
    const profileImagePreview = document.querySelector('.profile-photo');

    // Обновление аватарки при выборе файла
    if (profileImageInput && profileImagePreview) {
        profileImageInput.addEventListener('change', function (event) {
            const file = event.target.files[0];
            if (file) {
                // Проверяем, что это изображение
                if (file.type.startsWith("image/")) {
                    const reader = new FileReader();
                    reader.onload = function (e) {
                        profileImagePreview.src = e.target.result;
                    };
                    reader.readAsDataURL(file);
                } else {
                    alert('Пожалуйста, выберите изображение.');
                    profileImageInput.value = ''; // Сбросить выбранный файл
                }
            }
        });
    }

    // Автокапитализация первых букв в ФИО по вводу
    fieldsToCapitalize.forEach(id => {
        const input = document.getElementById(id);
        if (input) {
            input.addEventListener('input', function () {
                const cursorPos = input.selectionStart;
                const value = input.value;
                if (value.length > 0) {
                    input.value = value.charAt(0).toUpperCase() + value.slice(1).toLowerCase();
                    input.setSelectionRange(cursorPos, cursorPos);
                }
            });
        }
    });

    // Функция для форматирования номера телефона
    function formatPhoneNumber(value) {
        value = value.replace(/\D/g, ''); // Убираем нецифры
        if (!value.startsWith('7')) {
            value = '7' + value;
        }
        let result = '+7';
        if (value.length > 1) result += ' ' + value.slice(1, 4);
        if (value.length > 4) result += ' ' + value.slice(4, 7);
        if (value.length > 7) result += '-' + value.slice(7, 9);
        if (value.length > 9) result += '-' + value.slice(9, 11);
        return result;
    }

    // Автоформат номера при вводе
    if (phoneInput) {
        phoneInput.addEventListener('input', function (e) {
            const rawValue = e.target.value.replace(/\D/g, ''); // Только цифры
            const formatted = formatPhoneNumber(rawValue); // Форматируем номер
            const cursorPos = phoneInput.selectionStart; // Текущая позиция курсора

            // Устанавливаем отформатированное значение
            e.target.value = formatted;

            // Вычисляем новую позицию курсора
            let newCursorPos = cursorPos;
            for (let i = 0; i < cursorPos; i++) {
                if (formatted[i] === ' ' || formatted[i] === '-') {
                    newCursorPos++; // Сдвигаем курсор, если он попал на пробел или дефис
                }
            }

            // Гарантируем, что курсор всегда справа от последней введенной цифры
            if (rawValue.length > 0) {
                newCursorPos = formatted.indexOf(rawValue[rawValue.length - 1]) + 1;
            }
        });
    }

    // Валидация телефона
    function validatePhoneNumber(phoneNumber) {
        const phonePattern = /^\+7\s\d{3}\s\d{3}-\d{2}-\d{2}$/;
        return phonePattern.test(phoneNumber);
    }

    // Валидация email
    function validateEmail(email) {
        const emailPattern = /^[\w.-]+@(mail|gmail|yandex|bk|list)\.(ru|com)$/;
        return emailPattern.test(email);
    }

    // Валидация пароля
    function validatePassword(password) {
        return password === "" || password.length >= 6;
    }

    // Отправка формы
    if (form) {
        form.addEventListener('submit', function (e) {
            const lastName = form.last_name;
            const firstName = form.first_name;
            const middleName = form.middle_name;
            const phone = form.phone_number;
            const email = form.email;
            const newPassword = form.new_password;

            // Капитализация перед отправкой (на всякий случай)
            lastName.value = lastName.value.charAt(0).toUpperCase() + lastName.value.slice(1).toLowerCase();
            firstName.value = firstName.value.charAt(0).toUpperCase() + firstName.value.slice(1).toLowerCase();
            middleName.value = middleName.value.charAt(0).toUpperCase() + middleName.value.slice(1).toLowerCase();

            // Проверка телефона
            if (!validatePhoneNumber(phone.value.trim())) {
                alert('Введите корректный номер телефона в формате +7 900 000-00-00');
                e.preventDefault();
                return;
            }

            // Проверка email
            if (!validateEmail(email.value.trim())) {
                alert('Введите корректный email с доменом: mail, gmail, yandex, bk, list');
                e.preventDefault();
                return;
            }

            // Проверка пароля
            if (newPassword.value.trim() && !validatePassword(newPassword.value.trim())) {
                alert('Пароль должен содержать минимум 6 символов');
                e.preventDefault();
                return;
            }

            // Если все проверки прошли успешно, форма отправляется
        });
    }
});