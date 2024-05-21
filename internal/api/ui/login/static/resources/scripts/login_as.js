document.addEventListener('DOMContentLoaded', function () {
    const form = document.querySelector('form.lng-login-as-search');
    const searchInput = document.querySelector('input.lng-login-as-search-field');
    const clearButton = document.querySelector('button.lng-login-as-search-clear-button');

    const toggleClearButton = () => {
        if (searchInput.value !== '') {
            clearButton.style.display = 'block';
        } else {
            clearButton.style.display = '';
        }
    };

    toggleClearButton();

    searchInput.addEventListener('input', toggleClearButton);

    clearButton.addEventListener('click', () => {
        searchInput.value = '';
        clearButton.style.display = '';
        form.submit();
    });
});