document.addEventListener('DOMContentLoaded', function () {
    const container = document.getElementsByClassName('lgn-account-selection')[0];
    let title = '';
    container.addEventListener('change', function (event) {
        const t = event.target;
        if (t.classList.contains('lgn-login-as')) {
            const btn = t.closest('.lgn-account-container').getElementsByClassName('lgn-account')[0];
            if (t.checked) {
                title = btn.getAttribute('title');
                btn.removeAttribute('title');
                btn.removeAttribute('disabled');
            } else {
                btn.setAttribute('title', title);
                btn.setAttribute('disabled', 'disabled');
            }
        }
    });
});