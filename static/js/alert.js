document.addEventListener('DOMContentLoaded', (event) => {
    setTimeout(() => {
        let alerts = document.querySelectorAll('.alert-dismissible');
        alerts.forEach((alert) => {
            $(alert).alert('close');
        });
    }, 5000);
});