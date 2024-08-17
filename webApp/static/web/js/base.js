function toest(title, message) {
    const toastLiveExample = document.getElementById('liveToast');
    const toastBootstrap = bootstrap.Toast.getOrCreateInstance(toastLiveExample);
 
    toastBootstrap.show();
    $('#toast-title').text(title);
    $('.toast-body').text(message);

    if (title == 'ERROR') {
        $('#toast-title').css('color', 'var(--red)');

    } else if (title == 'SUCCESS') {
        $('#toast-title').css('color', 'var(--blue-light)');

    } else if (title == 'WARNING') {
        $('#toast-title').css('color', 'orange');
    }
}
