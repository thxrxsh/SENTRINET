const csrftoken = Cookies.get('csrftoken');
var IS_SCANNING = false;


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


function formatDateTime(dateTimeStr) {
    const options = {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: true
    };
    
    const date = new Date(dateTimeStr);
    return date.toLocaleString('en-US', options);
}



function detectTimezone() {
    const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    // Send timezone to the server via AJAX or a form
    fetch('/set_timezone/', {
        method: 'POST',
        headers: {
            'X-CSRFToken': csrftoken,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ 'timezone': timezone })
    }).then(response => {
        console.log('Timezone sent successfully');
    }).catch(error => {
        console.error('Error sending timezone:', error);
    });
}

window.onload = detectTimezone;