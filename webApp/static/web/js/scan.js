$(document).ready(function () {
    
    
    
    $('#scan-img').click(function (e) { 
        var is_scaning = $('#scan-img').hasClass('scaning-animation');
        e.preventDefault();
        
        if (is_scaning) {
            $(this).removeClass('scaning-animation');
            console.log(is_scaning);
        
        } else {
            $(this).addClass('scaning-animation');
            console.log(is_scaning);

        }
    });

});