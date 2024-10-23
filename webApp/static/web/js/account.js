$(document).ready(function () {
    $('.account-link').click(function (e) { 
        e.preventDefault();
        $("#account-modal").modal("show");
    });
});