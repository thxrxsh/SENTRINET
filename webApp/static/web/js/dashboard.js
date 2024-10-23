$(document).ready(function () {


    $('#panel-hide').click(function (e) { 
        e.preventDefault();
        $('#sidebar-expand-content').addClass('hide');

        $('#sidebar').removeClass('col-3');
        $('#sidebar').addClass('col-1');

        $('#dashboard-content').removeClass('col-9');
        $('#dashboard-content').addClass('col-11');

        setTimeout(()=>{
            $('#sidebar-collapsed-content').removeClass('hide');

        }, 200);
        
    });


    $('#panel-show').click(function (e) { 
        e.preventDefault();
        $('#sidebar-collapsed-content').addClass('hide');

        $('#sidebar').removeClass('col-1');
        $('#dashboard-content').removeClass('col-11');

        $('#dashboard-content').addClass('col-9');
        $('#sidebar').addClass('col-3');

        setTimeout(()=>{
            $('#sidebar-expand-content').removeClass('hide');

        }, 200);
        
    });


    $('#dashboard-content').scroll(function () {
        if ($(this).scrollTop() > 300) {
          $('#scrollTopBtn').fadeIn();
        } else {
          $('#scrollTopBtn').fadeOut();
        }
      });
    
      // Scroll to the top when the button is clicked
      $('#scrollTopBtn').click(function () {
        $('#dashboard-content').animate({ scrollTop: 0 }, 'slow');
      });
    
      // Initially hide the button
      $('#scrollTopBtn').hide();


      

});