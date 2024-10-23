$(document).ready(function () {


  $('#reports-table tbody').find('tr').mouseover(function () { 
    $(this).addClass('table-active');
  });

  $('#reports-table tbody').find('tr').mouseleave(function () { 
      $(this).removeClass('table-active');
  });
  

  $('#reports-table tbody').find('.record_detail').click(function (e) {
    var record_id = $(this).parent().attr('id').split('_')[1];
    window.location.href = '/report/' + record_id;
  });


  $('#reports-table tbody').find('.report-action .record-delete').mouseover(function (e) {
      $(this).addClass('text-danger');
  });
  
  $('#reports-table tbody').find('.report-action .record-delete').mouseleave(function (e) {
    $(this).removeClass('text-danger');
  });


  $('#reports-table tbody').find('.report-action .record-delete').click(function (e) {
    var record_id = $(this).closest('tr').attr('id').split('_')[1];
    $('#delete_report-input').val(record_id);
    $('#delete_report-modal').modal('show');
  });


  $('#delete_report-yes_btn').click(function (e) { 
    var record_id = $('#delete_report-input').val();
    e.preventDefault();
    $.ajax({
      type: 'POST',
      url: '/reports/',
      headers: { 'X-CSRFToken': csrftoken },
      data: {
          "delete_report": record_id,
      },
      dataType: "json",
      success: function(response) {
          if (response.status === 'delete-ok') {
              toest("SUCCESS" , "Report deleted successfully");
              $('#record_' + record_id).remove();
          } else {
              toest("ERROR" , "Failed to delete report");
          }
      },
      error: function(xhr, status, error) {
          alert("Error: " + error);
      }
    });

    $('#delete_report-modal').modal('hide');
    
  });




});