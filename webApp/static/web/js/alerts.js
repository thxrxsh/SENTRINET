$(document).ready(function () {
    

    $('.alerts-link').click(function (e) { 
        e.preventDefault();
    
        // Call getAlerts and handle the response inside its success callback
        getAlerts(function(alerts) {

            if (alerts.unseen.length == 0 && alerts.seen.length == 0) {
                let seen_alerts_html = `<br><br><h6 class="text-center">You don't have any alerts yet</h6><br><br>`;
                $('.seen-alerts').html(seen_alerts_html);

            } else {

                if (alerts.unseen.length > 0) {
                    var unseen_alerts = alerts.unseen;
                    let unseen_alerts_html = `
                    <p class="text-center text-blue-4">Unseen Alerts</p>
                    
                    `;
        
                    unseen_alerts.forEach(alert => {
                        unseen_alerts_html += `
                            <div id="alert_${alert.id}" class="message-bubble rounded p-4 m-3 border border-1 ${alert.message_status}">
                                <p>${alert.message}</p>
                                <div class="row">
                                    <div class="col-8"><span class="alert_date_time poppins-light">${formatDateTime(alert.date_time)}</span></div>
                                    <div class="col-4 d-flex justify-content-end">
                                        <button class="btn btn-sm btn-outline-danger border border-0 delete_alert-btn" value="${alert.id}">
                                            <i class="bi bi-trash3-fill"></i>
                                        </button>
                                    </div>
                                </div>
                            </div>
                        `;
                    });
        
                    $('.unseen-alerts').html(unseen_alerts_html).removeClass('hide');
        
                } else {
                    $('.unseen-alerts').addClass('hide');
                }
        
                if (alerts.seen.length > 0) {
                    var seen_alerts = alerts.seen;
                    let seen_alerts_html = "";
        
                    seen_alerts.forEach(alert => {
                        seen_alerts_html += `
                            <div id="alert_${alert.id}" class="message-bubble rounded p-4 m-3 border border-1 ${alert.message_status}">
                                <p>${alert.message}</p>
                                <div class="row">
                                    <div class="col-8"><span class="alert_date_time poppins-light">${formatDateTime(alert.date_time)}</span></div>
                                    <div class="col-4 d-flex justify-content-end">
                                        <button class="btn btn-sm btn-outline-danger border border-0 delete_alert-btn" value="${alert.id}">
                                            <i class="bi bi-trash3-fill"></i>
                                        </button>
                                    </div>
                                </div>
                            </div>
                        `;
                    });
        
                    $('.seen-alerts').html(seen_alerts_html);
        
                }
            }
    
            $("#alerts-modal").modal("show");
            $('.bi-bell-fill').removeClass('new-alerts');
        });
    });
    

    function getAlerts(callback) {
        $.ajax({
            type: 'POST',
            url: '/alerts/get/',
            headers: { 'X-CSRFToken': csrftoken },
            success: function(response) {
                var alerts = response.alerts;
                if (alerts) {
                    console.log("Alerts", alerts);
                    callback(alerts); // Pass alerts to the callback function
                } else {
                    console.log("Failed to fetch alerts");
                }
            },
            error: function(xhr, status, error) {
                console.log("Error: " + error);
            }
        });
    }
    




    function addAlert(message, status) {
        $.ajax({
            type: 'POST',
            url: '/alerts/add/',
            headers: { 'X-CSRFToken': csrftoken },
            data: {
                'message': message,
                'status': status,
            },
            success: function(response) {
                if (response.alert) {
                    alert("Alert added successfully!");
                } else {
                    alert("Failed to add alert.");
                }
            },
            error: function(xhr, status, error) {
                console.log("Error: " + error);
            }
        });
    }

    
    function deleteAlert(alert_id) {
        $.ajax({
            type: 'POST',
            url: '/alerts/delete/',
            headers: { 'X-CSRFToken': csrftoken },
            data: {
                'alert_id': alert_id
            },
            success: function(response) {
                if (response) {
                    $('#alert_' + alert_id).remove();
                } else {
                }
            },
            error: function(xhr, status, error) {
                console.log("Error: " + error);
            }
        });
    }
    

    $(document).on('click', '.delete_alert-btn', function (e) {
        let alert_id = $(this).val();
        deleteAlert(alert_id);
    });
    







    checkForNewAlert()

    function checkForNewAlert() {
        $.ajax({
            type: 'POST',
            url: '/alerts/check/',
            headers: { 'X-CSRFToken': csrftoken },

            success: function(response) {
                console.log(response);

                if (response.new_alerts_count > 0) {
                    toest("ALERT" , "You have new alerts");
                    $('.bi-bell-fill').addClass('new-alerts');
                
                } else {
                    $('.bi-bell-fill').removeClass('new-alerts');
                }

                $('#new_alerts_count').text(response.new_alerts_count);
                $('#total_alerts_count').text(response.total_alerts_count);

                return response.new_alerts_count
            },
            error: function(xhr, status, error) {
                console.log("Error: " + error);
            }
        });
    }

    setInterval(checkForNewAlert, 30000);

});