let donutChart = null;


$(document).ready(function () {
    

    if (SCAN_RUNNING == 1){
        is_scaning = true;

        
        $('#spinner').removeClass('hide');
        $('#scan_msg').text("Starting Scan");
        
        $('#spinner').addClass('hide');
        $('#scan-img').addClass('scaning-animation');
        $('#scan_msg').addClass("hide");
        $('#status-container').removeClass('hide');
        
        updateStatus()

        function updateStatus() {
            $.ajax({
                type: "POST",
                url: "/scan/",
                headers: { 'X-CSRFToken': csrftoken },
                data: {
                    'action' : 'status',
                },
                dataType: "json",
                success: function (response) {
                    console.log(response);

                    let status = response.live_status.status;

                    $('#network_status').text(status);

                    if (status == "Protected") {
                        $('#network_status').removeClass().addClass('alert alert-success text-center poppins-semibold');
                
                    } else if (status == "Low Risk" || status == "Medium Risk") {
                        $('#network_status').removeClass().addClass('alert alert-warning text-center poppins-semibold');
                
                    } else {
                        $('#network_status').removeClass().addClass('alert alert-danger text-center poppins-semibold');
                    }
                }
            });
            
        }

        setInterval(updateStatus, 10000);

    }



    $('#scan-img').click(function (e) { 
        var is_scaning = $('#scan-img').hasClass('scaning-animation');
        e.preventDefault();
        
        if (is_scaning) {
            $('#spinner').removeClass('hide');
            $('#status-container').addClass('hide');
            $('#scan_msg').removeClass("hide");
            $('#scan_msg').text("Stopping Scan");

            setTimeout(()=>{

                $.ajax({
                    type: "POST",
                    url: "/scan/",
                    headers: { 'X-CSRFToken': csrftoken },
                    data: {
                        "action": "stop"
                    },
                    dataType: "json",
                    success: function (response) {
                        console.log(response);

                        if (response.status === 'scan-stopped') {

                            $('#scan-img').removeClass('scaning-animation');
                            $('#spinner').addClass('hide');
                            $('#scan_msg').text("Click to Scan");


                            var start_date = response.scan_summary.start_date;
                            var start_time = response.scan_summary.start_time;
                            var duration = response.scan_summary.duration;
                            var counts = response.scan_summary.counts;
                            var status = response.scan_summary.status;

                            var duration_text = "";

                            if (duration[0] != 0){
                                duration_text += duration[0] + " d ";
                            }

                            if (duration[1] != 0){
                                duration_text += duration[1] + " h ";
                            }

                            if (duration[2] != 0){
                                duration_text += duration[2] + " min ";
                            }

                            if (duration[3] != 0){
                                duration_text += duration[3] + " sec ";
                            }


                            $('#detail-start_date').text(start_date);
                            $('#detail-start_time').text(start_time);
                            $('#detail-duration').text(duration_text);
                            $('#scan_status').text(status);

                            if (status == "Protected") {
                                $('#scan_status').removeClass().addClass('alert alert-success text-center');
                          
                              } else if (status == "Low Risk" || status == "Medium Risk") {
                                $('#scan_status').removeClass().addClass('alert alert-warning text-center');
                          
                              } else {
                                $('#scan_status').removeClass().addClass('alert alert-danger text-center');
                              }

                            // Prepare data for the chart
                            var labels = [];
                            var data = [];

                            // Fill labels and data arrays from counts
                            for (var key in counts) {
                                if (counts.hasOwnProperty(key)) {
                                    labels.push(key);
                                    data.push(counts[key]);
                                }
                            }

                            // Generate the doughnut chart
                            const d_chart = document.getElementById('donutChart');

                            if (donutChart) {
                                donutChart.destroy();
                            }

                            donutChart = new Chart(d_chart, {
                                type: 'doughnut',
                                data: {
                                    labels: labels,
                                    datasets: [{
                                        data: data,
                                        borderWidth: 1
                                    }]
                                },
                                options: {
                                    plugins: {
                                      tooltip: {
                                        callbacks: {
                                          label: function(tooltipItem) {
                                            let total = tooltipItem.dataset.data.reduce((a, b) => a + b, 0);
                                            let value = tooltipItem.raw;
                                            let percentage = ((value / total) * 100).toFixed(2);
                                            return `${tooltipItem.label}: ${percentage}%`;
                                          }
                                        }
                                      },
                                      datalabels: {
                                        formatter: (value, context) => {
                                          let total = context.dataset.data.reduce((a, b) => a + b, 0);
                                          let percentage = ((value / total) * 100).toFixed(2);
                                          return percentage + '%';
                                        }
                                      }
                                    }
                                  }
                            });

                            $('#full_report-btn').attr('href', `/report/${response.scan_summary.record_id}/`);
                            $('#scan_results_summary').modal('show');
                        }
                    },
                    error: function (xhr, status, error) {
                        console.error('AJAX error:', status, error);
                    }
                });


            }, 1000);
            
        
        } else {
            
            $.ajax({
                type: "POST",
                url: "/scan/",
                headers: { 'X-CSRFToken': csrftoken },
                data: {
                    "action" : "start"
                },
                dataType: "json",
                success: function (response) {
                    
                    console.log(response);

                    if (response.status == "scan-started") {
                        
                        $('#spinner').removeClass('hide');
                        $('#scan_msg').text("Starting Scan");
    
                        setTimeout(() => {
                            $('#spinner').addClass('hide');
                            $('#scan-img').addClass('scaning-animation');
                            $('#scan_msg').addClass("hide");
                            $('#status-container').removeClass('hide');
                            
                        }, 5000);
                    }

                }
            });

        }
    });




});
