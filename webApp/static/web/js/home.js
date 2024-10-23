$(document).ready(function () {
    console.log(SCAN_RUNNING);

    function getTotalCounts(counts) {
        let total = 0;
    
        for (let key in counts) {
            if (key !== 'Normal') {
                total += counts[key];
            }
        }
    
        return total;
    }



    if (SCAN_RUNNING == 1){
        $('#scan-status-dot').removeClass('scan-inactive');
        $('#scan-status-dot').addClass('scan-active');

        $('#scan-status').text('Active');

        $('#intrusions_count-text').html(`<span id="intrusions_count">0</span> Intrusions Found`);


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
                    let status = response.live_status.status;
                    let counts = response.live_status.counts;

                    console.log(counts);
                    $('#intrusions_count').text();

                    $('#network-status').text(status);

                    if (status == "Protected") {
                        $('#network-status').removeClass().addClass('text-blue-4 poppins-semibold py-2 fs-ultra-large');
                
                    } else if (status == "Low Risk" || status == "Medium Risk") {
                        $('#network-status').removeClass().addClass('text-yellow poppins-semibold py-2');
                
                    } else {
                        $('#network-status').removeClass().addClass('text-red poppins-semibold py-2 fs-ultra-large');
                    }


                    let total_count = getTotalCounts(counts);
                    $('#intrusions_count').text(total_count);
                }
            });
            
        }

        setInterval(updateStatus, 10000);



        
    } else if (SCAN_RUNNING == 0) {
        $('#scan-status-dot').addClass('scan-inactive');
        $('#scan-status-dot').removeClass('scan-active');

        $('#scan-status').text('Inactive');

        $('#network-status').text("N/A");
        $('#network-status').removeClass().addClass('text-white-50 poppins-semibold py-2');

        $('#intrusions_count-text').html(`Start a Scan to see network status`);
        
    }
});