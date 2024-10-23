let donutChart = null;
let lineChart = null;

$(document).ready(function () {


  function updateStatus(status) {
    $('#status').text(status);
  
    if (status == "Protected") {
      $('#status').removeClass().addClass('alert alert-success text-center');

    } else if (status == "Low Risk" || status == "Medium Risk") {
      $('#status').removeClass().addClass('alert alert-warning text-center');

    } else {
      $('#status').removeClass().addClass('alert alert-danger text-center');
    }
  }

  function updateTable(start_time, start_date, duration, stop_time, stop_date) {

    if (stop_time && stop_date) {
      $('#stop_time').text(stop_time);
      $('#stop_date').text(stop_date);  
       
    } else {
      $('#stop_time-row').addClass('hide');
      $('#stop_date-row').addClass('hide');
    }

    $('#start_time').text(start_time);
    $('#start_date').text(start_date);

    let duration_text = "";
    
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

    $('#duration').text(duration_text);
  }


  

  function updateDonutChart(counts) {
    const d_chart = document.getElementById('donutChart');
  
    const colorMap = {
      'Normal': '#00CED1',
      'Probe': '#ffe184',
      'R2L': '#fca767',
      'DoS': '#ff6320',
      'U2R' : '#ff6c6c'
    };
    
    // Prepare data for the chart
    let labels = [];
    let data = [];
  
    // Fill labels and data arrays from counts
    for (let key in counts) {
      if (counts.hasOwnProperty(key)) {
        labels.push(key);
        data.push(counts[key]);
      }
    }
  
    // Now that labels are filled, map the colors
    const colors_map = labels.map(label => colorMap[label] || '#000000'); // Default to black if not in colorMap
  
    if (donutChart) {
      donutChart.destroy();
    }
  
    donutChart = new Chart(d_chart, {
      type: 'doughnut',
      data: {
        labels: labels,
        datasets: [{
          data: data,
          borderWidth: 1,
          backgroundColor: colors_map, // Set background colors for each segment
        }]
      },
      options: {
        plugins: {
          tooltip: {
            callbacks: {
              label: function (tooltipItem) {
                let total = tooltipItem.dataset.data.reduce((a, b) => a + b, 0);
                let value = tooltipItem.raw;
                let percentage = ((value / total) * 100).toFixed(2);
                return `${tooltipItem.label}: ${percentage}%`;
              }
            }
          }
        }
      }
    });
  }
  

  function updateLineChart(packetDetails) {
    const l_chart = document.getElementById('lineChart');
  
    if (lineChart) {
      lineChart.destroy();
    }
  
    // Extract unique IP addresses and count hits per attack type
    let attackTypes = {};
    let uniqueIPs = [];
  
    packetDetails.forEach(packet => {
      const ip = packet.ip_addr;
      const attackType = packet.attack_type;
  
      if (!attackTypes[attackType]) {
        attackTypes[attackType] = {};
      }
  
      if (!attackTypes[attackType][ip]) {
        attackTypes[attackType][ip] = 0;
      }
  
      attackTypes[attackType][ip] += 1; // Increment the hit count for this IP and attack type
  
      // Collect unique IP addresses
      if (!uniqueIPs.includes(ip)) {
        uniqueIPs.push(ip);
      }
    });
  
    // Create datasets for each attack type
    const datasets = Object.keys(attackTypes).map((type, index) => {
      return {
        label: type,
        data: uniqueIPs.map(ip => {
          return attackTypes[type][ip] || 0; // Assign the hit count or 0 if no data for that IP
        }),
        borderColor: getRandomColor(index), // Generate a random color for each line
        fill: true,
        tension: 0.1
      };
    });
  
    lineChart = new Chart(l_chart, {
      type: 'line',
      data: {
        labels: uniqueIPs, // X-axis represents unique IPs
        datasets: datasets // N datasets based on attack types
      },
      options: {
        scales: {
          y: {
            beginAtZero: true,
            title: {
              display: true,
              text: 'Hits Count'
            }
          },
          x: {
            title: {
              display: true,
              text: 'IP Addresses'
            },
            ticks: {
              maxRotation: 90, // Rotate labels for better visibility
              minRotation: 45,
              autoSkip: false // Ensure all IPs are shown even if there are many
            }
          }
        },
        plugins: {
          zoom: {
            pan: {
              enabled: true,  // Enable panning

            },
            zoom: {
              wheel: {
                enabled: true,  // Enable zooming via mouse wheel
              },
              pinch: {
                enabled: true,  // Enable zooming via pinch gestures
              },
              mode: 'x',  // Zoom only on the X axis
            },

          }
        }
      }
    });
  }
  
  // Helper function to generate random colors for the lines
  function getRandomColor(index) {
    const colors = ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF', '#FF9F40'];
    return colors[index % colors.length];
  }
  
  
  

  function updatePacketDetails(packet_details) {
    var packet_details_html = "";

    if (Array.isArray(packet_details)) {
        packet_details.forEach(packet => {
            packet_details_html += `
                <tr>
                  <td scope="row">${packet.date}</td>
                  <td>${packet.time.split('.')[0]}</td>
                  <td>${packet.ip_addr}</td>
                  <td class="scrollable-x user-select" >${packet.domain_name != null ? packet.domain_name : '-'}</td>
                  <td>${packet.attack_type}</td>
                  <td>${packet.attack_level}</td>
                </tr>
            `;
        });
    } else {
        packet_details_html = `<tr><td colspan="6">No data available</td></tr>`;
    }

    $('#attack-table-content').html(packet_details_html);
}


  // Function to request updated data from the server
  function fetchReportData() {
    $.ajax({
      type: "POST",
      url: "/report/0/",
      dataType: "json",
      headers: {
        'X-CSRFToken': csrftoken
      },
      success: function (response) {
        console.log(response);
        live_report = response.live_report;

        // Update the charts and status with new data
        updateStatus(live_report.status);
        updateTable(live_report.start_time, live_report.start_date, live_report.duration, live_report.stop_time ? live_report.stop_time : null , live_report.stop_date ? live_report.stop_date : null);
        updateDonutChart(live_report.counts);
        updateLineChart(live_report.packet_details);
        updatePacketDetails(live_report.packet_details);
      },
      error: function (xhr, status, error) {
        console.log("Error fetching report data: ", error);
      }

    });
  }

  // Check if the current path is '/report/0/' and set up periodic updates
  if (window.location.pathname === '/report/0/') {
    // Fetch data initially
    fetchReportData();

    // Periodically update data every 10 seconds (adjust the interval as needed)
    setInterval(fetchReportData, 10000); // 10000 ms = 10 seconds
  }




  console.log(report_data);

  var status = report_data.status;
  var counts = report_data.counts;
  var packet_details = report_data.packet_details;

  updateStatus(status);
  updateTable(report_data.start_time, report_data.start_date, report_data.duration, report_data.stop_time ? report_data.stop_time : null , report_data.stop_date ? report_data.stop_date : null);
  updateDonutChart(counts);
  updateLineChart(packet_details);
  updatePacketDetails(packet_details);

});
