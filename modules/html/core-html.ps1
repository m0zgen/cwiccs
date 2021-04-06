# HTML Body
$mainSnippet = @"
<div class="header">
<h1>Security report. $hostName</h1>
<hr>
<ul>
    <li>Computer name - <b>$hostName</b></li>
    <li>OS - <b>$osName</b>
        <ul>
            <li>Last boot time - <b>$osBootTime</b></li>
            <li>Has been up for - <b>$osWorksTime</b></li>
            <li>Installation date - <b>$osInstallDate</b></li>
            <li>Build number - <b>$osBuild</b></li>
            <li>Architecture - <b>$osArch</b></li>
            <li>Product ID - <b>$osSerial</b></li>
            <li>Product Key - <b>$osKey</b></li>
            <li>UUID - <b>$osUUID</b></li>
        </ul>
    </li>
    <li>User - <b>$currentUser (elevated - $isAdmin)</b></li>
    <li>Internal IP - <b>$internalIP</b></li>
    <li>Founded Errors / Warnings - <b id="errorTag">$countError</b></li>
</ul>
</div>
<hr>
<div class="main">
"@

$scriptSnippet = @"
</div>
<footer><i>Report created - <b>$timeStamp</b></i></footer>
<script type="text/javascript">
  var tds = document.getElementsByTagName('td');
  for (var i = 0; i < tds.length; i++) {
    if (tds[i].innerHTML.indexOf("FAIL") !== -1) {
      console.log('The ' + tds[i].textContent + ' is endangered!');
      tds[i].style.color = "#d85c5c";
      tds[i].style.fontWeight = "900";
    }
    if (tds[i].innerHTML.indexOf("OK") !== -1) {
      tds[i].style.color = "#4aa74a";
      tds[i].style.fontWeight = "900";
    }
    if (tds[i].innerHTML.indexOf("WARNING") !== -1) {
      tds[i].style.color = "#fd772d";
      tds[i].style.fontWeight = "900";
    }
    if (tds[i].innerHTML.indexOf("INFO") !== -1) {
      tds[i].style.color = "#003366";
    }
  var element = document.getElementById('errorTag');
  element.style.fontWeight = "900";
  if (element.innerHTML.indexOf("0") !== -1) {
      element.style.color = "#d85c5c";
    }
    else {
        element.style.color = "#d85c5c";
    }
  }
</script>
"@

# Bind HTML report with collected data
$html += $mainSnippet

$html += $localUsers | Select Name, Disabled, LockOut, 'Password Expires', 'Password Last Set', 'Last logon' | ConvertTo-Html -Fragment -As Table -PreContent "<h2>Local Users Information</h2>"
$html += $diskInfo | Select Name, 'Total(GB)', 'Free(GB)', 'Free(%)' | ConvertTo-Html -Fragment -As Table -PreContent "<h2>Disk info (sorted by free space percentage)</h2>"
$html += $localPasswordPolicy | Select Name, State, Status | ConvertTo-Html -Fragment -As Table -PreContent "<h2>Password policy info</h2>"
$html += $localAuditPolicy | Select Name, State, Status | ConvertTo-Html -Fragment -As Table -PreContent "<h2>Audit policy info</h2>"
$html += $localRegistryPolicy | Select Name, State, Status | ConvertTo-Html -Fragment -As Table -PreContent "<h2>Security Options policy info</h2>"
$html += $reportBaseSettings | Select Name, State, Status | ConvertTo-Html -Fragment -As Table -PreContent "<h2>Base security settings</h2>"
$html += $reportFeatures | Select Name, State, Status | ConvertTo-Html -Fragment -As Table -PreContent "<h2>Installed Windows features</h2>"
$html += $reportRequiredServices | Select Name, State, Status | ConvertTo-Html -Fragment -As Table -PreContent "<h2>Requred services status</h2>"
$html += $reportRestrictedServices | Select Name, State, Status | ConvertTo-Html -Fragment -As Table -PreContent "<h2>Restricted services status</h2>"
$html += $reportPorts | Select Name, State, Status | ConvertTo-Html -Fragment -As Table -PreContent "<h2>Listening ports</h2>"
$html += $reportSoft | Select Name, State, Status | ConvertTo-Html -Fragment -As Table -PreContent "<h2>Software</h2>"

$html += $scriptSnippet

