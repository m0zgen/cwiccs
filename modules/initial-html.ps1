
# HTML
# -------------------------------------------------------------------------------------------\

$Head = @"
<title>Security report from $hostName</title>

<style>
body {
    font-family: "Arial";
    font-size: 9pt;
    color: #4C607B;
    background-color: #f5f5f5;
}
.header { margin-top: -11px; }
.header p { font-size: 11pt; line-height: 19px; }
footer {
    padding-left: 5px;
}
h1, h2 {
    display: block;
    padding-left: 6px;
}
h1::first-letter, h2::first-letter {
    font-size: 120%;
    color: #3b4e67;
}
ul {
    list-style: circle;
}
li {
    font-size: 10pt;
    padding-top: 5px;
}

table { width:800px; margin-left:5px; margin-bottom:20px;}
table td:nth-child(2), table td:nth-child(3) { width: 90px; }
th, td {
    border: 1px solid #e57300;
    border-collapse: collapse;
    padding: 5px;
}
th {
    font-size: 1.2em;
    text-align: left;
    background-color: #003366;
    color: #ffffff;
}
td { color: #000000; }
tr:Nth-Child(Even) {Background-Color: #ececec;}
tr:Hover TD {Background-Color: #C1D5F8;}

.green {
background-color: green;
}
.red {
background-color: red;
}

</style>
"@