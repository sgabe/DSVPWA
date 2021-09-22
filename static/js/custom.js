function process(data)
{
    alert("Surname(s) from JSON results: " + Object.keys(data).map(function(k) {return data[k]}));
};

var index = document.location.hash.indexOf('lang=');
if (index != -1)
{
    document.write('<div style=\"position: absolute; top: 5px; right: 5px;\">Chosen language: <b>' + decodeURIComponent(document.location.hash.substring(index + 5)) + '</b></div>');
}
