(function ()
{
    var output = document.getElementById('dom-xss-output');
    if (!output)
    {
        return;
    }

    // Reload fragment-only navigation so document.write runs during parsing.
    window.addEventListener('hashchange', function ()
    {
        window.location.reload();
    });

    var params = new URLSearchParams(window.location.hash.substring(1));
    var language = params.get('lang');
    if (language === null)
    {
        language = 'en';
    }

    if (output.getAttribute('data-security-mode') === 'secure')
    {
        output.textContent = language;
    }
    else
    {
        // Intentionally vulnerable: keep this script parser-blocking in the panel.
        document.write(language);
    }
}());
