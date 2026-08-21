function process(data)
{
    alert("Surname(s) from JSON results: " + Object.keys(data).map(function(k) {return data[k]}));
};

var index = document.location.hash.indexOf('lang=');
if (index != -1)
{
    document.write('<div style=\"position: absolute; top: 5px; right: 5px;\">Chosen language: <b>' + decodeURIComponent(document.location.hash.substring(index + 5)) + '</b></div>');
}

(function ()
{
    var button = document.getElementById('lesson-card-toggle');
    var cards = document.querySelectorAll('.lesson-card');
    var storageKey = 'dsvpwa.lessonCardsVisible';

    if (!button || cards.length === 0)
    {
        return;
    }

    function readPreference()
    {
        try
        {
            return window.sessionStorage.getItem(storageKey) === 'true';
        }
        catch (error)
        {
            return false;
        }
    }

    function savePreference(visible)
    {
        try
        {
            window.sessionStorage.setItem(storageKey, String(visible));
        }
        catch (error)
        {
            // The control still works if browser storage is unavailable.
        }
    }

    function setLessonCardsVisible(visible)
    {
        Array.prototype.forEach.call(cards, function (card)
        {
            card.classList.toggle('d-none', !visible);
            card.setAttribute('aria-hidden', String(!visible));
        });

        button.textContent = visible ? 'Hide lesson' : 'Show lesson';
        button.setAttribute('aria-expanded', String(visible));
    }

    button.hidden = false;
    setLessonCardsVisible(readPreference());

    button.addEventListener('click', function ()
    {
        var visible = button.getAttribute('aria-expanded') !== 'true';
        setLessonCardsVisible(visible);
        savePreference(visible);
    });
}());
