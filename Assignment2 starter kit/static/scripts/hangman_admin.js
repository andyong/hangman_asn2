function init() {
    
    // Hide the loading message and display the control buttons
    $('#players').css('display', 'inline-block').click(showPlayers);
    $('#words').css('display', 'inline-block').click(showWords);
  
    // Rescale the canvas if the screen is wider than 700px
    if (screen.innerWidth >= 700) {
        canvas.getContext('2d').scale(1.5, 1.5);
    }

    console.log("done");
}


function showPlayers()
{
    var sortBy = $('input[name=player_sortby]:checked').val();
    var order = $('input[name=player_order]:checked').val();

    getListOfPlayersFromServer(sortBy, order);
}

function onGetListOfPlayersFromServerComplete(player_list)
{
    var headers = ["name", "games_created", "games_played", "games_won", "games_lost"];
    createTable(headers, player_list);
}

function createTable(headers, tableData)
{
    var data = $('#data');
    data.empty();
    var table = document.createElement("table");
    table.id = "resulttable";
    data.append(table);
    var row = document.createElement("tr");

    for (var i = 0; i < headers.length; i++)
    {
        var h = document.createElement("th");
        h.textContent = headers[i];
        row.appendChild(h);    
    }
    table.appendChild(row);

    for (var i = 0; i < tableData.length; i++) 
    {
        row = document.createElement("tr");
        for (var j = 0; j < headers.length; j++)
        {
            var data = document.createElement("td");
            data.textContent = tableData[i][headers[j]];
            row.appendChild(data);
        }
        table.appendChild(row);
    }
}


function showWords()
{
    var sortBy = $('input[name=words_sortby]:checked').val();
    var order = $('input[name=words_order]:checked').val();

    getListOfWordsFromServer(sortBy, order);
}

function onGetListOfWordsFromServerComplete(words_list)
{
    var headers = ["word", "wins", "losses"];
    createTable(headers, words_list);
}

// gets the list of players from the server
function getListOfPlayersFromServer(sortBy, order)
{
    var xmlhttp = new XMLHttpRequest();
    var url = "/admin/players?sortby=" + sortBy + "&order=" + order;

    xmlhttp.onreadystatechange = function() {
        if (xmlhttp.readyState == 4 && xmlhttp.status == 200) {
            var player_list = JSON.parse(xmlhttp.responseText);
            console.log(player_list);
            onGetListOfPlayersFromServerComplete(player_list);
        }
    };

    xmlhttp.open("GET", url, true);
    xmlhttp.setRequestHeader("Authorization", "Token " + sessionStorage.token);
    xmlhttp.send();
}

// gets the list of players from the server
function getListOfWordsFromServer(sortBy, order)
{
    var xmlhttp = new XMLHttpRequest();
    var url = "/admin/words?sortby=" + sortBy + "&order=" + order;

    xmlhttp.onreadystatechange = function() {
        if (xmlhttp.readyState == 4 && xmlhttp.status == 200) {
            var words_list = JSON.parse(xmlhttp.responseText);
            console.log(words_list);
            onGetListOfWordsFromServerComplete(words_list);
        }
    };

    xmlhttp.open("GET", url, true);
    xmlhttp.setRequestHeader("Authorization", "Token " + sessionStorage.token);
    xmlhttp.send();
}