function init() {
    var helptext = $('#helptext'),
        w = screen.availWidth <= 800 ? screen.availWidth : 800;

    // Hide the loading message and display the control buttons
    //$('#notsignedin').hide();
    $('#signin').css('display', 'inline-block').click(signIn);
    $('#signup').css('display', 'inline-block').click(signUp);
    $('#oauthsignin').css('display', 'inline-block').click(OAuthSignIn);
    $('#creategame').css('display', 'inline-block').click(createGame);
    $('#deletebutton').css('display', 'inline-block').click(deleteGame);
    $('#help').click(function(e) {
        $('body').append('<div id="mask"></div>');
        helptext.show().css('margin-left', (w-300)/2 + 'px');
    });
    $('#close').click(function(e) {
        $('#mask').remove();
        helptext.hide();
    });

    // Rescale the canvas if the screen is wider than 700px
    if (screen.innerWidth >= 700) {
        canvas.getContext('2d').scale(1.5, 1.5);
    }

    console.log("done");
}

function signIn(){
    var username = $('#username_input').val();
    var password = $('#password_input').val();
    signInToServer(username, password, false);
    console.log("sign in");
}

function signUp(){
    var username = $('#username_input').val();
    var password = $('#password_input').val();
    signInToServer(username, password, true);
    console.log("sign up");
}

function onSignInComplete(token)
{
    // not so nice, but we'll make do for now
    // token is to be saved in the sessionStorage
    sessionStorage.token = token;
    location.reload();
}

function OAuthSignIn()
{
    // redirects user to get permission to retrieve information from OAuth 2.0 provider
    location.assign("oauth2callback");
}

function createGame(){
    // create a game on server
    console.log("Create Game on Server");
    var word = $('#word_input').val();
    var hint = $('#hint_input').val();
    createGameOnServer(word, hint);
}

function onCreateGameComplete(game_properties){
    // reloads the page to show that the game is created
    location.reload();
}

function deleteGame(){
    var selected_game = $('input[name=delete_game]:checked').val();
    deleteGameOnServer(selected_game);
}

function onDeleteGameComplete()
{
    // reload the page to show that the game is deleted
    location.reload();
}
// sign in to server by sending the credentials over to the server
// set register to true if you want to create this user with the new credentials
function signInToServer(username, password, register = false)
{
    var xmlhttp = new XMLHttpRequest();
    var url = "/token";

    xmlhttp.onreadystatechange = function() {
        if (xmlhttp.readyState == 4 && xmlhttp.status == 200) {
            var token = JSON.parse(xmlhttp.responseText);
            onSignInComplete(token.token);
            console.log(token.token);
        }
    };
    var method = "GET";

    if (register)
    {
        // if we are using this credentials to register, then use a POST request
        method = "POST";
    }

    xmlhttp.open(method, url, true);
    xmlhttp.setRequestHeader("Authorization", "Basic " + btoa(username+":"+password));
    xmlhttp.send();
}

// sign in to server by sending the credentials over to the server
// set register to true if you want to create this user with the new credentials
function createGameOnServer(word, hint)
{
    var xmlhttp = new XMLHttpRequest();
    var url = "/games";
    var game_details = {};
    game_details['word'] = word;
    game_details['hint'] = hint;

    xmlhttp.onreadystatechange = function() {
        if (xmlhttp.readyState == 4 && xmlhttp.status == 200) {
            var game_properties = JSON.parse(xmlhttp.responseText);
            console.log(game_properties);
            onCreateGameComplete(game_properties);
        }
    };

    xmlhttp.open("POST", url, true);
    xmlhttp.setRequestHeader("Authorization", "Token " + sessionStorage.token);
    xmlhttp.send(JSON.stringify(game_details));
}

// delete games on the server
// delete all games if there is nothing selected
// server is to check if the request has
function deleteGameOnServer(game_id = '')
{
    var xmlhttp = new XMLHttpRequest();
    var game_uri = (game_id=='')?'':'/'+game_id
    var url = "/games" + game_uri;

    xmlhttp.onreadystatechange = function() {
        if (xmlhttp.readyState == 4 && xmlhttp.status == 200) {
            console.log("Game Deleted");
            onDeleteGameComplete()
        }
    };

    console.log(url);
    xmlhttp.open("DELETE", url, true);
    xmlhttp.setRequestHeader("Authorization", "Token " + sessionStorage.token);
    xmlhttp.send();
}
