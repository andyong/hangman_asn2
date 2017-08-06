// Global variables
var canvas = document.getElementById('stage'),
    word = document.getElementById('word'),
    letters = document.getElementById('letters')

function init() {
    var helptext = $('#helptext'),
        w = screen.availWidth <= 800 ? screen.availWidth : 800;
    
    // Hide the loading message and display the control buttons
    $('#loading').hide();
    //$('#play').css('display', 'inline-block').click(newGame);
    //$('#clear').css('display', 'inline-block').click(resetScore);
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
    initGame(word_length);
    //checkLetterWithServer('');
    //showScore();
}

// Display the score in the canvas
function showScore()
{
    //getCurrentScoreFromServer();
} 
function drawScore(score)
{
    var won = score.games_won,
        lost = score.games_lost,
        c = canvas.getContext('2d');
    // clear the canvas
    canvas.width = canvas.width;
    c.font = 'bold 24px Optimer, Arial, Helvetica, sans-serif';
    c.fillStyle = 'red';
    c.textAlign = 'center';
    c.fillText('YOUR SCORE', 100, 50);
    c.font = 'bold 18px Optimer, Arial, Helvetica, sans-serif';
    c.fillText('Won: ' + won + ' Lost: ' + lost, 100, 80);
}


// Start new game
function newGame() {
    // get word from server, and after getting a response, the function calls the initGame function
    requestNewGameFromServer();
}

function initGame(word_length) {
    var placeholders = '',
        frag = document.createDocumentFragment(),
        abc = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'];
    
    for (i = 0; i < word_length; i++ )
    {
        placeholders += '_';
    }
    word.innerHTML = placeholders;
    // create an alphabet pad to select letters
    letters.innerHTML = '';
    for (i = 0; i < 26; i++) {
        var div = document.createElement('div');
        div.style.cursor = 'pointer';
        div.innerHTML = abc[i];
        //div.onclick = getLetter;
        var div = $("<div>");
        div.text(abc[i]);
        div.css('cursor', 'pointer');
        //div.on("click", getLetter);
        div.appendTo(letters);
        //frag.appendChild(div);
    }
    letters.appendChild(frag);
    enableLetters();
    drawHangman(0);
}

function disableLetters()
{
    $("#letters :not(.selected)").addClass("disabledLetterButtons");
    $("#letters :not(.selected)").off("click");
}

function enableLetters()
{
    $("#letters :not(.selected)").removeClass("disabledLetterButtons");
    $("#letters :not(.selected)").on("click", getLetter);
}

// Get selected letter and remove it from the alphabet pad
function getLetter() {
    disableLetters();
    $(this).addClass("selected");
    checkLetter(this.innerHTML);
    //this.innerHTML = '&nbsp;';
    this.style.cursor = 'default';
    this.onclick = null;
}

// Check whether selected letter is in the word to be guessed
function checkLetter(letter){
    checkLetterWithServer(letter);
}

function showCurrentGameState(attempt_result) {
    var game_state = attempt_result.game_state;
    word.innerHTML = attempt_result.word_state;
    if (game_state == "WIN")
    {
        // win the game!
        drawWin();
    }
    else if (game_state == "ONGOING")
    {
        // display the curent state of the game
        drawHangman(attempt_result.bad_guesses);
    }
    else // lose game
    {
        drawHangman(8); // 8 guesses to lose
        drawLose(attempt_result.answer);     
    }
}

// Draw the canvas
function drawHangman(badGuesses) {
    var c = canvas.getContext('2d');
    // reset the canvas and set basic styles
    canvas.width = canvas.width;
    c.lineWidth = 10;
    c.strokeStyle = 'green';
    c.font = 'bold 24px Optimer, Arial, Helvetica, sans-serif';
    c.fillStyle = 'red';
    // draw the ground
    drawLine(c, [20,190], [180,190]);
    // start building the gallows if there's been a bad guess
    if (badGuesses > 0) {
        // create the upright
        c.strokeStyle = '#A52A2A';
        drawLine(c, [30,185], [30,10]);
        if (badGuesses > 1) {
            // create the arm of the gallows
            c.lineTo(150,10);
            c.stroke();
        }
        if (badGuesses > 2) {
            c.strokeStyle = 'black';
            c.lineWidth = 3;
            // draw rope
            drawLine(c, [145,15], [145,30]);
            // draw head
            c.beginPath();
            c.moveTo(160, 45);
            c.arc(145, 45, 15, 0, (Math.PI/180)*360);
            c.stroke(); 
        }
        if (badGuesses > 3) {
            // draw body
            drawLine(c, [145,60], [145,130]);
        }
        if (badGuesses > 4) {
            // draw left arm
            drawLine(c, [145,80], [110,90]);
        }
        if (badGuesses > 5) {
            // draw right arm
            drawLine(c, [145,80], [180,90]);
        }
        if (badGuesses > 6) {
            // draw left leg
            drawLine(c, [145,130], [130,170]);
        }
        if (badGuesses > 7) {
            // draw right leg and end game
            drawLine(c, [145,130], [160,170]);
            c.fillText('Game over', 45, 110);
            // remove the alphabet pad
            letters.innerHTML = '';
        }
    }
}

function drawWin()
{
    // if the word has been guessed correctly, display message,
    // update score of games won, and then show score after 2 seconds
    letters.innerHTML = '';
    var c = canvas.getContext('2d');
    c.fillText('You won!', 45,110);
    // increase score of won games
    // display score
    setTimeout(showScore, 2000);
}

function drawLine(context, from, to) {
    context.beginPath();
    context.moveTo(from[0], from[1]);
    context.lineTo(to[0], to[1]);
    context.stroke();
}

function drawLose(answer)
{
    // display the correct answer
    // need to use setTimeout to prevent race condition
    setTimeout(function(){ showResult(answer); }, 200);
    // increase score of lost games
    // display the score after two seconds
    setTimeout(showScore, 2000);
}

// When the game is over, display missing letters in red
function showResult(answer) {
    var placeholders = word.innerHTML;
    placeholders = placeholders.split('');
    for (i = 0; i < placeholders.length; i++) {
        if (placeholders[i] == '_') {
            placeholders[i] = '<span style="color:red">' + answer.charAt(i).toUpperCase() + '</span>';
        }
    }
    word.innerHTML = placeholders.join('');
}

// Reset stored scores to zero
function resetScore() {
    word.innerHTML = '';
    letters.innerHTML = '';
    resetScoreInServer();
}

function requestFailed(evt)
{
    alert("Network error!");
}

// Select random word to guess
function requestNewGameFromServer() {
    var xmlhttp = new XMLHttpRequest();
    var url = "/new_game";

    xmlhttp.onreadystatechange = function() {
        if (xmlhttp.readyState == 4 && xmlhttp.status == 200) {
            var word_length = JSON.parse(xmlhttp.responseText).word_length;
            initGame(word_length);
            //console.log(wordToGuess);
        }
    };
    xmlhttp.addEventListener("error", requestFailed);

    xmlhttp.open("POST", url, true);
    xmlhttp.setRequestHeader("Authorization", "Token " + sessionStorage.token);
    xmlhttp.send();
}

// check with the server whether this letter is in the word
function checkLetterWithServer(letter)
{
    var xmlhttp = new XMLHttpRequest();
    var url = "/games/check_letter/" + game_id ;


    xmlhttp.onreadystatechange = function() {
        if (xmlhttp.readyState == 4) {
            if (xmlhttp.status == 200) {
                var attempt_result = JSON.parse(xmlhttp.responseText);
                showCurrentGameState(attempt_result);
                console.log(attempt_result);
            }
            enableLetters();
        }
    };
    xmlhttp.addEventListener("error", requestFailed);

    xmlhttp.open("POST", url, true);
    xmlhttp.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
    xmlhttp.setRequestHeader("Authorization", "Token " + sessionStorage.token);
    xmlhttp.send(JSON.stringify({ guess : letter }));
}

// get current score from server
function getCurrentScoreFromServer()
{
    var xmlhttp = new XMLHttpRequest();
    var url = "/score";

    xmlhttp.onreadystatechange = function() {
        if (xmlhttp.readyState == 4 && xmlhttp.status == 200) {
            var score = JSON.parse(xmlhttp.responseText);
            drawScore(score);
            console.log(score);
        }
    };
    xmlhttp.addEventListener("error", requestFailed);

    xmlhttp.open("GET", url, true);
    xmlhttp.send();
}

// reset score 
function resetScoreInServer()
{
    var xmlhttp = new XMLHttpRequest();
    var url = "/score";

    xmlhttp.onreadystatechange = function() {
        if (xmlhttp.readyState == 4 && xmlhttp.status == 200) {
            var score = JSON.parse(xmlhttp.responseText);
            drawScore(score);
            console.log(score);
        }
    };
    xmlhttp.addEventListener("error", requestFailed);

    xmlhttp.open("DELETE", url, true);
    xmlhttp.setRequestHeader("Authorization", "Token " + sessionStorage.token);
    xmlhttp.send();
}