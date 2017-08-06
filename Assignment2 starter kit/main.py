# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# [START app]
import logging
import urllib2
import json
import os
import re
import base64
import hashlib
import uuid
import random
import string

from flask import Flask, flash, render_template, request, session, redirect, url_for, escape
from google.appengine.ext import ndb
from google.appengine.ext.ndb import metadata
from random import choice
from string import digits
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
#from Account import Account

app = Flask(__name__)
app.secret_key = os.urandom(24)

def init_game():
    session['word_to_guess'] = ''#GenerateRandomWord() #new word
    session['word_state'] = init_word_state(session['word_to_guess'])
    session['bad_guesses'] = 0
    session['no_of_games_created'] = 0
    session['no_of_games_played'] = 0
    session['word_hint'] = ''
    session['game_ID'] = generategameid(10)
    pass

def init_word_state(words):
    return "_" * len(words) #length of word in _

def GenerateRandomWord():
    urlreq = urllib2.Request('http://setgetgo.com/randomword/get.php')
    response = urllib2.urlopen(urlreq)
    word = response.read()
    return word

def generategameid(length):
   return ''.join(random.choice(string.digits) for i in range(length))

@app.route('/')
def index():
    init_game()
    game_list = Room.query()
    game_list2 = list()
    for result2 in game_list: #each game in Room
        result = {}
        result ['hint'] = result2.hint
        result ['word_length'] = result2.word_length
        result ['game_id'] = result2.key.id()
        game_list2.append(result) #add to dict

    if 'signed_in' not in session:
        session['signed_in'] = False
        session['admin'] = False
    if 'signed_in_name' not in session:
        session['signed_in_name'] = ""

    if session['signed_in'] == True:
        session['signed_in_name'] = session['username']

    logging.debug(session['signed_in_name'])
    #logging.debug

    return render_template('main.html', signed_in = session['signed_in'], signed_in_name = session['signed_in_name'], game_list = game_list2) #renders main page

class Account(ndb.Model):
    username = ndb.StringProperty()
    hashedpassword = ndb.StringProperty()
    token = ndb.StringProperty()
    isAdmin = ndb.BooleanProperty()
    games_created = ndb.IntegerProperty()
    games_played = ndb.IntegerProperty()
    games_won = ndb.IntegerProperty()
    games_lost = ndb.IntegerProperty()

    def HashPassword(self, password):
        #salt = uuid.uuid4().hex
        #hashed_password = hashlib.sha512(password + salt).hexdigest()
        self.hashedpassword = generate_password_hash(password)

    def CheckPassword(self, password):
		return check_password_hash(self.hashedpassword, password)

    def GenerateNewToken(self):
        newtoken = uuid.uuid4().hex
        self.newtoken = newtoken
        self.put()

    def CreateGame(self):
        self.games_created += 1
        self.put()

    def PlayGame(self):
        self.games_played += 1
        self.put()

    def WinGame(self):
        self.games_won += 1
        self.put()

    def LoseGame(self):
        self.games_lost += 1
        self.put()

    def NewAccount(cls, name, password, isAdmin):
        user = Account()
        user.username = name
        user.HashPassword(password)
        user.isAdmin = isAdmin
        user.games_created = 0
        user.games_played = 0
        user.games_won = 0
        user.games_lost = 0
        user.put()
        return user

    def GetPlayerByUserName(cls, name):
		query = Account.query(Account.username == name)
		return query.get()

    def GetAllPlayers(cls, sortbyType, sortbyOrder):
        #data = Account.query().fetch()
        if sortbyOrder == "asc":
            if sortbyType == "wins":
                data = Account.query().order(Account.games_won)
            elif sortbyType == "losses":
                data = Account.query().order(Account.games_lost)
            elif sortbyType == "alphabetical":
                data = Account.query().order(Account.username)
        else: #descending order
            if sortbyType == "wins":
                data = Account.query().order(-Account.games_won)
            elif sortbyType == "losses":
                data = Account.query().order(-Account.games_lost)
            elif sortbyType == "alphabetical":
                data = Account.query().order(-Account.username)

        userlist = []
        for user in data.fetch():
            result = {
            'name' : user.username,
            'games_created' : user.games_created,
            'games_played' : user.games_played,
            'games_won' : user.games_won,
            'games_lost' : user.games_lost
            }
            userlist.append(result)
        return userlist


@app.route('/token', methods=['GET', 'POST'])
def get_token():
    session['username'] = request.authorization.username
    session['password'] = request.authorization.password

    if request.method == 'GET':
        if(PlayerExistInDB(session['username'])):
            if(ValidatePassword(session['username'], session['password'])):
                return AddTokenToAccount(Account().GetPlayerByUserName(session['username']))
            else:
                return redirect('/', code = 302)

        else:
            errormsg = {
            'Error' : "User does not exist"
            }
            return json.dumps(errormsg)

    elif request.method == 'POST':
        if(not PlayerExistInDB(session['username'])):
            return AddNewAccount(session['username'], session['password'])
        else:
            errormsg = {
            'Error' : "User ID already exists"
            }
            return json.dumps(errormsg)

    result = {
    #"token" : session['token_string']
    }
    return json.dumps(result)

def PlayerExistInDB(username):
	return Account().GetPlayerByUserName(username) != None

def ValidatePassword(username, password):
	user = Account().GetPlayerByUserName(username)
	return user.CheckPassword(password)

def AddNewAccount(username, password):
    user = Account().NewAccount(username, password, False)
    return AddTokenToAccount(user)

def AddTokenToAccount(user):
    session['signed_in'] = True
    session['signed_in_name'] = user.username
    user.GenerateNewToken()
    return CheckToken(user.newtoken)

def CheckToken(usertoken):
    token = {}
    token['token'] = usertoken
    return json.dumps(token)

#list ongoing games, create or delete games
@app.route('/games', methods=['GET', 'POST', 'DELETE'])
def games():
    if request.method == 'POST':
        data = json.loads(request.data)
        roomdata = {
        'username' : session['signed_in_name'],
        'word_hint' : data['hint'],
        'word_to_guess' : data['word']
        }
        gameroom = Room().NewRoom(roomdata)
        roomcontent = {
        'hint' : gameroom.hint,
        'word_length' : gameroom.word_length,
        'game_id' : str(gameroom.game_id)
        }
        user = Account().GetPlayerByUserName(session['signed_in_name'])
        logging.debug(user.isAdmin)
        user.CreateGame() #create game count + 1
        '''session['word_hint'] = data["hint"]
        session['word_to_guess'] = data["word"]
        session['word_state'] = init_word_state(session['word_to_guess'])
        data.update({'game_id' : str(id)})'''
        #room_state = Room(hint = session['word_hint'], word = session['word_to_guess'], state = session['word_state'], word_length = len(session['word_to_guess']))
        return json.dumps(roomcontent)

    elif request.method == 'GET':
        return Room.query().fetch()

    elif request.method == 'DELETE':
        DeleteAllGames()
        return ""

    return ""#json.dumps(result)

@app.route('/games/<id>', methods=['GET', 'DELETE'])
def play_game(id):
    game_property = {}
    game_list = Room.query()
    if request.method == 'GET':
        ongoinggame = GetRoomID(int(id))
        game_property ['hint'] = ongoinggame.hint
        game_property ['word_length'] = ongoinggame.word_length
        game_property ['game_id'] = id
        logging.debug(game_property)
        user = Account().GetPlayerByUserName(session['signed_in_name'])
        user.PlayGame() #play count + 1

    elif request.method == 'DELETE':
        roomtodelete = GetRoomID(int(id))
        roomtodelete.DeleteSpecifiedGame()
        deletemsg = {
        "message" : "Game was deleted"
        }
        return json.dumps(deletemsg)

    return render_template('game.html', game_property = game_property)


class Room(ndb.Model):
    username = ndb.StringProperty()
    word_state = ndb.StringProperty()
    hint = ndb.StringProperty()
    word = ndb.StringProperty()
    word_length = ndb.IntegerProperty()
    game_id = ndb.IntegerProperty()
    bad_guesses = ndb.IntegerProperty()
    wins = ndb.IntegerProperty()
    losses = ndb.IntegerProperty()

    def NewRoom(cls, data):
        room_state = Room()
        room_state.username = data['username']
        room_state.hint = data['word_hint']
        room_state.word = data['word_to_guess']
        room_state.word_state = init_word_state(data['word_to_guess'])
        room_state.word_length = len(data['word_to_guess'])
        room_state.bad_guesses = 0
        room_state.wins = 0
        room_state.losses = 0
        room_state.put()
        room_state.game_id = room_state.key.id()
        room_state.put()
        return room_state

    def WinGame(self):
        self.wins += 1
        self.put()

    def LoseGame(self):
        self.losses += 1
        self.put()

    def DeleteSpecifiedGame(self):
        return self.key.delete()

    def GetAllGames(cls, sortbyType, sortbyOrder):
        if sortbyOrder == "asc":
            if sortbyType == "solved":
                data = Room.query().order(Room.wins)
            elif sortbyType == "length":
                data = Room.query().order(Room.word_length)
            elif sortbyType == "alphabet":
                data = Room.query().order(Room.word)
        else: #descending order
            if sortbyType == "solved":
                data = Room.query().order(-Room.wins)
            elif sortbyType == "length":
                data = Room.query().order(-Room.word_length)
            elif sortbyType == "alphabet":
                data = Room.query().order(-Room.word)

        gamelist = []
        for game in data.fetch():
            result = {
            'word' : game.word,
			'wins' : game.wins,
			'losses' : game.losses
            }
            gamelist.append(result)
        return gamelist

def GetRoomID(game_id):
    roomid = Room.query(Room.game_id == game_id)
    return roomid.get()

def DeleteAllGames():
    ndb.delete_multi(Room.query().fetch(keys_only=True))

'''def GetCurrentGame(id, name):
    currentGame = RoomState.query(RoomState.gameID == id, RoomState.username == name)
    return currentGame.get()'''
###########################################################################################################################################
@app.route('/games/check_letter/<id>', methods=['POST'])
def check_letter(id):
    integerID = int(id)
    data = json.loads(request.data)
    #guess_letter = request.json
    guess_letter = data['guess']

    '''letter = "/[a-zA-z]?/"
    if request.json is None:
        return 'Error! Input of a letter is required!'
    elif request.json != letter:
        return 'Error! A valid character is needed!'''

    currentgame = GetRoomID(integerID)
    #currentgameprogress = GetCurrentGame(integerID, session['signed_in_name'])
    #logging.debug(currentgameprogress)

    if guess_letter == '': #player enter nothing
        user = Account().GetPlayerByUserName(session['signed_in_name'])
        #if user is not None:
            #user.PlayGame() #player playcount +1

        result = {
        "game_state" : "ONGOING",
        "word_state" : currentgame.word_state,
        "bad_guesses" : currentgame.bad_guesses
        }
        #logging.debug(newGameState)
        return json.dumps(result)

        if currentgame.bad_guesses == 8: #lose
            result = {
            "game_state" : "LOSE",
            "word_state" : currentgame.word_state,
            "answer" : currentgame.word,
            }
            #session['no_of_games_lost'] += 1
            return json.dumps(result)

        elif currentgame.word == currentgame.word_state: #win
            result = {
            "game_state" : "WIN",
            "word_state" : currentgame.word_state,
            }
            #session['no_of_games_won'] += 1
            return json.dumps(result)

        else: #ongoing
            result = {
            "game_state" : "ONGOING",
            "word_state" : currentgame.word_state,
            "bad_guesses" : currentgame.bad_guesses
            }
            return json.dumps(result)
    #guess_letter = request.json
    #logging.debug(guess_letter['guess'])
    else:
        return check_input(guess_letter, id)

def check_input(input, id):
    input = str(input).lower()

    integerId = int(id)
    game = GetRoomID(integerId)
    #currentgameprogress = GetCurrentGame(integerId, session['signed_in_name'])

    if input in game.word:
        fill_in_letter(input, id)
    else:
        #currentgameprogress.bad_guesses += 1
        #currentgameprogress.put()
        game.bad_guesses += 1
        game.put()
        #logging.debug(bad_guesses)

    if game.bad_guesses == 8: #lose
        user = Account().GetPlayerByUserName(session['signed_in_name'])
        result = {
        "game_state" : "LOSE",
        "word_state" : game.word_state,
        "answer" : game.word,
        }
        user.LoseGame()
        game.LoseGame()
        return json.dumps(result)
        #session['no_of_games_lost'] += 1

    elif game.word == game.word_state: #win
        user = Account().GetPlayerByUserName(session['signed_in_name'])
        result = {
        "game_state" : "WIN",
        "word_state" : game.word_state,
        }
        user.WinGame()
        game.WinGame()
        #session['no_of_games_won'] += 1
        return json.dumps(result)

    else: #ongoing
        result = {
        "game_state" : "ONGOING",
        "word_state" : game.word_state,
        "bad_guesses" : game.bad_guesses
        }
        return json.dumps(result)

def fill_in_letter(guess, id): #fill in the letter if it exists in the word
    integerId = int(id)
    currentGame = GetRoomID(integerId)
    #currentgameprogress = GetCurrentGame(integerId, session['signed_in_name'])
    x = list(currentGame.word_state)
    if guess in currentGame.word:#session['word_to_guess']:
        indices = find_all(currentGame.word, guess)
        x = list(currentGame.word_state)
        for i in indices:
            x[i] = guess
            currentGame.word_state = "".join(x)
            currentGame.put() #store word_state again

    return currentGame.word_state#session['word_state']

def find_all(word, input): #check if letter exists in the word
    return [i for i, letter in enumerate(word) if letter == input]
################################################################################################################################################################

@app.route('/admin', methods=['GET'])
def get_adminpage():
    user = Account().GetPlayerByUserName(session['signed_in_name'])
    if user.isAdmin:
        return render_template('admin.html')
    else:
        "No permission to view this page!"

@app.route('/admin/players', methods=['GET'])
def admin_getplayers():
    sortType = request.args.get('sortby')
    sortOrder = request.args.get('order')
    userlist = Account().GetAllPlayers(sortType, sortOrder)
    return json.dumps(userlist)

@app.route('/admin/words', methods=['GET'])
def admin_getlistofwords():
    sortType = request.args.get('sortby')
    sortOrder = request.args.get('order')
    wordlist = Room().GetAllGames(sortType, sortOrder)
    return json.dumps(wordlist)

if __name__ == "__main__":
    # set the secret key.  keep this really secret:
    app.run(debug=True)

@app.errorhandler(400)
def client_error(e):
    logging.exception('An error occurred during a request')
    return redirect('/', code = 400)
    #return 'Bad Request.', 400

@app.errorhandler(403)
def user_error(e):
    logging.exception('An error occurred during a request')
    return redirect('/', code = 403)
    #return redirect('/success')
    return 'Forbidden.', 403

@app.errorhandler(404)
def not_found_error(e):
    logging.exception('An error occurred during a request')
    return redirect('/', code = 404)
    #return 'Error, requested resource could not be found.', 404

@app.errorhandler(405)
def not_allowed_error(e):
    logging.exception('An error occurred during a request')
    return redirect('/', code = 405)
    #return 'Error, requested resource could not be found.', 405

@app.errorhandler(500)
def server_error(e):
    # Log the error and stacktrace.
    logging.exception('An error occurred during a request.')
    return redirect('/', code = 500)
    #return 'An internal error occurred.', 500
# [END app]
