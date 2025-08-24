import os
import random
import string

import nacl.pwhash
import nacl.utils
from nacl import secret


FLAG = os.getenv('FLAG', 'PSUTICTF{fake_flag}')
GAMES_COUNT = 35
GUESS_COUNTS = 6


def gen_guessable():
    return ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=5))


class FieldOfWonders:
    def __init__(self):
        self.guessable = self.guesses = self.salt = self.keyphrase = self.key = None
        self.reset()

    def reset(self):
        self.guessable = [gen_guessable() for _ in range(5)]
        self.salt = nacl.utils.random(nacl.pwhash.argon2id.SALTBYTES)
        self.keyphrase = ' '.join(random.choices(self.guessable, k=3))
        self.key = nacl.pwhash.argon2id.kdf(
            size=secret.Aead.KEY_SIZE,
            password=self.keyphrase.encode(),
            salt=self.salt,
            opslimit=nacl.pwhash.argon2id.OPSLIMIT_MODERATE,
            memlimit=nacl.pwhash.argon2id.MEMLIMIT_MODERATE,
        )
        self.guesses = 0

    def open_word(self, word_ctxt: str):
        if self.guesses > GUESS_COUNTS:
            print('Enough is enough...')
            return False
        self.guesses += 1
        try:
            secret.Aead(self.key).decrypt(bytes.fromhex(word_ctxt))
            print('You guessed the correct word, congratulations!')
            return True
        except:
            print('Unfortunately not')
            return False

    def guess_phrase(self, guess: str):
        if self.keyphrase == guess:
            print('And... We have a winner!')
            return True
        else:
            print('Oops... Seems that was an error.')
            return False


def menu():
    print('| 1. Guess a word by using a hint from the encryption algorithm')
    print('| 2. Guess the full phrase')


def main():
    print(
        'Welcome to PSUTICTF\'s Field Of Wonders! It\'s like your usual Field of Wonders,'
        ' but specifically for crypto players.\nWe offer you the opportunity to win the whole FLAG today by properly'
        ' guessing the words in the phrase.\nIf you can guess the full phrase by doing up to 6 guesses in 35 games'
        ' consistently we would give you a flag for free, you do not even need to spin the wheel.\n'
        'But as guessing just words from the prase would be too boring, instead we would use our extremely secure'
        ' encryption algorithm using the keyphrase which should give you a hint about if word is in that phrase or '
        'not.\nHave fun!'
    )
    wins = 0
    game = FieldOfWonders()
    for i in range(GAMES_COUNT):
        game.reset()
        print(f'Game #{i+1} / {GAMES_COUNT}')
        print(f'Sponsor of this game is:\n{game.salt.hex()}')
        print(f'And a little hint on which words can be in the phrase:\n{game.guessable}')
        while True:
            print('What would you like to do now?')
            menu()
            option = input('> ')
            if option not in {'1', '2'}:
                print('I do not think you can do that, I\'m sorry.')
                continue
            if option == '1':
                word_ctxt = input('> Enter your best guess (in hex): ')
                game.open_word(word_ctxt)
            else:
                keyphrase = input('> So what do you think the keyphrase is? ')
                if game.guess_phrase(keyphrase):
                    wins += 1
                break
        if wins != i + 1:
            print('It seems you lost, but do not be sad. You can have another try!')
            break
    else:
        if wins == 35:
            print('Thanks for playing such a wonderful streak of 35 games!')
            print('I think you fully deserved the flag for that:', FLAG)
        else:
            print('What? Are you using some black magic or something?')


if __name__ == '__main__':
    main()
