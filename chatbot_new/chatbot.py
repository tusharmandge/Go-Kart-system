import os

import nltk

from cbseevents import settings

nltk.download('punkt')
nltk.download('popular')
from chatterbot import ChatBot
from chatterbot.trainers import ListTrainer
from chatterbot.trainers import ChatterBotCorpusTrainer

# Creating ChatBot Instancecd
chatbot = ChatBot(
    'CoronaBot',
    storage_adapter='chatterbot.storage.SQLStorageAdapter',
    logic_adapters=[
        'chatterbot.logic.MathematicalEvaluation',
        'chatterbot.logic.TimeLogicAdapter',
        'chatterbot.logic.BestMatch',
        {
            'import_path': 'chatterbot.logic.BestMatch',
            'default_response': 'I am sorry, but I do not understand. I am still learning.',
            'maximum_similarity_threshold': 0.90
        }
    ],
    database_uri='sqlite:///database.sqlite3'
)

# Training with Personal Ques & Ans
training_data_quesans = open('chatbot_new/training_data/ques_ans.txt').read().splitlines()
training_data_personal = open('chatbot_new/training_data/personal_ques.txt').read().splitlines()

training_data = training_data_quesans + training_data_personal

trainer = ListTrainer(chatbot)
trainer.train(training_data)

# Training with English Corpus Data
trainer_corpus = ChatterBotCorpusTrainer(chatbot)
path_english = os.path.join(settings.BASE_DIR, 'chatterbot-corpus-master',
                            'chatterbot_corpus', 'data', 'english')
trainer_corpus.train(
    path_english
)
