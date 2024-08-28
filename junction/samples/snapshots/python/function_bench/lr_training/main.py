from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import joblib
import json

import pandas as pd
import numpy as np

from time import time
import re

cleanup_re = re.compile('[^a-z]+')


def cleanup(sentence):
    sentence = sentence.lower()
    sentence = cleanup_re.sub(' ', sentence).strip()
    return sentence


def function_handler(request_json):
    dataset_path = request_json['dataset_path']

    with open(dataset_path) as f:
        df = pd.read_csv(f)

        start = time()
        df['train'] = df['Text'].apply(cleanup)

        tfidf_vect = TfidfVectorizer(min_df=100).fit(df['train'])

        train = tfidf_vect.transform(df['train'])

        model = LogisticRegression()
        model.fit(train, df['Score'])
        latency = time() - start

        # model_file_path = "/tmp/model.pkl"
        # joblib.dump(model, model_file_path) TODO: avoiding creating files for
        # now on Junction

        return "latency : " + str(latency)
