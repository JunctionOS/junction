from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import joblib
import json
import urllib3
from minio import Minio

import pandas as pd
import numpy as np

from time import time
import re

cleanup_re = re.compile('[^a-z]+')

http = urllib3.PoolManager()
data_path = '/tmp/'

def cleanup(sentence):
    sentence = sentence.lower()
    sentence = cleanup_re.sub(' ', sentence).strip()
    return sentence


def function_handler(request_json):
    dataset_path = request_json['data']
    addr = request_json['minio_addr']

    path = f"{data_path}/{dataset_path}"

    minio = Minio(addr,
                  http_client = http, # for some reason this makes urllib use ipv4 instead of unix sockets
                  access_key='minioadmin',
                  secret_key='minioadmin',
                  secure=False)
    
    minio.fget_object('bucket', dataset_path, path)

    with open(path) as f:
        df = pd.read_csv(f)

        start = time()
        df['train'] = df['Text'].apply(cleanup)
        tfidf_vect = TfidfVectorizer(min_df=100).fit(df['train'])
        train = tfidf_vect.transform(df['train'])
        model = LogisticRegression()
        model.fit(train, df['Score'])
        latency = time() - start

        return "latency : " + str(latency)
