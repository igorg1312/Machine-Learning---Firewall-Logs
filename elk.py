import json
import logging
import pandas as pd

from elasticsearch import Elasticsearch, client
from elasticsearch.helpers import scan
from flask import Flask, render_template
from elasticsearch_dsl import Search
import matplotlib.pyplot as plt
import numpy
import numpy as np
import pandas as pd
import seaborn as sns
from tensorflow.keras.layers import Concatenate, Dense
np.set_printoptions(precision=3, suppress=True)
import tensorflow as tf
from elasticsearch import Elasticsearch



try:
    # custom host with sniffing turned on
    elastic = Elasticsearch(
        ["https://igorgarofano:Erminio86@192.168.65.52:9200/"],
        verify_certs=False
        )
except Exception as error:
    print ("Elasticsearch Client Error:", error)
    # make asimple default connection if error
    elastic = Elasticsearch()

# print client object instance to console terminal
print ("\nELASTICSEARCH INSTANCE:", elastic)
print ("CLIENT ATTRIBUTES:", dir(elastic))


#res= elastic.indices.create("train")
#print("Response from server" .format(res))

x = elastic.get(index='train', doc_type='pet', id=29)
z1 = elastic.get(index='prediction', doc_type='pet', id=1)
#y = elastic.get(index='wazuh-archives-3.x-2021.03.10', doc_type='_doc', id="iUvkG3gBHdFbDPZL1hnx")


z = x['_source']
z2 = z1['_source']
print(z)
print(z2)
d = []
o = []

res = elastic.search(index="wazuh-archives-3.x-2021.03.14", body={"query": {"match_all": {}}})
#print(res['hits']['total'])
for hit in res['hits']['hits']:
        d.append((hit["_source"]["data"]["dstip"]))
        o.append(hit["_source"]["data"]["dstport"])


#print(d)
df = pd.DataFrame(o,d,columns = ['DestPort'])
dataset = pd.get_dummies(df, prefix_sep='')
#print(dataset)
#train_dataset = dataset.sample(frac=0.5, random_state=0)
#print(train_dataset)
#print(df)
anomaly=(df.value_counts())

print(anomaly)
#print(df)
#df1 = pd.DataFrame(anomaly)



sns.pairplot(dataset, hue='DestPort161',palette='rocket',kind='scatter', diag_kind="hist").savefig("DestIP.png")
#sns.pairplot(df1).savefig("Anomalie.png")

#sysmon logs parser
#d.append(hit["_source"]["data"]["win"]["eventdata"]["targetUserSid"])

#df = pd.DataFrame(d, columns = ['Igor'])
#print(df)

#dataset = pd.get_dummies(df, prefix_sep='')
#print(dataset)

#train_dataset = dataset.sample(frac=0.5, random_state=0)
#test_dataset = dataset.drop(train_dataset.index)

#sns.pairplot(train_dataset[['IgorS-1-5-18','IgorS-1-5-21-2246378431-306020416-2726261967-6618']],diag_kind='hist').savefig("ultimo.png")



#print(y)


app = Flask(__name__)

w = []
r = []
f = []
pred = []

@app.route('/')
def index():
    y = elastic.get(index='train', doc_type='pet', id=28)
    z1 = elastic.get(index='prediction', doc_type='pet', id=0)
    z2 = elastic.get(index='prediction', doc_type='pet', id=1)
    z3 = elastic.get(index='prediction', doc_type='pet', id=2)

    m = y['_source']
    m1 = z1['_source']
    m2 = z2['_source']
    m3 = z3['_source']
    print(m1)
    for (k, v) in m.items():

        f.append(float(v))

    for (k, v) in z.items():
        r.append(k)
        w.append(float(v))
    #return str(r)+str(w)
    for (k, v) in m1.items():
        pred.append(float(v))
    for (k, v) in m2.items():
        pred.append(float(v))
    for (k, v) in m3.items():
        pred.append(float(v))
    return render_template('index.html', w=w, r=r, f=f, pred=pred)


