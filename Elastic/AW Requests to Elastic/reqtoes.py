

import nltk
from nltk.tokenize import RegexpTokenizer
import pandas as pd
import time
import numpy as np
import argparse
import sys
import time
from elasticsearch import Elasticsearch
import json
import os
from elasticsearch import helpers

def reqclean(s):
    if "multipart/form-data" in s:
        return s.split(';')[0]
    else:
        return s
    

def reqtodict(f):
    corpus_root = f+'/'
    tokenizer = RegexpTokenizer('\s+', gaps=True)
    sent_tokenizer=RegexpTokenizer('\n', gaps=True)

    wordlists_2 = nltk.corpus.PlaintextCorpusReader(corpus_root, '.*',word_tokenizer=tokenizer,sent_tokenizer=sent_tokenizer,encoding="Latin-1")


    dictll={'transid':[],'meth':[],'hosts':[],'uri':[],'req_length':[],'resp_length':[],'req_type':[],'resp_type':[],'resp_encoding':[],'status_code':[],'filename':[]}


    for fi in wordlists_2.fileids():

        lsd=wordlists_2.sents(fi)

        c=None
        i=None
        d=None
        x=None
        tmpdictll={'transid':[],'meth':[],'hosts':[],'uri':[],'req_length':[],'resp_length':[],'req_type':[],'resp_type':[],'resp_encoding':[],'status_code':[],'filename':[]}
        indx=0
        for c,i in enumerate(lsd):
            if 'event:' in i and len(i)==2 and 'request' in lsd[c+1]:

                tmpdictll['transid'].append(i[1].split(',')[-1])
                tmpdictll['meth'].append('None')
                tmpdictll['hosts'].append('')
                tmpdictll['uri'].append('')
                tmpdictll['req_length'].append(0)
                tmpdictll['req_type'].append('None')
                tmpdictll['resp_length'].append(0)
                tmpdictll['resp_type'].append('None')
                tmpdictll['resp_encoding'].append('None')
                tmpdictll['status_code'].append('None')
                for d,x in enumerate(lsd[c+1:]):
                    if 'event:' in x and len(x)==2:
                        indx+=1
                        break
                    else:
                        if 'HTTP/' in x[-1]:
                            tmpdictll['meth'][indx]=x[0]
                            tmpdictll['uri'][indx]=x[1]
                        if 'Content-Length:' in x:
                            try:
                                tmpdictll['req_length'][indx]=int(x[1])
                            except Exception as e:
                                print e
                                print fi, i , x
                                tmpdictll['req_length'][indx]=0
                        if 'Host:' in x:
                            tmpdictll['hosts'][indx]=" ".join(x[1:])
                        if 'Content-Type:' in x:
                            tmpdictll['req_type'][indx]=" ".join(x[1:]).lower()
                        if tmpdictll['transid'][indx]=='4035443391':
                            print 'found trans:',  tmpdictll['meth'][indx],tmpdictll['uri'][indx]
                        if tmpdictll['transid'][indx]=='4035413978':
                            print 'found thr pther trans'


        indx=0
        c=None
        i=None
        d=None
        x=None
        findd=0



        for c,i in enumerate(lsd):
            if 'event:' in i and len(i)==2 and 'reply' in lsd[c+1]:
                transi=i[1].split(',')[-1]
                findx=-1
                for d,x in enumerate(tmpdictll['transid']):
                    if transi==x:
                        findx=d


                d=None
                x=None
                if findx==-1:
                    print 'couldnt find matching request\n' # two cases - reply , no request, request, no reply
                    tmpdictll['transid'].append(i[1].split(',')[-1])
                    tmpdictll['meth'].append('None')
                    tmpdictll['hosts'].append('')
                    tmpdictll['uri'].append('')
                    tmpdictll['req_length'].append(0)
                    tmpdictll['req_type'].append('None')
                for d,x in enumerate(lsd[c+1:]):
                    if 'event:' in x and len(x)==2:
                        if len(tmpdictll['status_code']) < len(tmpdictll['transid']):
                            tmpdictll['status_code'].append('None')
                        if len(tmpdictll['resp_length']) < len(tmpdictll['transid']):
                            tmpdictll['resp_length'].append(0)
                        if len(tmpdictll['resp_type']) < len(tmpdictll['transid']):
                            tmpdictll['resp_type'].append('None')
                        if len(tmpdictll['resp_encoding']) < len(tmpdictll['transid']):
                            tmpdictll['resp_encoding'].append('None')
                        break
                    else:
                        if 'HTTP/' in x[0] and findx >=0 :
                            tmpdictll['status_code'][findx]=" ".join(x[1:])
                        elif 'HTTP/' in x[0] and findx ==-1 :
                            tmpdictll['status_code'].append(" ".join(x[1:]))

                        if 'Content-Length:' in x and findx >=0 :
                            try:
                                tmpdictll['resp_length'][findx]=int(x[1])
                            except Exception as e:
                                print e
    #                            print fi, i , x
                                tmpdictll['resp_length'][findx]=0
                        elif 'Content-Length:' in x and findx ==-1 :
                            try:
                                tmpdictll['resp_length'].append(int(x[1]))
                            except Exception as e:
                                print e
    #                            print fi, i , x
                                tmpdictll['resp_length'].append(0)

                        if 'Content-Type:' in x and findx >=0 :
                            tmpdictll['resp_type'][findx]=" ".join(x[1:]).lower()

                        elif 'Content-Type:' in x and findx ==-1 :
                            tmpdictll['resp_type'].append(" ".join(x[1:]).lower())


                        if 'Content-Encoding:' in x and findx >=0 :
                            tmpdictll['resp_encoding'][findx]=" ".join(x[1:])

                        elif 'Content-Encoding:' in x and findx ==-1 :
                            tmpdictll['resp_encoding'].append(" ".join(x[1:]))


        tempsize=len(tmpdictll['filename'])
        tmpdictll['filename']=tmpdictll['filename']+[fi]*(len(tmpdictll['transid'])-tempsize)


        for k in tmpdictll:
            dictll[k]=dictll[k]+tmpdictll[k]
    return dictll



if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    #optional arguments
    parser.add_argument("--requestsfolder", type=str,help="requests folder name")
    parser.add_argument("--requestindx", type=str,help="request elastic index")

    args = parser.parse_args()
    dictfn=reqtodict(args.requestsfolder)


    df= pd.DataFrame(dictfn)
    df['req_type_cleaned']=df['req_type'].apply(reqclean)

    jsonlist=df.to_dict("rows")

    es = Elasticsearch([{'host': '10.107.246.16', 'port': '9200'}])
    es.indices.delete(index=args.requestindx, ignore=[400, 404])

    indexes=[args.requestindx]

    for ind in indexes:
        es.indices.create(index=ind, ignore=400)


    helpers.bulk(es, jsonlist, index=args.requestindx, request_timeout=200,ignore=[400, 404])



                
