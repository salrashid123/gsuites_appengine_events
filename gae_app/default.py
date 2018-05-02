import logging
import os
import sys

from google.appengine.ext import webapp

from apiclient.discovery import build
import httplib2
from oauth2client.service_account import ServiceAccountCredentials
from oauth2client.client import AccessTokenCredentials
from oauth2client.client import GoogleCredentials
import logging
import json
import sys
import time
import urllib,urllib2, httplib
from urllib2 import URLError, HTTPError
import random

from apiclient import discovery
import oauth2client
from oauth2client import client
from oauth2client import tools

from google.auth import app_engine

from google.appengine.api import app_identity
from google.appengine.api import urlfetch

import logging
import pprint
import traceback

from datetime import datetime, timedelta


from flask import Flask, render_template, request, abort

app = Flask(__name__)

GSUITES_SCOPE = 'https://www.googleapis.com/auth/admin.reports.audit.readonly https://www.googleapis.com/auth/admin.directory.user.readonly'


PROJECT_ID = 'fabled-ray-104117'
GAE_SVC_ACCOUNT = 'fabled-ray-104117@appspot.gserviceaccount.com'
GSUITES_CUSTOMER_ID = 'C023zw3x8'
GSUITES_DOMAIN = 'esodemoapp2.com' 
CREATE_DELEGATED_SUB = 'admin@esodemoapp2.com'
Channel_Token_value = 'target=channelToken'
Channel_Id_value = '72064707-f035-4192-aeb5-badf61c3b81b'



def getAccessToken(scopes):
  cc = GoogleCredentials.get_application_default()
  iam_scopes = 'https://www.googleapis.com/auth/iam https://www.googleapis.com/auth/cloud-platform'
  if cc.create_scoped_required():
    cc = cc.create_scoped(iam_scopes)
  http = cc.authorize(httplib2.Http())
  service = build(serviceName='iam', version= 'v1',http=http)
  resource = service.projects()   
  iss = GAE_SVC_ACCOUNT
  now = int(time.time())
  exptime = now + 3600
  claim =('{"iss":"%s",'
          '"scope":"%s",'
          '"aud":"https://accounts.google.com/o/oauth2/token",'
          '"sub":"%s",'  
          '"exp":%s,'
          '"iat":%s}') %(iss,scopes,CREATE_DELEGATED_SUB,exptime,now)
  slist = resource.serviceAccounts().signJwt(name='projects/' + PROJECT_ID + '/serviceAccounts/' + GAE_SVC_ACCOUNT, body={'payload': claim })
  resp = slist.execute()   
  signed_jwt = resp['signedJwt'] 
  url = 'https://accounts.google.com/o/oauth2/token'
  data = {'grant_type' : 'assertion',
          'assertion_type' : 'http://oauth.net/grant_type/jwt/1.0/bearer',
          'assertion' : signed_jwt }
  headers = {"Content-type": "application/x-www-form-urlencoded"}
  
  data = urllib.urlencode(data)
  req = urllib2.Request(url, data, headers)

  try:
    resp = urllib2.urlopen(req).read()
    parsed = json.loads(resp)
    expires_in = parsed.get('expires_in')
    access_token = parsed.get('access_token')
    #logging.debug('access_token: ' + access_token)
    return access_token
  except HTTPError, e:
    logging.error('HTTPError on getting delegated access_token: ' + str(e.reason))
    logging.error(e.read())
    raise e
  except URLError, e:
    logging.error( 'URLError on getting delegated access_token: ' + str(e.reason))
    logging.error(e.read())
    raise e
  except Exception as e:
    logging.error(traceback.format_exc())    
    raise e


def validateHeaders(headers, hkey, hvalue):
  try:
   if ( headers.get(hkey) == hvalue):
    return True
  except KeyError:
    logging.error("Key: " + hkey + " not found")
  return False


@app.route('/', methods=['GET'])   
def index():
  return 'ok'

@app.route('/list_users', methods=['GET'])    
def list_users():
  try:
    http = httplib2.Http()
    credentials = AccessTokenCredentials(getAccessToken(GSUITES_SCOPE),'my-user-agent/1.0')    
    http = httplib2.Http()
    http = credentials.authorize(http)
    service = discovery.build('admin', 'directory_v1', http=http)
    results = service.users().list(customer=GSUITES_CUSTOMER_ID, domain=GSUITES_DOMAIN).execute()
    users = results.get('users', [])
    logging.debug(json.dumps(users, sort_keys=True, indent=4))
    r = ''
    for u in users:
      r = r + json.dumps(u['primaryEmail'], sort_keys=True, indent=4) +'\n'
    return ('List Users: ' + r )
  except Exception as e:
    logging.error("Error: " + str(e))
    abort(500)

def verify_auditEvent(payload):
  re =  []
  try:
    http = httplib2.Http()
    credentials = AccessTokenCredentials(getAccessToken(GSUITES_SCOPE),'my-user-agent/1.0')    
    http = httplib2.Http()
    http = credentials.authorize(http)
    service = discovery.build('admin', 'directory_v1', http=http)

    payload = json.loads(payload.replace('\\"',''))

    payload_id = payload.get("id")
    pstartTime= payload_id.get("time")
    pendTime= payload_id.get("time")
    puniqueQualifier = payload_id.get("uniqueQualifier")    

    payload_actor = payload.get("actor")
    pemail = payload_actor.get("email")

    pevents = payload.get("events")

    pfilters=''
    for e in pevents:
       if ( (e.get("type")=="GROUP_SETTINGS") ):
         for p in e.get("parameters"):
           if p.get("USER_EMAIL"):
             pfilters = 'USER_EMAIL=='+ p.get("value")

    http = httplib2.Http()
    credentials = AccessTokenCredentials(getAccessToken(GSUITES_SCOPE),'my-user-agent/1.0')    
    http = httplib2.Http()
    http = credentials.authorize(http)
    service = discovery.build('admin', 'reports_v1', http=http)
    results = service.activities().list(userKey='all', applicationName='admin',
       startTime=pstartTime,endTime=pendTime).execute()

    items = results['items']
    for itm in items:
        i = itm.get('id')
        startTime = i.get('time')
        endTime = i.get('time')
        applicaitonName= i.get('applicationName')
        customerId = i.get('customerId')
        uniqueQualifier = i.get('uniqueQualifier')
        a = itm.get('actor')
        email = a.get('email')
        e_list = itm.get('events')
        for e in e_list:
            etype = e.get('type')
            ename = e.get('name')
            params = e.get('parameters')
            for p in params:
                k = p.get('name')
                v = p.get('value')
                # use these values to verify the push endpoint's payload is real/verified or not, if needed.
                # startTime uniqueQualifier applicaitonName uniqueQualifier email etyp,ename k, v
                if puniqueQualifier==uniqueQualifier:
                  re.append({"uniqueQualifier":uniqueQualifier, 'type':etype, 'name':ename, 'startTime': startTime })
    return re
  except Exception as e:
    logging.error("Error: " + str(e))
    abort(500)
  


@app.route('/push', methods=['POST'])    
def webhook():
  logging.info("HEADERS >>>>>> : {}".format( request.headers ))
  logging.info("------------------------------------------------------") 
  logging.info("BODY >>>>>>>> : {}".format(request.data))

  if request.data == "":
    return 'ok'
    
  if (validateHeaders(request.headers, 'X-Goog-Channel-Token', Channel_Token_value) and validateHeaders(request.headers, 'X-Goog-Channel-Id', Channel_Id_value)):
    events = verify_auditEvent(request.data)
    logging.info("Validation Response: " + str(events))
    return("ok")
  else:
    logging.error("Error: Webhook notification missing correct token and/or ID headers")
    abort(500)

@app.errorhandler(500)
def server_error(e):
  logging.exception('An error occurred during a request.')
  return 'An internal error occurred.', 500
