# nimda.py
NIMDA.py is a Bruteforcing tool for any login page
you need to provide necessary details and then ready to go

parameters:

	help -> python brute.py help
	
	url -> target url for submition post request
		example: python brute.py url='http://exmpl.cm/lg.php' 

	username -> username detiles with html form name and it's value
		example: <input type="text" value="site_admin" name="pg_user">
			then: python brute.py url='http://exmpl.cm/lg.php' username='pg_user=site_admin'
	
	password -> list file for dictionary attack. Pass likewise username
		example: <input type="password" value="" name="pg_passwd">
		dict file: ./lsts/passwords.lst
			then: python brute.py url='http://exmpl.cm/lg.php' username='pg_user=site_admin' password='pg_passwd=./lsts/passwords.lst'

	Some login forms are protected with some CSRF TOKENS.
		Web page generates token injects in login page and excepts this value for next login request.
		If it isn't there or is incorrect value then server blocks our requests.
		But we can bypass it by specifing csrf-token-name and csrf-selector
		example: <input type="hidden" value="GFHKJ4576jhasldL:IUGBVCRTU" name="cstf_hid_token">
			then: csrf-token-name='cstf_hid_token'
		And csrf-selector is document.querySelector syntax in order to find this value inside response HTML and send it back.
			then: csrf-selector='input[name="cstf_hid_token"]'
			so result looks like:
			python brute.py url='http://exmpl.cm/lg.php' username='pg_user=site_admin' password='pg_passwd=./lsts/passwords.lst' csrf-token-name='cstf_hid_token' csrf-selector='input[name="cstf_hid_token"]'



	**post-data** -> it is all post data parameters+value except csrf-token username and password
		example: 
		```
		<input type="submit" name="login" value="Sign In">
		<input type="hidden" name="error" value="0">
		```
			then: data='login=Sign In&error=0'

