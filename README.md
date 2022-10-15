onepassword_integration
=========

`onepassword_integration` is an implementation for One Password Integration in pure JS.

## install

With [npm](https://npmjs.org) do:

`npm install onepassword_integration` and `var onepassword_integration = require('onepassword_integration')`

## methods

* `fetchAttributes` - Takes an input with format {"newDevice":boolean,"deviceUUID":string,"email":string,"recoverykey":string,"password":string,"Vault Name":string,"website":string,"search_username":string}	
* where:
* newDevice is an indicator that is true when you're using the script for the first time and false if not. After you run the function the first time you will get the deviceUUID from the logs.
* deviceUUID contains the deviceUUID that you received the first time that you run the app. In case you provided newDevice=true the value will be ignored. The first time that you run the app you can provide "" as a value.
* email is the email of your account
* recoverykey is the key that is in your emergency kit (for example "A3-2ABCDE-EFGHIJ-KLMNOP-QRSTUVQ-XYZAB-CDEFG")
* password is the password of your account
* Vault Name is the name of the vault that you want to search
* website is the name of the website in the vault for which you want to extract credentials
* search_username is the username for which you want to extract your password
* The result is the password
## license

MIT
