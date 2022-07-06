# asset-manager
IT asset management web app that uses Python Flask and PostgreSQL.


## How to Install
### 1. Install dependencies:
&ensp; a. sudo apt-get install python3 postgresql  
&ensp; b. sudo apt install python3-pip  
&ensp; c. pip3 install flask flask-session psycopg2-binary ldap3  
  
### 2. Set up PostgreSQL
&ensp; a. sudo -i -u postgres psql  
&ensp; b. \password postgres (Enter new password)  
&ensp; c. Change the PostgreSQL password in inventory.conf to match the new one specified.  
&ensp; d. Run init.py  

### 2. Test the App
&ensp; a. Run app.py  
&ensp; a. Login with username: "admin" and password: "admin".  
&emsp; By default, authentication mode is in "setup". A normal user can be tested with username: "user" and password "password".
