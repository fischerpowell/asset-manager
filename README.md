# asset-manager
IT asset management web app that uses Python Flask, PostgreSQL, and LDAP authentication. 

## User guide 
### Inventory Table
Track device details.  
  
![Inventory Screen](screens/inventory.png?raw=true "Title")  
##### 1. Edit Record  
&ensp; Quickly open a form to edit record information.  
##### 2. Sort  
&ensp; Sort each table by any desired column.    
##### 3. Last Hostname Link  
&ensp; Click a hostname to view specific information.  
##### 4. Transaction History 
&ensp; Opens transaction history for the selected device.  
  
### Transactions Table
Track device assignments and locations.  
  
![Transactions Screen](screens/transactions.png?raw=true "Title")  
##### 1. Barcode Link  
&ensp; Click a barcode to view the inventory entry for that device.
##### 2. Retired Icon  
&ensp; Devices that have been given a "Date Retired" will show an icon next to them, indicating that the device is no longer in use.   
##### 3. Quick Add Button  
&ensp; Want to quickly add a similar record? This button will open an add record form with identical information in the blanks.
    
### Hostnames Table
Track desktop hostnames.  
  
![Hostnames Screen](screens/hostnames.png?raw=true "Title")  
##### 1. Active / Inactive  
&ensp; Track whether the hostname is still in use. Can only be checked or unchecked in the edit record form.
##### 2. Assignment History Button 
&ensp; View transaction history where the given hostname has been assigned.   
  
### Dropdowns Table
Quickly and easily edit the dropdown lists that are used when adding an inventory record. Only accessible to admins.  
  
![Dropdowns Screen](screens/dropdowns.png?raw=true "Title")  
  
### Logs Table
View database action history, including username and timestamp of action. Also saves a copy of the previous record when editing or deleting.  
  
![Logs Screen](screens/logs.png?raw=true "Title")  
  
### Search
All tables except for dropdowns are able to be searched by any column.  
  
![Search Screen](screens/search.png?raw=true "Title")  
  
### Add Record
An example of an add record form. This one is for the inventory table.  
  
![Add Inventory Screen](screens/addrecord.png?raw=true "Title")  
  
### Dark Mode
Yes, this thing has dark mode.  
  
![Dark Mode Screen](screens/darkmode.png?raw=true "Title")  
  
  
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
  
### 3. Test the App
&ensp; a. Run app.py  
&ensp; b. Login with username: "admin" and password: "admin".  
&emsp; By default, authentication mode is in "setup". A normal user can be tested with username: "user" and password "password".

### 4. Configure LDAP and Flask
&ensp; a. Open inventory.conf in a text editor  
&ensp; b. Change auth_type to "ldap"  
&ensp; c. Change Flask secret key to a secure string.  
&ensp; d. Configure LDAP settings with your own server specifications.  
  
### 5. Moving Forward
&ensp; a. A postgres user with SELECT, INSERT, UPDATE, DELETE on database tables should be created and used for all app functions.  
&ensp; b. Before populating the database, inventory form dropdown options should be added by logging in as an admin and navigating to the "Dropdowns" Panel.
