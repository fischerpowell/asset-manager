import configparser
import flask
import psycopg2
from psycopg2 import sql
from flask import Flask, render_template, request, redirect, session, url_for
from flask_session import Session
from ldap3 import Server, Connection, ALL, NTLM
from ldap3.core.exceptions import LDAPException, LDAPBindError
from datetime import datetime
from functools import wraps

config = configparser.ConfigParser()
config.read('inventory.conf')

conn = psycopg2.connect(database=config.get('postgres', 'database_name'),
    user=config.get('postgres', 'user'),
    password=config.get('postgres', 'password'),
    host=config.get('postgres', 'host_ip'),
    port=config.get('postgres', 'host_port'))

cursor = conn.cursor()

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False

app.config["SESSION_TYPE"] = "filesystem"

app.config["SESSION_FILE_DIR"] = config.get('flask', 'session_file_dir')

app.secret_key = config.get('flask', 'secret_key')

error_dict = {0 : 'Given barcode is already in inventory table.',
    1 : 'Given barcode is not in inventory table.',
    3 : 'Search yielded no results.',
    4 : 'No transactions exist for given barcode.',
    5 : 'Given transaction ID is not in transactions table.',
    6 : 'Given barcode is not in inventory table or transaction table.',
    7 : 'Given option value is already in given dropdown list.',
    8 : 'You do not have admin permissions.',
    9 : 'Given option value is not in given dropdown list.',
    10 : 'Barcode does not exist in Inventory table.',
    11 : 'Given hostname is already in hostname table.',
    12 : 'Given hostname does not exist.'}

def logged_in_user(f): #Wrapper function used to verify that user logged in has at least user permissions
    @wraps(f)
    def decorated_func(*args, **kwargs):
        if get_session_value('loggedin', 'invalid') in ('user', 'admin'): #If session "loggedin" value is user or admin, return func.
            return f(*args, **kwargs)
        else:
            return redirect('/login') # Else, redirect to login
    return decorated_func

def logged_in_admin(f): #Wrapper function used to verify that user logged in is an admin
    @wraps(f)
    def decorated_func(*args, **kwargs):
        if get_session_value('loggedin', 'invalid') == 'admin': #If session "loggedin" value is an admin, return func
            return f(*args, **kwargs)
        elif get_session_value('loggedin', 'invalid') == 'user': #If session "loggedin" value is user, yield an error for insufficient privileges
            return redirect(url_for('error', error_code=8))
        else: #If session "loggedin" value is invalid, redirect to login
            return redirect('/login')
    return decorated_func

def update_last_hostname(barcode): #takes device barcode, gets the most recent hostname specified for the device in the transactions table, then updates the corresponding device last_hostname record in inventory table to match it.
    cursor.execute('''SELECT hostname FROM transactions WHERE barcode=%s 
        ORDER BY date DESC LIMIT 1;''', (barcode,)) #gets latest hostname for device as specified in transactions table
    newest_hostname = cursor.fetchone()
    cursor.execute('SELECT last_hostname from inventory where barcode=%s', (barcode,)) #Gets the current last_hostname in the inventory table
    old_last_hostname = cursor.fetchone()
    if newest_hostname != old_last_hostname: #If the newest hostname is different than what is currently in the inventory table last_hostname field
        cursor.execute('''UPDATE INVENTORY
            SET last_hostname=%s
            WHERE barcode=%s''', (newest_hostname,barcode))
        conn.commit()

def entries_to_list(entrieslist): #Takes a SQL SELECT rows with junk characters and makes it clean and iterable to use with the dropdown lists
    formattedlist = []
    for tuple in entrieslist:
        tuple = str(tuple)
        tuple = tuple.replace('(', '').replace(')', '').replace(',', '').replace("'", '')
        formattedlist.append(tuple)
    return formattedlist

def create_log(actiontype, database, recordcopy): #Creates a log for the inventory and transaction table functions
    log_data = (str(session['username']), actiontype, database, recordcopy)
    cursor.execute('''INSERT INTO logs(username, actiontype, database, timestamp, recordcopy)
        VALUES (%s, %s, %s, CURRENT_TIMESTAMP, %s)''', log_data)
    conn.commit()

def make_wildcard(string): #Makes a wildcard to be used with the transactions assigned search function
    wildcard_string = '%%' + string + '%%'
    return wildcard_string

def get_form_value(variable_name): #Tests if a form input has been filled out. This is for non-mandatory input fields that may not contain data
    try:
        if request.form[variable_name] == '': #Returns null if input space was empty
            return None
        else: 
            return request.form[variable_name]
    except:
        return None

def get_sortby(default_sortby, replace_space): #Gets the column to sort table by from the POST value on the page
    try:
        sortby = request.form['sortby']
        sortby_SQL = sortby.lower().replace(' ', replace_space).replace('/', '') #Formats displayed value to SQL identifier value format. replace_space is what to replace the space in the option with, depending on the table
    except: #Sorts by default if no value has been selected
        sortby = default_sortby
        sortby_SQL = default_sortby.lower()
    return sortby, sortby_SQL

def get_dropdown(column): #Gets the dropdown list for deivcetype or devicedeparment for use in inventory table forms
    cursor.execute(sql.SQL('''SELECT {0} FROM dropdowns
                WHERE NOT {0} IS NULL 
                ORDER BY {0};''').format(sql.Identifier(column))) #Gets devicetype select field
    return entries_to_list(cursor.fetchall())

def is_int(test_integer): #Tests if a number is an integer. Used with generated links that allow users to input values that aren't integers into integer fields
    try:
        int(test_integer)
        return True
    except:
        return False

def ldap_auth():
    if config.get('general', 'auth_type') == 'ldap':
        try:
            ldap_server = Server(config.get('ldap', 'ldap_server_ip'), port=int(config.get('ldap', 'ldap_server_port')), use_ssl=True, get_info=ALL) #LDAP Server connection
            ldap_conn = Connection(ldap_server, 
                user='local\\{}'.format(session['username']), 
                password=session['password'], 
                authentication=NTLM, auto_bind=True) #Uses session variables to attempt an NTLM bind. Fails if no variables are set
            ldap_conn.search(config.get('ldap', 'ldap_user_dir').replace('"', ''), 
                '(&(objectcategory=person)(sAMAccountname={}))'.format(session['username']), 
                attributes=['CN']) #Searches for the person associated with the username provided
            real_name = str(ldap_conn.entries).replace(
                str(ldap_conn.entries)[:str(ldap_conn.entries)
                .find('cn: ') + 4], '').replace('\n]', '') #Formats the search results to only contain "Firstname Lastname"
            ldap_conn.search(config.get('ldap', 'ldap_user_dir').replace('"', ''), 
                '(&(objectcategory=group)(CN={}))'.format(config.get('ldap', 'admin_group_cn')), 
                attributes=['member']) #Searches for all members in the IT inventory admin list
            admin_list = str(ldap_conn.entries)
            if real_name in admin_list: #If user is in admin group
                session['loggedin'] = 'admin'
            else:
                session['loggedin'] = 'user' #If user is in user group
        except:
            session['loggedin'] = 'invalid' #If bind is unsuccessful (authentication failed)
    elif config.get('general', 'auth_type') == 'setup':
        login_dict = {'user' : 'password', 'admin' : 'admin'}
        try:
            if session['password'] == login_dict[session['username']]:
                if session['username'] == 'admin':
                    session['loggedin'] = 'admin'
                else:
                    session['loggedin'] = 'user'
            else:
                session['loggedin'] = 'invalid'
        except:
            session['loggedin'] = 'invalid'

def get_session_value(session_name, default_value): #Used to retrieve a session value. If value is unassigned, initializes it with a default value.
    try:
        return session[session_name] # Error is raised if given session value is uninitialized
    except:
        session[session_name] = default_value # Initializes the session value with a given default value and returns it
        return session[session_name]

def get_retired_dict(): #Makes a dictionary with barcodes as keys and whether they've been retired as the value
    cursor.execute('SELECT barcode, date_retired FROM inventory;')
    entries = cursor.fetchall()
    retired_dict = {} #initializes retired_dict
    for entry in entries: #If barcode has a retired date, sets the value to true, otherwise false
        if entry[1] != None:
            retired_dict[entry[0]] = True
        else:
            retired_dict[entry[0]] = False
    cursor.execute('''SELECT barcode FROM transactions 
        WHERE barcode NOT IN (SELECT barcode FROM inventory);''') #Gets all barcodes in transactions that do not have an item linked to them in the inventory table
    unlinked_barcodes = cursor.fetchall()
    if unlinked_barcodes != []: #If there are any unlinked barcodes
        for barcode in unlinked_barcodes:
            retired_dict[barcode[0]] = True
    return retired_dict

def get_hostnames_list(): #Returns a list of all hostnames to be used in the datalist on transactions add/edit form
    hostnames_list = []
    cursor.execute('SELECT hostname FROM hostnames ORDER BY hostname;')
    hostname_entries = cursor.fetchall()
    for hostname in hostname_entries:
        hostnames_list.append(hostname[0]) #For every entry in the SQL selection, appends it to the hostname list
    return hostnames_list

def get_hostnames_pattern(): #Returns a string of all hostnames separated by "|" to be used for data validation on the hostname field on transaction add/edit form
    hostnames_pattern = ''
    cursor.execute('SELECT hostname FROM hostnames ORDER BY hostname;')
    hostname_entries = cursor.fetchall()
    for hostname in hostname_entries:
        hostnames_pattern = hostnames_pattern + hostname[0] + '|'
    return hostnames_pattern

def validate_changed(new_record, old_record): #Used in the edit record functions. This is to ensure that the submitted "edited" record has actually changed, and the save button wasn't clicked without changing anything
    changed = False
    for place, entry in enumerate(new_record):
        if str(entry) != str(old_record[place]):
            changed = True
    return changed

def format_quick_add_record(quick_add_record): #Used to make an indexible list for the quick add feature in the transactions table. Indexing allows us to fill in spaces in the add record form with data from a previous record
    quick_add_record = quick_add_record[1:] #These two lines remove the parentheses surrounding the record
    quick_add_record = quick_add_record[:len(quick_add_record) - 1]
    raw_list = quick_add_record.split(',') #Splits by commas. This does make the date field unusable, but it is not used in the quick add anyway.
    #Because it splits by commas, this entire function will break if commas are used in any field in the transactions table.
    quick_add_list = [] #Initializes the list that will be indexed to get quick add values
    for entry in raw_list:
        formatted_entry = entry.lstrip().strip().replace("'", '') #Removes the junk characters left over from the string formatting
        quick_add_list.append(formatted_entry) #Adds each formatted entry to the new list.
    return quick_add_list

@app.route('/')
def main_page():
    return redirect('/login')

@app.route('/login/', methods = ['POST', 'GET'])
def login():
    if request.method in ('POST'): #POST method has two functions tied to it: logout and validate credentials
        try: #Tests if coming from logout button and clears session.
            request.form['logout']
            session.clear()
            session['view_style'] = 'light_style'
            return render_template('login.html',
                view_style = session['view_style'])
        except:
            try: #Validates credentials given.
                session['username'] = request.form['username'].strip()
                session['password'] = request.form['password'].strip()
                ldap_auth()
                if get_session_value('loggedin', 'invalid') in ('user', 'admin'):
                    return redirect('/inventory/')
                else:
                    return render_template('login.html', 
                        login_invalid = True,
                        view_style = session['view_style'])
            except: 
                return render_template('login.html',
                    view_style = session['view_style'])
    else: #If GET method
        if get_session_value('loggedin', 'invalid') in ('user', 'admin'): #Already logged in
            return redirect('/inventory/')
        else:
            try: #Sets view style to default 'light_style' if there isn't a session value already
                session['view_style'] 
            except:
                session['view_style'] = 'light_style'
            return render_template('login.html',
                view_style = session['view_style'])

@app.route('/inventory/', methods = ['POST', 'GET'])
@logged_in_user
def inv_show_table():
    sortby_list = ['Barcode', 
        'Serial', 'Model', 'Category', 
        'Department', 'Date Purchased', 
        'Date Retired', 'Last Hostname']
    session['last_inv_page'] = '/inventory'
    sortby = get_sortby('Barcode', '_')[0]
    sortby_SQL = get_sortby('Barcode', '_')[1]
    cursor.execute(sql.SQL('SELECT * FROM inventory ORDER BY {};')
        .format(sql.Identifier(sortby_SQL)))
    inventorytable = cursor.fetchall()
    sortby_list.remove(sortby)
    sortby_list.insert(0, sortby) #Removes the sortby value from its original place in the list and inserts it at the top
    return render_template('inventorytable/inventorytable.html', 
        inventorytable = inventorytable, 
        sortby_list  = sortby_list, 
        active_page = 'inventory', 
        searched_table = False,     
        view_style = session['view_style']) #active_page is for bolding the nav_bar links

@app.route('/inventory/add-record', methods = ['POST', 'GET'])
@logged_in_user
def inv_add_record_form():
    if request.method in ('POST'): #If the form has been submitted
        barcode = request.form['barcode']
        cursor.execute('SELECT * FROM inventory WHERE barcode=%s;', (barcode,))
        if cursor.fetchall() == []: #If no entries exist for that barcode already
            date_purchased = get_form_value('date_purchased') #Field is non-mandatory, so special function is required
            date_retired = get_form_value('date_retired') #Field is non-mandatory, so special function is required
            serial = get_form_value('serial') #Field is non-mandatory, so special function is required
            item_data = (barcode, serial, request.form['model'], 
            request.form['category'], request.form['department'], 
            date_purchased, date_retired) 
            cursor.execute('''INSERT INTO inventory(barcode, serial, model,
            category, department, date_purchased, date_retired)
            VALUES (%s, %s, %s, %s, %s, %s, %s);''', item_data)
            cursor.execute('SELECT * FROM inventory WHERE barcode=%s;', (barcode,)) #Gets a copy of the new entry
            recordcopy=cursor.fetchone()
            create_log('Add', 'Inventory', recordcopy)
            conn.commit()
            return redirect(get_session_value('last_inv_page', '/inventory'))
        else:
            return redirect(url_for('error', error_code=0))
    else:
        devicetypelist = get_dropdown('devicetype') #Gets devicetype select list for the form
        devicedepartmentlist = get_dropdown('devicedepartment') #Gets devicedepartment select list for the form
        return render_template('inventorytable/inv_add_record_form.html', 
            devicetypelist = devicetypelist, 
            devicedepartmentlist = devicedepartmentlist,
            last_inv_page = get_session_value('last_inv_page', '/inventory'),
            active_page = 'inventory',
            view_style = session['view_style'])

@app.route('/inventory/remove-record/<barcode>', methods = ['POST', 'GET'])
@logged_in_user
def inv_remove_record(barcode):
    if is_int(barcode): #Makes sure that the barcode field in the link is an integer
        if request.method in ('POST'): #If the form has been submitted
            try:
                request.form['cancel'] #If cancel button was clicked
                return redirect(get_session_value('last_inv_page', '/inventory'))
            except:    
                cursor.execute('SELECT * FROM inventory WHERE barcode=%s;', (barcode,)) 
                old_record = cursor.fetchone()
                create_log('Remove', 'Inventory', old_record) #Makes a log of the record before deletion
                cursor.execute('DELETE FROM inventory WHERE barcode=%s', (barcode,))
                conn.commit()
                return redirect(get_session_value('last_inv_page', '/inventory'))
        else:
            cursor.execute('SELECT * FROM inventory WHERE barcode=%s;', (barcode,)) 
            old_record = cursor.fetchall()
            if old_record != []: #If there is a record for the specified barcode
                return render_template('inventorytable/inv_remove_record_form.html',
                old_barcode = barcode,
                view_style = session['view_style'],
                active_page = 'inventory')
            else:
                return redirect(url_for('error', error_code=1))
    else:
        return redirect(url_for('error', error_code=1))

@app.route('/inventory/edit-record/<old_barcode>', methods = ['POST', 'GET'])
@logged_in_user
def inv_edit_record_form(old_barcode):
    if is_int(old_barcode): #Makes sure that the barcode field in the link is an integer
        if request.method in ('POST'): #If the form has been submitted
            cursor.execute('SELECT * FROM inventory WHERE barcode=%s;', (old_barcode,))
            old_record = cursor.fetchone()
            new_barcode = request.form['barcode']
            cursor.execute('SELECT * FROM inventory WHERE barcode=%s AND NOT serial=%s;', (new_barcode, old_record[1]))
            if cursor.fetchall() == []: #If a record exists with the new (edited) barcode that's not the old record (Meaning that the barcode hasn't changed). 
                date_purchased = get_form_value('date_purchased') #Field is non-mandatory, so special function is required
                date_retired = get_form_value('date_retired') #Field is non-mandatory, so special function is required
                serial = get_form_value('serial') #Field is non-mandatory, so special function is required
                edit_item_data = (request.form['barcode'], serial, request.form['model'], 
                    request.form['category'], request.form['department'], 
                    date_purchased, date_retired)
                if validate_changed(edit_item_data, old_record) == True:
                    create_log('Edit', 'Inventory', old_record) #Makes a log of the record before edit
                    cursor.execute('''UPDATE INVENTORY
                        SET barcode = %s,
                            serial = %s,
                            model = %s,
                            category = %s,
                            department = %s,
                            date_purchased = %s,
                            date_retired = %s
                        WHERE barcode = %s;''', (edit_item_data + (old_barcode,)))
                    conn.commit()
                    return redirect(get_session_value('last_inv_page', '/inventory'))
                else:
                    return redirect(get_session_value('last_inv_page', '/inventory'))
            else:
                return redirect(url_for('error', error_code=0))
                
        else:
            if len(old_barcode) < 6: #Protects from SQL numeric range injections
                cursor.execute('SELECT * FROM inventory WHERE barcode=%s;', (old_barcode,))
                old_record = list(cursor.fetchone())
                if old_record != None: #If a record exists with the given barcode
                    old_devicetype = old_record[3]
                    cursor.execute('''SELECT devicetype FROM dropdowns
                        WHERE NOT devicetype IS NULL
                        AND NOT devicetype = %s
                        ORDER BY devicetype;''', (old_devicetype,)) #I didn't use the get_dropdown function because I also exclude the current column values on these SQL statements
                    devicetypelist = entries_to_list(cursor.fetchall())
                    devicetypelist.insert(0, old_devicetype) #Places the current entry at the front of the list
                    old_devicedepartment = old_record[4]
                    cursor.execute('''SELECT devicedepartment FROM dropdowns 
                        WHERE NOT devicedepartment IS NULL 
                        AND NOT devicedepartment = %s
                        ORDER BY devicedepartment;''', (old_devicedepartment,)) #Gets devicedepartment select list for the form
                    devicedepartmentlist = entries_to_list(cursor.fetchall())
                    devicedepartmentlist.insert(0, old_devicedepartment) #Places the current entry at the front of the list
                    if old_record[1] == None: #If Serial field is empty, sets the value to empty instead of having the default field text be "None"
                        old_record[1] = ''
                    return render_template('inventorytable/inv_edit_record_form.html', 
                        devicetypelist = devicetypelist, 
                        devicedepartmentlist = devicedepartmentlist,
                        old_barcode = old_barcode,
                        old_serial = old_record[1],
                        old_model = old_record[2],
                        old_datepurchased = old_record[5],
                        old_dateretired = old_record[6],
                        last_hostname = old_record[7],
                        last_inv_page = get_session_value('last_inv_page', '/inventory'),
                        active_page = 'inventory',
                        view_style = session['view_style'])
                else:
                    return redirect(url_for('error', error_code=1))
    else:
        return redirect(url_for('error', error_code=1))

@app.route('/inventory/search', methods = ['POST', 'GET'])
@logged_in_user
def inv_search_form():
    if request.method in ('POST'): #If form submitted
        return redirect(url_for('search_inventory', 
            search_category = request.form['search_category'], 
            criteria = request.form['criteria'])) #Redirects to search page with form data
    else:
        return render_template('inventorytable/inv_search_form.html',
            last_inv_page = get_session_value('last_inv_page', '/inventory'),
            active_page = 'inventory', 
            view_style = session['view_style']) #Renders form

@app.route('/inventory/search/<search_category>/<criteria>', methods = ['POST', 'GET'])
@logged_in_user
def search_inventory(search_category, criteria):
    session['last_inv_page'] = '/inventory/search/{}/{}'.format(search_category, criteria) #Where to return to if an edit occurs while on this page
    format_dict = {'barcode' : 'int', 
        'serial' : 'str', 
        'model' : 'str',
        'category' : 'str', 
        'department' : 'str', 
        'date_purchased' : 'date',
        'date_retired' : 'date', 
        'last_hostname' : 'str'} #Returns the formatting style for the SQL statement. strings have wildcard, int validates input as int, date validates input as date
    sortby_list = ['Barcode', 'Serial', 
        'Model', 'Category', 'Department', 
        'Date Purchased', 'Date Retired', 
        'Last Hostname']
    sortby = get_sortby('Barcode', '_')[0]
    sortby_SQL = get_sortby('Barcode', '_')[1]

    if format_dict[search_category] == 'int':
        if is_int(criteria):
            cursor.execute(sql.SQL('SELECT * FROM inventory WHERE barcode = %s ORDER BY {};')
                .format(sql.Identifier(sortby_SQL)), (criteria,))
            inventorytable = cursor.fetchall()
            search_category = search_category.capitalize() #Sets search category for display on the webpage
        else:
            return redirect(url_for('error', error_code=3))

    elif format_dict[search_category] == 'str':
        wildcard_criteria = make_wildcard(criteria) #Adds wildcard characters so exact string value isn't required
        cursor.execute(sql.SQL('SELECT * FROM inventory WHERE {} ILIKE %s ORDER BY {};')
            .format(sql.Identifier(search_category), sql.Identifier(sortby_SQL)), (wildcard_criteria,))
        inventorytable = cursor.fetchall()
        search_category = search_category.capitalize() #Sets search category for display on the webpage

    elif format_dict[search_category] == 'date':
        specificity_list = [None, 'year', 'month', 'day'] #Used to get the specificity of the user's input
        validation_blocks = ['%Y', '-%m', '-%d'] #Used to create the guide for input validation
        criteria_listform = criteria.split('-') #Replaces all separating characters with hyphens and splits each value into a list using those hyphens
        specificity = specificity_list[len(criteria_listform)]
        while len(criteria_listform) < 3: #Fills in the unspecified time values with zeroes
            criteria_listform.append('01') #Fills in month and day with 01
        criteria_formatted = '{0}-{1}-{2}'.format(*criteria_listform) #Takes the list and turns it back into a formatted date
        validation_guide = '' #Initiializes validation_guide
        for time_spot in range(specificity_list.index(specificity)): #Creates a formatting guide for datetime that is the length of the user's input
            validation_guide = validation_guide + validation_blocks[time_spot]
        try:  
            datetime.strptime(criteria, validation_guide).date() #Validates that the input is in timestamp form
        except:
            return redirect(url_for('error', error_code=3))
        cursor.execute(sql.SQL('SELECT * FROM inventory WHERE DATE_TRUNC(%s, {}) = %s ORDER BY {};')
                .format(sql.Identifier(search_category), sql.Identifier(sortby_SQL)), (specificity, criteria_formatted))
        inventorytable = cursor.fetchall()
        search_category = search_category.replace('_', ' ').capitalize()

    if inventorytable != []: #If search yielded results
        sortby_list.remove(sortby)
        sortby_list.insert(0, sortby) #Removes the sortby value from its original place in the list and inserts it at the top
        return render_template('inventorytable/inventorytable.html', 
        inventorytable = inventorytable, 
        search_category = search_category, 
        criteria = criteria, 
        sortby_list = sortby_list, 
        searched_table = True,
        active_page = 'inventory', 
        view_style = session['view_style'])

    else:
        try: #Error is thrown if there is no request.referrer
            if 'remove' in request.referrer: #Protects from error loop after deleting the last record in a search
                return redirect('/inventory')
            elif 'transactions' in request.referrer: #If accessed from transactions page by "view item" link and no records exist
                return redirect(url_for('error', error_code=10))
            else:
                return redirect(url_for('error', error_code=3))
        except:
            return redirect(url_for('error', error_code=3))

@app.route('/transactions/', methods = ['POST', 'GET'])
@logged_in_user
def trans_show_table():
    session['last_trans_page'] = '/transactions' #Where to return to if an edit occurs while on this page
    sortby_list = ['Transaction ID', 
        'Barcode', 'In/Out', 'Username', 
        'Assigned To', 'Hostname', 'Date']
    sortby = get_sortby('Date', '')[0]
    sortby_SQL = get_sortby('Date', '')[1]
    cursor.execute(sql.SQL('SELECT * FROM transactions ORDER BY {}, transactionid;')
        .format(sql.Identifier(sortby_SQL)))
    transactionstable = cursor.fetchall()
    sortby_list.remove(sortby)
    sortby_list.insert(0, sortby) #Removes the sortby value from its original place in the list and inserts it at the top
    return render_template('transactionstable/transactionstable.html', 
        transactionstable = transactionstable, 
        sortby_list=sortby_list, 
        retired_dict = get_retired_dict(), 
        searched_table = False,
        active_page = 'transactions', 
        view_style = session['view_style'])

@app.route('/transactions/add-record', methods = ['POST', 'GET'])
@logged_in_user
def trans_add_record_form():
    if request.method in ('POST'): #If form has been submitted
        try:
            quick_add_record = request.form['quick_add'] #If the form has been accessed via quick add button
            quick_add_list = format_quick_add_record(quick_add_record) #Formats the record into an indexable list.
            return render_template('transactionstable/trans_add_record_form.html',
                default_barcode = quick_add_list[1],
                default_inout = quick_add_list[2],
                default_username = quick_add_list[3],
                default_assignedto = quick_add_list[4],
                default_hostname = quick_add_list[5],
                hostnames_list = get_hostnames_list(),
                hostnames_pattern = get_hostnames_pattern(),
                last_trans_page = get_session_value('last_trans_page', '/transactions'),
                active_page = 'transactions',
                view_style = session['view_style'])
        except:
            barcode = request.form['barcode']
            cursor.execute('''SELECT * FROM inventory WHERE barcode=%s;''', (barcode,))
            if cursor.fetchall() != []: #If there is an inventory entry with the specified barcode
                cursor.execute('''SELECT transactionid FROM transactions 
                    ORDER BY transactionid DESC LIMIT 1;''')
                prev_id = cursor.fetchone() #Gets the latest transactionid before the one to be added
                try:
                    transactionid = int(prev_id[0]) + 1 #The transactionid for the record to be added
                except TypeError:
                    transactionid = 1
                username = get_form_value('username') #Field is non-mandatory, so special function is required
                hostname = get_form_value('hostname')
                transaction_data = (transactionid, barcode, request.form['inout'], 
                    username, request.form['assignedto'], hostname,
                    request.form['date']) 
                cursor.execute('''INSERT INTO transactions(transactionid, barcode, inout, username,
                assignedto, hostname, date)
                VALUES (%s, %s, %s, %s, %s, %s, %s);''', transaction_data)
                cursor.execute('SELECT * FROM transactions WHERE transactionid=%s;', (transactionid,))
                recordcopy=cursor.fetchone() 
                create_log('Add', 'Transactions', recordcopy) #Makes a log of the new record
                update_last_hostname(barcode)#updates the last_hostname field for the device in inventory.
                conn.commit()
                return redirect(get_session_value('last_trans_page', '/transactions'))
            else:
                return redirect(url_for('error', error_code=1))
    else:
        return render_template('transactionstable/trans_add_record_form.html',
        hostnames_list = get_hostnames_list(),
        hostnames_pattern = get_hostnames_pattern(),
        last_trans_page = get_session_value('last_trans_page', '/transactions'),
        active_page = 'transactions',
        view_style = session['view_style'])

@app.route('/transactions/remove-record/<transactionid>', methods = ['POST', 'GET'])
@logged_in_user
def trans_remove_record(transactionid):
    if is_int(transactionid):
        if request.method in ('POST'): #If form has been submitted
            try:
                request.form['cancel']
                return redirect(get_session_value('last_trans_page', '/transactions'))
            except:
                cursor.execute('SELECT * FROM transactions WHERE transactionid=%s;', (transactionid,))
                old_record = cursor.fetchone()
                create_log('Remove', 'Transactions', old_record) #Makes a log of the record before deletion
                cursor.execute('DELETE FROM transactions WHERE transactionid=%s;', (transactionid,))
                update_last_hostname(old_record[1])#updates the last_hostname field for the device in inventory.
                conn.commit()
                return redirect(get_session_value('last_trans_page', '/transactions'))
        else:
            cursor.execute('SELECT * FROM transactions WHERE transactionid=%s;', (transactionid,))
            old_record = cursor.fetchall()
            if old_record != []: #If there is an entry with the given transactionid
                return render_template('transactionstable/trans_remove_record_form.html',
                old_transactionid = transactionid,
                view_style = session['view_style'],
                active_page = 'transactions')
            else:
                return redirect(url_for('error', error_code=5))
    else:
        return redirect(url_for('error', error_code=5))

@app.route('/transactions/edit-record/<transactionid>', methods = ['POST', 'GET'])
@logged_in_user
def trans_edit_record_form(transactionid):
    if is_int(transactionid):
        if request.method in ('POST'): #If form has been submitted
            barcode = request.form['barcode']
            cursor.execute('SELECT * FROM inventory WHERE barcode=%s;', (barcode,))
            barcode_in_inventory = cursor.fetchall() 
            cursor.execute('SELECT * FROM transactions WHERE barcode=%s;', (barcode,))
            barcode_in_transactions = cursor.fetchall() #If given barcode is in inventory or transactions tables
            if barcode_in_inventory != [] or barcode_in_transactions != []: #If a barcode entry is deleted from inventory, it can still be edited in transactions
                cursor.execute('SELECT * FROM transactions WHERE transactionid=%s;', (transactionid,))
                old_record = cursor.fetchone()
                username = get_form_value('username') #Field is non-mandatory, so special function is required
                hostname = get_form_value('hostname')
                edit_trans_data = (barcode, request.form['inout'], username, 
                    request.form['assignedto'], hostname, request.form['date']) 
                if validate_changed((transactionid,) + edit_trans_data, old_record) == True:
                    create_log('Edit', 'Transactions', old_record) #Makes a log of the record before edit
                    cursor.execute('''UPDATE transactions
                        SET barcode = %s,
                            inout = %s,
                            username = %s,
                            assignedto = %s,
                            hostname = %s,
                            date = %s
                        WHERE transactionid = %s;''', (edit_trans_data + (transactionid,)))
                    update_last_hostname(barcode)#updates the last_hostname field for the device in inventory.
                    conn.commit()
                    return redirect(get_session_value('last_trans_page', '/transactions'))
                else:
                    return redirect(get_session_value('last_trans_page', '/transactions'))
            else:
                return redirect(url_for('error', error_code=6))
        else:
            if len(transactionid) < 6: #Protects from SQL numeric range injections
                cursor.execute('SELECT * FROM transactions WHERE transactionid=%s;', (transactionid,))
                old_record = list(cursor.fetchone())
                cursor.execute('SELECT date_retired FROM inventory WHERE barcode=%s;', (old_record[1],)) #Gets date_retired from inventory table
                date_retired = cursor.fetchall()
                if date_retired != []: #If there is an inventory entry for the barcode
                    entry = date_retired[0] #Frees the entry tuple from the list created by the fetchall function
                    if entry[0] != None: #If the device has been retired, sets a boolean value to true to be used in html
                        retired = True
                    else:
                        retired = False
                else:
                    retired = True
                if old_record != None: #If a record exists with the given transactionid
                    if old_record[3] == None: #If Username field is empty, sets the value to empty instead of having the default field text be "None"
                        old_record[3] = ''
                    if old_record[5] == None: #If Hostname field is empty, sets the value to empty instead of having the default field text be "None"
                        old_record[5] = ''
                    return render_template('/transactionstable/trans_edit_record_form.html',
                        old_transactionid = old_record[0],
                        old_barcode = old_record[1],
                        old_inout = old_record[2],
                        old_username = old_record[3],
                        old_assignedto = old_record[4],
                        old_hostname = old_record[5],
                        old_date = old_record[6],
                        hostnames_list = get_hostnames_list(),
                        hostnames_pattern = get_hostnames_pattern(),
                        retired = retired,
                        last_trans_page = get_session_value('last_trans_page', '/transactions'),
                        active_page = 'transactions', 
                        view_style = session['view_style']) #Passes old record data into the default spaces in the form
                else:
                    return redirect(url_for('error', error_code=5))
            else: 
                return redirect(url_for('error', error_code=5))
    else:
        return redirect(url_for('error', error_code=5))

@app.route('/transactions/search', methods = ['POST', 'GET'])
def trans_search_form():
    if request.method in ('POST'): #If form submitted
        return redirect(url_for('search_transactions', 
            search_category = request.form['search_category'], 
            criteria = request.form['criteria'])) #Redirects to search page with form data
    else:
        return render_template('transactionstable/trans_search_form.html',
            last_trans_page = get_session_value('last_trans_page', '/transactions'),
            active_page = 'transactions', 
            view_style = session['view_style']) #Renders form
    
@app.route('/transactions/search/<search_category>/<criteria>', methods = ['POST', 'GET'])
@logged_in_user
def search_transactions(search_category, criteria):
    session['last_trans_page'] = '/transactions/search/{}/{}'.format(search_category, criteria) #Where to return to if an edit occurs while on this page
    sortby_list = ['Transaction ID', 
        'Barcode', 'In/Out', 'Username', 
        'Assigned To', 'Hostname', 'Date']
    format_dict = {
        'transactionid' : 'int', 
        'barcode' : 'int', 
        'username' : 'str', 
        'assignedto' : 'str', 
        'hostname' : 'str', 
        'date' : 'date'} #Returns the formatting style for SQL statements. Int and date are validated, str gets wildcard
    sortby = get_sortby('Date', '')[0]
    sortby_SQL = get_sortby('Date', '')[1]

    if format_dict[search_category] == 'int':
        if is_int(criteria):
            criteria = int(criteria) #Ensures that the barcode number provided is an integer
            cursor.execute(sql.SQL('SELECT * FROM transactions WHERE {} = %s ORDER BY {}, transactionid;')
                .format(sql.Identifier(search_category), sql.Identifier(sortby_SQL)), (criteria,))
            transactionstable = cursor.fetchall()
            if search_category == 'transactionid': #Sets search category for display on the webpage
                search_category = 'Transaction ID'
            else:
                search_category = search_category.capitalize() 
        else:
            return redirect(url_for('error', error_code=3))

    elif format_dict[search_category] == 'str':
        wildcard_criteria = make_wildcard(criteria) #Adds wildcard characters so exact username isn't required
        cursor.execute(sql.SQL('SELECT * FROM transactions WHERE {} ILIKE %s ORDER BY {}, transactionid;')
            .format(sql.Identifier(search_category), sql.Identifier(sortby_SQL)), (wildcard_criteria,))
        transactionstable = cursor.fetchall()
        if search_category == 'assignedto': #Sets search category for display on the webpage
            search_category = '"Assigned To"'
        else:
            search_category = search_category.capitalize()

    elif format_dict[search_category] == 'date':
        specificity_list = [None, 'year', 'month', 'day'] #Used to get the specificity of the user's input
        validation_blocks = ['%Y', '-%m', '-%d'] #Used to create the guide for input validation
        criteria_listform = criteria.split('-') #Replaces all separating characters with hyphens and splits each value into a list using those hyphens
        specificity = specificity_list[len(criteria_listform)]
        while len(criteria_listform) < 3: #Fills in the unspecified time values with zeroes
            criteria_listform.append('01') #Fills in month and day with 01
        criteria_formatted = '{0}-{1}-{2}'.format(*criteria_listform) #Takes the list and turns it back into a formatted date
        validation_guide = '' #Initiializes validation_guide
        for time_spot in range(specificity_list.index(specificity)): #Creates a formatting guide for datetime that is the length of the user's input
            validation_guide = validation_guide + validation_blocks[time_spot]
        try:  
            datetime.strptime(criteria, validation_guide).date() #Validates that the input is in timestamp form
        except:
            return redirect(url_for('error', error_code=3))
        cursor.execute(sql.SQL('SELECT * FROM transactions WHERE DATE_TRUNC(%s, {}) = %s ORDER BY {};')
                .format(sql.Identifier(search_category), sql.Identifier(sortby_SQL)), (specificity, criteria_formatted))
        transactionstable = cursor.fetchall()
        search_category = search_category.capitalize()

    if transactionstable != []: #If search yielded results
        sortby_list.remove(sortby)
        sortby_list.insert(0, sortby) #Removes the sortby value from its original place in the list and inserts it at the top
        return render_template('transactionstable/transactionstable.html', 
            transactionstable = transactionstable, 
            search_category = search_category, 
            criteria = criteria, 
            sortby_list = sortby_list, 
            retired_dict = get_retired_dict(),
            searched_table = True, 
            active_page = 'transactions', 
            view_style = session['view_style'])

    else:
        try: #Error is thrown if there is no referrer
            if 'remove' in request.referrer: #Protects from error loop after deleting the last record in a search
                return redirect('/transactions')
            elif 'inventory' in request.referrer: #If accessed from inventory page by barcode history and no records exist
                return redirect(url_for('error', error_code=4))
            else:
                return redirect(url_for('error', error_code=3))
        except:
            return redirect(url_for('error', error_code=3))

@app.route('/hostnames', methods = ['GET', 'POST'])
@logged_in_user
def show_hostnames():
    session['last_hostnames_page'] = '/hostnames'#Where to return to if an edit occurs while on this page
    sortby_list = ['Hostname', 'Description']
    sortby = get_sortby('Hostname', '')[0]
    sortby_SQL = get_sortby('Hostname', '')[1]
    try: #If active_only has been specified, set it to what it is, otherwise default to false
        active_only = request.form['active_only']
    except:
        active_only = False
    if active_only == 'True': #If filtering by only active hostnames, uses the correct query
        cursor.execute(sql.SQL('SELECT * FROM hostnames WHERE active=true ORDER BY {};')
            .format(sql.Identifier(sortby_SQL)))
    else:
        cursor.execute(sql.SQL('SELECT * FROM hostnames ORDER BY {};')
            .format(sql.Identifier(sortby_SQL)))
    hostnametable = cursor.fetchall()
    sortby_list.remove(sortby)
    sortby_list.insert(0, sortby) #Removes the sortby value from its original place in the list and inserts it at the top
    return render_template('hostnamestable/show_hostnames.html', 
        hostnametable = hostnametable, 
        active_page = 'hostnames',
        sortby_list = sortby_list,
        active_only = active_only,
        searched_table = False,
        view_style = session['view_style'])

@app.route('/hostnames/add', methods = ['GET', 'POST'])
@logged_in_user
def add_hostname_form():
    if request.method in ('POST'): #If form has been submitted
        hostname = request.form['hostname']
        cursor.execute('SELECT * FROM hostnames WHERE hostname=%s;', (hostname,))
        if cursor.fetchall() == []: #If no entries exist for that hostname already
            if get_form_value('active') == 'true':
                active = 'true'
            else:
                active = 'false'
            cursor.execute('''INSERT INTO hostnames(hostname, description, active)
                VALUES (%s, %s, %s);''', (hostname, request.form['description'], active))
            cursor.execute('SELECT * FROM hostnames WHERE hostname=%s;', (hostname,)) #Gets a copy of the new entry
            recordcopy = cursor.fetchone()
            create_log('Add', 'Hostnames', recordcopy)
            conn.commit()
            return redirect(get_session_value('last_hostnames_page', '/hostnames'))
        else:
            return redirect(url_for('error', error_code=11))
    else:
        return render_template('hostnamestable/add_hostname_form.html', 
            last_hostnames_page = get_session_value('last_hostnames_page', '/hostnames'),
            active_page = 'hostnames', 
            view_style = session['view_style'])

@app.route('/hostnames/edit/<old_hostname>', methods = ['POST', 'GET'])
@logged_in_user
def hostname_edit_record_form(old_hostname):
    if request.method in ('POST'): #If form has been submitted
        cursor.execute('SELECT * FROM hostnames WHERE hostname=%s;', (old_hostname,))
        old_record = cursor.fetchone()
        new_hostname = request.form['hostname']
        cursor.execute('SELECT * FROM hostnames WHERE hostname=%s AND NOT description=%s;', (new_hostname, old_record[1]))
        if cursor.fetchall() == []: #If a record exists with the new (edited) hostname that's not the old record (Meaning that the hostname hasn't changed). 
            if get_form_value('active') == 'true':
                new_active = 'True'
            else:
                new_active = 'False'
            edit_hostname_data = (new_hostname, request.form['description'], new_active)
            if validate_changed(edit_hostname_data, old_record) == True:
                create_log('Edit', 'Hostnames', old_record) #Makes a log of the record before edit 
                cursor.execute('''UPDATE hostnames
                    SET hostname = %s,
                        description = %s,
                        active = %s
                    WHERE hostname = %s;''', 
                    (edit_hostname_data + (old_hostname,)))
                conn.commit()
                return redirect(get_session_value('last_hostnames_page', '/hostnames'))
            else:
                return redirect(get_session_value('last_hostnames_page', '/hostnames'))
        else:
            return redirect(url_for('error', error_code=11))
    else:
        if len(old_hostname) < 20: #Protects from SQL range injections
            cursor.execute('SELECT * FROM hostnames WHERE hostname=%s;', (old_hostname,))
            old_record = cursor.fetchone()
            if old_record != None: #If a record exists with the given hostname
                return render_template('hostnamestable/hostname_edit_record_form.html',
                    old_hostname = old_record[0],
                    old_description = old_record[1],
                    old_active = old_record[2],
                    last_hostnames_page = get_session_value('last_hostnames_page', '/hostnames'),
                    active_page = 'hostnames', 
                    view_style = session['view_style']) #Passes old record data into the default spaces in the form
            else:
                return redirect(url_for('error', error_code=12))
        else: 
            return redirect(url_for('error', error_code=12))

@app.route('/hostnames/remove/<old_hostname>', methods = ['POST', 'GET'])
@logged_in_user
def hostname_remove_record_form(old_hostname):
    if request.method in ('POST'): #If form has been submitted
        try:
            request.form['cancel'] #If the user hit the cancel button
            return redirect(get_session_value('last_hostnames_page', '/hostnames'))
        except:
            cursor.execute('SELECT * FROM hostnames WHERE hostname=%s;', (old_hostname,))
            old_record = cursor.fetchone()
            create_log('Remove', 'Hostnames', old_record) #Makes a log of the record before deletion
            cursor.execute('DELETE FROM hostnames WHERE hostname=%s;', (old_hostname,))
            conn.commit()
            return redirect(get_session_value('last_hostnames_page', '/hostnames'))

    else:
        if len(old_hostname) < 20:
            cursor.execute('SELECT * FROM hostnames WHERE hostname=%s;', (old_hostname,))
            old_record = cursor.fetchall()
            if old_record != []: #If there is an entry with the given hostname
                return render_template('hostnamestable/hostname_remove_record_form.html',
                old_hostname = old_hostname,
                view_style = session['view_style'],
                active_page = 'hostnames')
            else:
                return redirect(url_for('error', error_code=12))
        else:
            return redirect(url_for('error', error_code=12))

@app.route('/hostnames/search', methods = ['POST', 'GET'])
@logged_in_user
def hostnames_search_form():
    if request.method in ('POST'): #If form submitted
        return redirect(url_for('search_hostnames', 
            search_category = request.form['search_category'], 
            criteria = request.form['criteria'])) #Redirects to search page with form data
    else:
        return render_template('hostnamestable/hostnames_search_form.html',
            last_hostnames_page = get_session_value('last_hostnames_page', '/hostnames'),
            active_page = 'hostnames', 
            view_style = session['view_style'])

@app.route('/hostnames/search/<search_category>/<criteria>', methods = ['POST', 'GET'])
@logged_in_user
def search_hostnames(search_category, criteria):
    session['last_hostnames_page'] = '/hostnames/search/{}/{}'.format(search_category, criteria) #Where to return to if an edit occurs while on this page
    sortby_list = ['Hostname', 'Description']
    sortby = get_sortby('Hostname', '')[0]
    sortby_SQL = get_sortby('Hostname', '')[1] #This search function does not use the format_dict like the other table searches because the only possible formats are str
    wildcard_criteria = make_wildcard(criteria) #Adds wildcard characters so exact username isn't required
    try: #If active_only has been specified, set it to what it is, otherwise default to false
        active_only = request.form['active_only']
    except:
        active_only = False
    if active_only == 'True': #If filtering by only active hostnames, uses the correct query
        cursor.execute(sql.SQL('SELECT * FROM hostnames WHERE {} ILIKE %s AND active=true ORDER BY {};')
        .format(sql.Identifier(search_category), sql.Identifier(sortby_SQL)), (wildcard_criteria,))
    else:
        cursor.execute(sql.SQL('SELECT * FROM hostnames WHERE {} ILIKE %s ORDER BY {};')
        .format(sql.Identifier(search_category), sql.Identifier(sortby_SQL)), (wildcard_criteria,))
    hostnametable = cursor.fetchall()
    search_category = search_category.capitalize()
    if hostnametable != []: #If search yielded results
        sortby_list.remove(sortby)
        sortby_list.insert(0, sortby) #Removes the sortby value from its original place in the list and inserts it at the top
        return render_template('hostnamestable/show_hostnames.html', 
            hostnametable = hostnametable, 
            search_category = search_category, 
            criteria = criteria, 
            sortby_list = sortby_list, 
            active_only = active_only,
            searched_table = True, 
            active_page = 'hostnames', 
            view_style = session['view_style'])
    else:
        try: #Error is thrown if there is no referrer
            if 'remove' in request.referrer: #Protects from error loop after deleting the last record in a search
                return redirect('/hostnames')
            else:
                return redirect(url_for('error', error_code=3))
        except:
            return redirect(url_for('error', error_code=3))

@app.route('/admin-tools')
@logged_in_admin
def admin_tools():
    return render_template('admin/admin_tools.html', active_page = 'admin_tools',
        view_style = session['view_style'])

@app.route('/admin-tools/logs/', methods = ['POST', 'GET'])
@logged_in_admin
def show_logs():
    sortby_list = ['Username', 'Action Type', 'Database', 'Timestamp']
    sortby = get_sortby('Timestamp', '')[0]
    sortby_SQL = get_sortby('Timestamp', '')[1]
    cursor.execute(sql.SQL('SELECT * FROM logs ORDER BY {};')
        .format(sql.Identifier(sortby_SQL)))
    logtable = cursor.fetchall()
    sortby_list.remove(sortby)
    sortby_list.insert(0, sortby) #Removes the sortby value from its original place in the list and inserts it at the top
    return render_template('admin/show_logs.html', 
        logtable = logtable, 
        sortby_list = sortby_list, 
        searched_table = False,
        active_page = 'admin_tools', 
        view_style = session['view_style'])

@app.route('/admin-tools/logs/search', methods = ['POST', 'GET'])
@logged_in_admin
def logs_search_form():
    if request.method in ('POST'): #If form submitted
        return redirect(url_for('search_logs', 
            search_category = request.form['search_category'], 
            criteria = request.form['criteria'])) #Redirects to search page with form data
    else:
        return render_template('admin/logs_search_form.html',
            active_page = 'admin_tools', 
            view_style = session['view_style']) #Renders form

@app.route('/admin-tools/logs/search/<search_category>/<criteria>', methods = ['POST', 'GET'])
@logged_in_admin
def search_logs(search_category, criteria):
    sortby_list = ['Username', 'Action Type', 
        'Database', 'Timestamp']
    sortby = get_sortby('Timestamp', '')[0]
    sortby_SQL = get_sortby('Timestamp', '')[1]
    format_dict = {
        'username' : 'str', 
        'actiontype' : 'str', 
        'database' : 'str', 
        'timestamp' : 'timestamp', 
        'recordcopy' : 'str'} #Returns the formatting style for SQL statements. Int and timestamp are validated, str gets wildcard

    if format_dict[search_category] == 'str':
        wildcard_criteria = make_wildcard(criteria) #Adds wildcard characters so exact username isn't required
        cursor.execute(sql.SQL('SELECT * FROM logs WHERE {} ILIKE %s ORDER BY {}, timestamp;')
            .format(sql.Identifier(search_category), sql.Identifier(sortby_SQL)), (wildcard_criteria,))
        logtable = cursor.fetchall()
        if search_category == 'assignedto': #Sets search category for display on the webpage
            search_category = '"Assigned To"'
        else:
            search_category = search_category.capitalize()

    elif format_dict[search_category] == 'timestamp':
        specificity_list = [None, 'year', 'month', 'day', 
            'hour', 'minute', 'second'] #Used to get the specificity of the user's input
        validation_blocks = ['%Y', '-%m', '-%d', ' %H', ':%M', ':%S'] #Used to create the guide for input validation
        criteria_listform = criteria.replace(' ', '-').replace(':', '-').split('-') #Replaces all separating characters with hyphens and splits each value into a list using those hyphens
        specificity = specificity_list[len(criteria_listform)]
        while len(criteria_listform) < 6: #Fills in the unspecified time values with zeroes
            if len(criteria_listform) < 3:
                criteria_listform.append('01') #Fills in month and day with 01, because the values cannot be 00
            else:
                criteria_listform.append('00')
        criteria_formatted = '{0}-{1}-{2} {3}:{4}:{5}'.format(*criteria_listform) #Takes the list and turns it back into a formatted date
        validation_guide = '' #Initiializes validation_guide
        for time_spot in range(specificity_list.index(specificity)): #Creates a formatting guide for datetime that is the length of the user's input
            validation_guide = validation_guide + validation_blocks[time_spot]
        try:  
            datetime.strptime(criteria, validation_guide).date() #Validates that the input is in timestamp form
        except:
            return redirect(url_for('error', error_code=3))
        cursor.execute(sql.SQL('SELECT * FROM logs WHERE DATE_TRUNC(%s, timestamp)=%s ORDER BY {}, timestamp;')
            .format(sql.Identifier(sortby_SQL)), 
            (specificity, criteria_formatted)) #Searches the database, truncating on specificity provided by user
        logtable = cursor.fetchall()
        search_category = search_category.capitalize()

    if logtable != []: #If search yielded results
        sortby_list.remove(sortby)
        sortby_list.insert(0, sortby) #Removes the sortby value from its original place in the list and inserts it at the top
        return render_template('admin/show_logs.html', 
            logtable = logtable, 
            search_category = search_category, 
            criteria = criteria, 
            sortby_list = sortby_list, 
            searched_table = True,
            active_page = 'admin_tools', 
            view_style = session['view_style'])

    else:
        try: #Error is thrown if there is no referrer
            if 'remove' in request.referrer: #Protects from error loop after deleting the last record in a search
                return redirect('/transactions')
            elif 'inventory' in request.referrer: #If accessed from inventory page by barcode history and no records exist
                return redirect(url_for('error', error_code=4))
            else:
                return redirect(url_for('error', error_code=3))
        except:
            return redirect(url_for('error', error_code=3))

@app.route('/admin-tools/dropdowns', methods = ['POST', 'GET'])
@logged_in_admin
def show_dropdowns():
    cursor.execute('''SELECT * FROM dropdowns WHERE 
        devicetype IS NULL OR devicedepartment IS NULL LIMIT 1;''')
    diff_length_row = cursor.fetchone() #Gets the first row where either devicetype list or devicedepartment list is empty
    if diff_length_row == None: #If there isn't a row (meaning that the lists are the same length)
        cursor.execute('SELECT * FROM dropdowns;')
    elif diff_length_row[0] == None: #If the devicetype field is empty at the selected row (meaning that devicedepartment is longer)
        cursor.execute('SELECT * FROM dropdowns ORDER BY devicetype;') #sorts by the shorter list so the "None" values are at the bottom of the table
    elif diff_length_row[1] == None: #Opposite of the earlier elif: if devicetype is longer
        cursor.execute('SELECT * FROM dropdowns ORDER BY devicedepartment;') #Sorts by the shorter list
    dropdowntable = cursor.fetchall()
    if request.method in ('POST'):
        try:
            edit_column = request.form['edit_column']
        except:
            edit_column = False
    else:
        edit_column = False
    return render_template('admin/show_dropdowns.html', 
        edit_column = edit_column,
        dropdowntable = dropdowntable, 
        active_page = 'admin_tools',
        view_style = session['view_style'])

@app.route('/admin-tools/dropdowns/add', methods = ['POST', 'GET'])
@logged_in_admin
def add_dropdown_form():
    if request.method in ('POST'): #If form has been submitted
        newoption = request.form['newoption']
        edit_dropdown = request.form['dropdown']
        opposing_dropdown_dict = {
            'devicetype' : 'devicedepartment', 
            'devicedepartment' : 'devicetype'} #Used to reference the opposing dropdown during sql executions
        cursor.execute(sql.SQL("SELECT * FROM dropdowns WHERE {} = %s;").format(sql.Identifier(edit_dropdown)), (newoption,))
        if cursor.fetchall() == []: #If the option to be added does not exist already
            cursor.execute(sql.SQL('SELECT * FROM dropdowns WHERE {} IS NULL;')
                .format(sql.Identifier(edit_dropdown)))#Finds any rows where the given dropdown list is empty
            if cursor.fetchall() == []: #If there are no rows where given dropdown field is empty
                cursor.execute(sql.SQL('INSERT INTO dropdowns({}) VALUES(%s);')
                    .format(sql.Identifier(edit_dropdown)), (newoption,))
            else: #If there is at least one row where given dropdown field is empty
                opposing_dropdown = opposing_dropdown_dict[edit_dropdown]
                cursor.execute(sql.SQL('''UPDATE dropdowns
                    SET {0} = %s
                    WHERE {1} IN (SELECT {1}
                    FROM dropdowns
                    WHERE {0} IS NULL
                    LIMIT 1);''')
                    .format(sql.Identifier(edit_dropdown), 
                    sql.Identifier(opposing_dropdown)), (newoption,)) #Sets only one empty dropdown field to the new option value.
            conn.commit()
            return redirect('/admin-tools/dropdowns')
        else:
            return redirect(url_for('error', error_code=7))
    else:
        return render_template('admin/add_dropdown_form.html', 
            active_page = 'admin_tools',
            view_style = session['view_style'])

@app.route('/admin-tools/dropdowns/remove', methods = ['POST', 'GET'])
@logged_in_admin
def remove_dropdown_form():
    if request.method in ('POST'): #If form has been submitted
        removeoption = request.form['removeoption']
        edit_dropdown = request.form['dropdown']
        cursor.execute(sql.SQL('SELECT * FROM dropdowns WHERE {}=%s;').format(sql.Identifier(edit_dropdown)), (removeoption,))
        if cursor.fetchall() != []: #If option exists in given dropdown list
            cursor.execute(sql.SQL('''UPDATE dropdowns
                SET {0} = NULL
                WHERE {0} = %s''').format(sql.Identifier(edit_dropdown)), (removeoption,))
            cursor.execute('''DELETE FROM dropdowns WHERE 
                devicetype IS NULL 
                AND devicedepartment IS NULL;''') #Removes any dead rows that might be "None, None"
            conn.commit()
            return redirect('/admin-tools/dropdowns')
        else:
            return redirect(url_for('error', error_code=9))
    else:
        return render_template('admin/remove_dropdown_form.html',
            active_page = 'admin_tools', 
            view_style = session['view_style'])

@app.route('/admin-tools/dropdowns/remove/<edit_dropdown>/<old_dropdown>', methods = ['POST', 'GET'])
@logged_in_admin
def dropdown_remove_record_form(edit_dropdown, old_dropdown):
    if request.method in ('POST'): #If form has been submitted
        try:
            request.form['cancel'] #If the user hit the cancel button
            return redirect('/admin-tools/dropdowns')
        except:
            cursor.execute(sql.SQL('SELECT * FROM dropdowns WHERE {}=%s;').format(sql.Identifier(edit_dropdown)), (old_dropdown,))
            if cursor.fetchall() != []: #If option exists in given dropdown list
                cursor.execute(sql.SQL('''UPDATE dropdowns
                    SET {0} = NULL
                    WHERE {0} = %s''').format(sql.Identifier(edit_dropdown)), (old_dropdown,))
                cursor.execute('''DELETE FROM dropdowns WHERE 
                    devicetype IS NULL 
                    AND devicedepartment IS NULL;''') #Removes any dead rows that might be "None, None"
                conn.commit()
                return redirect('/admin-tools/dropdowns')
            else:
                return redirect(url_for('error', error_code=9))
    else:
        if len(old_dropdown) < 40:
            cursor.execute(sql.SQL('SELECT * FROM dropdowns WHERE {} = %s;').format(sql.Identifier(edit_dropdown)), (old_dropdown,))
            old_record = cursor.fetchall()
            if old_record != []: #If there is an entry with the given hostname
                return render_template('admin/remove_dropdown_form.html',
                old_dropdown = old_dropdown,
                view_style = session['view_style'],
                active_page = 'admin_tools')
            else:
                return redirect(url_for('error', error_code=9))
        else:
            return redirect(url_for('error', error_code=9))

@app.route('/error/<error_code>')
@logged_in_user
def error(error_code): #Takes error code and outputs a message based on error_dict dictionary
    if request.referrer == None: #Sets the navbar link to bold depending on the category of the page that led to the error.
        last_page = '/inventory' #If the page is visited by typing URL (No referrer), sets values to default: Button goes to inventory, no bolded navbar link
        active_page = None
    elif 'admin-tools' in request.referrer: 
        last_page = request.referrer
        active_page = 'admin_tools'
    elif 'inventory' in request.referrer:
        last_page = request.referrer
        active_page = 'inventory'
    elif 'hostnames' in request.referrer:
        last_page = request.referrer
        active_page = 'hostnames'
    else:
        last_page = request.referrer
        active_page = 'transactions'
    try: #If given an invalid error code, redirects to inventory table
        error_message = error_dict[int(error_code)]
        return render_template('error.html', 
            error=error_message, 
            last_page = last_page,
            active_page = active_page, 
            view_style = session['view_style'])
    except:
        return redirect('/inventory')

@app.route('/toggle-view')
def toggle_view(): #Changes the view between light_style and dark_style when visited and redirects to the last page visited
    try:
        if session['view_style'] == 'light_style':
            session['view_style'] = 'dark_style'
        else:
            session['view_style'] = 'light_style'
    except:
        session['view_style'] = 'light_style' #If no view style has been set, defaults to light
    try:
        return redirect(request.referrer)
    except:
        return redirect('/login') #If page is visited by link, sends to login

if __name__ == '__main__':
    Session(app)
    app.run()
    conn.close()