#!/bin/env python

from os import urandom, mkdir, chown, unlink, path
import sys
import pwd
import ldap
import logging
import argparse
import tempfile
import ldap.modlist as modlist
from getpass import getpass
from pprint import PrettyPrinter
import subprocess
from socket import gethostname, getfqdn
# Modules for email
import smtplib
import lxml.html
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

log_file = '/var/log/manageusers.log'
secret_alphabet = "ABCDEFGHJKLMNPQRSTUVXYZabcdefghijklmnopqrstuwxyz0!@#$%:;"
logFormatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")

loginfile_h = logging.FileHandler(log_file)
loginfile_h.setFormatter(logFormatter)
loginconsole_h = logging.StreamHandler()
loginconsole_h.setFormatter(logFormatter)

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
logger.addHandler(loginfile_h)
logger.addHandler(loginconsole_h)

pp = PrettyPrinter(indent=4)

ldap_protocol = ldap.VERSION2
scope = ldap.SCOPE_ONELEVEL
host = gethostname()
fdqn = getfqdn()
ldap_host = "ldap://" + fdqn
sender = 'felix.homa@wur.nl'
admin_dn = "cn=youradminusername,dc=net,dc=domain"
baseUserDN = "ou=users,dc=net,dc=domain"
baseGrpDN = "ou=groups,dc=net,dc=domain"
departments = ['MICEVO', 'BACGEN', 'MICFYS', 'MOLECO', 'SSB', 'EXTERNAL']
minGid = 1000
# minUID for MIB will start at 20000
minUid = 1000
homedir = '/homefolder'

msg = '''
Welcome to admin interactive script.
With this you will be able to do the following actions:
listgrp: List all LDAP groups
addgrp : Add new group to LDAP
getLastGid: Return the highest group number

What do you want to do?
'''

mail_body = """\
Dear {name},<br/>
<p>
A user name has been created for you on {hostname},<br/> 
please take some time to read about web manuel <a href={link}>{link}</a> <br/>
Your temporary password is {pwd} change it as soon as possible.
<p/>
Regards,<br/>
Admin
PS: This is an automatic email
"""

mail_deleteUser = """\
Dear {name},<br/>
<div><p>
Your user name has been deleted from MIB servers.
We wish you good luck for the future.
</p></div>
Regards,<br/>
Admin
"""

def gen_password(length=12, charset=secret_alphabet):
  random_bytes = urandom(length)
  len_charset = len(charset)
  indices = [int(len_charset * (ord(byte) / 256.0)) for byte in random_bytes]
  return "".join([charset[index] for index in indices])

def make_home(dirname, uid, gid, mode=0755):
  ''' Creates home folder and assign it to the correct uid/gid '''
  uid = int(uid)
  gid = int(gid)
  if not path.exists(dirname):
    mkdir(dirname, mode)
    chown(dirname, uid, gid)
  else:
    logger.error("Home folder already exists {}".format(dirname))

def sendmail(sender, receiver, subject, message, hostname='net.wur.nl', port=25, encode="utf-8"):
  ''' Send email to a receiver. 
  arguments:
    sender: email address to send message to
    receiver: destination address
    message: mail body
    hostname: fdqn of the mail server, default is localhost
    port: port number to use
    encode: encoding for the message
  '''
  mimetext = 'html' if lxml.html.fromstring(mail_body).find('.//*') is not None else 'text'
  msg = MIMEMultipart()
  msg['Subject'] = subject
  msg['From'] = sender
  msg['To'] = receiver
  msg.attach(MIMEText(message, mimetext, encode))

  try:
    server = smtplib.SMTP(hostname, port)
    server.sendmail(sender, receiver, msg.as_string())
    logger.info("Email has been sent to {}".format(receiver))
  except Exception, e:
    logger.error("Error: Unable to send email\n{}".format(e))
    sys.exit(-1)

def getldap():
  ''' Return a new ldap object '''
  #l = ldap.initialize("ldap://localhost", bytes_mode=True)
  l = ldap.initialize(ldap_host, trace_level=0)
  l.SASL_AVAIL = 0
  l.TLS_AVAIL = 1
  l.start_tls_s()
  return l

def getallgroups():
  """ List all groups """
  retrieveAttributes = []
  searchFilter = "(objectClass=posixGroup)"
  try:
    l = getldap()
    ldap_result_id = l.search_s(baseGrpDN, scope, searchFilter, retrieveAttributes)
  except ldap.LDAPError, e:
    logger.error(e)
    sys.exit(-1)
  return ldap_result_id

def _ldap_search(basedn, scope=scope, searchFilter=None, retrieveAttributes=[]):
  ''' Return the result of a search '''
  try:
    l = getldap()
    ldap_result_id = l.search_s(basedn, scope, searchFilter, retrieveAttributes)
  except ldap.LDAPError, e:
    logger.error(e)
    sys.exit(-1)
  return ldap_result_id

def listgrp(args):
  ''' Print a list of all groups '''
  cn='**'
  gid='-1'
  desc='No desc'
  for dn, entries in getallgroups():
    if 'cn' in entries:
      cn = entries['cn'][0]
    if 'gidNumber' in entries:
      gid = entries['gidNumber'][0]
    if 'description' in entries:
      desc = entries['description'][0]
    print "{cn:15}\t{gid:4}\t{desc}".format(cn=cn, gid=gid, desc=desc)

def getallusers():
  ''' Return the raw list of all users '''
  retrieveAttributes = []
  searchFilter = "objectClass=shadowAccount"
  try:
    l = getldap()
    ldap_result_id = l.search_s(baseUserDN, scope, searchFilter, retrieveAttributes)
  except ldap.LDAPError, e:
    logger.error(e)
    sys.exit(-1)
  return ldap_result_id

def listusers(args):
  ''' List all users '''
  for dn, entries in getallusers():
    uid = entries['uid'][0]
    uidNum = entries['uidNumber'][0]
    cn = entries['cn'][1]
    homed = entries['homeDirectory'][0]
    mail = entries['mail'][0]
    print "{uid:15}\t{uidNum}\t{cn:25}\t{hdir:20}\t{mail}".format(uid=uid, uidNum=uidNum, cn=cn, hdir=homed, mail=mail)

def getLastGid():
  ''' Return the gidNumber of lastest added group '''
  retrieveAttributes = ['gidNumber']
  searchFilter = "(objectClass=posixGroup)"
  try:
    l = getldap()
    ldap_result_id = l.search_s(baseGrpDN, scope, searchFilter, retrieveAttributes)
  except ldap.LDAPError, e:
    logger.error(e)
    sys.exit(-1)

  max_gid = 0
  for dn,entry in ldap_result_id:
    if 'gidNumber' in entry:
      max_gid = int(entry['gidNumber'][0]) > max_gid and int(entry['gidNumber'][0]) or max_gid
  return max_gid

def getNextUid():
  ''' Return the uidNumber of the latest added user '''
  retrieveAttributes = ['uidNumber']
  searchFilter = "(objectClass=shadowAccount)"
  try:
    l = getldap()
    ldap_result_id = l.search_s(baseUserDN, scope, searchFilter, retrieveAttributes)
  except ldap.LDAPError, e:
    logger.error(e)
    sys.exit(-1)

  nextuid = 0
  uidnumbers = []
  for dn,entry in ldap_result_id:
    if 'uidNumber' in entry:
      uidnumbers.append(int(entry['uidNumber'][0]))
  uidnumbers.sort()
  if 0 >= len(uidnumbers): nextuid = minUid
  else: nextuid = uidnumbers[-1] + 1

  if nextuid < minUid: nextuid = minUid
  while nextuid in map(lambda a: a.pw_uid, pwd.getpwall()):
    nextuid +=1

#  i = 1
#  max_idx = len(uidnumbers) -1
#  while i <= max_idx and uidnumbers[i] - uidnumbers[i-1] <= 1:
#    i += 1
#  if i <= max_idx:
#    if uidnumbers[i] - uidnumbers[i-1] > 1:
#      nextuid = uidnumbers[i-1] + 1
  return nextuid

def getGid(cn):
  ''' Return the gidNumber of the given cn '''
  retrieveAttributes = ['gidNumber', 'cn']
  searchFilter = "(cn=" + cn + ")"
  try:
    l = getldap()
    ldap_result_id = l.search_s(baseGrpDN, scope, searchFilter, retrieveAttributes)
  except ldap.LDAPError, e:
    logger.error(e)
    sys.exit(-1)
  for dn,entry in ldap_result_id:
    if 'cn' in entry and str(entry['cn'][0]) == cn:
      return entry['gidNumber'][0]
  return 0

def addgrp(params):
  """ Add a new group to LDAP """
  lastGid = getLastGid()
  if lastGid < minGid:
    logger.error("The latest group ID found is smaller "
      "than 100, which might be because no group has been "
      "added before or because this scipt is "
      "misfunctionning, please contact the admin")
  group_ldif = {}
  group_ldif['objectClass'] = ['top', 'posixGroup']
  group_ldif['gidNumber'] = [str(1 + lastGid)]
  group_ldif['cn'] = [params.name]
  group_ldif['description'] = [params.desc]
  ldif = modlist.addModlist(group_ldif)
  dn="cn=" + params.name + "," + baseGrpDN
  try:
    l = getldap()
    l.simple_bind_s(admin_dn, getpass())
    l.add_s(dn, ldif)
  except ldap.ALREADY_EXISTS, ex:
    #print "Group {} already exists!"
    logger.exception(
      "Group {} already exists!".format(params.name))
  except ldap.LDAPError, e:
    logger.error(e)
    sys.exit(-1)

def checkmail(mail):
  ''' This only check the format of the email 
  Check that there is at most 1 @ and at least 1 '.'
  '''
  import re
  max_tries = 3
  while not re.match(r'[^@]+@[^@]+\.[^@]+', str(mail)) and max_tries > 0:
    mail = raw_input("Wrong email format, type again: ")
    max_tries -= 1
  if max_tries <= 0:
    return ""
  return mail

def checkattr(attribute, value, returnattr=[]):
  ''' Check if given attribute/value already exists '''
  attribute, value = str(attribute), str(value)
  retrieveAttributes = returnattr.append(attribute)
  searchFilter = "(" + attribute + "=" + value + ")"
  try:
    l = getldap()
    ldap_result_id = l.search_s(baseUserDN, scope, searchFilter, retrieveAttributes)
  except ldap.LDAPError, e:
    logger.error(e)
    sys.exit(-1)
  for dn,entry in ldap_result_id:
    if len(entry) > 1:
      return entry
    if attribute in entry and str(entry[attribute][0]) == value:
      return entry[attribute][0]
  return 0

def checkuid(uid):
  ''' Check uid number is availbale if not user can choose 
  another one. The maximum number of tries is 3'''
  uid = str(uid)
  max_tries = 3

  while max_tries > 0 and checkattr('uid', uid) != 0:
    uid = raw_input("UID : {} is already taken. Please choose a different one: ".format(uid))
    max_tries -= 1
  if max_tries <= 0:
    return ""
  return uid

def getmanager(department):
  ''' Retreive supervisor based on department and title
  a supervisor has 'supervisor' as title'''
  allusers = getallusers()
  for dn, entry in allusers:
    if entry['departmentNumber'][0] == department and entry['title'][0].lc == 'supervisor':
      return dn
  return ""

def _ldap_modify(dn, modlist):
  ''' Run modify operation from ldap module '''
  try:
    l = getldap()
    l.simple_bind_s(admin_dn, getpass())
    l.modify_s(str(dn), modlist)
  except ldap.LDAPError, e:
    logger.error(e)
    sys.exit(-1)

def _ldap_add(dn, modlist):
  ''' Run add operation from ldap module '''
  try:
    l = getldap()
    l.simple_bind_s(admin_dn, getpass())
    l.add_s(str(dn), modlist)
  except ldap.LDAPError, e:
    logger.error(e)
    sys.exit(-1)

def _ldap_delete(dn):
  ''' Run delete operation from ldap module '''
  try:
    l = getldap()
    l.simple_bind_s(admin_dn, getpass())
    l.delete_s(str(dn))
  except ldap.LDAPError, e:
    logger.error(e)
    sys.exit(-1)

def addusertogroup(params): #(uid, gid):
  ''' Add an existing user to an existing group '''
  gid = str(params.gid)
  if checkattr('gid', gid) <> 0:
    logger.error("Wrong group name")
    sys.exit()
  dn = "cn=" + gid + "," + baseGrpDN
  ldif = []
  if params.addall:
    # Get all users then add them all to ldif
    # if dry print LDIF, if not add to LDAP
    users = getallusers()
  else:
    users = []
    for uid in params.uid:
      users.append(("dn", checkattr('uid', uid, returnattr=['"uid"'])))

  for dn_entry, entries in users:
    uid = str(entries['uid'][0])
    ldif.append( (ldap.MOD_ADD, 'memberUid', uid) )
  if params.dry:
    logger.info("ADDING USERS TO GROUP {}:\n{}".format(gid, pp.pformat(ldif)))
  else:
    logger.info("ADDING USERS TO {}:\n{}".format(gid, pp.pformat(ldif)))
    _ldap_modify(dn, ldif)

def removeuserfromgroup(params):
  ''' Remove an existing user to an existing group '''
  uid, gid, email = params.uname, params.gname, params.email
  dn = "cn=" + gid + "," + baseGrpDN
  ldif = [(ldap.MOD_DELETE, 'memberUid', uid)]
  if params.dry:
    logger.info("Removing USER {} from GRP {}".format(uid, gid))
  else:
    logger.info("Removing USER {} from GRP {}".format(uid, gid))
    _ldap_modify(dn, ldif)

def deletegrp(params):
  ''' Remove a given cn from groups '''
  if params.dry:
    logger.info("Removing user {} from LDAP".format(params.name))
  else:
    logger.info("Removing user {} from LDAP".format(params.name))
    dn="cn=" + params.name + "," + baseGrpDN
    _ldap_delete(dn)

def deleteuser(params):
  ''' Remove a given cn from users and groups'''
  uid = params.name
  is_email = params.email
  search_filter = "(memberUid={})".format(uid)
  search_filter2 = "(uid={})".format(uid)
  res = _ldap_search(baseGrpDN, scope, search_filter, ['cn'])
  hom = _ldap_search(baseUserDN, scope, search_filter2, ['homeDirectory'])
  email = _ldap_search(baseUserDN, scope, search_filter2, ['mail'])
  is_home = len(hom)

  if is_home:
    hom = hom[0][1]['homeDirectory'][0]
  for dn, entry in res:
    grp = entry['cn'][0] # Removing user from groups
    if params.dry:
      logger.info("Preparing to remove USER {} from GRP {}".format(uid, grp))
    else:
      logger.info("Preparing to remove USER {} from GRP {}".format(uid, grp))
      params.uname = uid
      params.gname = grp
      params.email = False
      removeuserfromgroup(params)
  if params.dry:
    logger.info("Deleting user {} from LDAP".format(uid))
    logger.info("Moving home directory {}".format(hom))
  else:
    dn="uid=" + uid + "," + baseUserDN
    _ldap_delete(dn)
    #if is_home:
    #  _delete_home(hom)
    logger.info("Deleting user {} from LDAP".format(uid))
  if is_email:
    txt = mail_deleteUser.format(name=uid)
    email = email[0][1]['mail'][0]
    subject = "Deleting username {} from MIB".format(uid)
    sendmail(sender, email, subject, txt)


def adduser(args):
  ''' Create a new user in the LDAP '''
  uid = checkuid(raw_input("Choose a login name: "))
  if uid == "":
    logger.error("Wrong uid!")
    sys.exit(-1)

  print('')
  listgrp(args)
  gid = raw_input("GID: ")
  gidNumber = getGid( gid )
  if not gidNumber:
    logger.error("Error: Wrong group name!")
    sys.exit(-1)

  print('')
  givenname = raw_input("First name: ")
  lastname = raw_input("Last name: ")

  print('')
  mail = checkmail(raw_input("Type your email: "))
  if mail == "":
    logger.error("Wrong email!")
    sys.exit(-1)

  print('')
  title = raw_input("What is your position? (PhD, staff...) ")

  print('')
  print(departments)
  departmentNumber = raw_input("Which department do you work for? ")
  if departmentNumber not in departments:
    logger.warn("if it's a new department please contact admin")
    logger.error("department should be one of the following {}".format(', '.join(departments)))
    sys.exit()

  pasw = gen_password()
  with tempfile.NamedTemporaryFile(delete=False) as fp:
    fp.write(pasw)
    tmpf = fp.name
  process = subprocess.Popen(['slappasswd', '-T', tmpf], stdout=subprocess.PIPE)
  userPassword, err = process.communicate()
  userPassword = userPassword.strip()
  unlink(tmpf)
  if process.returncode != 0:
    logger.error(err)
    logger.error("Password could not be processed")
    sys.exit(-1)

  uidNumber = getNextUid()
  cnn = " ".join([givenname, lastname])

  homed = path.join(homedir, uid)
  if args.mkhome:
    shell = '/bin/bash'
  else:
    shell = '/bin/false'

  #ppolicyDN = 'cn=passwordNewUser,ou=Policies,dc=wurnet,dc=nl'
  ppolicyDN = 'cn=default,ou=Policies,dc=wurnet,dc=nl'
  if gid <> 'users':
    ppolicyDN = 'cn=guest,ou=policies,dc=wurnet,dc=nl'
  dn = "uid=" + uid + "," + baseUserDN
  group_ldif = {}
  group_ldif['objectClass'] = ['top', 'inetOrgPerson', 'posixAccount', 'shadowAccount']
  group_ldif['cn'] = [uid, cnn]
  group_ldif['uid'] = [str(uid)]
  group_ldif['givenName'] = [givenname]
  group_ldif['sn'] = [lastname]
  group_ldif['mail'] = [mail]
  group_ldif['uidNumber'] = [str(uidNumber)]
  group_ldif['gidNumber'] = [str(gidNumber)]
  group_ldif['homeDirectory'] = [homed]
  group_ldif['pwdPolicySubentry'] = [ppolicyDN]
  group_ldif['departmentNumber'] = [departmentNumber]
  group_ldif['title'] = [title]
  group_ldif['userPassword'] = [userPassword]
  group_ldif['loginShell'] = [shell]
  group_ldif['ou'] = [departmentNumber]

  ldif = modlist.addModlist(group_ldif)

  mail_new_user = mail_body.format(hostname=host, name=givenname, link='http://platecarpus.wur.nl/wiki.potato/index', pwd=pasw)
  sub = 'Your new account on MIB infrastructure'

  if not args.dry:
    _ldap_add(dn, ldif)
    args.uid = [uid]
    args.gid = gid
    #args.email = False
    args.addall = False
    addusertogroup(args)
    if args.mkhome:
      make_home(homed, uidNumber, gidNumber, mode=0755)
    if args.email:
      sendmail(sender, mail, sub, mail_new_user)
  else:
    logger.debug("DN: {}\nLDIF:{}".format(dn, pp.pformat(ldif)))
    if args.mkhome:
      logger.debug("Creating home folderin {} for uid/gid {}/{}".format(homed,uid,gid))
    if args.email:
      sendmail(sender, mail, sub, mail_new_user)
  logger.info("Passwd: {}".format(pasw))

if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='Manages LDAP users and groups')
  subparsers = parser.add_subparsers(title='New users',
                           description='New users subcommands',
                           help='additional help')
  # Dry run? Does not create anything, just print INFO or debug info
  # TODO Run LDIF file
  # TODO Send email notification

  parser.add_argument('--dry', action="store_true", dest="dry",
                    help='No modifications will be made to the LDAP')

  userparser = subparsers.add_parser('newuser', help='Create a new user in LDAP')
  userparser.add_argument('--no-createhome', action="store_false", dest="mkhome",
                    help='If true a home will be created for the new user and shell loin will be set to bash')
  userparser.add_argument('--email', action="store_true", dest="email",
                    help='Send email notification')

  dltusrparser = subparsers.add_parser('deleteUser', help='Delete a user from LDAP')
  dltusrparser.add_argument('--email', action="store_true", dest="email",
                    help='Send email notification')
  dltusrparser.add_argument('--name', required=True, default=None,
                    help='Name of the user to remove from LDAP')

  dltusrfromgrpparser = subparsers.add_parser('removeUserFromGroup', 
                    help='Remove a user from a group')
  dltusrfromgrpparser.add_argument('--email', action="store_true", dest="email",
                    help='Send email notification')
  dltusrfromgrpparser.add_argument('--uname', required=True, default=None,
                    help='Name of the user to remove from GROUP')
  dltusrfromgrpparser.add_argument('--gname', required=True, default=None,
                    help='Name of the group')

  grpparser = subparsers.add_parser('addGroup', 
                    help='Create a new group in LDAP')
  grpparser.add_argument('--name', required=True, default=None,
                    help='A name for the new group')
  grpparser.add_argument('--desc', required=True, default=None,
                    help='Describe the purpose of this group')

  dltgrpparser = subparsers.add_parser('deleteGroup', 
                    help='Delete a group from LDAP')
  dltgrpparser.add_argument('--name', required=True, default=None, 
                    help="CN of the group to delete")

  addusertogrp = subparsers.add_parser('addUserToGroup', 
                    help='Add a user to a group in LDAP')
  addusertogrp.add_argument('--email', action="store_true", dest="email",
                    help='Send email notification')
  addusertogrp.add_argument('--all', action="store_true", dest="addall",
                    help='Add all users to group')
  addusertogrp.add_argument('--uid', required=True,
                    default=None, nargs='+',
                    help='UID to add to the group')
  addusertogrp.add_argument('--gid', required=True, default=None,
                    help='GID of the group to add the UID to')


  listgrpparser = subparsers.add_parser('listgroup', 
                    help='List all groups present in LDAP')
  listusrparser = subparsers.add_parser('listusers', 
                    help='List all users present in LDAP')

# The following parses are used for testing purpose
  parseLastGid = subparsers.add_parser('getLastGid', 
                    help='Print last Gid create in stdout')
  parseNextUid = subparsers.add_parser('getNextUid', 
                    help='Print next UID to be created in stdout')

  userparser.set_defaults(func=adduser, mkhome=True, email=False)
  dltusrparser.set_defaults(func=deleteuser, email=False)

  dltusrfromgrpparser.set_defaults(func=removeuserfromgroup, email=False)

  grpparser.set_defaults(func=addgrp)
  dltgrpparser.set_defaults(func=deletegrp)
  addusertogrp.set_defaults(func=addusertogroup, email=False, addall=False)

  listgrpparser.set_defaults(func=listgrp)
  listusrparser.set_defaults(func=listusers)

  p = lambda text: logger.info( getLastGid() )
  g = lambda text: logger.info( getNextUid() )
  parseLastGid.set_defaults(func=p)
  parseNextUid.set_defaults(func=g)

  parser.set_defaults(dry=False)

  param = parser.parse_args()
  if param.dry:
    logger.info("Dry run activated, no modifications will be made to the LDAP")
  param.func(param)

