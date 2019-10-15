import boto3
from datetime import datetime, timezone
import csv
from csv import DictWriter

client = boto3.client('iam')
response = client.list_users()

#Create lists to populate with information from credential report
userInformation = []
passwordAge = []
passDays = []
mfaStatus = []
userActivity = []
loginDays = []
accessKeyAge = []
keyDaysAge = []
credential_info = []

#Generate and pull down IAM credential report into .csv file for parsing
resp1 = client.generate_credential_report()
response = client.get_credential_report()
credential_report = []
reportText=response['Content'].decode("utf-8").splitlines()
reader = csv.DictReader(reportText, delimiter=',')
for row in reader:
    credential_report.append(row)


with open('credential_report.csv','w', newline='') as outfile:
    writer = DictWriter(outfile, ('user','arn', 'user_creation_time', 'password_enabled', 'password_last_used', 'password_last_changed', 'password_next_rotation', 'mfa_active', \
        'access_key_1_active', 'access_key_1_last_rotated', 'access_key_1_last_used_date', 'access_key_1_last_used_region', 'access_key_1_last_used_service', \
        'access_key_2_active', 'access_key_2_last_rotated', 'access_key_2_last_used_date', 'access_key_2_last_used_region', 'access_key_2_last_used_service', \
        'cert_1_active', 'cert_1_last_rotated', 'cert_2_active', 'cert_2_last_rotated'))
    writer.writeheader()
    writer.writerows(credential_report)


with open('credential_report.csv') as file:
    reader = csv.DictReader(file)
    for row in reader:
        lastPassDate = row['password_last_changed']
        passwordAge.append(lastPassDate)

with open('credential_report.csv') as file:
    reader = csv.DictReader(file)
    for row in reader:
        mfaEnabled = row['mfa_active']
        mfaStatus.append(mfaEnabled)

with open('credential_report.csv') as file:
    reader = csv.DictReader(file)
    for row in reader:
        lastLogin = row['password_last_used']
        userActivity.append(lastLogin)

with open('credential_report.csv') as file:
    reader = csv.DictReader(file)
    for row in reader:
        keyAge = row['access_key_1_last_rotated']
        accessKeyAge.append(keyAge)

#Populate lists with number of days since credentials have changed. 
for i in passwordAge:
    if i == 'not_supported' or i == 'N/A':
        passAge = 'No Password Assigned'
    else:
        i = i[:-6]
        date_time_obj = datetime.strptime(i, '%Y-%m-%dT%H:%M:%S')
        age_of_password = datetime.now() - date_time_obj
        passAge = age_of_password.days
    passDays.append(passAge)

for i in userActivity:
    if i == 'no_information' or i == 'N/A':
        loginAge = 'No Password Assigned'
    else:
        i = i[:-6]
        date_time_obj = datetime.strptime(i, '%Y-%m-%dT%H:%M:%S')
        age_of_login =  datetime.now() - date_time_obj
        loginAge = age_of_login.days
    loginDays.append(loginAge)

for i in accessKeyAge:
    if i == 'N/A':
        keyDays = 'No Keys Assigned'
    else:
        i = i[:-6]
        date_time_obj = datetime.strptime(i, '%Y-%m-%dT%H:%M:%S')
        age_of_key = datetime.now() - date_time_obj
        keyDays = age_of_key.days
    keyDaysAge.append(keyDays)

#Remove default user information from lists
del loginDays[0]
del passDays[0]
del mfaStatus[0]
del keyDaysAge[0]

#Remove unneeded information from IAM Credential report
user_client = boto3.client('iam')
userResponse = user_client.list_users()

for userInfo in userResponse['Users']:
    userName = userInfo['UserName']
    userInfo.pop('Path')
    userInfo.pop('Arn')
    userInfo.pop('CreateDate')
    if 'PasswordLastUsed' in userInfo:
        userInfo.pop('PasswordLastUsed')
       
#Create key/value pairs for userInfo dictionary to be sent to csv writer.         
    userInfo['Access_Key_Age'] = keyDaysAge[0]
    userInfo['Password_Age'] = passDays[0]
    userInfo['User_Last_Login'] = loginDays[0]
    userInfo['MFA_Active'] = mfaStatus[0]

    del passDays[0]
    del loginDays[0]
    del mfaStatus[0]
    del keyDaysAge[0]    
    userInformation.append(userInfo)


#Check age of credentials and disable user login if credentials are not up to date.
for userData in userInformation:
    if int(userData['Access_Key_Age']) > 90 or \
        int(userData['Password_Age']) > 90 or \
        userData['User_Last_Login'] > 90 or\
        userData['MFA_Active'] == 'false':
        try:
            deleteLogin = client.delete_login_profile(UserName=userName)
        except Exception:
            pass





    
        







   

        
