import boto3
from datetime import datetime, timezone
import csv
from csv import DictWriter
from time import sleep
 
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
if resp1['State'] == 'COMPLETE':
    response = client.get_credential_report()
    reportText=response['Content'].decode("utf-8").splitlines()
    reader = csv.DictReader(reportText, delimiter=',')
    credential_report = []
    for row in reader:
        credential_report.append(row)
else:
    sleep(2)
    response = client.get_credential_report()
    reportText=response['Content'].decode("utf-8").splitlines()
    reader = csv.DictReader(reportText, delimiter=',')
    credential_report = []
    for row in reader:
        credential_report.append(row)


#Populate lists from credential report dictionary
for data in credential_report:
    lastPassDate = data['password_last_changed']
    passwordAge.append(lastPassDate)

    mfaEnabled = data['mfa_active']
    mfaStatus.append(mfaEnabled)

    lastLogin = data['password_last_used']
    userActivity.append(lastLogin)

    keyAge = data['access_key_1_last_rotated']
    accessKeyAge.append(keyAge)        

#Populate lists with number of days since credentials have changed. Using 91 for invalid entries in order to disable login profile. 
for i in passwordAge:
    if i == 'not_supported' or i == 'N/A':
        passAge = 91
    else:
        i = i[:-6]
        date_time_obj = datetime.strptime(i, '%Y-%m-%dT%H:%M:%S')
        age_of_password = datetime.now() - date_time_obj
        passAge = age_of_password.days
    passDays.append(passAge)

for i in userActivity:
    if i == 'no_information' or i == 'N/A':
        loginAge = 91
    else:
        i = i[:-6]
        date_time_obj = datetime.strptime(i, '%Y-%m-%dT%H:%M:%S')
        age_of_login =  datetime.now() - date_time_obj
        loginAge = age_of_login.days
    loginDays.append(loginAge)

for i in accessKeyAge:
    if i == 'N/A':
        keyDays = 91
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

#Check age of credentials and send alert to SNS topic if Access Key age exceeds 90 days.
for userData in userInformation:
    if userData['Access_Key_Age'] > 90:                   

# Send notification to SNS topic
        sns = boto3.client('sns')
        response = sns.publish(
        TopicArn='arn:aws:sns:us-east-1:001395329297:NotifyMe',    
        Message="The Access Key for user " + userData['UserName'] + " is older than 90 days. Please rotate the users access key and notify them of the change."
        )
        print(response)
       






    
        







   

        
