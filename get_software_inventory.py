import boto3 
from csv import DictWriter


ssm = boto3.client('ssm')
ec2 = boto3.resource('ec2')
s3 = boto3.client('s3')

# Get instance-Ids from Prod VPC info list
response = ec2.instances.filter(Filters=[{'Name': 'vpc-id', 'Values': ['vpc-099b436e86f46bef3']}])
instances = []

for i in response:
    instances.append(i.id) 

# Get software on instances using ssm agent
software_info = []
instanceIds = []
for i in instances:
    response = ssm.list_inventory_entries(InstanceId = i, TypeName = "AWS:Application")

    for entry in response['Entries']:
        software_inventory = {}
        software_inventory['InstanceId'] = i
        software_inventory['SoftwareName'] = entry['Name']
        software_inventory['SoftwareVersion'] = entry['Version']
        publisher = entry['Publisher']
        software_inventory['Publisher'] = publisher.replace(',','')

        try:   
            software_inventory['InstallDate'] = entry['InstalledTime']
        except Exception:
            pass       
        software_info.append(software_inventory)


with open('InstanceSoftwareInfo.csv','w', newline='') as outfile:
    writer = DictWriter(outfile, ('InstanceId','SoftwareName', 'SoftwareVersion', 'Publisher', 'InstallDate'))
    writer.writeheader()
    writer.writerows(software_info)
