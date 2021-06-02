## Moving towards devops approach to manage AWS networking resources
The repository contains the code that helps managing networking resources (for example - security groups) via pipeline. Assumption is you are using a security group with tag key set to ```pipeline-managed``` and value set to ```true``` in your AWS environment. You can manage any existing/new security groups as long as the security group has this tag. If the VPC doesn't have any security group with tag ```pipeline-managed:true```, then pipeline will create a new security group within each VPC with Name ```Pipeline_Managed_SG``` that can be associated with any of the resources as appropriate. 

The config parameters for the security groups are passed from a csv file with the following format :

```
direction;ipv4cidrs;ipv6cidrs;from_port;to_port;protocol;security_groups_references;prefix_list;
```

The below snippet will create a security group rule that allows IPv4 CIDRs of 172.16.0.0/16 and 10.0.0.0/8 on TCP port 8060.
```
ingress;172.16.0.0/16,10.0.0.0/8;;8060;8060;tcp;;
```

## Folder structure
The folder structure for any networking resources managed via this pipeline follows the convention as below:

- ResourceName
  - validation-checks-template
  - accounts-dev.txt
  - accounts-prod.txt
  - cfn-guard.rules
  - config folder
      - cloudformation-resource-template
      - code folder
        - code.py
        - resource_config.csv
      
*validation-checks-template*: These templates contain various tools and tests that needs to be performed to validate your network infrastructure and ensure the proposed changes do not cause any downtime. Templates for tools like VPC reachability analyzer, debugging tool for network connectivity, or Transit gateway Network Manager Route Analyzer can be created here.

*accounts-dev.txt*: The file consists of the IDs of OUs for dev environment. An example content of the file: 
```
[ “ou-abcd-pqrsx1z” ]
```

*accounts-prod.txt*: The file consists of the IDs of OUs for production environment. The format of the file is same as the dev :
```
[ “ou-abcd-pqrsx2z” ]
```

*cloudformation-resource-template*: This is the template for creating or managing the networking resource that needs to be deployed in the accounts and regions by Cloudformation.

*cfn-guard.rules*: This file contains various Checks AWS CloudFormation templates for policy compliance using a simple, policy-as-code, declarative syntax.

*code.py* : The file contains the code written in python or any other language to perform the necessary api calls required for managing the resource.

*resource_config.csv*: The csv file contains expected rules for the resource that requires to be modified or created.


## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

