# How-To
This is a guide to install N7 project on AWS plateform

## STEP 1 : Create the Blockchain Network
### 1. Open the [Managed Blockchain console](https://us-east-1.console.aws.amazon.com/managedblockchain/)
### 2. Choose Create private network
#### 2.a Parameters
	Framework version : 2.2
	Network edition : Starter
	Network Name : N7
	Description : Amazon Managed Blockchain. Creates network with members and peer nodes
	Voting policy : Greater than 50%
#### 2.b Choose Next
#### 2.c Create Member
	Member Name
	Description
	Admin username
	Admin password
#### 2.d Choose Next and then Choose Create network and member
### 3. Check the network is available

## STEP 2 : Create and Configure the Interface VPC Endpoint
### 1. Open the Managed Blockchain console
### 2. Choose N7 Network
### 3. Choose Create VPC endpoint
### 4. Choose a VPC
### 5. Choose subnet
### 6. Choose security groups (select the same security group that the framework client EC2 instance is associated with)
### 7. Choose Create

## STEP 3 : Create a Peer Node
### 1. Open the Managed Blockchain console
### 2. Choose N7 Network
### 3. Select a Member
### 4. Choose Create peer node
#### 4.a Parameters
	Blockchain instance type : bc.t3.medium
	State DB Configuration : CouchDB
	Availability Zone : us-east-1a
	Logging configuration
#### 4.b Choose create peer node

## STEP 4 : Set up a Fabric client node
### 1. Open Cloud9 IDE : 
### 2. mkdir config
### 3. copy fabric-client-node.yaml and vpc-client-node.sh
#### fabric-client-node.yaml
```yaml
# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
 
AWSTemplateFormatVersion:                         '2010-09-09'
Description:                                      >
  This template creates a Fabric client node, which will run the Fabric CLI and
  interact with a Fabric network. The client node is an EC2 instance, and will be created in
  its own VPC. Private VPC Endpoints will also be created, pointing to the Fabric service.
Parameters:
  KeyName:
    Type:                                         AWS::EC2::KeyPair::KeyName
    Description:                                  Name of an existing EC2 key pair to enable SSH access to the EC2 instance
  BlockchainVpcEndpointServiceName:
    Type:                                         String
    Description:                                  Name of the Blockchain VPC Endpoint. Obtained from running 'aws managedblockchain get-network'
 
Resources:
  BlockchainWorkshopRootRole:
    Type:                                         "AWS::IAM::Role"
    Properties:
      AssumeRolePolicyDocument:
        Version:                                  "2012-10-17"
        Statement:
          -
            Effect:                               "Allow"
            Principal:
              Service:
                -                                 "ec2.amazonaws.com"
            Action:
              -                                   "sts:AssumeRole"
      Path:                                       "/"
      MaxSessionDuration:                         10800
      Policies:
        -
          PolicyName:                             "root"
          PolicyDocument:
            Version:                              "2012-10-17"
            Statement:
              -
                Effect:                           "Allow"
                Action:                           "*"
                Resource:                         "*"
 
  BlockchainWorkshopRootInstanceProfile:
    Type:                                         "AWS::IAM::InstanceProfile"
    Properties:
      Path:                                       "/"
      Roles:
        -
          Ref:                                    "BlockchainWorkshopRootRole"
 
  BlockchainWorkshopVPC:
    Type:                                         AWS::EC2::VPC
    Properties:
      CidrBlock:                                  10.0.0.0/16
      EnableDnsSupport:                           True
      EnableDnsHostnames:                         True
      InstanceTenancy:                            default
      Tags:
        - Key:                                    BlockchainWorkshop
          Value:                                  VPC
 
  BlockchainWorkshopPublicSubnet:
    Type:                                         AWS::EC2::Subnet
    Properties:
        VpcId:                                    !Ref BlockchainWorkshopVPC
        MapPublicIpOnLaunch:                      false
        CidrBlock:                                10.0.0.0/18
        Tags:
        - Key:                                    BlockchainWorkshop
          Value:                                  PublicSubnet
 
  BlockchainWorkshopSecurityGroup:
        Type:                                     AWS::EC2::SecurityGroup
        Properties:
          GroupDescription:                       Fabric Client Node Security Group
          VpcId:                                  !Ref BlockchainWorkshopVPC
          SecurityGroupIngress:
          - IpProtocol:                           tcp
            CidrIp:                               0.0.0.0/0
            FromPort:                             22
            ToPort:                               22
          - IpProtocol:                           tcp
            CidrIp:                               0.0.0.0/0
            FromPort:                             0
            ToPort:                               65535
          Tags:
          - Key:                                  BlockchainWorkshop
            Value:                                FabricClientNodeSecurityGroup
 
  BlockchainWorkshopSecurityGroupIngress:
    Type:                                         AWS::EC2::SecurityGroupIngress
    Properties:
      IpProtocol:                                 -1
      FromPort:                                   -1
      GroupId:                                    !GetAtt BlockchainWorkshopSecurityGroup.GroupId
      ToPort:                                     -1
      SourceSecurityGroupId:                      !GetAtt BlockchainWorkshopSecurityGroup.GroupId
      Tags:
      - Key:                                      BlockchainWorkshop
        Value:                                    BaseSecurityGroupIngress
 
  BlockchainWorkshopInternetGateway:
    Type:                                         "AWS::EC2::InternetGateway"
    Properties:
      Tags:
      - Key:                                      BlockchainWorkshop
        Value:                                    InternetGateway
 
  BlockchainWorkshopAttachGateway:
    Type:                                         AWS::EC2::VPCGatewayAttachment
    Properties:
       VpcId:                                     !Ref BlockchainWorkshopVPC
       InternetGatewayId:                         !Ref BlockchainWorkshopInternetGateway
 
  BlockchainWorkshopRouteTable:
    Type:                                         AWS::EC2::RouteTable
    Properties:
        VpcId:                                    !Ref BlockchainWorkshopVPC
        Tags:
          - Key:                                  BlockchainWorkshop
            Value:                                RouteTable
 
  BlockchainWorkshopRoute:
    Type:                                         AWS::EC2::Route
    Properties:
        RouteTableId:                             !Ref BlockchainWorkshopRouteTable
        DestinationCidrBlock:                     0.0.0.0/0
        GatewayId:                                !Ref BlockchainWorkshopInternetGateway
 
  BlockchainWorkshopSubnetRouteTableAssociation:
    Type:                                         AWS::EC2::SubnetRouteTableAssociation
    Properties:
        SubnetId:                                 !Ref BlockchainWorkshopPublicSubnet
        RouteTableId:                             !Ref BlockchainWorkshopRouteTable
 
  BlockchainWorkshopVPCEndpoint:
    Type:                                         AWS::EC2::VPCEndpoint
    Properties:
        VpcId:                                    !Ref BlockchainWorkshopVPC
        PrivateDnsEnabled:                        True
        ServiceName:                              !Ref BlockchainVpcEndpointServiceName
        VpcEndpointType:                          Interface
        SubnetIds:                                [!Ref BlockchainWorkshopPublicSubnet]
        SecurityGroupIds:                         [!Ref BlockchainWorkshopSecurityGroup]
 
  BlockchainWorkshopEC2:
    Type:                                         AWS::EC2::Instance
    Properties:
        KeyName:                                  !Ref KeyName
        ImageId:                                  'ami-0434d5878c6ad6d4c'
        InstanceType:                             't2.medium'
        IamInstanceProfile:                       !Ref BlockchainWorkshopRootInstanceProfile
        NetworkInterfaces:
        - AssociatePublicIpAddress:               true
          DeviceIndex:                            0
          GroupSet:                               [!Ref BlockchainWorkshopSecurityGroup]
          SubnetId:                               !Ref BlockchainWorkshopPublicSubnet
        Tags:
          - Key:                                  Name
            Value:                                ManagedBlockchainWorkshopEC2ClientInstance
 
  BlockchainWorkshopELB:
    Type:                                         AWS::ElasticLoadBalancing::LoadBalancer
    Properties:
      SecurityGroups:                             [!Ref BlockchainWorkshopSecurityGroup]
      Subnets:                                    [!Ref BlockchainWorkshopPublicSubnet]
      Instances:
        - !Ref                                    BlockchainWorkshopEC2
      Listeners:
        - LoadBalancerPort:                       '80'
          InstancePort:                           '3000'
          Protocol:                               TCP
      HealthCheck:
        Target:                                   HTTP:3000/health
        HealthyThreshold:                         '3'
        UnhealthyThreshold:                       '5'
        Interval:                                 '10'
        Timeout:                                  '5'
      Tags:
        - Key:                                    Name
          Value:                                  BlockchainWorkshopELB
 
Outputs:
  VPCID:
    Description:                                  VPC ID
    Value:
      !Ref                                        BlockchainWorkshopVPC
  PublicSubnetID:
    Description:                                  Public Subnet ID
    Value:
      !Ref                                        BlockchainWorkshopPublicSubnet
  SecurityGroupID:
    Description:                                  Security Group ID
    Value:
      !GetAtt                                     BlockchainWorkshopSecurityGroup.GroupId
  EC2URL:
    Description:                                  Public DNS of the EC2 Fabric client node instance
    Value:
      !GetAtt                                     BlockchainWorkshopEC2.PublicDnsName
  EC2ID:
    Description:                                  Instance ID of the EC2 Fabric client node instance
    Value:
      !Ref                                        BlockchainWorkshopEC2
  ELBDNS:
    Description:                                  Public DNS of the ELB
    Value:
      !GetAtt                                     BlockchainWorkshopELB.DNSName
  BlockchainVPCEndpoint:
    Description:                                  VPC Endpoint ID
    Value:
      !Ref                                        BlockchainWorkshopVPCEndpoint
```
#### vpc-client-node.sh
```bash
#!/bin/bash

# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# 
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# or in the "license" file accompanying this file. This file is distributed 
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either 
# express or implied. See the License for the specific language governing 
# permissions and limitations under the License.

echo Creating VPC - TODO. Create the VPC, subnets, security group, EC2 client node, VPC endpoint
echo Create a keypair


REGION=us-east-1
STACKNAME=$(aws cloudformation describe-stacks --region $REGION --query "Stacks[?Description==null] | [0].StackName" --output text)
NETWORKNAME=N7
NETWORKID=$(aws managedblockchain list-networks --name $NETWORKNAME --region $REGION --query 'Networks[0].Id' --output text)
VPCENDPOINTSERVICENAME=$(aws managedblockchain get-network --region $REGION --network-id $NETWORKID --query 'Network.VpcEndpointServiceName' --output text)

echo Searching for existing keypair named $NETWORKNAME-keypair
keyname=$(aws ec2 describe-key-pairs --key-names $NETWORKNAME-keypair --region $REGION --query 'KeyPairs[0].KeyName' --output text)
if  [[ "$keyname" == "$NETWORKNAME-keypair" ]]; then
    echo Keypair $NETWORKNAME-keypair already exists. Please choose another keypair name by editing this script
    exit 1
fi
 
echo Creating a keypair named $NETWORKNAME-keypair. The .pem file will be in your $HOME directory
aws ec2 create-key-pair --key-name $NETWORKNAME-keypair --region $REGION --query 'KeyMaterial' --output text > ~/$NETWORKNAME-keypair.pem
if [ $? -gt 0 ]; then
    echo Keypair $NETWORKNAME-keypair could not be created
    exit $?
fi

chmod 400 ~/$NETWORKNAME-keypair.pem
sleep 10

echo Create the VPC, the Fabric client node and the VPC endpoints
aws cloudformation deploy --stack-name $NETWORKNAME-fabric-client-node --template-file fabric-client-node.yaml \
--capabilities CAPABILITY_NAMED_IAM \
--parameter-overrides KeyName=$NETWORKNAME-keypair BlockchainVpcEndpointServiceName=$VPCENDPOINTSERVICENAME \
--region $REGION
```
### 4. ./vpc-client-node.sh

## STEP 5 : Enroll admin user
### 1. Open [EC2 Management console](https://us-east-1.console.aws.amazon.com/ec2/)
### 2. Choose Network&Security and then Choose Key Pairs
#### 2.a Check keys
### 3. Choose Instances and Choose ManagedBlockchainWorkshopEC2ClientInstance
### 4. Copy the public IPv4 DNS
### 5. Open Cloud9 IDE
```bash
cd ~
ssh ec2-user@<DNS of EC2 instance> -i "N7-keypair.pem"
```
### 6. copy fabric-export.sh (ex : 1 organisation)
```bash
#!/bin/bash

# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# 
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# or in the "license" file accompanying this file. This file is distributed 
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either 
# express or implied. See the License for the specific language governing 
# permissions and limitations under the License.

echo Updating AWS CLI to the latest version
sudo pip install awscli --upgrade
cd ~

export REGION=us-east-1
export STACKNAME=aws-cloud9-N7-0953e2fa4e9e474d9f30fd4d4898660c
export NETWORKNAME=N7
export CONAME=ContentOwner
export NETWORKVERSION=2.2
export COADMINUSER=COAdmin
export COADMINPWD=cooooowxhwxhn\&Dm1n
export NETWORKID=n-WRKIRG52YFDBPC22V7RDZI4ZIQ
export COID=m-T4PX3Z7JWRBUVOSBFFVU2FLBUI

VpcEndpointServiceName=$(aws managedblockchain get-network --region $REGION --network-id $NETWORKID --query 'Network.VpcEndpointServiceName' --output text)
OrderingServiceEndpoint=$(aws managedblockchain get-network --region $REGION --network-id $NETWORKID --query 'Network.FrameworkAttributes.Fabric.OrderingServiceEndpoint' --output text)
COCaEndpoint=$(aws managedblockchain get-member --region $REGION --network-id $NETWORKID --member-id $COID --query 'Member.FrameworkAttributes.Fabric.CaEndpoint' --output text)
CONodeID=$(aws managedblockchain list-nodes --region $REGION --network-id $NETWORKID --member-id $COID --query 'Nodes[?Status==`AVAILABLE`] | [0].Id' --output text)
COPeerEndpoint=$(aws managedblockchain get-node --region $REGION --network-id $NETWORKID --member-id $COID --node-id $CONodeID --query 'Node.FrameworkAttributes.Fabric.PeerEndpoint' --output text)
COPeerEventEndpoint=$(aws managedblockchain get-node --region $REGION --network-id $NETWORKID --member-id $COID --node-id $CONodeID --query 'Node.FrameworkAttributes.Fabric.PeerEventEndpoint' --output text)
export ORDERINGSERVICEENDPOINT=$OrderingServiceEndpoint
export ORDERINGSERVICEENDPOINTNOPORT=${ORDERINGSERVICEENDPOINT::-6}
export VPCENDPOINTSERVICENAME=$VpcEndpointServiceName
export COCASERVICEENDPOINT=$COCaEndpoint
export COPEERNODEID=$CONodeID
export COPEERSERVICEENDPOINT=$COPeerEndpoint
export COPEERSERVICEENDPOINTNOPORT=${COPEERSERVICEENDPOINT::-6}
export COPEEREVENTENDPOINT=$COPeerEventEndpoint

echo Useful information stored in EXPORT variables
echo REGION: $REGION
echo NETWORKNAME: $NETWORKNAME
echo NETWORKVERSION: $NETWORKVERSION
echo COADMINUSER: $COADMINUSER
echo COADMINPWD: $COADMINPWD
echo CONAME: $CONAME
echo NETWORKID: $NETWORKID
echo COID: $COID
echo ORDERINGSERVICEENDPOINT: $ORDERINGSERVICEENDPOINT
echo ORDERINGSERVICEENDPOINTNOPORT: $ORDERINGSERVICEENDPOINTNOPORT
echo VPCENDPOINTSERVICENAME: $VPCENDPOINTSERVICENAME
echo COCASERVICEENDPOINT: $COCASERVICEENDPOINT
echo COPEERNODEID: $COPEERNODEID
echo COPEERSERVICEENDPOINT: $COPEERSERVICEENDPOINT
echo COPEERSERVICEENDPOINTNOPORT: $COPEERSERVICEENDPOINTNOPORT
echo COPEEREVENTENDPOINT: $COPEEREVENTENDPOINT

# Exports to be exported before executing any Fabric 'peer' commands via the CLI
cat << EOF > peer-exports.sh
export COMSP_PATH=/opt/home/coadmin-msp
export COMSP=$COID
export ORDERER=$ORDERINGSERVICEENDPOINT
export COPEER=$COPEERSERVICEENDPOINT
export CHANNEL=n7ch1
export CAFILE=/opt/home/managedblockchain-tls-chain.pem
export CHAINCODENAME=n7code
export CHAINCODEVERSION=v0
export CHAINCODESEQUENCE=1
export CHAINCODELABEL=n7_0
export CHAINCODEDIR=/opt/home/ec2-user/N7/n7code/java
EOF
```
### 7. Export
```bash
source fabric-exports.sh
source peer-exports.sh
```
### 8. Get the latet version of the Managed Blockchain PEM file
```bash
aws s3 cp s3://us-east-1.managedblockchain/etc/managedblockchain-tls-chain.pem /home/ec2-user/managedblockchain-tls-chain.pem
```
### 9. enroll admin identity with the Fabric CA
```bash
export PATH=$PATH:/home/ec2-user/go/src/github.com/hyperledger/fabric-ca/bin
cd~
fabric-ca-client enroll -u https://$ADMINUSER:$ADMINPWD@CASERVICEENDPOINT --tls.certfiles /home/ec2-user/managedblockchain-tls-chain.pem -M /home/ec2-user/admin-msp
```
### 10. Coping useful files
```bash
mkdir -p /home/ec2-user/admin-msp/admincerts
cp ~/admin-msp/signcerts/* ~/admin-msp/admincerts/
```

## STEP 6 : Install packages
### 1. Install JAVA 11 
```bash
sudo yum install java-11-amazon-corretto
sudo alternatives --config java
java --version
```
### 2. Install Gradle
```bash
sudo mkdir /opt/gradle
wget -c https://services.gradle.org/distributions/gradle-7.6-bin.zip
sudo unzip -d /opt/gradle gradle-7.6-bin.zip
export PATH=$PATH:/opt/gradle/gradle-7.6/bin
```

## STEP 7 : Create a Hyperledger Fabric Channel
### 1. Copy configtx.yaml (ex : 1 organisation)
```yaml
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

---
################################################################################
#
#   Section: Organizations
#
#   - This section defines the different organizational identities which will
#   be referenced later in the configuration.
#
################################################################################
Organizations:

    - &CO
        # DefaultOrg defines the organization which is used in the sampleconfig
        # of the fabric.git development environment
        Name: m-T4PX3Z7JWRBUVOSBFFVU2FLBUI

        # ID to load the MSP definition as
        ID: m-T4PX3Z7JWRBUVOSBFFVU2FLBUI

        MSPDir: /opt/home/coadmin-msp

        AnchorPeers:
            # AnchorPeers defines the location of peers which can be used
            # for cross org gossip communication.  Note, this value is only
            # encoded in the genesis block in the Application section context
            - Host:
              Port:

        # SkipAsForeign can be set to true for org definitions which are to be
        # inherited from the orderer system channel during channel creation.  This
        # is especially useful when an admin of a single org without access to the
        # MSP directories of the other orgs wishes to create a channel.  Note
        # this property must always be set to false for orgs included in block
        # creation.
        SkipAsForeign: false
        Policies: &COPolicies
            Readers:
                Type: Signature
                Rule: "OR('CO.member')"
                # If your MSP is configured with the new NodeOUs, you might
                # want to use a more specific rule like the following:
                # Rule: "OR('CO.admin', 'CO.peer', 'CO.client')"
            Writers:
                Type: Signature
                Rule: "OR('CO.member')"
                # If your MSP is configured with the new NodeOUs, you might
                # want to use a more specific rule like the following:
                # Rule: "OR('CO.admin', 'CO.client')"
            Admins:
                Type: Signature
                Rule: "OR('CO.admin')"

################################################################################
#
#   CAPABILITIES
#
#   This section defines the capabilities of fabric network. This is a new
#   concept as of v1.1.0 and should not be utilized in mixed networks with
#   v1.0.x peers and orderers.  Capabilities define features which must be
#   present in a fabric binary for that binary to safely participate in the
#   fabric network.  For instance, if a new MSP type is added, newer binaries
#   might recognize and validate the signatures from this type, while older
#   binaries without this support would be unable to validate those
#   transactions.  This could lead to different versions of the fabric binaries
#   having different world states.  Instead, defining a capability for a channel
#   informs those binaries without this capability that they must cease
#   processing transactions until they have been upgraded.  For v1.0.x if any
#   capabilities are defined (including a map with all capabilities turned off)
#   then the v1.0.x peer will deliberately crash.
#
################################################################################
Capabilities:
    # Channel capabilities apply to both the orderers and the peers and must be
    # supported by both.
    # Set the value of the capability to true to require it.
    # Note that setting a later Channel version capability to true will also
    # implicitly set prior Channel version capabilities to true. There is no need
    # to set each version capability to true (prior version capabilities remain
    # in this sample only to provide the list of valid values).
    Channel: &ChannelCapabilities
        # V2.0 for Channel is a catchall flag for behavior which has been
        # determined to be desired for all orderers and peers running at the v2.0.0
        # level, but which would be incompatible with orderers and peers from
        # prior releases.
        # Prior to enabling V2.0 channel capabilities, ensure that all
        # orderers and peers on a channel are at v2.0.0 or later.
        V2_0: true
    # Orderer capabilities apply only to the orderers, and may be safely
    # used with prior release peers.
    # Set the value of the capability to true to require it.
    Orderer: &OrdererCapabilities
        # V1.1 for Orderer is a catchall flag for behavior which has been
        # determined to be desired for all orderers running at the v1.1.x
        # level, but which would be incompatible with orderers from prior releases.
        # Prior to enabling V2.0 orderer capabilities, ensure that all
        # orderers on a channel are at v2.0.0 or later.
        V2_0: true
    # Application capabilities apply only to the peer network, and may be safely
    # used with prior release orderers.
    # Set the value of the capability to true to require it.
    # Note that setting a later Application version capability to true will also
    # implicitly set prior Application version capabilities to true. There is no need
    # to set each version capability to true (prior version capabilities remain
    # in this sample only to provide the list of valid values).
    Application: &ApplicationCapabilities
        # V2.0 for Application enables the new non-backwards compatible
        # features and fixes of fabric v2.0.
        # Prior to enabling V2.0 orderer capabilities, ensure that all
        # orderers on a channel are at v2.0.0 or later.
        V2_0: true
        
################################################################################
#
#   SECTION: Application
#
#   - This section defines the values to encode into a config transaction or
#   genesis block for application related parameters
#
################################################################################
Application: &ApplicationDefaults

    # Organizations is the list of orgs which are defined as participants on
    # the application side of the network
    Organizations:

    # Policies defines the set of policies at this level of the config tree
    # For Application policies, their canonical path is
    #   /Channel/Application/<PolicyName>
    Policies: &ApplicationDefaultPolicies
        LifecycleEndorsement:
            Type: ImplicitMeta
            Rule: "ANY Readers"
        Endorsement:
            Type: ImplicitMeta
            Rule: "ANY Readers"
        Readers:
            Type: ImplicitMeta
            Rule: "ANY Readers"
        Writers:
            Type: ImplicitMeta
            Rule: "ANY Writers"
        Admins:
            Type: ImplicitMeta
            Rule: "MAJORITY Admins"

    Capabilities:
        <<: *ApplicationCapabilities

################################################################################
#
#   CHANNEL
#
#   This section defines the values to encode into a config transaction or
#   genesis block for channel related parameters.
#
################################################################################
Channel: &ChannelDefaults
    # Policies defines the set of policies at this level of the config tree
    # For Channel policies, their canonical path is
    #   /Channel/<PolicyName>
    Policies:
        # Who may invoke the 'Deliver' API
        Readers:
            Type: ImplicitMeta
            Rule: "ANY Readers"
        # Who may invoke the 'Broadcast' API
        Writers:
            Type: ImplicitMeta
            Rule: "ANY Writers"
        # By default, who may modify elements at this config level
        Admins:
            Type: ImplicitMeta
            Rule: "MAJORITY Admins"
    # Capabilities describes the channel level capabilities, see the
    # dedicated Capabilities section elsewhere in this file for a full
    # description
    Capabilities:
        <<: *ChannelCapabilities

################################################################################
#
#   Profile
#
#   - Different configuration profiles may be encoded here to be specified
#   as parameters to the configtxgen tool
#
################################################################################
Profiles:

    N7ApplicationGenesis:
        <<: *ChannelDefaults
        Consortium: AWSSystemConsortium
        Application:
            <<: *ApplicationDefaults
            Organizations:
                - <<: *CO
```
### 2. Generate the configtx peer block
```bash
docker exec cli configtxgen -outputCreateChannelTx /opt/home/$CHANNEL.pb -profile N7ApplicationGenesis -channelID $CHANNEL --configPath /opt/home/
```
### 3. Set environment variables for the orderer
```bash
echo $OrderingServiceEndpoint
export ORDERER=orderer.n-xxxx.managedblockchain.us-east-1.amazonaws.com:30001
```
#### 3.a Add the export to ~/.bash_profile
```bash
export ORDERER=orderer.n-xxxx.managedblockchain.us-east-1.amazonaws.com:30001
source ~/.bash_profile
```
### 4. Create the channel
#### 4.a Create the channel
```bash
docker exec -e "CORE_PEER_TLS_ENABLED=true" -e "CORE_PEER_TLS_ROOTCERT_FILE=/opt/home/managedblockchain-tls-chain.pem"     -e "CORE_PEER_ADDRESS=$COPEER" -e "CORE_PEER_LOCALMSPID=$COMSP" -e "CORE_PEER_MSPCONFIGPATH=$COMSP_PATH"     cli peer channel create -c $CHANNEL -f /opt/home/$CHANNEL.pb -o $ORDERER --cafile $CAFILE --tls --timeout 900s
```
#### 4.b Check block
```bash
ls -lt /home/ec2-user/fabric-samples/chaincode/hyperledger/fabric/peer
```
#### 4.c If the channel creation times out
```bash
docker exec -e "CORE_PEER_TLS_ENABLED=true" -e "CORE_PEER_TLS_ROOTCERT_FILE=/opt/home/managedblockchain-tls-chain.pem"      -e "CORE_PEER_ADDRESS=$COPEER"  -e "CORE_PEER_LOCALMSPID=$COMSP" -e "CORE_PEER_MSPCONFIGPATH=$COMSP_PATH"     cli peer channel fetch oldest /opt/home/fabric-samples/chaincode/hyperledger/fabric/peer/$CHANNEL.block     -c $CHANNEL -o $ORDERER --cafile /opt/home/managedblockchain-tls-chain.pem --tls
```
#### 4.d Check block
```bash
ls -lt /home/ec2-user/fabric-samples/chaincode/hyperledger/fabric/peer
```
#### 4.e Copy the block to home
```bash
sudo cp /home/ec2-user/fabric-samples/chaincode/hyperledger/fabric/peer/n7ch1.block .
```
### 5. Join the peer node to the channel
```bash
docker exec -e "CORE_PEER_TLS_ENABLED=true" -e "CORE_PEER_TLS_ROOTCERT_FILE=/opt/home/managedblockchain-tls-chain.pem"     -e "CORE_PEER_ADDRESS=$COPEER" -e "CORE_PEER_LOCALMSPID=$COMSP" -e "CORE_PEER_MSPCONFIGPATH=$COMSP_PATH"     cli peer channel join -b $CHANNEL.block  -o $ORDERER --cafile $CAFILE --tls
```

## STEP 8 : Import N7 Project
### 1. Import github project
```bash
git clone https://github.com/YuntianDING001/N7.git
```
	
## STEP 9 : Install java chaincode on the channel (https://docs.aws.amazon.com/zh_cn/managed-blockchain/latest/hyperledger-fabric-dev/java-chaincode.html)
### 1. Download the Gradle Shadow plugin and add it to the chaincode project
```bash
mkdir plugin
cd plugin
wget https://plugins.gradle.org/m2/com/github/jengelman/gradle/plugins/shadow/5.1.0/shadow-5.1.0.jar
```
### 2. Configure build.gradle
```
/*
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * SPDX-License-Identifier: Apache-2.0
 */

buildscript {
    dependencies {
        classpath fileTree(dir: 'plugin', include:['*.jar'])
    }
}

plugins {
    //id 'com.github.johnrengelman.shadow' version '5.1.0'
    id 'java'
}

group 'org.hyperledger.fabric-chaincode-java'
version '1.0-SNAPSHOT'

sourceCompatibility = 1.8

repositories {
    mavenCentral()
    jcenter()
    maven {
        url 'https://jitpack.io'
    }
    maven {
        url "https://hyperledger.jfrog.io/hyperledger/fabric-maven"
    }
}

dependencies {
    compile group: 'org.hyperledger.fabric-chaincode-java', name: 'fabric-chaincode-shim', version: '2.2.1'
    implementation group: 'org.hyperledger.fabric-chaincode-java', name: 'fabric-chaincode-shim', version: '2.+'
    implementation group: 'org.json', name: 'json', version: '20220320'
    implementation 'com.owlike:genson:1.6'
    testImplementation 'org.junit.jupiter:junit-jupiter:5.9.0'
    testImplementation 'org.assertj:assertj-core:3.23.1'
    testImplementation 'org.mockito:mockito-core:4.8.0'
}

test {
    useJUnitPlatform()
    testLogging {
        events "passed", "skipped", "failed"
    }
}

apply plugin: 'com.github.johnrengelman.shadow'

shadowJar {
    baseName = 'n7code'
    version = null
    classifier = null

    manifest {
        attributes 'Main-Class': 'org.hyperledger.fabric_samples.ABstore'
    }
}

task getDeps(type: Copy) {
    from sourceSets.main.compileClasspath
    into 'libs/'
}


tasks.withType(JavaCompile) {
    options.compilerArgs << "-Xlint:unchecked" << "-Xlint:deprecation" << "-parameters"
}

targetCompatibility = JavaVersion.VERSION_1_9
```
### 2. Download dependencies and build the project
```bash
gradle getDeps
gradle build
```
### 3. Install the chaincode on the peer node
#### 3.a Packaging
```bash
docker exec -e "CORE_PEER_TLS_ENABLED=true" -e "CORE_PEER_TLS_ROOTCERT_FILE=/opt/home/managedblockchain-tls-chain.pem"     -e "CORE_PEER_ADDRESS=$COPEER" -e "CORE_PEER_LOCALMSPID=$COMSP" -e "CORE_PEER_MSPCONFIGPATH=$COMSP_PATH"     cli peer lifecycle chaincode package n7code.tar.gz -p /opt/home/N7/n7code/java/build/libs -l java --label $CHAINCODELABEL
```
#### 3.b Install
```bash
docker exec -e "CORE_PEER_TLS_ENABLED=true" -e "CORE_PEER_TLS_ROOTCERT_FILE=/opt/home/managedblockchain-tls-chain.pem"     -e "CORE_PEER_ADDRESS=$COPEER" -e "CORE_PEER_LOCALMSPID=$COMSP" -e "CORE_PEER_MSPCONFIGPATH=$COMSP_PATH"     cli peer lifecycle chaincode install n7code.tar.gz
```
#### 3.c Query chaincode and Get package ID
```bash
docker exec -e "CORE_PEER_TLS_ENABLED=true" -e "CORE_PEER_TLS_ROOTCERT_FILE=/opt/home/managedblockchain-tls-chain.pem"     -e "CORE_PEER_ADDRESS=$COPEER" -e "CORE_PEER_LOCALMSPID=$COMSP" -e "CORE_PEER_MSPCONFIGPATH=$COMSP_PATH"     cli peer lifecycle chaincode queryinstalled
export PACKAGE_ID=
```
#### 3.d Approve the chaincode definition for organisations
```bash
docker exec -e "CORE_PEER_TLS_ENABLED=true" -e "CORE_PEER_TLS_ROOTCERT_FILE=/opt/home/managedblockchain-tls-chain.pem"     -e "CORE_PEER_ADDRESS=$COPEER" -e "CORE_PEER_LOCALMSPID=$COMSP" -e "CORE_PEER_MSPCONFIGPATH=$COMSP_PATH"     cli peer lifecycle chaincode approveformyorg -o $ORDERER --tls --cafile /opt/home/managedblockchain-tls-chain.pem -C $CHANNEL -n $CHAINCODENAME -v $CHAINCODEVERSION --sequence $CHAINCODESEQUENCE --package-id $PACKAGE_ID
```
#### 3.e Check whether the chaincode definition is ready
```bash
docker exec -e "CORE_PEER_TLS_ENABLED=true" -e "CORE_PEER_TLS_ROOTCERT_FILE=/opt/home/managedblockchain-tls-chain.pem"     -e "CORE_PEER_ADDRESS=$COPEER" -e "CORE_PEER_LOCALMSPID=$COMSP" -e "CORE_PEER_MSPCONFIGPATH=$COMSP_PATH"     cli peer lifecycle chaincode checkcommitreadiness --orderer $ORDERER --tls --cafile /opt/home/managedblockchain-tls-chain.pem --channelID $CHANNEL --name $CHAINCODENAME --version $CHAINCODEVERSION --sequence $CHAINCODESEQUENCE
```
#### 3.f Commit the chaincode definition
```bash
docker exec -e "CORE_PEER_TLS_ENABLED=true" -e "CORE_PEER_TLS_ROOTCERT_FILE=/opt/home/managedblockchain-tls-chain.pem"     -e "CORE_PEER_ADDRESS=$COPEER" -e "CORE_PEER_LOCALMSPID=$COMSP" -e "CORE_PEER_MSPCONFIGPATH=$COMSP_PATH"     cli peer lifecycle chaincode commit --orderer $ORDERER --tls --cafile /opt/home/managedblockchain-tls-chain.pem --channelID $CHANNEL --name $CHAINCODENAME --version $CHAINCODEVERSION --sequence $CHAINCODESEQUENCE
```
#### 3.g Query the committed chaincode definitions
```bash
docker exec -e "CORE_PEER_TLS_ENABLED=true" -e "CORE_PEER_TLS_ROOTCERT_FILE=/opt/home/managedblockchain-tls-chain.pem"     -e "CORE_PEER_ADDRESS=$COPEER" -e "CORE_PEER_LOCALMSPID=$COMSP" -e "CORE_PEER_MSPCONFIGPATH=$COMSP_PATH"     cli peer lifecycle chaincode querycommitted --channelID $CHANNEL
```

## STEP 10 : Install java application
### 1. Build and deploy the application
```bash
sam build
source lambdaUserExport.sh
./deploy.sh
```
