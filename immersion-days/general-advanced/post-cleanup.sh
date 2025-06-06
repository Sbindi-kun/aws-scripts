#!/bin/bash
# This script is executed when an execution of AWS Nuke (via CodeBuild reset account job) finished successfully.
# It provides the opportunity to re-create default resources or cleanup stuff AWS Nuke was not aware of.

echo "Executing post-cleanup script"

# wait some time for last AWS Nuke API calls to finish
sleep 30

# assume role in AWS account that has just been cleaned up
echo "Assuming role in account $RESET_ACCOUNT"
aws sts assume-role --role-arn arn:aws:iam::$RESET_ACCOUNT:role/$RESET_ACCOUNT_ADMIN_ROLE_NAME --role-session-name NukeProcess > cred.json 
export s=$(jq -r '.Credentials.AccessKeyId' cred.json) 
export y=$(jq -r '.Credentials.SecretAccessKey' cred.json) 
export z=$(jq -r '.Credentials.SessionToken' cred.json)
export AWS_ACCESS_KEY_ID=$s
export AWS_SECRET_ACCESS_KEY=$y
export AWS_SESSION_TOKEN=$z

# re-create the default VPCs that have been removed by AWS Nuke before
echo "Creating default VPCs in us-east-1 and us-west-2 in account $RESET_ACCOUNT"
aws ec2 create-default-vpc --region us-east-1
aws ec2 create-default-vpc --region us-west-2

# Delete IAM resources
echo "Deleting IAM resources..."

# Delete IAM policy ReadSecrets
echo "Deleting IAM policy: ReadSecrets"
POLICY_ARN="arn:aws:iam::$RESET_ACCOUNT:policy/ReadSecrets"

# First, detach the policy from all users
echo "Detaching ReadSecrets policy from users"
ATTACHED_USERS=$(aws iam list-entities-for-policy --policy-arn $POLICY_ARN --entity-filter User --query 'PolicyUsers[].UserName' --output text 2>/dev/null)
if [ ! -z "$ATTACHED_USERS" ]; then
    for user_name in $ATTACHED_USERS; do
        echo "Detaching policy from user: $user_name"
        aws iam detach-user-policy --user-name $user_name --policy-arn $POLICY_ARN
    done
fi

# Detach the policy from all groups
echo "Detaching ReadSecrets policy from groups"
ATTACHED_GROUPS=$(aws iam list-entities-for-policy --policy-arn $POLICY_ARN --entity-filter Group --query 'PolicyGroups[].GroupName' --output text 2>/dev/null)
if [ ! -z "$ATTACHED_GROUPS" ]; then
    for group_name in $ATTACHED_GROUPS; do
        echo "Detaching policy from group: $group_name"
        aws iam detach-group-policy --group-name $group_name --policy-arn $POLICY_ARN
    done
fi

# Detach the policy from all roles
echo "Detaching ReadSecrets policy from roles"
ATTACHED_ROLES=$(aws iam list-entities-for-policy --policy-arn $POLICY_ARN --entity-filter Role --query 'PolicyRoles[].RoleName' --output text 2>/dev/null)
if [ ! -z "$ATTACHED_ROLES" ]; then
    for role_name in $ATTACHED_ROLES; do
        echo "Detaching policy from role: $role_name"
        aws iam detach-role-policy --role-name $role_name --policy-arn $POLICY_ARN
    done
fi

# Finally, delete the policy
aws iam delete-policy --policy-arn $POLICY_ARN
if [ $? -eq 0 ]; then
    echo "Successfully deleted IAM policy: ReadSecrets"
else
    echo "Failed to delete IAM policy: ReadSecrets (may not exist)"
fi

# Delete IAM role SSMInstanceProfile
echo "Deleting IAM role: SSMInstanceProfile"

# First, detach all managed policies from the role
echo "Detaching managed policies from role: SSMInstanceProfile"
ATTACHED_POLICIES=$(aws iam list-attached-role-policies --role-name SSMInstanceProfile --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null)
if [ ! -z "$ATTACHED_POLICIES" ]; then
    for policy_arn in $ATTACHED_POLICIES; do
        echo "Detaching policy: $policy_arn"
        aws iam detach-role-policy --role-name SSMInstanceProfile --policy-arn $policy_arn
    done
fi

# Delete inline policies from the role
echo "Deleting inline policies from role: SSMInstanceProfile"
INLINE_POLICIES=$(aws iam list-role-policies --role-name SSMInstanceProfile --query 'PolicyNames[]' --output text 2>/dev/null)
if [ ! -z "$INLINE_POLICIES" ]; then
    for policy_name in $INLINE_POLICIES; do
        echo "Deleting inline policy: $policy_name"
        aws iam delete-role-policy --role-name SSMInstanceProfile --policy-name $policy_name
    done
fi

# Remove role from any instance profiles
echo "Checking for instance profiles containing role: SSMInstanceProfile"
INSTANCE_PROFILES=$(aws iam list-instance-profiles-for-role --role-name SSMInstanceProfile --query 'InstanceProfiles[].InstanceProfileName' --output text 2>/dev/null)
if [ ! -z "$INSTANCE_PROFILES" ]; then
    for profile_name in $INSTANCE_PROFILES; do
        echo "Removing role from instance profile: $profile_name"
        aws iam remove-role-from-instance-profile --instance-profile-name $profile_name --role-name SSMInstanceProfile
    done
fi

# Finally, delete the role
aws iam delete-role --role-name SSMInstanceProfile
if [ $? -eq 0 ]; then
    echo "Successfully deleted IAM role: SSMInstanceProfile"
else
    echo "Failed to delete IAM role: SSMInstanceProfile (may not exist)"
fi

echo "IAM cleanup completed"
