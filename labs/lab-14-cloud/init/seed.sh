#!/bin/bash
# LocalStack init hook (runs when ready). Seeds a DELIBERATELY misconfigured local AWS
# simulation for M14. LAB ONLY — synthetic, benign LAB-FLAG markers. `awslocal` targets
# the in-container LocalStack endpoint.
set -e
echo "[seed] creating public bucket + objects"
awslocal s3 mb s3://northwind-public
echo "LAB-FLAG-cloud-public-bucket" > /tmp/flag.txt
awslocal s3 cp /tmp/flag.txt s3://northwind-public/backups/flag.txt
# make the bucket world-readable (the misconfig)
awslocal s3api put-bucket-acl --bucket northwind-public --acl public-read || true

echo "[seed] creating a private bucket (should NOT be public)"
awslocal s3 mb s3://northwind-secrets
echo "LAB-FLAG-cloud-private-only" > /tmp/secret.txt
awslocal s3 cp /tmp/secret.txt s3://northwind-secrets/db-creds.txt

echo "[seed] creating an IAM user with an over-permissive policy"
awslocal iam create-user --user-name lowpriv || true
awslocal iam put-user-policy --user-name lowpriv --policy-name toobroad \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:*","s3:*","sts:AssumeRole"],"Resource":"*"}]}' || true
awslocal iam create-access-key --user-name lowpriv > /tmp/lowpriv-key.json || true

echo "[seed] creating an admin role with a benign flag in its description"
awslocal iam create-role --role-name admin-role \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}' \
  --description "LAB-FLAG-cloud-assumed-admin-role" || true
echo "[seed] done"
