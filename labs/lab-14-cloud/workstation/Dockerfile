# Cloud attacker workstation: awscli configured to hit the local LocalStack simulation.
FROM python:3.12-slim
RUN pip install --no-cache-dir awscli awscli-local 2>/dev/null || pip install --no-cache-dir awscli
ENV AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1 \
    AWS_ENDPOINT_URL=http://localstack:4566
CMD ["sh","-c","echo 'cloud workstation up. Use: aws --endpoint-url $AWS_ENDPOINT_URL s3 ls'; sleep infinity"]
