#Deriving the latest base image
FROM python:latest

WORKDIR /app

COPY . .

CMD [ "python3", "src/manage.py"]
