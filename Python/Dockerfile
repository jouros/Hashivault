# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY code.py /app/
COPY data.json /app/

# Make port 8080 available to the world outside this container
EXPOSE 8080

# Run serve_json.py when the container launches
CMD ["python", "./code.py"]

