FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir flask==3.1.*
COPY app.py .
ENV COWRIE_DATA=/data
EXPOSE 8080
CMD ["python", "app.py"]
