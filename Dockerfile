FROM python:3.10-slim

WORKDIR /kauma

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN ls -la
RUN ls -la testcases/

RUN chmod +x kauma
RUN chmod +x test.py

CMD ["./test.py"]