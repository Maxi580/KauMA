FROM python:3.10-slim

RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /kauma

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chmod +x kauma
RUN chmod +x test.py

RUN python3 build.py

CMD ["./test.py"]