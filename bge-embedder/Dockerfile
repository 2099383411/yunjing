FROM python:3.12-slim

RUN pip config set global.index-url https://mirrors.aliyun.com/pypi/simple && \
    pip config set global.trusted-host mirrors.aliyun.com

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libffi-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cu128

RUN pip install --no-cache-dir \
    sentence-transformers \
    fastapi \
    uvicorn[standard] \
    pydantic

# 设置 hf-mirror 镜像，方便运行时下载（如有需要）
ENV HF_ENDPOINT=https://hf-mirror.com

COPY server.py /app/server.py

EXPOSE 8000

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
