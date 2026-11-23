# 의도적으로 취약한 실습용 웹. 팀 격리망에서만 사용.
FROM python:3.12-slim

WORKDIR /app
COPY app.py /app/app.py

EXPOSE 80
CMD ["python", "/app/app.py"]
