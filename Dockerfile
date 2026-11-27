FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Run as an unprivileged user. The worker needs no root: its workspaces are tmpfs mounts owned by this user.
RUN useradd --system --uid 10001 --no-create-home soc
USER 10001
EXPOSE 5000
CMD ["gunicorn", "-b", "0.0.0.0:5000", "-w", "1", "app:app"]
