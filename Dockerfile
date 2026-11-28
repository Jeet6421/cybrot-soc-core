FROM python:3.12.16-slim
WORKDIR /app
# Read-only root filesystems are used at runtime, so do not write .pyc files into the image or the mounts.
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Run as an unprivileged user. The worker needs no root: its workspaces are tmpfs mounts owned by this user.
RUN useradd --system --uid 10001 --no-create-home soc
USER 10001
EXPOSE 5000
CMD ["gunicorn", "-b", "0.0.0.0:5000", "-w", "1", "app:app"]
