import os


bind = f"0.0.0.0:{os.environ.get('PORT', '10000')}"
worker_class = "gthread"
workers = 1
threads = 4
timeout = 30
graceful_timeout = 30
keepalive = 5
max_requests = 1000
max_requests_jitter = 100
limit_request_line = 4094
limit_request_fields = 100
umask = 0o077
accesslog = None
errorlog = "-"
loglevel = "info"
capture_output = True
