FROM python:3.12-slim
WORKDIR /app
COPY probe.py /app/
# ALL probing in the build stage RUN — stdout is captured verbatim in Helm7 build_log.
RUN python3 /app/probe.py 2>&1 | head -c 8192
# Runtime: minimal, just in case
EXPOSE 3000
CMD ["sleep","infinity"]