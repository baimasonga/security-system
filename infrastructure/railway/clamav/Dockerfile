# Private ClamAV daemon for upload quarantine (ADR-021). Deploy as its own Railway service with no public domain;
# the API reaches it at <service>.railway.internal:3310 (CLAMD_HOST / CLAMD_PORT).
FROM clamav/clamav:stable
# Files larger than StreamMaxLength fail the scan, and the platform then rejects them (fail closed). Keep this at least
# as large as the biggest plan's share_max_file_bytes (free plan: 250 MB).
RUN sed -i -E 's/^#?\s*StreamMaxLength.*/StreamMaxLength 300M/' /etc/clamav/clamd.conf \
 && (grep -q '^StreamMaxLength' /etc/clamav/clamd.conf || echo 'StreamMaxLength 300M' >> /etc/clamav/clamd.conf)
EXPOSE 3310
